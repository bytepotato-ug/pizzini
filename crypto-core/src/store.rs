//! Per-device libsignal session store. Each Pizzini install owns one
//! `DeviceStore`; peers exchange PreKey bundles out-of-band (QR), then
//! encrypt/decrypt via wire-format ciphertexts shipped over a relay.
//!
//! Bundle wire format (`v2`, big-endian):
//!
//! ```text
//! u8  version = 2
//! u32 registration_id
//! u32 device_id
//! u8  has_one_time_prekey       (0 or 1)
//! [ if has_one_time_prekey: ]
//!   u32 one_time_pre_key_id
//!   u16 one_time_pre_key_public_len + bytes
//! u32 signed_pre_key_id
//! u16 signed_pre_key_public_len + bytes
//! u16 signed_pre_key_signature_len + bytes
//! u32 kyber_pre_key_id
//! u32 kyber_pre_key_public_len + bytes   (Kyber1024 ≈ 1568 B)
//! u16 kyber_pre_key_signature_len + bytes
//! u16 identity_key_len + bytes           (33 B, X25519 public)
//! u16 delivery_token_verify_key_len + bytes  (33 B, libsignal PublicKey
//!                                              serialize() — 1-byte DJB
//!                                              type prefix + 32-byte point)
//! ```
//!
//! `delivery_token_verify_key` is the recipient's per-pair-issuer side of
//! Phase 3's delivery-token system: tokens minted for THIS peer carry an
//! XEd25519 signature whose verifier is this key. The signing half is
//! derived deterministically via HKDF-SHA512 from the IdentityKeyPair, so
//! a Keychain restore reconstructs both keys without a separate secret.
//!
//! Hand-rolled rather than protobuf to keep the dependency surface minimal —
//! libsignal does not export a wire-stable bundle encoder.
//!
//! Store snapshot wire format (`v2`, big-endian):
//!
//! ```text
//! u8  store_version = 2
//! u32 identity_keypair_len + bytes
//! u32 registration_id
//! u32 next_pre_key_id
//! u32 next_signed_pre_key_id
//! u32 next_kyber_pre_key_id
//! u32 peer_count
//!   for each peer:
//!     u16 peer_identity_pub_len + bytes (33)
//! u32 pre_key_count
//!   for each pre_key:
//!     u32 id
//!     u32 record_len + bytes
//! u32 signed_pre_key_count        (same shape as pre_key list)
//! u32 kyber_pre_key_count         (same shape)
//! u32 session_count
//!   for each session:
//!     u16 peer_identity_pub_len + bytes
//!     u32 session_record_len + bytes
//! u32 sender_certificate_len + bytes  (0 if not yet minted)
//! ```
//!
//! v1 blobs (no trailing sender-certificate) deserialize by treating the
//! cert as absent — `ensure_sender_certificate` mints fresh on demand.

use std::time::SystemTime;

use futures_util::FutureExt as _;
use hkdf::Hkdf;
use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, ContentHint, DeviceId, GenericSignedPreKey,
    IdentityKey, IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore, KeyPair,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyRecord, PreKeySignalMessage,
    PreKeyStore, PrivateKey, ProtocolAddress, PublicKey, SenderCertificate, ServerCertificate,
    SessionRecord, SessionStore, SignalMessage, SignalProtocolError, SignedPreKeyRecord,
    SignedPreKeyStore, Timestamp, UnidentifiedSenderMessageContent, kem, message_decrypt,
    message_encrypt, sealed_sender_decrypt_to_usmc, sealed_sender_encrypt_from_usmc,
    process_prekey_bundle,
};
use rand::{Rng, TryRngCore as _, rngs::OsRng};
use sha2::Sha512;

const BUNDLE_VERSION: u8 = 2;
const STORE_VERSION: u8 = 2;
const DEVICE_ID: u8 = 1;

/// Self-signed SenderCertificate validity. Long enough that a peer who
/// goes offline for a few weeks can still send without a refresh round
/// trip; short enough that a forgotten device's certs lapse on their own.
const SENDER_CERT_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Mint a fresh cert if the cached one is within this window of expiry,
/// so we never sign an envelope with a cert about to lapse mid-flight.
const SENDER_CERT_REFRESH_MARGIN_MS: u64 = 24 * 60 * 60 * 1000;
/// HKDF info string for the long-term delivery-token signing key. Stable
/// across versions: rotating it is equivalent to rotating every peer's
/// stash in lock-step, which we don't want as a side effect of an
/// unrelated change.
const DELIVERY_TOKEN_HKDF_INFO: &[u8] = b"pizzini.delivery-token.v1";

/// libsignal-native public-key wire size: 1-byte DJB type prefix + 32-byte
/// Curve25519 point. The bundle field carries exactly this many bytes;
/// rejecting other sizes keeps the relay's per-recipient verify-key table
/// predictable, and any future migration to a different curve flavour
/// will trip the size check loudly instead of silently mis-verifying.
pub const DELIVERY_TOKEN_VERIFY_KEY_LEN: usize = 33;

pub struct DeviceStore {
    inner: InMemSignalProtocolStore,
    next_pre_key_id: u32,
    next_signed_pre_key_id: u32,
    next_kyber_pre_key_id: u32,
    /// Identity-public bytes for every peer we've ever set up an outbound
    /// session with (initiate_session) or accepted an inbound PreKey from
    /// (decrypt). The list is the index used during `serialize` to enumerate
    /// libsignal session records — InMemSessionStore exposes no iterator.
    peers: Vec<Vec<u8>>,
    /// Cached SenderCertificate for sealed-sender SENDs. Lazily minted by
    /// `ensure_sender_certificate`; persisted by `serialize`. Refreshed
    /// when within `SENDER_CERT_REFRESH_MARGIN_MS` of expiry so an
    /// in-flight envelope never carries a just-lapsed cert.
    sender_certificate: Option<SenderCertificate>,
}

pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub is_prekey: bool,
}

/// Result of `seal_receive`: the claimed sender's identity_pub (verified
/// against the embedded cert), the 16-byte message_id (extracted from the
/// USMC contents header — the relay never sees this), and the inner
/// plaintext.
#[derive(Debug)]
pub struct SealReceived {
    pub sender_identity_pub: Vec<u8>,
    pub message_id: [u8; 16],
    pub plaintext: Vec<u8>,
}

impl DeviceStore {
    pub fn fresh() -> Result<Self, SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let id = IdentityKeyPair::generate(&mut rng);
        let reg = registration_id(&mut rng);
        Ok(Self {
            inner: InMemSignalProtocolStore::new(id, reg)?,
            next_pre_key_id: 1,
            next_signed_pre_key_id: 1,
            next_kyber_pre_key_id: 1,
            peers: Vec::new(),
            sender_certificate: None,
        })
    }

    /// Rehydrate from a previously-saved IdentityKeyPair (i.e. the bytes from
    /// `identity_keypair_bytes`). Registration id is freshly drawn and any
    /// prior session/prekey state is lost — for full continuity use
    /// `from_serialized` instead.
    pub fn from_identity(seed_bytes: &[u8]) -> Result<Self, SignalProtocolError> {
        let id = IdentityKeyPair::try_from(seed_bytes)?;
        let mut rng = OsRng.unwrap_err();
        let reg = registration_id(&mut rng);
        Ok(Self {
            inner: InMemSignalProtocolStore::new(id, reg)?,
            next_pre_key_id: 1,
            next_signed_pre_key_id: 1,
            next_kyber_pre_key_id: 1,
            peers: Vec::new(),
            sender_certificate: None,
        })
    }

    pub fn identity_keypair_bytes(&self) -> Vec<u8> {
        self.local_identity_keypair().serialize().to_vec()
    }

    /// 33-byte serialized IdentityKey (the public half). Used as the routing
    /// peer-id and as the `name` in libsignal's ProtocolAddress (hex-encoded).
    pub fn identity_public_bytes(&self) -> Vec<u8> {
        self.local_identity_keypair().identity_key().serialize().to_vec()
    }

    pub fn registration_id(&self) -> u32 {
        self.inner
            .identity_store
            .get_local_registration_id()
            .now_or_never()
            .expect("in-mem store is sync")
            .expect("infallible for in-mem identity store")
    }

    pub fn local_identity_keypair(&self) -> IdentityKeyPair {
        self.inner
            .identity_store
            .get_identity_key_pair()
            .now_or_never()
            .expect("in-mem store is sync")
            .expect("infallible for in-mem identity store")
    }

    /// Direct access to the underlying libsignal store. Used by the sealed-
    /// sender feasibility test (`tests/sealed_sender.rs`) which drives the
    /// libsignal sealed-sender API directly. Phase 1 wraps this with
    /// proper `seal_send`/`seal_receive` methods on DeviceStore.
    pub fn inner_mut(&mut self) -> &mut InMemSignalProtocolStore {
        &mut self.inner
    }

    /// Derive the long-term delivery-token signing keypair from the
    /// IdentityKeyPair via HKDF-SHA512. Deterministic, so a Keychain
    /// restore reconstructs exactly the same key — peers' stashes
    /// keep verifying after a reinstall without an extra refresh round.
    /// XEd25519 (libsignal's PrivateKey.calculate_signature) is used for
    /// signatures; the recipient publishes the public half in their bundle.
    pub fn delivery_token_keypair(&self) -> Result<KeyPair, SignalProtocolError> {
        let id_kp = self.local_identity_keypair();
        let ikm = id_kp.serialize();
        let hk = Hkdf::<Sha512>::new(None, &ikm);
        let mut seed = [0u8; 32];
        hk.expand(DELIVERY_TOKEN_HKDF_INFO, &mut seed)
            .expect("32-byte expand never overflows HKDF-SHA512");
        let private_key = PrivateKey::deserialize(&seed)?;
        let public_key = private_key.public_key()?;
        Ok(KeyPair::new(public_key, private_key))
    }

    pub fn delivery_token_verify_key_bytes(&self) -> Result<Vec<u8>, SignalProtocolError> {
        Ok(self.delivery_token_keypair()?.public_key.serialize().to_vec())
    }

    pub fn publish_bundle(&mut self) -> Result<Vec<u8>, SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let id_kp = self.local_identity_keypair();
        let token_verify_key = self.delivery_token_verify_key_bytes()?;

        let pre_id = self.next_pre_key_id;
        self.next_pre_key_id = next_id(self.next_pre_key_id);
        let pre_kp = KeyPair::generate(&mut rng);
        self.inner
            .save_pre_key(pre_id.into(), &PreKeyRecord::new(pre_id.into(), &pre_kp))
            .now_or_never()
            .expect("in-mem store is sync")?;

        let signed_id = self.next_signed_pre_key_id;
        self.next_signed_pre_key_id = next_id(self.next_signed_pre_key_id);
        let signed_kp = KeyPair::generate(&mut rng);
        let signed_sig = id_kp
            .private_key()
            .calculate_signature(&signed_kp.public_key.serialize(), &mut rng)?;
        self.inner
            .save_signed_pre_key(
                signed_id.into(),
                &SignedPreKeyRecord::new(
                    signed_id.into(),
                    Timestamp::from_epoch_millis(now_millis()),
                    &signed_kp,
                    &signed_sig,
                ),
            )
            .now_or_never()
            .expect("in-mem store is sync")?;

        let kyber_id = self.next_kyber_pre_key_id;
        self.next_kyber_pre_key_id = next_id(self.next_kyber_pre_key_id);
        let kyber_kp = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
        let kyber_sig = id_kp
            .private_key()
            .calculate_signature(&kyber_kp.public_key.serialize(), &mut rng)?;
        self.inner
            .save_kyber_pre_key(
                kyber_id.into(),
                &KyberPreKeyRecord::new(
                    kyber_id.into(),
                    Timestamp::from_epoch_millis(now_millis()),
                    &kyber_kp,
                    &kyber_sig,
                ),
            )
            .now_or_never()
            .expect("in-mem store is sync")?;

        Ok(encode_bundle(
            self.registration_id(),
            DEVICE_ID as u32,
            (pre_id, &pre_kp.public_key),
            signed_id,
            &signed_kp.public_key,
            &signed_sig,
            kyber_id,
            &kyber_kp.public_key,
            &kyber_sig,
            id_kp.identity_key(),
            &token_verify_key,
        ))
    }

    pub fn initiate_session(
        &mut self,
        peer_identity: &[u8],
        bundle_bytes: &[u8],
    ) -> Result<(), SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let decoded = decode_bundle(bundle_bytes)?;
        let bundle = &decoded.bundle;
        let bundle_identity = bundle.identity_key()?;
        let provided_identity = IdentityKey::decode(peer_identity)?;
        if bundle_identity.serialize() != provided_identity.serialize() {
            return Err(SignalProtocolError::InvalidArgument(
                "peer identity does not match bundle identity_key".into(),
            ));
        }
        let peer_addr = address_for(peer_identity);
        let local_addr = address_for(&self.identity_public_bytes());
        process_prekey_bundle(
            &peer_addr,
            &local_addr,
            &mut self.inner.session_store,
            &mut self.inner.identity_store,
            bundle,
            SystemTime::now(),
            &mut rng,
        )
        .now_or_never()
        .expect("in-mem store is sync")?;
        self.register_peer(peer_identity);
        // Phase 3 stores `decoded.delivery_token_verify_key` per-peer for
        // out-of-band sanity checks; for Phase 1 we just verified it
        // decoded to the right size.
        let _ = decoded.delivery_token_verify_key;
        Ok(())
    }

    /// Idempotently track an identity_pub. Used both internally (whenever a
    /// session lands in libsignal's session store) and from the FFI when the
    /// host wants to pre-seed a peer (e.g. right after a QR scan, before the
    /// actual handshake — so the peer survives `serialize`/`from_serialized`
    /// even if the session never completed).
    pub fn register_peer(&mut self, peer_identity: &[u8]) {
        if !self.peers.iter().any(|p| p.as_slice() == peer_identity) {
            self.peers.push(peer_identity.to_vec());
        }
    }

    pub fn forget_peer(&mut self, peer_identity: &[u8]) {
        self.peers.retain(|p| p.as_slice() != peer_identity);
        // Also drop the libsignal session and known-identity entry so a
        // future inbound message can't silently resume the chat.
        let addr = address_for(peer_identity);
        let _ = self
            .inner
            .session_store
            .store_session(&addr, &SessionRecord::new_fresh())
            .now_or_never();
    }

    pub fn encrypt(
        &mut self,
        peer_identity: &[u8],
        plaintext: &[u8],
    ) -> Result<EncryptResult, SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let peer_addr = address_for(peer_identity);
        let local_addr = address_for(&self.identity_public_bytes());
        let outgoing = message_encrypt(
            plaintext,
            &peer_addr,
            &local_addr,
            &mut self.inner.session_store,
            &mut self.inner.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .now_or_never()
        .expect("in-mem store is sync")?;
        let is_prekey = outgoing.message_type() == CiphertextMessageType::PreKey;
        Ok(EncryptResult {
            ciphertext: outgoing.serialize().to_vec(),
            is_prekey,
        })
    }

    pub fn decrypt(
        &mut self,
        peer_identity: &[u8],
        ciphertext: &[u8],
        is_prekey: bool,
    ) -> Result<Vec<u8>, SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let peer_addr = address_for(peer_identity);
        let local_addr = address_for(&self.identity_public_bytes());
        let parsed = if is_prekey {
            CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(ciphertext)?)
        } else {
            CiphertextMessage::SignalMessage(SignalMessage::try_from(ciphertext)?)
        };
        let pt = message_decrypt(
            &parsed,
            &peer_addr,
            &local_addr,
            &mut self.inner.session_store,
            &mut self.inner.identity_store,
            &mut self.inner.pre_key_store,
            &self.inner.signed_pre_key_store,
            &mut self.inner.kyber_pre_key_store,
            &mut rng,
        )
        .now_or_never()
        .expect("in-mem store is sync")?;
        self.register_peer(peer_identity);
        Ok(pt)
    }

    /// Mint a fresh self-signed SenderCertificate if the cached one is
    /// missing or within `SENDER_CERT_REFRESH_MARGIN_MS` of expiry. The
    /// trust chain collapses onto the IdentityKeyPair: trust root,
    /// ServerCertificate.key, and SenderCertificate signer all resolve
    /// to the local identity, which is the no-CA shape that Phase 0
    /// proved feasible against libsignal v0.93.2.
    fn ensure_sender_certificate_inner(
        &mut self,
    ) -> Result<&SenderCertificate, SignalProtocolError> {
        let now = now_millis();
        let needs_mint = match &self.sender_certificate {
            None => true,
            Some(cert) => {
                let exp = cert.expiration()?.epoch_millis();
                exp <= now || exp - now <= SENDER_CERT_REFRESH_MARGIN_MS
            }
        };
        if needs_mint {
            let mut rng = OsRng.unwrap_err();
            let id_kp = self.local_identity_keypair();
            let id_pub = *id_kp.public_key();
            let id_priv = id_kp.private_key();
            // Self-signed ServerCertificate: trust root signs the cert
            // body. We use our own identity at every level (server-cert
            // key, sender-cert signer) — Phase 0 verified this collapses
            // cleanly through libsignal's two-tier validate().
            let server_cert =
                ServerCertificate::new(/*key_id=*/ 1, id_pub, id_priv, &mut rng)?;
            let expiration = Timestamp::from_epoch_millis(now + SENDER_CERT_TTL_MS);
            let sender_cert = SenderCertificate::new(
                hex_lower(&self.identity_public_bytes()),
                None,
                id_pub,
                DeviceId::new(DEVICE_ID).expect("device id non-zero"),
                expiration,
                server_cert,
                id_priv,
                &mut rng,
            )?;
            self.sender_certificate = Some(sender_cert);
        }
        Ok(self
            .sender_certificate
            .as_ref()
            .expect("just minted or already cached"))
    }

    /// Public form for the FFI. Returns the wire-format cert bytes. Mostly
    /// useful as a debug surface; production callers reach `seal_send`
    /// directly which calls this internally on every send.
    pub fn ensure_sender_certificate(&mut self) -> Result<Vec<u8>, SignalProtocolError> {
        let cert = self.ensure_sender_certificate_inner()?;
        Ok(cert.serialized()?.to_vec())
    }

    /// Sealed-sender SEND. Wraps `plaintext` in a libsignal ratchet
    /// ciphertext, sandwiches `(message_id, is_prekey, ratchet_ct)` into
    /// the `UnidentifiedSenderMessageContent.contents`, and seals to
    /// `peer_identity_pub`. The 16-byte `message_id` rides at the USMC
    /// layer (not inside the ratchet) so the recipient can dedup before
    /// advancing the ratchet.
    pub fn seal_send(
        &mut self,
        peer_identity: &[u8],
        message_id: &[u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SignalProtocolError> {
        // Mint/refresh the cert first; subsequent ratchet step doesn't
        // re-borrow the cert struct so we drop the &-borrow eagerly.
        let cert = self.ensure_sender_certificate_inner()?.clone();
        let mut rng = OsRng.unwrap_err();
        let peer_addr = address_for(peer_identity);
        let local_addr = address_for(&self.identity_public_bytes());
        let inner = message_encrypt(
            plaintext,
            &peer_addr,
            &local_addr,
            &mut self.inner.session_store,
            &mut self.inner.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .now_or_never()
        .expect("in-mem store is sync")?;
        let is_prekey = inner.message_type() == CiphertextMessageType::PreKey;

        let mut content = Vec::with_capacity(16 + 1 + inner.serialize().len());
        content.extend_from_slice(message_id);
        content.push(if is_prekey { 1 } else { 0 });
        content.extend_from_slice(inner.serialize());

        let usmc = UnidentifiedSenderMessageContent::new(
            inner.message_type(),
            cert,
            content,
            ContentHint::Default,
            None,
        )?;

        sealed_sender_encrypt_from_usmc(
            &peer_addr,
            &usmc,
            &self.inner.identity_store,
            &mut rng,
        )
        .now_or_never()
        .expect("in-mem store is sync")
    }

    /// Sealed-sender RECEIVE. Opens the envelope, looks the claimed
    /// sender's identity_pub up in our trusted peers list, validates the
    /// embedded cert against THAT identity (so a forged cert claiming a
    /// known peer but signed by anyone else fails), then unwraps the
    /// inner ratchet ciphertext.
    ///
    /// Returns the verified sender identity_pub, the 16-byte message_id
    /// (caller owns dedup), and the inner plaintext.
    pub fn seal_receive(
        &mut self,
        sealed: &[u8],
    ) -> Result<SealReceived, SignalProtocolError> {
        let usmc = sealed_sender_decrypt_to_usmc(sealed, &self.inner.identity_store)
            .now_or_never()
            .expect("in-mem store is sync")?;

        let claimed_pub = usmc.sender()?.key()?;
        let claimed_bytes = IdentityKey::new(claimed_pub).serialize().to_vec();

        // Contact gate: refuse to advance the ratchet for an unknown
        // peer. The relay's rules around bundle exchange + first-contact
        // PoW already forbid this in steady state, but we defend in
        // depth here too — a malicious relay could otherwise inject
        // sealed envelopes from arbitrary identities.
        let trusted = self.peers.iter().any(|p| p.as_slice() == claimed_bytes.as_slice());
        if !trusted {
            return Err(SignalProtocolError::InvalidArgument(
                "sealed sender claim does not match a known contact".into(),
            ));
        }

        let trust_root = IdentityKey::decode(&claimed_bytes)?;
        let validation_time = Timestamp::from_epoch_millis(now_millis());
        if !usmc.sender()?.validate(trust_root.public_key(), validation_time)? {
            return Err(SignalProtocolError::InvalidArgument(
                "sealed sender certificate does not validate against the contact's identity".into(),
            ));
        }

        let inner_bytes = usmc.contents()?;
        if inner_bytes.len() < 17 {
            return Err(SignalProtocolError::InvalidArgument(
                "sealed sender inner content shorter than message_id||is_prekey header".into(),
            ));
        }
        let mut message_id = [0u8; 16];
        message_id.copy_from_slice(&inner_bytes[..16]);
        let is_prekey = inner_bytes[16] != 0;
        let ratchet = &inner_bytes[17..];

        let parsed = if is_prekey {
            CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(ratchet)?)
        } else {
            CiphertextMessage::SignalMessage(SignalMessage::try_from(ratchet)?)
        };
        let mut rng = OsRng.unwrap_err();
        let sender_addr = address_for(&claimed_bytes);
        let local_addr = address_for(&self.identity_public_bytes());
        let pt = message_decrypt(
            &parsed,
            &sender_addr,
            &local_addr,
            &mut self.inner.session_store,
            &mut self.inner.identity_store,
            &mut self.inner.pre_key_store,
            &self.inner.signed_pre_key_store,
            &mut self.inner.kyber_pre_key_store,
            &mut rng,
        )
        .now_or_never()
        .expect("in-mem store is sync")?;

        Ok(SealReceived {
            sender_identity_pub: claimed_bytes,
            message_id,
            plaintext: pt,
        })
    }

    /// Snapshot the entire libsignal store + ratchet state to a versioned
    /// binary blob. Pair with `from_serialized` for full session continuity
    /// across launches. Format documented at the top of this module.
    pub fn serialize(&self) -> Result<Vec<u8>, SignalProtocolError> {
        let mut out = Vec::with_capacity(8192);
        out.push(STORE_VERSION);
        let id_kp = self.local_identity_keypair();
        write_u32_blob(&mut out, &id_kp.serialize());
        out.extend_from_slice(&self.registration_id().to_be_bytes());
        out.extend_from_slice(&self.next_pre_key_id.to_be_bytes());
        out.extend_from_slice(&self.next_signed_pre_key_id.to_be_bytes());
        out.extend_from_slice(&self.next_kyber_pre_key_id.to_be_bytes());

        out.extend_from_slice(&(self.peers.len() as u32).to_be_bytes());
        for peer in &self.peers {
            write_u16_blob(&mut out, peer);
        }

        let pre_key_ids: Vec<u32> = self
            .inner
            .pre_key_store
            .all_pre_key_ids()
            .map(|id| (*id).into())
            .collect();
        out.extend_from_slice(&(pre_key_ids.len() as u32).to_be_bytes());
        for id in pre_key_ids {
            let record = self
                .inner
                .pre_key_store
                .get_pre_key(id.into())
                .now_or_never()
                .expect("in-mem store is sync")?;
            out.extend_from_slice(&id.to_be_bytes());
            write_u32_blob(&mut out, &record.serialize()?);
        }

        let spk_ids: Vec<u32> = self
            .inner
            .signed_pre_key_store
            .all_signed_pre_key_ids()
            .map(|id| (*id).into())
            .collect();
        out.extend_from_slice(&(spk_ids.len() as u32).to_be_bytes());
        for id in spk_ids {
            let record = self
                .inner
                .signed_pre_key_store
                .get_signed_pre_key(id.into())
                .now_or_never()
                .expect("in-mem store is sync")?;
            out.extend_from_slice(&id.to_be_bytes());
            write_u32_blob(&mut out, &record.serialize()?);
        }

        let kpk_ids: Vec<u32> = self
            .inner
            .kyber_pre_key_store
            .all_kyber_pre_key_ids()
            .map(|id| (*id).into())
            .collect();
        out.extend_from_slice(&(kpk_ids.len() as u32).to_be_bytes());
        for id in kpk_ids {
            let record = self
                .inner
                .kyber_pre_key_store
                .get_kyber_pre_key(id.into())
                .now_or_never()
                .expect("in-mem store is sync")?;
            out.extend_from_slice(&id.to_be_bytes());
            write_u32_blob(&mut out, &record.serialize()?);
        }

        let mut session_entries = Vec::new();
        for peer in &self.peers {
            let addr = address_for(peer);
            if let Some(session) = self
                .inner
                .session_store
                .load_session(&addr)
                .now_or_never()
                .expect("in-mem store is sync")?
            {
                let bytes = session.serialize()?;
                if !bytes.is_empty() {
                    session_entries.push((peer.clone(), bytes));
                }
            }
        }
        out.extend_from_slice(&(session_entries.len() as u32).to_be_bytes());
        for (peer, bytes) in &session_entries {
            write_u16_blob(&mut out, peer);
            write_u32_blob(&mut out, bytes);
        }

        // Sender certificate: empty blob if not yet minted. Re-mint on
        // demand is cheap (an extra signature on next seal_send), so the
        // common-case "store hasn't sent anything yet" path is covered
        // without forcing a mint at serialize time.
        let cert_bytes: &[u8] = match self.sender_certificate.as_ref() {
            Some(c) => c.serialized()?,
            None => &[],
        };
        write_u32_blob(&mut out, cert_bytes);

        Ok(out)
    }

    pub fn from_serialized(bytes: &[u8]) -> Result<Self, SignalProtocolError> {
        let mut r = Cursor::new(bytes);
        let version = r.u8()?;
        // v1 blobs (no trailing sender-certificate field) are accepted —
        // they pre-date Phase 1, were already in production Keychains,
        // and migrate transparently because the cert is mintable on
        // demand. Anything past v2 is genuinely from-the-future and
        // refuses to load.
        if version != STORE_VERSION && version != 1 {
            return Err(SignalProtocolError::InvalidArgument(format!(
                "unknown store version {version}"
            )));
        }
        let id_kp_bytes = r.u32_blob()?;
        let id_kp = IdentityKeyPair::try_from(id_kp_bytes)?;
        let registration_id = r.u32()?;
        let next_pre_key_id = r.u32()?;
        let next_signed_pre_key_id = r.u32()?;
        let next_kyber_pre_key_id = r.u32()?;

        let mut store = InMemSignalProtocolStore::new(id_kp, registration_id)?;
        let mut peers: Vec<Vec<u8>> = Vec::new();
        let peer_count = r.u32()? as usize;
        for _ in 0..peer_count {
            peers.push(r.u16_blob()?.to_vec());
        }

        let pre_count = r.u32()? as usize;
        for _ in 0..pre_count {
            let id = r.u32()?;
            let record = PreKeyRecord::deserialize(r.u32_blob()?)?;
            store
                .save_pre_key(id.into(), &record)
                .now_or_never()
                .expect("in-mem store is sync")?;
        }
        let spk_count = r.u32()? as usize;
        for _ in 0..spk_count {
            let id = r.u32()?;
            let record = SignedPreKeyRecord::deserialize(r.u32_blob()?)?;
            store
                .save_signed_pre_key(id.into(), &record)
                .now_or_never()
                .expect("in-mem store is sync")?;
        }
        let kpk_count = r.u32()? as usize;
        for _ in 0..kpk_count {
            let id = r.u32()?;
            let record = KyberPreKeyRecord::deserialize(r.u32_blob()?)?;
            store
                .save_kyber_pre_key(id.into(), &record)
                .now_or_never()
                .expect("in-mem store is sync")?;
        }
        let session_count = r.u32()? as usize;
        for _ in 0..session_count {
            let peer = r.u16_blob()?;
            let session_bytes = r.u32_blob()?;
            let record = SessionRecord::deserialize(session_bytes)?;
            let addr = address_for(peer);
            store
                .session_store
                .store_session(&addr, &record)
                .now_or_never()
                .expect("in-mem store is sync")?;
            // Re-pin the peer's identity in the identity store so future
            // is_trusted_identity checks compare against what we already know.
            let identity = IdentityKey::decode(peer)?;
            store
                .identity_store
                .save_identity(&addr, &identity)
                .now_or_never()
                .expect("in-mem store is sync")?;
        }

        let sender_certificate = if version >= STORE_VERSION && !r.is_empty() {
            let cert_bytes = r.u32_blob()?;
            if cert_bytes.is_empty() {
                None
            } else {
                Some(SenderCertificate::deserialize(cert_bytes)?)
            }
        } else {
            None
        };

        Ok(Self {
            inner: store,
            next_pre_key_id,
            next_signed_pre_key_id,
            next_kyber_pre_key_id,
            peers,
            sender_certificate,
        })
    }
}

fn registration_id<R: Rng>(rng: &mut R) -> u32 {
    (rng.random::<u16>() as u32 & 0x3FFF) | 1
}

fn next_id(id: u32) -> u32 {
    let n = id.wrapping_add(1);
    if n == 0 { 1 } else { n }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn address_for(identity_public: &[u8]) -> ProtocolAddress {
    ProtocolAddress::new(
        hex_lower(identity_public),
        DeviceId::new(DEVICE_ID).expect("device id non-zero"),
    )
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

#[allow(clippy::too_many_arguments)]
fn encode_bundle(
    registration_id: u32,
    device_id: u32,
    one_time_pre_key: (u32, &PublicKey),
    signed_pre_key_id: u32,
    signed_pre_key_public: &PublicKey,
    signed_pre_key_sig: &[u8],
    kyber_pre_key_id: u32,
    kyber_pre_key_public: &kem::PublicKey,
    kyber_pre_key_sig: &[u8],
    identity_key: &IdentityKey,
    delivery_token_verify_key: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(2048);
    out.push(BUNDLE_VERSION);
    out.extend_from_slice(&registration_id.to_be_bytes());
    out.extend_from_slice(&device_id.to_be_bytes());
    out.push(1);
    out.extend_from_slice(&one_time_pre_key.0.to_be_bytes());
    write_u16_blob(&mut out, &one_time_pre_key.1.serialize());
    out.extend_from_slice(&signed_pre_key_id.to_be_bytes());
    write_u16_blob(&mut out, &signed_pre_key_public.serialize());
    write_u16_blob(&mut out, signed_pre_key_sig);
    out.extend_from_slice(&kyber_pre_key_id.to_be_bytes());
    write_u32_blob(&mut out, &kyber_pre_key_public.serialize());
    write_u16_blob(&mut out, kyber_pre_key_sig);
    write_u16_blob(&mut out, &identity_key.serialize());
    write_u16_blob(&mut out, delivery_token_verify_key);
    out
}

/// Decoded form of a bundle: the libsignal handshake material plus the
/// peer's published delivery-token verify key (Phase 3 uses this on the
/// relay side; for Phase 1 we just plumb the bytes so the wire format is
/// final).
pub struct DecodedBundle {
    pub bundle: PreKeyBundle,
    pub delivery_token_verify_key: Vec<u8>,
}

fn decode_bundle(bytes: &[u8]) -> Result<DecodedBundle, SignalProtocolError> {
    let mut r = Cursor::new(bytes);
    let version = r.u8()?;
    if version != BUNDLE_VERSION {
        return Err(SignalProtocolError::InvalidArgument(format!(
            "unknown bundle version {version}"
        )));
    }
    let registration_id = r.u32()?;
    let device_id_raw = r.u32()?;
    let device_id_u8: u8 = device_id_raw
        .try_into()
        .map_err(|_| SignalProtocolError::InvalidArgument("device_id must fit in u8".into()))?;
    let device_id = DeviceId::new(device_id_u8)
        .map_err(|_| SignalProtocolError::InvalidArgument("device_id must be non-zero".into()))?;
    let has_otp = r.u8()? != 0;
    let one_time = if has_otp {
        let id = r.u32()?;
        let pk = PublicKey::try_from(r.u16_blob()?)?;
        Some((id.into(), pk))
    } else {
        None
    };
    let signed_id = r.u32()?;
    let signed_pub = PublicKey::try_from(r.u16_blob()?)?;
    let signed_sig = r.u16_blob()?.to_vec();
    let kyber_id = r.u32()?;
    let kyber_pub = kem::PublicKey::deserialize(r.u32_blob()?)?;
    let kyber_sig = r.u16_blob()?.to_vec();
    let identity = IdentityKey::decode(r.u16_blob()?)?;
    let token_verify_key = r.u16_blob()?.to_vec();
    if token_verify_key.len() != DELIVERY_TOKEN_VERIFY_KEY_LEN {
        return Err(SignalProtocolError::InvalidArgument(format!(
            "delivery_token_verify_key must be {} bytes, got {}",
            DELIVERY_TOKEN_VERIFY_KEY_LEN,
            token_verify_key.len(),
        )));
    }
    if !r.is_empty() {
        return Err(SignalProtocolError::InvalidArgument(
            "trailing bytes after bundle".into(),
        ));
    }
    let bundle = PreKeyBundle::new(
        registration_id,
        device_id,
        one_time,
        signed_id.into(),
        signed_pub,
        signed_sig,
        kyber_id.into(),
        kyber_pub,
        kyber_sig,
        identity,
    )?;
    Ok(DecodedBundle {
        bundle,
        delivery_token_verify_key: token_verify_key,
    })
}

fn write_u16_blob(out: &mut Vec<u8>, blob: &[u8]) {
    let len: u16 = blob.len().try_into().expect("blob fits u16");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(blob);
}

fn write_u32_blob(out: &mut Vec<u8>, blob: &[u8]) {
    let len: u32 = blob.len().try_into().expect("blob fits u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(blob);
}

struct Cursor<'a> {
    buf: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf } }
    fn is_empty(&self) -> bool { self.buf.is_empty() }
    fn take(&mut self, n: usize) -> Result<&'a [u8], SignalProtocolError> {
        if self.buf.len() < n {
            return Err(SignalProtocolError::InvalidArgument(
                "truncated bundle".into(),
            ));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, SignalProtocolError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, SignalProtocolError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, SignalProtocolError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u16_blob(&mut self) -> Result<&'a [u8], SignalProtocolError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn u32_blob(&mut self) -> Result<&'a [u8], SignalProtocolError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_devices_round_trip() {
        let mut alice = DeviceStore::fresh().unwrap();
        let mut bob = DeviceStore::fresh().unwrap();

        let bob_bundle = bob.publish_bundle().unwrap();
        alice
            .initiate_session(&bob.identity_public_bytes(), &bob_bundle)
            .unwrap();

        let m1 = alice.encrypt(&bob.identity_public_bytes(), b"hi bob").unwrap();
        assert!(m1.is_prekey);

        let pt1 = bob
            .decrypt(&alice.identity_public_bytes(), &m1.ciphertext, true)
            .unwrap();
        assert_eq!(pt1, b"hi bob");

        let m2 = bob.encrypt(&alice.identity_public_bytes(), b"hi alice").unwrap();
        assert!(!m2.is_prekey, "bob's reply must be Whisper, session is set up");

        let pt2 = alice
            .decrypt(&bob.identity_public_bytes(), &m2.ciphertext, false)
            .unwrap();
        assert_eq!(pt2, b"hi alice");

        let m3 = alice.encrypt(&bob.identity_public_bytes(), b"again").unwrap();
        assert!(!m3.is_prekey, "alice's next message must be Whisper too");
        let pt3 = bob
            .decrypt(&alice.identity_public_bytes(), &m3.ciphertext, false)
            .unwrap();
        assert_eq!(pt3, b"again");
    }

    #[test]
    fn rehydrate_keeps_identity() {
        let store = DeviceStore::fresh().unwrap();
        let id_bytes = store.identity_keypair_bytes();
        let pub_bytes = store.identity_public_bytes();
        drop(store);

        let rehydrated = DeviceStore::from_identity(&id_bytes).unwrap();
        assert_eq!(rehydrated.identity_public_bytes(), pub_bytes);
    }

    #[test]
    fn bundle_identity_mismatch_rejected() {
        let mut alice = DeviceStore::fresh().unwrap();
        let mut bob = DeviceStore::fresh().unwrap();
        let bob_bundle = bob.publish_bundle().unwrap();
        // Pretend the peer is somebody else — should be caught.
        let bogus = DeviceStore::fresh().unwrap().identity_public_bytes();
        let err = alice.initiate_session(&bogus, &bob_bundle).unwrap_err();
        assert!(matches!(err, SignalProtocolError::InvalidArgument(_)));
    }

    #[test]
    fn bundle_round_trips_through_wire_format() {
        let mut s = DeviceStore::fresh().unwrap();
        let bytes = s.publish_bundle().unwrap();
        let decoded = decode_bundle(&bytes).unwrap();
        assert_eq!(
            decoded.bundle.registration_id().unwrap(),
            s.registration_id()
        );
        assert_eq!(
            decoded.bundle.identity_key().unwrap().serialize().as_ref(),
            s.identity_public_bytes().as_slice()
        );
        assert_eq!(
            decoded.delivery_token_verify_key,
            s.delivery_token_verify_key_bytes().unwrap()
        );
        assert_eq!(decoded.delivery_token_verify_key.len(), DELIVERY_TOKEN_VERIFY_KEY_LEN);
    }

    #[test]
    fn delivery_token_keypair_is_deterministic_per_identity() {
        // Two stores rehydrated from the same identity bytes derive the
        // same verify key — proves a Keychain restore works without a
        // separate signing-key backup.
        let s1 = DeviceStore::fresh().unwrap();
        let id_bytes = s1.identity_keypair_bytes();
        let s1_vk = s1.delivery_token_verify_key_bytes().unwrap();
        drop(s1);
        let s2 = DeviceStore::from_identity(&id_bytes).unwrap();
        assert_eq!(s2.delivery_token_verify_key_bytes().unwrap(), s1_vk);

        // A different identity produces a different verify key.
        let s3 = DeviceStore::fresh().unwrap();
        assert_ne!(s3.delivery_token_verify_key_bytes().unwrap(), s1_vk);
    }

    #[test]
    fn seal_round_trips() {
        // Five-message round-trip through DeviceStore::seal_send /
        // seal_receive — mirrors the integration test but proves the
        // public DeviceStore API (which is what Phase 1's FFI wraps).
        let mut alice = DeviceStore::fresh().unwrap();
        let mut bob = DeviceStore::fresh().unwrap();
        let alice_id = alice.identity_public_bytes();
        let bob_id = bob.identity_public_bytes();

        let bob_bundle = bob.publish_bundle().unwrap();
        alice.initiate_session(&bob_id, &bob_bundle).unwrap();
        // Pre-trust Alice on Bob's side so seal_receive's contact-gate
        // accepts her first inbound message.
        bob.register_peer(&alice_id);

        for i in 0..5u8 {
            let mut msg_id = [0u8; 16];
            msg_id[0] = i;
            let payload = format!("msg {i}");
            let (sender, recipient, payload_str) = if i % 2 == 0 {
                (&mut alice, &mut bob, &payload)
            } else {
                (&mut bob, &mut alice, &payload)
            };
            let peer_id = if i % 2 == 0 { bob_id.clone() } else { alice_id.clone() };
            let sealed = sender
                .seal_send(&peer_id, &msg_id, payload_str.as_bytes())
                .unwrap();
            let received = recipient.seal_receive(&sealed).unwrap();
            assert_eq!(received.message_id, msg_id);
            assert_eq!(received.plaintext, payload_str.as_bytes());
            assert_eq!(
                received.sender_identity_pub,
                if i % 2 == 0 { alice_id.clone() } else { bob_id.clone() },
            );
        }
    }

    #[test]
    fn seal_rejects_unknown_sender() {
        // A peer who isn't in our trusted contacts should not be able to
        // make us advance our ratchet via a sealed envelope.
        let mut alice = DeviceStore::fresh().unwrap();
        let mut bob = DeviceStore::fresh().unwrap();
        let bob_id = bob.identity_public_bytes();
        let bundle = bob.publish_bundle().unwrap();
        alice.initiate_session(&bob_id, &bundle).unwrap();
        // Note: we deliberately do NOT call bob.register_peer(&alice_id).
        let sealed = alice.seal_send(&bob_id, &[0u8; 16], b"surprise").unwrap();
        let err = bob.seal_receive(&sealed).unwrap_err();
        assert!(matches!(err, SignalProtocolError::InvalidArgument(_)));
    }

    #[test]
    fn seal_serializes_through_store_snapshot() {
        // Cached SenderCertificate must survive a serialize/from_serialized
        // round-trip. Otherwise Phase 4's iOS app would mint a new cert on
        // every cold launch — wasteful and would also bump cert key_ids
        // mid-conversation, which complicates rotation/revocation.
        let mut alice = DeviceStore::fresh().unwrap();
        let mut bob = DeviceStore::fresh().unwrap();
        let alice_id = alice.identity_public_bytes();
        let bob_id = bob.identity_public_bytes();
        let bundle = bob.publish_bundle().unwrap();
        alice.initiate_session(&bob_id, &bundle).unwrap();
        bob.register_peer(&alice_id);

        // Force cert mint then snapshot.
        let _ = alice.seal_send(&bob_id, &[1u8; 16], b"first").unwrap();
        let cert_before = alice.ensure_sender_certificate().unwrap();
        let snap = alice.serialize().unwrap();
        drop(alice);

        let mut alice2 = DeviceStore::from_serialized(&snap).unwrap();
        let cert_after = alice2.ensure_sender_certificate().unwrap();
        assert_eq!(cert_before, cert_after, "cert must round-trip via serialize");

        // And the rehydrated store can still be received from.
        let sealed = alice2.seal_send(&bob_id, &[2u8; 16], b"after-snap").unwrap();
        let received = bob.seal_receive(&sealed).unwrap();
        assert_eq!(received.plaintext, b"after-snap");
    }

    #[test]
    fn serialize_round_trips_full_session() {
        // Establish Alice ↔ Bob, send a couple of messages, snapshot Alice's
        // store, rehydrate, and prove the ratchet picks up where it left off.
        let mut alice = DeviceStore::fresh().unwrap();
        let mut bob = DeviceStore::fresh().unwrap();
        let bob_id = bob.identity_public_bytes();
        let alice_id = alice.identity_public_bytes();

        let bundle = bob.publish_bundle().unwrap();
        alice.initiate_session(&bob_id, &bundle).unwrap();

        let m1 = alice.encrypt(&bob_id, b"hello").unwrap();
        let _ = bob.decrypt(&alice_id, &m1.ciphertext, true).unwrap();
        let m2 = bob.encrypt(&alice_id, b"hi back").unwrap();
        let _ = alice.decrypt(&bob_id, &m2.ciphertext, false).unwrap();

        let snapshot = alice.serialize().unwrap();
        let mut alice2 = DeviceStore::from_serialized(&snapshot).unwrap();
        assert_eq!(alice2.identity_public_bytes(), alice_id);

        // Continue the conversation across the rehydrate boundary.
        let m3 = alice2.encrypt(&bob_id, b"and again").unwrap();
        assert!(!m3.is_prekey, "session continued — must be Whisper");
        let pt3 = bob.decrypt(&alice_id, &m3.ciphertext, false).unwrap();
        assert_eq!(pt3, b"and again");
    }

    #[test]
    fn fresh_store_serializes_to_a_minimal_blob() {
        let s = DeviceStore::fresh().unwrap();
        let blob = s.serialize().unwrap();
        let s2 = DeviceStore::from_serialized(&blob).unwrap();
        assert_eq!(s.identity_keypair_bytes(), s2.identity_keypair_bytes());
        assert_eq!(s.registration_id(), s2.registration_id());
    }

    #[test]
    fn forget_peer_drops_session() {
        let mut alice = DeviceStore::fresh().unwrap();
        let mut bob = DeviceStore::fresh().unwrap();
        let bob_id = bob.identity_public_bytes();
        let bundle = bob.publish_bundle().unwrap();
        alice.initiate_session(&bob_id, &bundle).unwrap();
        let _ = alice.encrypt(&bob_id, b"hi").unwrap();
        alice.forget_peer(&bob_id);
        // Encrypting again must now fail — session was dropped.
        match alice.encrypt(&bob_id, b"again") {
            Err(SignalProtocolError::SessionNotFound(_)) => {}
            Ok(_) => panic!("expected SessionNotFound; encrypt succeeded"),
            Err(e) => panic!("expected SessionNotFound, got {e:?}"),
        }
    }
}
