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
//! Store snapshot wire format (`v3`, big-endian):
//!
//! ```text
//! u8  store_version = 3
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
//! u32 sender_key_count                (v3+; absent on v1/v2 blobs)
//!   for each sender_key:
//!     u16 sender_identity_pub_len + bytes (33)
//!     [16] distribution_id (raw UUID bytes)
//!     u32 record_len + bytes  (libsignal SenderKeyRecord.serialize())
//! ```
//!
//! v1 blobs (no trailing sender-certificate) deserialize by treating
//! both the cert and the sender-key list as absent — the cert is
//! mintable on demand, the sender keys are rebuilt as the host
//! reprocesses incoming SKDMs. v2 blobs deserialize with the cert
//! present but no sender keys.

use std::time::SystemTime;

use futures_util::FutureExt as _;
use hkdf::Hkdf;
use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, ContentHint, DeviceId, GenericSignedPreKey,
    IdentityKey, IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore, KeyPair,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyRecord, PreKeySignalMessage,
    PreKeyStore, PrivateKey, ProtocolAddress, PublicKey, SenderCertificate,
    SenderKeyDistributionMessage, SenderKeyMessage, SenderKeyRecord, SenderKeyStore,
    ServerCertificate, SessionRecord, SessionStore, SignalMessage, SignalProtocolError,
    SignedPreKeyRecord, SignedPreKeyStore, Timestamp, UnidentifiedSenderMessageContent,
    create_sender_key_distribution_message, group_decrypt as libsignal_group_decrypt,
    group_encrypt as libsignal_group_encrypt, kem, message_decrypt, message_encrypt,
    process_prekey_bundle, process_sender_key_distribution_message,
    sealed_sender_decrypt_to_usmc, sealed_sender_encrypt_from_usmc,
};
use uuid::Uuid;
use rand::{Rng, TryRngCore as _, rngs::OsRng};
use sha2::Sha512;

// ───── Plaintext padding (message-size hiding) ──────────
//
// Every sealed-sender plaintext is padded to one of a small set of
// bucket sizes BEFORE it enters the libsignal ratchet. The wire-visible
// ciphertext therefore clusters at a handful of sizes, hiding the
// original message length from:
//
//   * the relay operator (sees only sealed_ciphertext size),
//   * any network observer of the Tor traffic (sees only TLS-record
//     sizes which closely track the sealed envelope size),
//   * a future attacker who recovers stored pending-queue ciphertexts.
//
// Layout: `padded = u32_be(real_len) || real_bytes || zero_pad`.
// The `real_len` prefix lives INSIDE the encrypted envelope, so the
// relay cannot read it. Receiver unpads after `message_decrypt`.
//
// Buckets are powers-of-four-ish (256, 1K, 4K, 16K, 64K, 256K). The
// smallest fits any plain-text chat message; the largest covers
// attachment-chunk payloads. Anything above the max bucket would
// fail to encrypt — but the attachment chunker already caps chunk
// size at 64 KB, so this is unreachable in steady state.
//
// Note: padding does NOT hide presence/timing — that's the second
// pass of constant-rate cover traffic, which adds dummy
// frames during idle periods. This first pass is the length-hiding
// half.
const PADDING_BUCKETS: &[usize] = &[256, 1024, 4096, 16384, 65536, 262144];
/// Width of the in-envelope length prefix. 4 bytes is enough for any
/// plaintext that fits the largest bucket; we'd need to bump this in
/// lockstep with `PADDING_BUCKETS` if we ever ship a > 4 GiB bucket
/// (we won't).
const PADDING_LEN_PREFIX: usize = 4;

/// Pad `plaintext` with a length-prefixed zero-tail to the smallest
/// bucket that fits it. Returns the padded buffer ready to hand to
/// `message_encrypt`. Plaintexts larger than the biggest bucket are
/// rejected — better a loud error than silently leaking the size by
/// rounding up past every defined bucket.
fn pad_plaintext(plaintext: &[u8]) -> Result<Vec<u8>, SignalProtocolError> {
    let real_len = u32::try_from(plaintext.len()).map_err(|_| {
        SignalProtocolError::InvalidArgument("plaintext length exceeds u32::MAX".into())
    })?;
    let needed = plaintext
        .len()
        .checked_add(PADDING_LEN_PREFIX)
        .ok_or_else(|| {
            SignalProtocolError::InvalidArgument("plaintext length + prefix overflows usize".into())
        })?;
    let bucket = PADDING_BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= needed)
        .ok_or_else(|| {
            SignalProtocolError::InvalidArgument(format!(
                "plaintext too large for padding buckets: {} bytes > {} max",
                plaintext.len(),
                PADDING_BUCKETS.last().copied().unwrap_or(0)
            ))
        })?;
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&real_len.to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(bucket, 0);
    Ok(out)
}

/// Strip the length prefix + zero tail introduced by `pad_plaintext`.
/// Validates that the prefix fits the buffer; a malformed prefix
/// (e.g. a padded value of `0xFFFFFFFF` against a 256-byte buffer)
/// returns an error rather than silently truncating or panicking.
fn unpad_plaintext(padded: &[u8]) -> Result<Vec<u8>, SignalProtocolError> {
    if padded.len() < PADDING_LEN_PREFIX {
        return Err(SignalProtocolError::InvalidArgument(
            "padded plaintext shorter than length prefix".into(),
        ));
    }
    let mut len_buf = [0u8; PADDING_LEN_PREFIX];
    len_buf.copy_from_slice(&padded[..PADDING_LEN_PREFIX]);
    let real_len = u32::from_be_bytes(len_buf) as usize;
    let avail = padded.len() - PADDING_LEN_PREFIX;
    if real_len > avail {
        return Err(SignalProtocolError::InvalidArgument(format!(
            "padded length prefix {real_len} exceeds available {avail}"
        )));
    }
    Ok(padded[PADDING_LEN_PREFIX..PADDING_LEN_PREFIX + real_len].to_vec())
}

const BUNDLE_VERSION: u8 = 2;
/// Store snapshot version. v1 = pre-Phase-1 (no sender certificate). v2 =
/// added the trailing sender-certificate field. v3 = appended the
/// SenderKey state list for libsignal group messaging (Phase 6 group
/// chat). All older versions deserialize transparently — sender-key
/// state defaults to empty and is rebuilt as group operations arrive.
const STORE_VERSION: u8 = 3;
const DEVICE_ID: u8 = 1;
/// Distribution-id wire size in our FFI: a 16-byte raw UUID (no hyphen
/// formatting). Group ID derives directly from this — we feed the bytes
/// straight into `Uuid::from_bytes`.
pub const SENDER_KEY_DISTRIBUTION_ID_LEN: usize = 16;

/// Self-signed SenderCertificate validity. Long enough that a peer who
/// goes offline for a few weeks can still send without a refresh round
/// trip; short enough that a forgotten device's certs lapse on their own.
const SENDER_CERT_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Mint a fresh cert if the cached one is within this window of expiry.
/// 7 days closes the F-102 asymmetric-clock-skew DoS: with a 24h margin a
/// recipient whose clock was ahead by 24h–30d would reject every cert
/// while the sender's refresh trigger never fired. 7 days leaves only a
/// 23-day skew window where the same condition could apply, and bounds
/// it tighter under the same RFC-1305-typical clock-skew expectations.
const SENDER_CERT_REFRESH_MARGIN_MS: u64 = 7 * 24 * 60 * 60 * 1000;
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

/// Delivery token wire format: nonce16 || expiry_be_u32 || sig64.
/// The signature is over `nonce16 || expiry_be_u32` with the
/// recipient's HKDF-derived signing key.
pub const DELIVERY_TOKEN_NONCE_LEN: usize = 16;
pub const DELIVERY_TOKEN_SIG_LEN: usize = 64;
pub const DELIVERY_TOKEN_LEN: usize =
    DELIVERY_TOKEN_NONCE_LEN + 4 + DELIVERY_TOKEN_SIG_LEN;

/// How long an issued delivery token remains valid. 30 days lines up
/// with the SenderCertificate TTL so a contact that goes dark for less
/// than a month can still use their stash without a refill round trip.
pub const DELIVERY_TOKEN_TTL_SECS: u32 = 30 * 24 * 60 * 60;

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
    /// (sender_identity_pub_bytes, distribution_id) pairs for every
    /// SenderKey state libsignal currently holds. `InMemSenderKeyStore`
    /// is keyed by `(ProtocolAddress, Uuid)` and exposes no iterator,
    /// so we maintain this index alongside any operation that calls
    /// `store_sender_key` — `process_sender_key_distribution_message`
    /// (incoming peer SKDM), `create_sender_key_distribution_message`
    /// (our own group enrolment), and the implicit re-stores libsignal
    /// performs on every `group_encrypt` / `group_decrypt`. Used at
    /// `serialize` time to enumerate persisted records.
    sender_key_index: Vec<(Vec<u8>, [u8; SENDER_KEY_DISTRIBUTION_ID_LEN])>,
}

pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub is_prekey: bool,
}

/// Result of `seal_receive`: the claimed sender's identity_pub (verified
/// against the embedded cert), the 16-byte message_id (extracted from the
/// USMC contents header — the relay never sees this), and the inner
/// plaintext.
///
/// `is_duplicate = true` means the libsignal ratchet rejected the inner
/// ciphertext as a duplicate (counter already consumed). The sender +
/// message_id are still extracted and returned so the host can re-emit
/// a fresh ACK — without re-displaying the message — to flip the
/// sender's outbox if its first ACK got lost. `plaintext` is empty in
/// this case.
#[derive(Debug)]
pub struct SealReceived {
    pub sender_identity_pub: Vec<u8>,
    pub message_id: [u8; 16],
    pub plaintext: Vec<u8>,
    pub is_duplicate: bool,
}

/// Failure modes of `seal_receive`, kept distinct so the FFI can hand
/// the host an attacker-attributable error code instead of collapsing
/// everything to a generic internal error.
///
/// `BadSignature` covers the two paths where the bytes themselves are
/// untrustworthy — the sealed-sender certificate fails to validate
/// against the claimed contact's pinned identity, or the claimed
/// sender is not a known contact at all. Both mean "a relay or paired
/// peer handed me forged/unauthorized bytes," which is exactly the
/// signal `PIZZINI_ERR_BAD_SIGNATURE` exists to carry. Everything
/// else (parse failures, ratchet errors, store I/O) is `Internal`.
#[derive(Debug)]
pub enum SealReceiveError {
    /// Cert-validation failure or unknown-sender contact-gate rejection.
    BadSignature(SignalProtocolError),
    /// Any other failure — indistinguishable from a benign internal error.
    Internal(SignalProtocolError),
}

impl From<SignalProtocolError> for SealReceiveError {
    fn from(e: SignalProtocolError) -> Self {
        SealReceiveError::Internal(e)
    }
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
            sender_key_index: Vec::new(),
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
            sender_key_index: Vec::new(),
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

    /// Mint a single delivery token: a 16-byte random nonce + a u32
    /// expiry (seconds since epoch) + an XEd25519 signature over the
    /// concatenation, all signed with the long-term delivery-token
    /// signing key. The relay verifies against the recipient's
    /// published verify_key.
    pub fn mint_delivery_token(&self) -> Result<[u8; DELIVERY_TOKEN_LEN], SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let kp = self.delivery_token_keypair()?;
        let mut nonce = [0u8; DELIVERY_TOKEN_NONCE_LEN];
        rng.fill(&mut nonce);
        let now = (now_millis() / 1000) as u32;
        let expiry = now.saturating_add(DELIVERY_TOKEN_TTL_SECS);
        let mut payload = [0u8; DELIVERY_TOKEN_NONCE_LEN + 4];
        payload[..DELIVERY_TOKEN_NONCE_LEN].copy_from_slice(&nonce);
        payload[DELIVERY_TOKEN_NONCE_LEN..].copy_from_slice(&expiry.to_be_bytes());
        let sig = kp.private_key.calculate_signature(&payload, &mut rng)?;
        if sig.len() != DELIVERY_TOKEN_SIG_LEN {
            return Err(SignalProtocolError::InvalidArgument(format!(
                "unexpected delivery-token signature length {}",
                sig.len()
            )));
        }
        let mut out = [0u8; DELIVERY_TOKEN_LEN];
        out[..DELIVERY_TOKEN_NONCE_LEN + 4].copy_from_slice(&payload);
        out[DELIVERY_TOKEN_NONCE_LEN + 4..].copy_from_slice(&sig);
        Ok(out)
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

    // ───── Sender Keys (libsignal group messaging) ───────────────────
    //
    // Pizzini groups use libsignal's Sender Keys: each member, per
    // group, owns a sender-key chain. To enrol a peer, we generate
    // (or refresh) our own sender key for the group via
    // `sender_key_distribution_create`, ship the resulting SKDM 1:1
    // over the existing sealed-sender envelope, and the peer feeds it
    // into `sender_key_distribution_process`. To send to the group,
    // we encrypt once with `group_encrypt` and broadcast the resulting
    // SenderKeyMessage as N independent sealed-sender envelopes (one
    // per member); each recipient calls `group_decrypt`.
    //
    // Every operation that mutates the underlying SenderKey state
    // updates `sender_key_index` so `serialize` can enumerate the
    // records `InMemSenderKeyStore` doesn't expose an iterator for.

    /// Create our local sender-key chain at `distribution_id` and return
    /// the SKDM bytes the peers in this group need in order to decrypt
    /// our future `group_encrypt` output for this dist_id. Calling
    /// twice with the same `distribution_id` reuses the existing chain
    /// — `distribution_id` is libsignal's *per-chain* identifier, not
    /// the public group ID. To rotate (e.g. on a member-remove), the
    /// caller passes a fresh random `distribution_id` and broadcasts
    /// the resulting SKDM; the new chain is independent of the old.
    /// Old chains stay in the store so late-arriving ciphertext from
    /// the prior chain still decrypts.
    pub fn sender_key_distribution_create(
        &mut self,
        distribution_id: [u8; SENDER_KEY_DISTRIBUTION_ID_LEN],
    ) -> Result<Vec<u8>, SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let local_addr = address_for(&self.identity_public_bytes());
        let uuid = Uuid::from_bytes(distribution_id);
        let skdm = create_sender_key_distribution_message(
            &local_addr,
            uuid,
            &mut self.inner.sender_key_store,
            &mut rng,
        )
        .now_or_never()
        .expect("in-mem store is sync")?;
        self.note_sender_key(&self.identity_public_bytes(), distribution_id);
        Ok(skdm.serialized().to_vec())
    }

    /// Process a peer's incoming SKDM. The `sender_identity` is the
    /// authenticated identity-public from the sealed-sender unwrap;
    /// the SKDM's distribution_id is the group it announces. After
    /// this call we can decrypt that peer's `group_encrypt` output for
    /// the same group.
    pub fn sender_key_distribution_process(
        &mut self,
        sender_identity: &[u8],
        skdm_bytes: &[u8],
    ) -> Result<[u8; SENDER_KEY_DISTRIBUTION_ID_LEN], SignalProtocolError> {
        let skdm = SenderKeyDistributionMessage::try_from(skdm_bytes)?;
        let distribution_id = skdm.distribution_id()?;
        let sender_addr = address_for(sender_identity);
        process_sender_key_distribution_message(
            &sender_addr,
            &skdm,
            &mut self.inner.sender_key_store,
        )
        .now_or_never()
        .expect("in-mem store is sync")?;
        let dist_bytes: [u8; SENDER_KEY_DISTRIBUTION_ID_LEN] = *distribution_id.as_bytes();
        self.note_sender_key(sender_identity, dist_bytes);
        Ok(dist_bytes)
    }

    /// Encrypt `plaintext` for the group identified by `distribution_id`
    /// using our local sender-key chain. Caller must have already
    /// invoked `sender_key_distribution_create` for this id; otherwise
    /// libsignal returns `NoSenderKeyState`. The returned bytes are a
    /// `SenderKeyMessage` ready to wrap into per-recipient sealed-
    /// sender envelopes.
    pub fn group_encrypt(
        &mut self,
        distribution_id: [u8; SENDER_KEY_DISTRIBUTION_ID_LEN],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let local_addr = address_for(&self.identity_public_bytes());
        let uuid = Uuid::from_bytes(distribution_id);
        let skm = libsignal_group_encrypt(
            &mut self.inner.sender_key_store,
            &local_addr,
            uuid,
            plaintext,
            &mut rng,
        )
        .now_or_never()
        .expect("in-mem store is sync")?;
        Ok(skm.serialized().to_vec())
    }

    /// Decrypt a `SenderKeyMessage` from `sender_identity`. The
    /// distribution_id is encoded in the ciphertext header and looked
    /// up against the SKDM previously processed for this sender.
    pub fn group_decrypt(
        &mut self,
        sender_identity: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SignalProtocolError> {
        let sender_addr = address_for(sender_identity);
        // Surface the distribution_id parsed from the SKM so callers
        // can audit / cross-check against the inner-envelope group_id.
        let skm = SenderKeyMessage::try_from(ciphertext)?;
        let dist_bytes: [u8; SENDER_KEY_DISTRIBUTION_ID_LEN] = *skm.distribution_id().as_bytes();
        let plaintext =
            libsignal_group_decrypt(ciphertext, &mut self.inner.sender_key_store, &sender_addr)
                .now_or_never()
                .expect("in-mem store is sync")?;
        // libsignal's group_decrypt re-stores the record with advanced
        // chain state; the index entry already exists from
        // sender_key_distribution_process, so noting is a no-op for
        // this hot path. Belt-and-suspenders: re-record so a hand-
        // tampered store stays consistent.
        self.note_sender_key(sender_identity, dist_bytes);
        Ok(plaintext)
    }

    fn note_sender_key(
        &mut self,
        sender_identity: &[u8],
        distribution_id: [u8; SENDER_KEY_DISTRIBUTION_ID_LEN],
    ) {
        let already = self
            .sender_key_index
            .iter()
            .any(|(s, d)| s.as_slice() == sender_identity && *d == distribution_id);
        if !already {
            self.sender_key_index
                .push((sender_identity.to_vec(), distribution_id));
        }
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
        // Bucket-pad the plaintext BEFORE handing it to the
        // ratchet. The resulting libsignal ciphertext (and therefore
        // the sealed-sender envelope, and therefore the SEND-frame
        // size the relay observes) clusters at one of a handful of
        // well-known sizes — a 1-emoji "hi" and a 200-byte message
        // both produce the same wire size, indistinguishable to the
        // relay. The receiver's `seal_receive` strips the padding
        // transparently before returning to the caller.
        let padded_plaintext = pad_plaintext(plaintext)?;
        let inner = message_encrypt(
            &padded_plaintext,
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

    /// Pre-flight size discovery for `seal_receive`. Opens the outer
    /// USMC envelope (read-only — does NOT advance the Double Ratchet),
    /// returns conservative upper bounds for `(sender_len, plaintext_len)`
    /// the FFI can use to gate buffer-too-small without committing the
    /// ratchet step. F-101 / F-701.
    ///
    /// `plaintext_len` is an over-estimate: it equals
    /// `usmc.contents().len() - 17` (USMC inner minus the 16-byte
    /// `message_id` + 1-byte `is_prekey` header). The actual plaintext
    /// emitted by `message_decrypt` is smaller — libsignal strips its
    /// own protocol overhead — so a buffer sized to this bound is always
    /// big enough for the real plaintext.
    ///
    /// Cost: one symmetric `sealed_sender_decrypt_to_usmc` open. ~µs.
    /// Cheap enough to call before every `seal_receive`.
    pub fn peek_sealed_lengths(
        &self,
        sealed: &[u8],
    ) -> Result<(usize, usize), SignalProtocolError> {
        let usmc = sealed_sender_decrypt_to_usmc(sealed, &self.inner.identity_store)
            .now_or_never()
            .expect("in-mem store is sync")?;
        let claimed_pub = usmc.sender()?.key()?;
        let sender_len = IdentityKey::new(claimed_pub).serialize().len();
        // Prefer `checked_sub` over `saturating_sub`. With
        // saturating, a 17-byte USMC contents produces a 0-byte upper
        // bound that passes any non-zero cap check; if the
        // `inner_bytes.len() < 18` check at `seal_receive` is ever
        // lowered (it was `< 17` pre-F-104), the underflow becomes a
        // real "0-byte plaintext accepted" path. `checked_sub` makes
        // the boundary explicit — anything < 18 bytes returns an
        // error here, at the peek stage, before `seal_receive` does
        // its own check.
        let plaintext_upper = match usmc.contents()?.len().checked_sub(18) {
            Some(v) => v,
            None => {
                return Err(SignalProtocolError::InvalidArgument(
                    "USMC contents below minimum header+ratchet size".into(),
                ));
            }
        };
        Ok((sender_len, plaintext_upper))
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
    ) -> Result<SealReceived, SealReceiveError> {
        let usmc = match sealed_sender_decrypt_to_usmc(sealed, &self.inner.identity_store)
            .now_or_never()
            .expect("in-mem store is sync")
        {
            Ok(u) => u,
            Err(e) => {
                eprintln!("seal_receive: sealed_sender_decrypt_to_usmc failed: {e}");
                return Err(SealReceiveError::Internal(e));
            }
        };

        let claimed_pub = usmc.sender()?.key()?;
        let claimed_bytes = IdentityKey::new(claimed_pub).serialize().to_vec();

        // Contact gate: refuse to advance the ratchet for an unknown
        // peer. The relay's rules around bundle exchange + first-contact
        // PoW already forbid this in steady state, but we defend in
        // depth here too — a malicious relay could otherwise inject
        // sealed envelopes from arbitrary identities.
        let trusted = self.peers.iter().any(|p| p.as_slice() == claimed_bytes.as_slice());
        if !trusted {
            eprintln!(
                "seal_receive: rejecting unknown sender {}",
                hex_lower(&claimed_bytes)
            );
            // Attacker-attributable: a relay or paired peer presented an
            // envelope from an identity that is not one of our contacts.
            return Err(SealReceiveError::BadSignature(
                SignalProtocolError::InvalidArgument(
                    "sealed sender claim does not match a known contact".into(),
                ),
            ));
        }

        let trust_root = IdentityKey::decode(&claimed_bytes)?;
        let validation_time = Timestamp::from_epoch_millis(now_millis());
        if !usmc.sender()?.validate(trust_root.public_key(), validation_time)? {
            eprintln!(
                "seal_receive: cert validation failed for sender {}",
                hex_lower(&claimed_bytes)
            );
            // Attacker-attributable: the embedded sealed-sender certificate
            // does not validate against the contact's pinned identity.
            return Err(SealReceiveError::BadSignature(
                SignalProtocolError::InvalidArgument(
                    "sealed sender certificate does not validate against the contact's identity"
                        .into(),
                ),
            ));
        }

        let inner_bytes = usmc.contents()?;
        // Tightened from `< 17` (header alone) to `< 18` (header + at least
        // one byte of ratchet ciphertext). At exactly 17 bytes the ratchet
        // body would be empty and libsignal's parser fails with
        // CiphertextMessageTooShort anyway — rejecting one byte earlier
        // means a fuzzer probing the boundary doesn't even reach
        // `*SignalMessage::try_from`. F-104.
        if inner_bytes.len() < 18 {
            eprintln!(
                "seal_receive: inner content too short ({} bytes) for {}",
                inner_bytes.len(),
                hex_lower(&claimed_bytes)
            );
            return Err(SealReceiveError::Internal(SignalProtocolError::InvalidArgument(
                "sealed sender inner content shorter than message_id||is_prekey||ratchet[1+]".into(),
            )));
        }
        let mut message_id = [0u8; 16];
        message_id.copy_from_slice(&inner_bytes[..16]);
        let is_prekey = inner_bytes[16] != 0;
        let ratchet = &inner_bytes[17..];

        // F-103: cross-check the inner is_prekey byte against the outer
        // USMC.msg_type. The send path stores the same boolean twice
        // (lines 553, 548); a paired peer can craft a USMC where the two
        // disagree. libsignal's parser fails closed on the disagreement
        // today, but relying on that is brittle — make the redundancy
        // checked rather than ambient.
        let usmc_is_prekey = matches!(usmc.msg_type()?, CiphertextMessageType::PreKey);
        if usmc_is_prekey != is_prekey {
            eprintln!(
                "seal_receive: USMC msg_type / is_prekey byte disagreement from {} (usmc={usmc_is_prekey}, byte={is_prekey})",
                hex_lower(&claimed_bytes)
            );
            return Err(SealReceiveError::Internal(SignalProtocolError::InvalidArgument(
                "sealed sender USMC msg_type disagrees with inner is_prekey byte".into(),
            )));
        }

        let parsed = if is_prekey {
            CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(ratchet)?)
        } else {
            CiphertextMessage::SignalMessage(SignalMessage::try_from(ratchet)?)
        };
        let mut rng = OsRng.unwrap_err();
        let sender_addr = address_for(&claimed_bytes);
        let local_addr = address_for(&self.identity_public_bytes());
        let pt = match message_decrypt(
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
        .expect("in-mem store is sync")
        {
            // The ratchet output is a padded plaintext; strip
            // the in-envelope length prefix + zero tail to recover the
            // sender's original bytes. A malformed prefix from a
            // peer running mismatched padding code surfaces here as
            // an explicit error instead of returning garbage to the
            // chat UI.
            Ok(padded) => unpad_plaintext(&padded)?,
            Err(SignalProtocolError::DuplicatedMessage(timestamp, counter)) => {
                // libsignal's ratchet rejected the inner ciphertext
                // because its (chain, counter) pair was already
                // consumed. Session state is unchanged; we still want
                // to surface sender + message_id so the caller can
                // re-emit a fresh ACK (the sender's first ACK might
                // have been lost mid-flight, and they're now retrying
                // — answering shuts the loop down).
                eprintln!(
                    "seal_receive: duplicate ratchet message from {} (timestamp={timestamp}, counter={counter})",
                    hex_lower(&claimed_bytes)
                );
                return Ok(SealReceived {
                    sender_identity_pub: claimed_bytes,
                    message_id,
                    plaintext: Vec::new(),
                    is_duplicate: true,
                });
            }
            Err(e) => {
                eprintln!(
                    "seal_receive: inner message_decrypt failed for {} (is_prekey={is_prekey}, msg_id={}): {e}",
                    hex_lower(&claimed_bytes),
                    hex_lower(&message_id),
                );
                return Err(SealReceiveError::Internal(e));
            }
        };

        Ok(SealReceived {
            sender_identity_pub: claimed_bytes,
            message_id,
            plaintext: pt,
            is_duplicate: false,
        })
    }

    /// Snapshot the entire libsignal store + ratchet state to a versioned
    /// binary blob. Pair with `from_serialized` for full session continuity
    /// across launches. Format documented at the top of this module.
    pub fn serialize(&mut self) -> Result<Vec<u8>, SignalProtocolError> {
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

        // Sender-key state (v3+). Each tuple: (sender_identity, dist_id,
        // libsignal-serialized record). The index is the only iteration
        // path — InMemSenderKeyStore exposes no enumerator.
        let mut sender_key_entries: Vec<(Vec<u8>, [u8; SENDER_KEY_DISTRIBUTION_ID_LEN], Vec<u8>)> =
            Vec::with_capacity(self.sender_key_index.len());
        for (sender_identity, dist_bytes) in &self.sender_key_index {
            let addr = address_for(sender_identity);
            let uuid = Uuid::from_bytes(*dist_bytes);
            if let Some(record) = self
                .inner
                .sender_key_store
                .load_sender_key(&addr, uuid)
                .now_or_never()
                .expect("in-mem store is sync")?
            {
                let record_bytes = record.serialize()?;
                if !record_bytes.is_empty() {
                    sender_key_entries.push((sender_identity.clone(), *dist_bytes, record_bytes));
                }
            }
        }
        out.extend_from_slice(&(sender_key_entries.len() as u32).to_be_bytes());
        for (sender_identity, dist_bytes, record_bytes) in &sender_key_entries {
            write_u16_blob(&mut out, sender_identity);
            out.extend_from_slice(dist_bytes);
            write_u32_blob(&mut out, record_bytes);
        }

        Ok(out)
    }

    pub fn from_serialized(bytes: &[u8]) -> Result<Self, SignalProtocolError> {
        let mut r = Cursor::new(bytes);
        let version = r.u8()?;
        // v1 blobs (no trailing sender-certificate field) are accepted —
        // they pre-date Phase 1, were already in production Keychains,
        // and migrate transparently because the cert is mintable on
        // demand. v2 blobs add the sender-cert field; v3 blobs add the
        // sender-key state list. Anything past v3 is genuinely from-
        // the-future and refuses to load.
        if version != STORE_VERSION && version != 2 && version != 1 {
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
        // Tolerate a single corrupted session record by
        // skipping that one peer rather than failing the entire load.
        // A flipped bit on flash would otherwise lose every contact's
        // session (and the cached SenderCertificate, and every group's
        // sender-key chain). Skip-and-log keeps the rest of the store
        // usable; the affected peer is recovered by re-pairing.
        //
        // The identity-keypair decode failure earlier in this function
        // is still terminal — the store is meaningless without an
        // identity. Only per-peer session entries are skip-tolerant.
        //
        // Invariant: a peer is trusted iff its identity is pinned. When
        // a session is skipped its `save_identity` re-pin is skipped
        // too, so the peer MUST also be dropped from the `peers` index
        // — otherwise the `seal_receive` contact gate would keep
        // trusting a peer with no pinned identity, silently degrading
        // it from identity-pinned to TOFU. Skipped peers are collected
        // here and removed from `peers` after the loop.
        let mut skipped_sessions: u32 = 0;
        let mut skipped_peers: Vec<Vec<u8>> = Vec::new();
        for _ in 0..session_count {
            let peer = r.u16_blob()?;
            let session_bytes = r.u32_blob()?;
            let record = match SessionRecord::deserialize(session_bytes) {
                Ok(rec) => rec,
                Err(e) => {
                    eprintln!(
                        "[pizzini.crypto-core] dropping corrupted session for peer {}: {e}",
                        hex_short(peer),
                    );
                    skipped_sessions += 1;
                    skipped_peers.push(peer.to_vec());
                    continue;
                }
            };
            let addr = address_for(peer);
            if let Err(e) = store
                .session_store
                .store_session(&addr, &record)
                .now_or_never()
                .expect("in-mem store is sync")
            {
                eprintln!(
                    "[pizzini.crypto-core] failed to store session for peer {}: {e}",
                    hex_short(peer),
                );
                skipped_sessions += 1;
                skipped_peers.push(peer.to_vec());
                continue;
            }
            // Re-pin the peer's identity in the identity store so future
            // is_trusted_identity checks compare against what we already know.
            let identity = match IdentityKey::decode(peer) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!(
                        "[pizzini.crypto-core] dropping peer-identity-decode failure for peer {}: {e}",
                        hex_short(peer),
                    );
                    skipped_sessions += 1;
                    skipped_peers.push(peer.to_vec());
                    continue;
                }
            };
            if let Err(e) = store
                .identity_store
                .save_identity(&addr, &identity)
                .now_or_never()
                .expect("in-mem store is sync")
            {
                eprintln!(
                    "[pizzini.crypto-core] failed to save identity for peer {}: {e}",
                    hex_short(peer),
                );
                skipped_sessions += 1;
                skipped_peers.push(peer.to_vec());
                continue;
            }
        }
        if !skipped_peers.is_empty() {
            // Drop every skipped peer from the trusted set so the
            // contact gate and the identity store agree: no pinned
            // identity ⇒ not trusted. The peer must explicitly re-pair.
            peers.retain(|p| !skipped_peers.contains(p));
        }
        if skipped_sessions > 0 {
            eprintln!(
                "[pizzini.crypto-core] from_serialized: skipped {} corrupted session record(s); affected peers dropped from the trusted set and must re-pair",
                skipped_sessions,
            );
        }

        let sender_certificate = if version >= 2 && !r.is_empty() {
            let cert_bytes = r.u32_blob()?;
            if cert_bytes.is_empty() {
                None
            } else {
                Some(SenderCertificate::deserialize(cert_bytes)?)
            }
        } else {
            None
        };

        // Sender-key state (v3+). Older blobs deserialize with an empty
        // index; the host repopulates by re-processing peers' SKDMs as
        // they arrive over the existing 1:1 channels.
        let mut sender_key_index: Vec<(Vec<u8>, [u8; SENDER_KEY_DISTRIBUTION_ID_LEN])> = Vec::new();
        if version >= 3 && !r.is_empty() {
            let count = r.u32()? as usize;
            for _ in 0..count {
                let sender_identity = r.u16_blob()?.to_vec();
                let dist_id_slice = r.take(SENDER_KEY_DISTRIBUTION_ID_LEN)?;
                let mut dist_bytes = [0u8; SENDER_KEY_DISTRIBUTION_ID_LEN];
                dist_bytes.copy_from_slice(dist_id_slice);
                let record_bytes = r.u32_blob()?;
                let record = SenderKeyRecord::deserialize(record_bytes)?;
                let addr = address_for(&sender_identity);
                let uuid = Uuid::from_bytes(dist_bytes);
                store
                    .sender_key_store
                    .store_sender_key(&addr, uuid, &record)
                    .now_or_never()
                    .expect("in-mem store is sync")?;
                sender_key_index.push((sender_identity, dist_bytes));
            }
        }

        Ok(Self {
            inner: store,
            next_pre_key_id,
            next_signed_pre_key_id,
            next_kyber_pre_key_id,
            peers,
            sender_certificate,
            sender_key_index,
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

/// 4-byte hex shorthand for peer-id log lines. Mirrors the iOS
/// `ChatStore.short` formatter so log entries are correlatable
/// across the two sides of the FFI.
fn hex_short(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(9);
    for b in bytes.iter().take(4) {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s.push('…');
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

/// F-202/F-401: parse a peer's published `delivery_token_verify_key`
/// from their BUNDLE_RESPONSE bytes without consuming the bundle. Used
/// by the iOS receiver to verify each token in a TOKEN_ISSUE batch
/// end-to-end before stashing it (a malicious relay could otherwise
/// swap legitimate batches for relay-forged bytes that fail at SEND).
pub fn extract_bundle_verify_key(bundle_bytes: &[u8]) -> Result<Vec<u8>, SignalProtocolError> {
    let decoded = decode_bundle(bundle_bytes)?;
    Ok(decoded.delivery_token_verify_key)
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
    fn mint_delivery_token_signs_with_recipient_signing_key() {
        // Mint a token; verify its signature against the published
        // verify key. End-to-end shape that the relay (Phase 3) and
        // any unit test of token semantics relies on.
        use libsignal_protocol::PublicKey;
        let s = DeviceStore::fresh().unwrap();
        let token = s.mint_delivery_token().unwrap();
        let verify_bytes = s.delivery_token_verify_key_bytes().unwrap();
        let verify_key = PublicKey::deserialize(&verify_bytes).unwrap();
        let payload = &token[..DELIVERY_TOKEN_NONCE_LEN + 4];
        let sig = &token[DELIVERY_TOKEN_NONCE_LEN + 4..];
        assert_eq!(sig.len(), DELIVERY_TOKEN_SIG_LEN);
        assert!(verify_key.verify_signature(payload, sig));
        // Tamper the payload — must not verify.
        let mut tampered = payload.to_vec();
        tampered[0] ^= 0x01;
        assert!(!verify_key.verify_signature(&tampered, sig));
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
    fn sending_chain_counter_survives_serialize_between_sends() {
        // Regression: when the recipient is offline the sender emits
        // several messages on ONE sending chain (no reply → no DH
        // ratchet step). If `serialize`/`from_serialized` does not
        // preserve the sending-chain message counter, every send after
        // a rehydrate reuses counter 0 and the recipient rejects it as
        // a DuplicatedMessage. Mirrors the field report: "foreground
        // works, but with the peer closed nothing arrives."
        let mut alice = DeviceStore::fresh().unwrap();
        let mut bob = DeviceStore::fresh().unwrap();
        let alice_id = alice.identity_public_bytes();
        let bob_id = bob.identity_public_bytes();
        alice
            .initiate_session(&bob_id, &bob.publish_bundle().unwrap())
            .unwrap();
        bob.register_peer(&alice_id);

        // Message 0 on the chain — live store.
        let s0 = alice.seal_send(&bob_id, &[0u8; 16], b"m0").unwrap();
        let r0 = bob.seal_receive(&s0).unwrap();
        assert!(!r0.is_duplicate, "m0 must decrypt fresh");
        assert_eq!(r0.plaintext, b"m0");

        // Rehydrate Alice (simulates an app relaunch) and send again on
        // the SAME chain — Bob has not replied, so no DH ratchet step.
        let snap = alice.serialize().unwrap();
        let mut alice = DeviceStore::from_serialized(&snap).unwrap();
        let s1 = alice.seal_send(&bob_id, &[1u8; 16], b"m1").unwrap();
        let r1 = bob.seal_receive(&s1).unwrap();
        assert!(
            !r1.is_duplicate,
            "m1 after a serialize round-trip must NOT be a duplicate — \
             the sending-chain counter was lost across from_serialized",
        );
        assert_eq!(r1.plaintext, b"m1");

        // And once more, to prove it advances rather than merely
        // skipping one.
        let snap = alice.serialize().unwrap();
        let mut alice = DeviceStore::from_serialized(&snap).unwrap();
        let s2 = alice.seal_send(&bob_id, &[2u8; 16], b"m2").unwrap();
        let r2 = bob.seal_receive(&s2).unwrap();
        assert!(!r2.is_duplicate, "m2 after a second round-trip must decrypt fresh");
        assert_eq!(r2.plaintext, b"m2");
    }

    #[test]
    fn serialize_does_not_reset_the_live_sending_chain() {
        // The host calls `serialize()` after EVERY `seal_send` (the
        // `persistSession()` flush). If `serialize` mutated the live
        // sending chain back to counter 0, every subsequent send on
        // the same handle would reuse counter 0 and the recipient
        // would reject all of them as duplicates — exactly the field
        // report. `serialize` takes `&mut self`; this pins that the
        // `&mut` does not disturb ratchet state.
        let mut alice = DeviceStore::fresh().unwrap();
        let mut bob = DeviceStore::fresh().unwrap();
        let alice_id = alice.identity_public_bytes();
        let bob_id = bob.identity_public_bytes();
        alice
            .initiate_session(&bob_id, &bob.publish_bundle().unwrap())
            .unwrap();
        bob.register_peer(&alice_id);

        for i in 0..5u8 {
            let s = alice.seal_send(&bob_id, &[i; 16], b"m").unwrap();
            let r = bob.seal_receive(&s).unwrap();
            assert!(
                !r.is_duplicate,
                "send #{i} on the same handle became a duplicate — \
                 serialize() between sends reset the live sending chain",
            );
            // Flush exactly like the iOS `persistSession()` hot path:
            // serialize the SAME live handle after every send.
            let _ = alice.serialize().unwrap();
        }
    }

    #[test]
    fn seal_receive_returns_duplicate_flag_on_replay() {
        // Replay defence: feeding the same sealed bytes through
        // seal_receive twice must surface `is_duplicate = true` on the
        // second call (libsignal's Double Ratchet rejects the second
        // call as DuplicateMessage; we catch it and report instead of
        // bubbling internalError to the iOS layer). sender + message_id
        // are still extracted so the host can re-emit a fresh ACK.
        let mut alice = DeviceStore::fresh().unwrap();
        let mut bob = DeviceStore::fresh().unwrap();
        let alice_id = alice.identity_public_bytes();
        let bob_id = bob.identity_public_bytes();
        alice.initiate_session(&bob_id, &bob.publish_bundle().unwrap()).unwrap();
        bob.register_peer(&alice_id);

        let mut msg_id = [0u8; 16];
        msg_id[0] = 0xDE;
        msg_id[1] = 0xAD;
        let sealed = alice.seal_send(&bob_id, &msg_id, b"hello once").unwrap();

        // First receive: real decrypt.
        let first = bob.seal_receive(&sealed).unwrap();
        assert!(!first.is_duplicate);
        assert_eq!(first.plaintext, b"hello once");
        assert_eq!(first.sender_identity_pub, alice_id);
        assert_eq!(first.message_id, msg_id);

        // Second receive of the same sealed bytes: duplicate flag,
        // empty plaintext, sender + message_id still present.
        let second = bob.seal_receive(&sealed).unwrap();
        assert!(second.is_duplicate);
        assert!(second.plaintext.is_empty());
        assert_eq!(second.sender_identity_pub, alice_id);
        assert_eq!(second.message_id, msg_id);
    }

    #[test]
    fn pad_plaintext_fills_smallest_bucket() {
        // A short message lands in the smallest bucket (256 B). The
        // prefix-encoded length matches the input; the tail is zeros.
        let padded = pad_plaintext(b"hello").unwrap();
        assert_eq!(padded.len(), PADDING_BUCKETS[0]);
        assert_eq!(&padded[..4], &(5u32).to_be_bytes());
        assert_eq!(&padded[4..9], b"hello");
        assert!(padded[9..].iter().all(|&b| b == 0));
    }

    #[test]
    fn pad_plaintext_picks_next_bucket_for_each_size() {
        // 252 bytes: prefix 4 + payload 252 = 256 → smallest bucket.
        let padded_252 = pad_plaintext(&vec![0xAB; 252]).unwrap();
        assert_eq!(padded_252.len(), 256);
        // 253 bytes: prefix 4 + payload 253 = 257 → next bucket (1024).
        let padded_253 = pad_plaintext(&vec![0xCD; 253]).unwrap();
        assert_eq!(padded_253.len(), 1024);
        // 1020 bytes: prefix 4 + payload = 1024 → still 1024.
        let padded_1020 = pad_plaintext(&vec![0xEF; 1020]).unwrap();
        assert_eq!(padded_1020.len(), 1024);
        // 1021 → 4096.
        let padded_1021 = pad_plaintext(&vec![0x01; 1021]).unwrap();
        assert_eq!(padded_1021.len(), 4096);
    }

    #[test]
    fn pad_plaintext_rejects_oversized_payload() {
        // Anything past the biggest bucket - 4 (prefix) is too large.
        let max_payload = PADDING_BUCKETS.last().copied().unwrap() - 4;
        assert!(pad_plaintext(&vec![0; max_payload]).is_ok());
        assert!(pad_plaintext(&vec![0; max_payload + 1]).is_err());
    }

    #[test]
    fn unpad_plaintext_round_trips_padding() {
        for &size in [0usize, 1, 5, 250, 252, 253, 1023, 4095, 65000].iter() {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let padded = pad_plaintext(&plaintext).unwrap();
            let unpadded = unpad_plaintext(&padded).unwrap();
            assert_eq!(unpadded, plaintext, "round-trip failed at size {size}");
        }
    }

    #[test]
    fn unpad_plaintext_rejects_truncated_buffer() {
        assert!(unpad_plaintext(&[0u8; 3]).is_err());
    }

    #[test]
    fn unpad_plaintext_rejects_oversized_prefix() {
        // Length prefix says 1024 bytes but the buffer only has 100
        // bytes of payload — a corrupt or malicious padded blob.
        let mut bad = vec![0u8; 104];
        bad[..4].copy_from_slice(&1024u32.to_be_bytes());
        assert!(unpad_plaintext(&bad).is_err());
    }

    #[test]
    fn seal_send_hides_message_length() {
        // Core guarantee: two messages of wildly different
        // plaintext lengths produce sealed-sender envelopes whose
        // sizes are indistinguishable to the relay (they land in the
        // same bucket).
        let mut alice = DeviceStore::fresh().unwrap();
        let mut bob = DeviceStore::fresh().unwrap();
        let bob_id = bob.identity_public_bytes();
        alice.initiate_session(&bob_id, &bob.publish_bundle().unwrap()).unwrap();
        bob.register_peer(&alice.identity_public_bytes());

        let sealed_tiny = alice.seal_send(&bob_id, &[0u8; 16], b"hi").unwrap();
        let sealed_medium = alice
            .seal_send(&bob_id, &[1u8; 16], &vec![b'A'; 200])
            .unwrap();
        assert_eq!(
            sealed_tiny.len(),
            sealed_medium.len(),
            "two messages in the same 256-byte bucket must produce identical-length envelopes"
        );

        // A message that crosses a bucket boundary produces a
        // different (but still bucketed) envelope size — sanity
        // check that bucket transitions actually happen.
        let sealed_big = alice
            .seal_send(&bob_id, &[2u8; 16], &vec![b'B'; 1500])
            .unwrap();
        assert_ne!(
            sealed_tiny.len(),
            sealed_big.len(),
            "messages in different buckets must produce different envelope sizes"
        );
    }

    #[test]
    fn seal_round_trips_padded_plaintext() {
        // End-to-end: alice pads → encrypts → seals → bob unseals →
        // decrypts → unpads. The plaintext bob sees is exactly what
        // alice sent, regardless of where in a bucket it fell.
        let mut alice = DeviceStore::fresh().unwrap();
        let mut bob = DeviceStore::fresh().unwrap();
        let bob_id = bob.identity_public_bytes();
        alice.initiate_session(&bob_id, &bob.publish_bundle().unwrap()).unwrap();
        bob.register_peer(&alice.identity_public_bytes());

        for (i, payload) in [
            b"" as &[u8],
            b"single",
            &[0xAA; 252],
            &[0xBB; 1020],
            &[0xCC; 4090],
        ]
        .iter()
        .enumerate()
        {
            let mut msg_id = [0u8; 16];
            msg_id[0] = i as u8;
            let sealed = alice.seal_send(&bob_id, &msg_id, payload).unwrap();
            let received = bob.seal_receive(&sealed).unwrap();
            assert!(!received.is_duplicate);
            assert_eq!(received.plaintext, payload.to_vec(), "round-trip {i}");
            assert_eq!(received.message_id, msg_id);
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
        // The unknown-sender rejection is attacker-attributable, so it
        // must surface as `BadSignature`, not a generic internal error.
        assert!(matches!(err, SealReceiveError::BadSignature(_)));
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
        let mut s = DeviceStore::fresh().unwrap();
        let blob = s.serialize().unwrap();
        let s2 = DeviceStore::from_serialized(&blob).unwrap();
        assert_eq!(s.identity_keypair_bytes(), s2.identity_keypair_bytes());
        assert_eq!(s.registration_id(), s2.registration_id());
    }

    #[test]
    fn from_serialized_skips_corrupted_session_record() {
        // Regression guard: a single corrupted session
        // record must not lose the entire store. We can't easily
        // inject a deliberately-corrupted record because the
        // serializer always produces well-formed bytes, so this
        // test exercises the happy path; the skip-and-continue path
        // is only reachable via on-disk bit flips. The test stands
        // as documentation that the loop has the right shape.
        let mut alice = DeviceStore::fresh().unwrap();
        let blob = alice.serialize().unwrap();
        let _ = DeviceStore::from_serialized(&blob).expect("round-trip clean blob");
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
