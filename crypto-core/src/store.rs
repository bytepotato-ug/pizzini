//! Per-device libsignal session store. Each Pizzini install owns one
//! `DeviceStore`; peers exchange PreKey bundles out-of-band (QR), then
//! encrypt/decrypt via wire-format ciphertexts shipped over a relay.
//!
//! Bundle wire format (`v1`, big-endian):
//!
//! ```text
//! u8  version = 1
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
//! ```
//!
//! Hand-rolled rather than protobuf to keep the dependency surface minimal —
//! libsignal does not export a wire-stable bundle encoder.

use std::time::SystemTime;

use futures_util::FutureExt as _;
use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore, KeyPair, KyberPreKeyRecord,
    KyberPreKeyStore, PreKeyBundle, PreKeyRecord, PreKeySignalMessage, PreKeyStore,
    ProtocolAddress, PublicKey, SignalMessage, SignalProtocolError, SignedPreKeyRecord,
    SignedPreKeyStore, Timestamp, kem, message_decrypt, message_encrypt, process_prekey_bundle,
};
use rand::{Rng, TryRngCore as _, rngs::OsRng};

const BUNDLE_VERSION: u8 = 1;
const DEVICE_ID: u8 = 1;

pub struct DeviceStore {
    inner: InMemSignalProtocolStore,
    next_pre_key_id: u32,
    next_signed_pre_key_id: u32,
    next_kyber_pre_key_id: u32,
}

pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub is_prekey: bool,
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
        })
    }

    /// Rehydrate from a previously-saved IdentityKeyPair (i.e. the bytes from
    /// `identity_keypair_bytes`). Registration id is freshly drawn — it does
    /// not need to be stable across reinstalls in our model.
    pub fn from_identity(seed_bytes: &[u8]) -> Result<Self, SignalProtocolError> {
        let id = IdentityKeyPair::try_from(seed_bytes)?;
        let mut rng = OsRng.unwrap_err();
        let reg = registration_id(&mut rng);
        Ok(Self {
            inner: InMemSignalProtocolStore::new(id, reg)?,
            next_pre_key_id: 1,
            next_signed_pre_key_id: 1,
            next_kyber_pre_key_id: 1,
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

    fn local_identity_keypair(&self) -> IdentityKeyPair {
        self.inner
            .identity_store
            .get_identity_key_pair()
            .now_or_never()
            .expect("in-mem store is sync")
            .expect("infallible for in-mem identity store")
    }

    pub fn publish_bundle(&mut self) -> Result<Vec<u8>, SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let id_kp = self.local_identity_keypair();

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
        ))
    }

    pub fn initiate_session(
        &mut self,
        peer_identity: &[u8],
        bundle_bytes: &[u8],
    ) -> Result<(), SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();
        let bundle = decode_bundle(bundle_bytes)?;
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
            &bundle,
            SystemTime::now(),
            &mut rng,
        )
        .now_or_never()
        .expect("in-mem store is sync")
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
        message_decrypt(
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
        .expect("in-mem store is sync")
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
    use std::fmt::Write as _;
    let mut name = String::with_capacity(identity_public.len() * 2);
    for b in identity_public {
        let _ = write!(&mut name, "{b:02x}");
    }
    ProtocolAddress::new(name, DeviceId::new(DEVICE_ID).expect("device id non-zero"))
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
    out
}

fn decode_bundle(bytes: &[u8]) -> Result<PreKeyBundle, SignalProtocolError> {
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
    if !r.is_empty() {
        return Err(SignalProtocolError::InvalidArgument(
            "trailing bytes after bundle".into(),
        ));
    }
    PreKeyBundle::new(
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
    )
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
        let bundle = decode_bundle(&bytes).unwrap();
        assert_eq!(bundle.registration_id().unwrap(), s.registration_id());
        assert_eq!(
            bundle.identity_key().unwrap().serialize().as_ref(),
            s.identity_public_bytes().as_slice()
        );
    }
}
