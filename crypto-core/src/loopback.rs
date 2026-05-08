//! In-process Alice ↔ Bob loopback for demoing the full PQXDH + ratchet stack
//! without a network. Both parties' protocol stores live in this struct, so
//! `alice_send` runs the full encrypt/decrypt round-trip in one call.
//!
//! This is *not* the production messaging path. It exists so the iOS UI can
//! show real libsignal traffic — PreKey messages flipping to Whisper as the
//! ratchet pumps — without an actual peer or relay.

use std::time::SystemTime;

use futures_util::FutureExt as _;
use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKeyPair,
    InMemSignalProtocolStore, KeyPair, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle,
    PreKeyRecord, PreKeySignalMessage, PreKeyStore, ProtocolAddress, SignalMessage,
    SignalProtocolError, SignedPreKeyRecord, SignedPreKeyStore, Timestamp, kem, message_decrypt,
    message_encrypt, process_prekey_bundle,
};
use rand::{Rng, TryRngCore as _, rngs::OsRng};

pub struct LoopbackState {
    alice_store: InMemSignalProtocolStore,
    bob_store: InMemSignalProtocolStore,
    alice_addr: ProtocolAddress,
    bob_addr: ProtocolAddress,
}

pub struct RoundtripResult {
    pub ciphertext: Vec<u8>,
    pub decrypted: Vec<u8>,
    pub is_prekey: bool,
}

impl LoopbackState {
    pub fn new() -> Result<Self, SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();

        let alice_addr = ProtocolAddress::new("alice".into(), DeviceId::new(1).unwrap());
        let bob_addr = ProtocolAddress::new("bob".into(), DeviceId::new(1).unwrap());

        let alice_id = IdentityKeyPair::generate(&mut rng);
        let bob_id = IdentityKeyPair::generate(&mut rng);
        let alice_reg: u32 = (rng.random::<u16>() as u32 & 0x3FFF) | 1;
        let bob_reg: u32 = (rng.random::<u16>() as u32 & 0x3FFF) | 1;
        let mut alice_store = InMemSignalProtocolStore::new(alice_id, alice_reg)?;
        let mut bob_store = InMemSignalProtocolStore::new(bob_id, bob_reg)?;

        // Bob populates his stores with one-time, signed, and PQ pre-keys.
        let bob_pre_kp = KeyPair::generate(&mut rng);
        bob_store
            .save_pre_key(1u32.into(), &PreKeyRecord::new(1u32.into(), &bob_pre_kp))
            .now_or_never()
            .expect("in-mem store is sync")?;

        let bob_signed_kp = KeyPair::generate(&mut rng);
        let bob_signed_sig = bob_id
            .private_key()
            .calculate_signature(&bob_signed_kp.public_key.serialize(), &mut rng)?;
        bob_store
            .save_signed_pre_key(
                1u32.into(),
                &SignedPreKeyRecord::new(
                    1u32.into(),
                    Timestamp::from_epoch_millis(now_millis()),
                    &bob_signed_kp,
                    &bob_signed_sig,
                ),
            )
            .now_or_never()
            .expect("in-mem store is sync")?;

        let bob_kyber_kp = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
        let bob_kyber_sig = bob_id
            .private_key()
            .calculate_signature(&bob_kyber_kp.public_key.serialize(), &mut rng)?;
        bob_store
            .save_kyber_pre_key(
                1u32.into(),
                &KyberPreKeyRecord::new(
                    1u32.into(),
                    Timestamp::from_epoch_millis(now_millis()),
                    &bob_kyber_kp,
                    &bob_kyber_sig,
                ),
            )
            .now_or_never()
            .expect("in-mem store is sync")?;

        let bundle = PreKeyBundle::new(
            bob_reg,
            DeviceId::new(1).unwrap(),
            Some((1u32.into(), bob_pre_kp.public_key)),
            1u32.into(),
            bob_signed_kp.public_key,
            bob_signed_sig.to_vec(),
            1u32.into(),
            bob_kyber_kp.public_key.clone(),
            bob_kyber_sig.to_vec(),
            *bob_id.identity_key(),
        )?;

        // Alice consumes the bundle. After this, she has a session ready.
        process_prekey_bundle(
            &bob_addr,
            &alice_addr,
            &mut alice_store.session_store,
            &mut alice_store.identity_store,
            &bundle,
            SystemTime::now(),
            &mut rng,
        )
        .now_or_never()
        .expect("in-mem store is sync")?;

        Ok(Self {
            alice_store,
            bob_store,
            alice_addr,
            bob_addr,
        })
    }

    /// Encrypts via Alice and decrypts on Bob in one round-trip.
    pub fn alice_send(&mut self, plaintext: &[u8]) -> Result<RoundtripResult, SignalProtocolError> {
        encrypt_and_decrypt(
            plaintext,
            // sender → recipient
            &mut self.alice_store,
            &self.alice_addr,
            &mut self.bob_store,
            &self.bob_addr,
        )
    }

    /// Encrypts via Bob and decrypts on Alice in one round-trip. Pumps the
    /// ratchet — after one bob_send, Alice's next alice_send is a Whisper
    /// message, not a PreKey one.
    pub fn bob_send(&mut self, plaintext: &[u8]) -> Result<RoundtripResult, SignalProtocolError> {
        encrypt_and_decrypt(
            plaintext,
            &mut self.bob_store,
            &self.bob_addr,
            &mut self.alice_store,
            &self.alice_addr,
        )
    }
}

fn encrypt_and_decrypt(
    plaintext: &[u8],
    sender_store: &mut InMemSignalProtocolStore,
    sender_addr: &ProtocolAddress,
    recipient_store: &mut InMemSignalProtocolStore,
    recipient_addr: &ProtocolAddress,
) -> Result<RoundtripResult, SignalProtocolError> {
    let mut rng = OsRng.unwrap_err();

    let outgoing = message_encrypt(
        plaintext,
        recipient_addr,
        sender_addr,
        &mut sender_store.session_store,
        &mut sender_store.identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .now_or_never()
    .expect("in-mem store is sync")?;

    let is_prekey = outgoing.message_type() == CiphertextMessageType::PreKey;
    let ciphertext_bytes = outgoing.serialize().to_vec();

    let parsed = if is_prekey {
        CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(outgoing.serialize())?)
    } else {
        CiphertextMessage::SignalMessage(SignalMessage::try_from(outgoing.serialize())?)
    };

    let decrypted = message_decrypt(
        &parsed,
        sender_addr,
        recipient_addr,
        &mut recipient_store.session_store,
        &mut recipient_store.identity_store,
        &mut recipient_store.pre_key_store,
        &recipient_store.signed_pre_key_store,
        &mut recipient_store.kyber_pre_key_store,
        &mut rng,
    )
    .now_or_never()
    .expect("in-mem store is sync")?;

    Ok(RoundtripResult {
        ciphertext: ciphertext_bytes,
        decrypted,
        is_prekey,
    })
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_first_message_is_prekey() {
        let mut s = LoopbackState::new().unwrap();
        let r = s.alice_send(b"hello").unwrap();
        assert!(r.is_prekey);
        assert_eq!(r.decrypted, b"hello");
    }

    #[test]
    fn loopback_after_bob_reply_alice_uses_whisper() {
        let mut s = LoopbackState::new().unwrap();
        let r1 = s.alice_send(b"first").unwrap();
        assert!(r1.is_prekey);
        let r2 = s.bob_send(b"reply").unwrap();
        // bob's first reply is a Whisper (session already established).
        assert!(!r2.is_prekey);
        let r3 = s.alice_send(b"second").unwrap();
        assert!(!r3.is_prekey, "alice should now be in Whisper mode");
        assert_eq!(r3.decrypted, b"second");
    }
}
