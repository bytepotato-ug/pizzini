//! Integration test: PQXDH handshake + first-message round-trip.
//!
//! Mirrors the flow in examples/pqxdh_roundtrip.rs (which is the human-facing
//! "CLI test client") but as a #[test] so `cargo test` catches regressions.

use std::time::SystemTime;

use futures_util::FutureExt as _;
use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKeyPair,
    InMemSignalProtocolStore, KeyPair, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle,
    PreKeyRecord, PreKeySignalMessage, PreKeyStore, ProtocolAddress, SignedPreKeyRecord,
    SignedPreKeyStore, Timestamp, kem, message_decrypt, message_encrypt, process_prekey_bundle,
};
use rand::{Rng, TryRngCore as _, rngs::OsRng};

#[test]
fn pqxdh_roundtrip_in_memory() {
    let mut rng = OsRng.unwrap_err();

    let alice_addr = ProtocolAddress::new("alice".into(), DeviceId::new(1).unwrap());
    let bob_addr = ProtocolAddress::new("bob".into(), DeviceId::new(1).unwrap());

    let alice_id = IdentityKeyPair::generate(&mut rng);
    let bob_id = IdentityKeyPair::generate(&mut rng);
    let alice_reg: u32 = (rng.random::<u16>() as u32 & 0x3FFF) | 1;
    let bob_reg: u32 = (rng.random::<u16>() as u32 & 0x3FFF) | 1;
    let mut alice_store = InMemSignalProtocolStore::new(alice_id, alice_reg).unwrap();
    let mut bob_store = InMemSignalProtocolStore::new(bob_id, bob_reg).unwrap();

    // Bob's prekeys.
    let bob_pre_kp = KeyPair::generate(&mut rng);
    let bob_pre_id: u32 = 1;
    bob_store
        .save_pre_key(
            bob_pre_id.into(),
            &PreKeyRecord::new(bob_pre_id.into(), &bob_pre_kp),
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    let bob_signed_kp = KeyPair::generate(&mut rng);
    let bob_signed_id: u32 = 1;
    let bob_signed_sig = bob_id
        .private_key()
        .calculate_signature(&bob_signed_kp.public_key.serialize(), &mut rng)
        .unwrap();
    bob_store
        .save_signed_pre_key(
            bob_signed_id.into(),
            &SignedPreKeyRecord::new(
                bob_signed_id.into(),
                Timestamp::from_epoch_millis(1_715_000_000_000),
                &bob_signed_kp,
                &bob_signed_sig,
            ),
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    let bob_kyber_kp = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let bob_kyber_id: u32 = 1;
    let bob_kyber_sig = bob_id
        .private_key()
        .calculate_signature(&bob_kyber_kp.public_key.serialize(), &mut rng)
        .unwrap();
    bob_store
        .save_kyber_pre_key(
            bob_kyber_id.into(),
            &KyberPreKeyRecord::new(
                bob_kyber_id.into(),
                Timestamp::from_epoch_millis(1_715_000_000_000),
                &bob_kyber_kp,
                &bob_kyber_sig,
            ),
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    let bundle = PreKeyBundle::new(
        bob_reg,
        DeviceId::new(1).unwrap(),
        Some((bob_pre_id.into(), bob_pre_kp.public_key)),
        bob_signed_id.into(),
        bob_signed_kp.public_key,
        bob_signed_sig.to_vec(),
        bob_kyber_id.into(),
        bob_kyber_kp.public_key.clone(),
        bob_kyber_sig.to_vec(),
        *bob_id.identity_key(),
    )
    .unwrap();

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
    .unwrap()
    .unwrap();

    let plaintext = b"PQXDH works on the first try, allegedly.";
    let outgoing = message_encrypt(
        plaintext,
        &bob_addr,
        &alice_addr,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .now_or_never()
    .unwrap()
    .unwrap();

    assert_eq!(outgoing.message_type(), CiphertextMessageType::PreKey);

    let parsed = CiphertextMessage::PreKeySignalMessage(
        PreKeySignalMessage::try_from(outgoing.serialize()).unwrap(),
    );

    let recovered = message_decrypt(
        &parsed,
        &alice_addr,
        &bob_addr,
        &mut bob_store.session_store,
        &mut bob_store.identity_store,
        &mut bob_store.pre_key_store,
        &bob_store.signed_pre_key_store,
        &mut bob_store.kyber_pre_key_store,
        &mut rng,
    )
    .now_or_never()
    .unwrap()
    .unwrap();

    assert_eq!(&recovered[..], plaintext);
}

#[test]
fn bidirectional_session_falls_back_to_whisper() {
    // Alice → Bob is PreKey until Bob replies. Once Bob sends a Whisper back,
    // Alice's subsequent messages are Whisper too. This exercises the ratchet
    // step on both sides.
    let mut rng = OsRng.unwrap_err();

    let alice_addr = ProtocolAddress::new("alice".into(), DeviceId::new(1).unwrap());
    let bob_addr = ProtocolAddress::new("bob".into(), DeviceId::new(1).unwrap());

    let alice_id = IdentityKeyPair::generate(&mut rng);
    let bob_id = IdentityKeyPair::generate(&mut rng);
    let alice_reg: u32 = (rng.random::<u16>() as u32 & 0x3FFF) | 1;
    let bob_reg: u32 = (rng.random::<u16>() as u32 & 0x3FFF) | 1;
    let mut alice_store = InMemSignalProtocolStore::new(alice_id, alice_reg).unwrap();
    let mut bob_store = InMemSignalProtocolStore::new(bob_id, bob_reg).unwrap();

    let bob_pre_kp = KeyPair::generate(&mut rng);
    bob_store
        .save_pre_key(1u32.into(), &PreKeyRecord::new(1u32.into(), &bob_pre_kp))
        .now_or_never()
        .unwrap()
        .unwrap();

    let bob_signed_kp = KeyPair::generate(&mut rng);
    let bob_signed_sig = bob_id
        .private_key()
        .calculate_signature(&bob_signed_kp.public_key.serialize(), &mut rng)
        .unwrap();
    bob_store
        .save_signed_pre_key(
            1u32.into(),
            &SignedPreKeyRecord::new(
                1u32.into(),
                Timestamp::from_epoch_millis(1_715_000_000_000),
                &bob_signed_kp,
                &bob_signed_sig,
            ),
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    let bob_kyber_kp = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let bob_kyber_sig = bob_id
        .private_key()
        .calculate_signature(&bob_kyber_kp.public_key.serialize(), &mut rng)
        .unwrap();
    bob_store
        .save_kyber_pre_key(
            1u32.into(),
            &KyberPreKeyRecord::new(
                1u32.into(),
                Timestamp::from_epoch_millis(1_715_000_000_000),
                &bob_kyber_kp,
                &bob_kyber_sig,
            ),
        )
        .now_or_never()
        .unwrap()
        .unwrap();

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
    )
    .unwrap();

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
    .unwrap()
    .unwrap();

    // First message: PreKey (encrypted handshake).
    let m1 = message_encrypt(
        b"hello",
        &bob_addr,
        &alice_addr,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .now_or_never()
    .unwrap()
    .unwrap();
    assert_eq!(m1.message_type(), CiphertextMessageType::PreKey);

    // Bob processes m1 so the session exists on his side.
    let m1_parsed = CiphertextMessage::PreKeySignalMessage(
        PreKeySignalMessage::try_from(m1.serialize()).unwrap(),
    );
    message_decrypt(
        &m1_parsed,
        &alice_addr,
        &bob_addr,
        &mut bob_store.session_store,
        &mut bob_store.identity_store,
        &mut bob_store.pre_key_store,
        &bob_store.signed_pre_key_store,
        &mut bob_store.kyber_pre_key_store,
        &mut rng,
    )
    .now_or_never()
    .unwrap()
    .unwrap();

    // Bob → Alice: first reply from Bob is Whisper (session already exists).
    let bob_reply = message_encrypt(
        b"hi back",
        &alice_addr,
        &bob_addr,
        &mut bob_store.session_store,
        &mut bob_store.identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .now_or_never()
    .unwrap()
    .unwrap();
    assert_eq!(bob_reply.message_type(), CiphertextMessageType::Whisper);

    // Alice decrypts Bob's reply.
    let bob_reply_parsed = CiphertextMessage::SignalMessage(
        libsignal_protocol::SignalMessage::try_from(bob_reply.serialize()).unwrap(),
    );
    let recovered = message_decrypt(
        &bob_reply_parsed,
        &bob_addr,
        &alice_addr,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &mut alice_store.pre_key_store,
        &alice_store.signed_pre_key_store,
        &mut alice_store.kyber_pre_key_store,
        &mut rng,
    )
    .now_or_never()
    .unwrap()
    .unwrap();
    assert_eq!(&recovered[..], b"hi back");

    // Now Alice's next message to Bob must be Whisper, not PreKey.
    let m3 = message_encrypt(
        b"and again",
        &bob_addr,
        &alice_addr,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .now_or_never()
    .unwrap()
    .unwrap();
    assert_eq!(m3.message_type(), CiphertextMessageType::Whisper);
}
