//! End-to-end PQXDH handshake demo.
//!
//! Two parties (Alice, Bob) each hold their own InMemSignalProtocolStore.
//! Bob publishes a PreKeyBundle (EC + signed-EC + Kyber1024); Alice processes
//! it to establish a session, encrypts a message, and Bob decrypts. Asserts
//! that the plaintext round-trips and that Alice's first message is of type
//! PreKey (i.e., she initiated via PQXDH).
//!
//! Run with: `cargo run --example pqxdh_roundtrip`

use std::time::SystemTime;

use futures_util::FutureExt as _;
use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKeyPair,
    InMemSignalProtocolStore, KeyPair, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle,
    PreKeyRecord, PreKeySignalMessage, PreKeyStore, ProtocolAddress, SignedPreKeyRecord,
    SignedPreKeyStore, Timestamp, kem, message_decrypt, message_encrypt, process_prekey_bundle,
};
use rand::{Rng, TryRngCore as _, rngs::OsRng};

fn main() {
    pqxdh_roundtrip().expect("PQXDH roundtrip");
    println!("== OK ==");
}

fn pqxdh_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    println!("== Pizzini PQXDH roundtrip demo ==");

    let mut rng = OsRng.unwrap_err();

    let alice_addr = ProtocolAddress::new("alice".into(), DeviceId::new(1).unwrap());
    let bob_addr = ProtocolAddress::new("bob".into(), DeviceId::new(1).unwrap());

    // ── Identity & store setup ────────────────────────────────────────
    let alice_id = IdentityKeyPair::generate(&mut rng);
    let bob_id = IdentityKeyPair::generate(&mut rng);
    // Registration IDs fit in 14 bits and must be nonzero.
    let alice_reg: u32 = (rng.random::<u16>() as u32 & 0x3FFF) | 1;
    let bob_reg: u32 = (rng.random::<u16>() as u32 & 0x3FFF) | 1;
    let mut alice_store = InMemSignalProtocolStore::new(alice_id, alice_reg)?;
    let mut bob_store = InMemSignalProtocolStore::new(bob_id, bob_reg)?;

    // ── Bob: generate one-time EC prekey ──────────────────────────────
    let bob_pre_id: u32 = 1;
    let bob_pre_kp = KeyPair::generate(&mut rng);
    bob_store
        .save_pre_key(
            bob_pre_id.into(),
            &PreKeyRecord::new(bob_pre_id.into(), &bob_pre_kp),
        )
        .now_or_never()
        .expect("in-mem store is sync")?;

    // ── Bob: signed prekey (long-term identity signs the public key) ──
    let bob_signed_id: u32 = 1;
    let bob_signed_kp = KeyPair::generate(&mut rng);
    let bob_signed_sig = bob_id
        .private_key()
        .calculate_signature(&bob_signed_kp.public_key.serialize(), &mut rng)?;
    let bob_signed_record = SignedPreKeyRecord::new(
        bob_signed_id.into(),
        Timestamp::from_epoch_millis(1715000000000),
        &bob_signed_kp,
        &bob_signed_sig,
    );
    bob_store
        .save_signed_pre_key(bob_signed_id.into(), &bob_signed_record)
        .now_or_never()
        .expect("in-mem store is sync")?;

    // ── Bob: Kyber1024 PQ prekey (also signed by identity) ───────────
    let bob_kyber_id: u32 = 1;
    let bob_kyber_kp = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let bob_kyber_sig = bob_id
        .private_key()
        .calculate_signature(&bob_kyber_kp.public_key.serialize(), &mut rng)?;
    let bob_kyber_record = KyberPreKeyRecord::new(
        bob_kyber_id.into(),
        Timestamp::from_epoch_millis(1715000000000),
        &bob_kyber_kp,
        &bob_kyber_sig,
    );
    bob_store
        .save_kyber_pre_key(bob_kyber_id.into(), &bob_kyber_record)
        .now_or_never()
        .expect("in-mem store is sync")?;

    println!(
        "[Bob ] published prekeys: ec={} signed={} kyber={}",
        bob_pre_id, bob_signed_id, bob_kyber_id
    );

    // ── Bob: assemble PreKeyBundle ────────────────────────────────────
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
    )?;

    // ── Alice: process bundle → session (PQXDH happens here) ─────────
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
    println!("[Alice] processed bundle — session established");

    // ── Alice: encrypt initial message (carries PQXDH handshake) ──────
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
    .expect("in-mem store is sync")?;

    assert_eq!(
        outgoing.message_type(),
        CiphertextMessageType::PreKey,
        "Alice's first message must be a PreKey signal message"
    );
    println!(
        "[Alice] encrypted: {} bytes, type=PreKey",
        outgoing.serialize().len()
    );

    // ── Wire format round-trip (serialize → parse) ────────────────────
    let parsed = CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(
        outgoing.serialize(),
    )?);

    // ── Bob: decrypt ──────────────────────────────────────────────────
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
    .expect("in-mem store is sync")?;

    assert_eq!(&recovered[..], plaintext, "plaintext must round-trip");
    println!(
        "[Bob ] decrypted: {:?}",
        std::str::from_utf8(&recovered).unwrap_or("<non-utf8>")
    );

    Ok(())
}
