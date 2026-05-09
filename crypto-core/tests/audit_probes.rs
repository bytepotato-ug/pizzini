//! Adversarial probes for Surface 1 (sealed sender). Originally
//! written by an external reviewer to demonstrate the F-101/F-701
//! buffer-too-small ratchet-advance bug; updated post-fix to verify
//! the corrected behaviour. Treat as regression coverage for the
//! peek-then-commit FFI contract.

use futures_util::FutureExt as _;
use libsignal_protocol::{
    CiphertextMessageType, ContentHint, DeviceId, ProtocolAddress, SenderCertificate,
    ServerCertificate, Timestamp, UnidentifiedSenderMessageContent, message_encrypt,
    sealed_sender_encrypt_from_usmc,
};
use rand::TryRngCore as _;
use rand::rngs::OsRng;

use pizzini_crypto_core::{
    pizzini_store_seal_receive, DeviceStore, PIZZINI_ERR_BUFFER_TOO_SMALL, PIZZINI_OK,
};

/// Helper: pair two stores so seal_send/seal_receive are bidirectional.
fn pair() -> (DeviceStore, DeviceStore) {
    let mut alice = DeviceStore::fresh().unwrap();
    let mut bob = DeviceStore::fresh().unwrap();
    let bob_id = bob.identity_public_bytes();
    let alice_id = alice.identity_public_bytes();
    let bundle = bob.publish_bundle().unwrap();
    alice.initiate_session(&bob_id, &bundle).unwrap();
    bob.register_peer(&alice_id);
    (alice, bob)
}

/// Regression for F-101 / F-701: when `pizzini_store_seal_receive`
/// returns BUFFER_TOO_SMALL, the libsignal ratchet must NOT have
/// advanced. The Swift wrapper's retry-with-bigger-buffer pattern
/// must surface the original plaintext on the second call. Was the
/// bug-confirming PoC; now the fix verifier.
#[test]
fn buffer_too_small_silently_advances_ratchet_via_ffi() {
    let (mut alice, mut bob) = pair();
    let bob_id = bob.identity_public_bytes();

    // Build a plaintext large enough that the inner is_prekey ratchet
    // ciphertext exceeds the Swift initial buffer of max(sealed+256, 1024).
    // Sealed grows roughly linearly with plaintext, so a moderate payload
    // is plenty to trip an artificially small out_plaintext_cap.
    let plaintext = b"hello bob this is a normal message".to_vec();
    let mut msg_id = [0u8; 16];
    msg_id[0] = 0xAB;
    let sealed = alice.seal_send(&bob_id, &msg_id, &plaintext).unwrap();

    // Drive seal_receive via the FFI with intentionally tiny output
    // buffers. We expect BUFFER_TOO_SMALL on the first call.
    let mut sender_buf = vec![0u8; 4]; // intentionally tiny
    let mut sender_len = 0usize;
    let mut msg_id_out = [0u8; 16];
    let mut pt_buf = vec![0u8; 4]; // intentionally tiny
    let mut pt_len = 0usize;
    let mut is_dup = 0u8;

    let bob_ptr: *mut DeviceStore = &mut bob;
    let rc = unsafe {
        pizzini_store_seal_receive(
            bob_ptr,
            sealed.as_ptr(),
            sealed.len(),
            sender_buf.as_mut_ptr(),
            sender_buf.len(),
            &mut sender_len,
            msg_id_out.as_mut_ptr(),
            pt_buf.as_mut_ptr(),
            pt_buf.len(),
            &mut pt_len,
            &mut is_dup,
        )
    };
    assert_eq!(rc, PIZZINI_ERR_BUFFER_TOO_SMALL);

    // Now retry with adequate buffers, just like Swift's two-shot path.
    let mut sender_buf2 = vec![0u8; sender_len];
    let mut pt_buf2 = vec![0u8; pt_len];
    let rc2 = unsafe {
        pizzini_store_seal_receive(
            bob_ptr,
            sealed.as_ptr(),
            sealed.len(),
            sender_buf2.as_mut_ptr(),
            sender_buf2.len(),
            &mut sender_len,
            msg_id_out.as_mut_ptr(),
            pt_buf2.as_mut_ptr(),
            pt_buf2.len(),
            &mut pt_len,
            &mut is_dup,
        )
    };
    assert_eq!(rc2, PIZZINI_OK);

    // Post F-101/F-701 fix: the FFI peeks USMC sizes BEFORE running
    // message_decrypt. The first call's BUFFER_TOO_SMALL did not advance
    // the ratchet, so the retry surfaces the original plaintext.
    assert_eq!(is_dup, 0, "ratchet must not advance on rc1=BUFFER_TOO_SMALL");
    assert_eq!(
        &pt_buf2[..pt_len],
        &plaintext[..],
        "retry must surface the original plaintext"
    );
}

/// Probe: forge a USMC where the outer msg_type is PreKey but the
/// inner is_prekey byte says 0 (Whisper). The receiver parses the
/// inner ratchet according to the BYTE, ignoring USMC msg_type. Does
/// this confuse the ratchet?
#[test]
fn is_prekey_byte_disagrees_with_usmc_msg_type() {
    use std::time::SystemTime;

    let mut alice = DeviceStore::fresh().unwrap();
    let mut bob = DeviceStore::fresh().unwrap();
    let bob_id = bob.identity_public_bytes();
    let alice_id = alice.identity_public_bytes();
    let bundle = bob.publish_bundle().unwrap();
    alice.initiate_session(&bob_id, &bundle).unwrap();
    bob.register_peer(&alice_id);

    // Encrypt a PreKey ratchet message using Alice's session.
    let alice_id_kp = alice.local_identity_keypair();
    let bob_addr = ProtocolAddress::new(hex_lower(&bob_id), DeviceId::new(1).unwrap());
    let alice_addr = ProtocolAddress::new(hex_lower(&alice_id), DeviceId::new(1).unwrap());

    let mut rng = OsRng.unwrap_err();
    let inner = {
        let store = alice.inner_mut();
        message_encrypt(
            b"pkmsg",
            &bob_addr,
            &alice_addr,
            &mut store.session_store,
            &mut store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .now_or_never()
        .unwrap()
        .unwrap()
    };
    assert_eq!(inner.message_type(), CiphertextMessageType::PreKey);

    // Build USMC contents with is_prekey byte = 0 (LIE) but USMC msg_type=PreKey.
    let mut content = Vec::new();
    let msg_id = [0xCDu8; 16];
    content.extend_from_slice(&msg_id);
    content.push(0); // LIE: claims Whisper
    content.extend_from_slice(inner.serialize());

    // Mint a sender cert for Alice (mirrors ensure_sender_certificate).
    let id_pub = *alice_id_kp.public_key();
    let id_priv = alice_id_kp.private_key();
    let server_cert = ServerCertificate::new(1, id_pub, id_priv, &mut rng).unwrap();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let expiration = Timestamp::from_epoch_millis(now + 30 * 24 * 60 * 60 * 1000);
    let sender_cert = SenderCertificate::new(
        hex_lower(&alice_id),
        None,
        id_pub,
        DeviceId::new(1).unwrap(),
        expiration,
        server_cert,
        id_priv,
        &mut rng,
    )
    .unwrap();

    let usmc = UnidentifiedSenderMessageContent::new(
        inner.message_type(), // PreKey
        sender_cert,
        content,
        ContentHint::Default,
        None,
    )
    .unwrap();

    let sealed = sealed_sender_encrypt_from_usmc(
        &bob_addr,
        &usmc,
        &alice.inner_mut().identity_store,
        &mut rng,
    )
    .now_or_never()
    .unwrap()
    .unwrap();

    // What does Bob do?
    let result = bob.seal_receive(&sealed);
    println!("is_prekey=0 + PreKey contents: {:?}", result.as_ref().map(|r| r.plaintext.clone()));
    // We expect this to fail (parse fails since try_from(SignalMessage)
    // sees a PreKey-tagged buffer). Verify it doesn't crash and that
    // the session state is in some recoverable form.
    assert!(result.is_err(), "lying is_prekey=0 with PreKey contents should fail to parse");
}

fn hex_lower(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        write!(&mut s, "{x:02x}").unwrap();
    }
    s
}

/// Probe: empty-ratchet smuggle. inner_bytes.len() == 17 means the
/// header consumes everything and `ratchet = &inner_bytes[17..]` is empty.
#[test]
fn empty_ratchet_after_header_does_not_crash() {
    use std::time::SystemTime;

    let mut alice = DeviceStore::fresh().unwrap();
    let mut bob = DeviceStore::fresh().unwrap();
    let bob_id = bob.identity_public_bytes();
    let alice_id = alice.identity_public_bytes();
    let bundle = bob.publish_bundle().unwrap();
    alice.initiate_session(&bob_id, &bundle).unwrap();
    bob.register_peer(&alice_id);

    let alice_id_kp = alice.local_identity_keypair();
    let bob_addr = ProtocolAddress::new(hex_lower(&bob_id), DeviceId::new(1).unwrap());
    let mut rng = OsRng.unwrap_err();

    // Build USMC contents with exactly 17 bytes: 16 message_id + 1 is_prekey.
    let mut content = vec![0u8; 17];
    content[16] = 0; // is_prekey false → SignalMessage::try_from(empty)

    let id_pub = *alice_id_kp.public_key();
    let id_priv = alice_id_kp.private_key();
    let server_cert = ServerCertificate::new(1, id_pub, id_priv, &mut rng).unwrap();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let expiration = Timestamp::from_epoch_millis(now + 30 * 24 * 60 * 60 * 1000);
    let sender_cert = SenderCertificate::new(
        hex_lower(&alice_id),
        None,
        id_pub,
        DeviceId::new(1).unwrap(),
        expiration,
        server_cert,
        id_priv,
        &mut rng,
    )
    .unwrap();

    // We need a CiphertextMessageType to satisfy USMC::new — pick Whisper to match the byte.
    let usmc = UnidentifiedSenderMessageContent::new(
        CiphertextMessageType::Whisper,
        sender_cert,
        content,
        ContentHint::Default,
        None,
    )
    .unwrap();

    let sealed = sealed_sender_encrypt_from_usmc(
        &bob_addr,
        &usmc,
        &alice.inner_mut().identity_store,
        &mut rng,
    )
    .now_or_never()
    .unwrap()
    .unwrap();

    let result = bob.seal_receive(&sealed);
    println!("empty ratchet body: {:?}", result.is_err());
    assert!(result.is_err(), "should error, not panic");
}
