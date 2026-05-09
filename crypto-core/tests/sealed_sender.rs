//! Phase 0 feasibility verification: prove that libsignal v0.93.2's
//! SealedSenderV1 with self-issued sender certificates is workable for
//! Pizzini's no-CA model.
//!
//! The relay v2 wire format strips `from_id` and `is_prekey` from the SEND
//! frame; both move *inside* the sealed envelope. This test exercises
//! exactly that shape: USMC contents are
//! `16-byte message_id || 1-byte is_prekey || ratchet ciphertext`, and the
//! recipient pulls the claimed sender identity_pub out of the cert to look
//! it up in its own contacts before validating.
//!
//! If this test ever stops compiling against a future libsignal pin, that
//! is a load-bearing signal — Phase 1's seal_send / seal_receive rest on
//! these primitives. Treat the failure as an architectural blocker, not a
//! flaky test.

use std::time::SystemTime;

use futures_util::FutureExt as _;
use libsignal_protocol::{
    CiphertextMessage, CiphertextMessageType, ContentHint, DeviceId, IdentityKey,
    PreKeySignalMessage, ProtocolAddress, SenderCertificate, ServerCertificate, SignalMessage,
    Timestamp, UnidentifiedSenderMessageContent, message_decrypt, message_encrypt,
    sealed_sender_decrypt_to_usmc, sealed_sender_encrypt_from_usmc,
};
use rand::TryRngCore as _;
use rand::rngs::OsRng;

use pizzini_crypto_core::DeviceStore;

const DEVICE_ID: u8 = 1;
const CERT_TTL_DAYS: u64 = 30;

#[test]
fn self_issued_sealed_sender_round_trips_five_messages() {
    // Bundle exchange both ways so each peer has the other registered as a
    // contact. After this, Alice and Bob each treat the other's
    // identity_pub as a sealed-sender trust root.
    let (mut alice, mut bob, alice_id, bob_id) = paired_peers();

    let alice_cert = self_issue_cert(&alice);
    let bob_cert = self_issue_cert(&bob);

    let alice_contacts = vec![bob_id.clone()];
    let bob_contacts = vec![alice_id.clone()];

    // 1) Alice → Bob, first message is a PreKey envelope.
    let m1 = b"hi bob";
    let id1 = [1u8; 16];
    let sealed1 = seal(&mut alice, &bob_id, &alice_cert, &id1, m1);
    let (sender1, ack_id1, pt1, was_prekey1) = unseal(&mut bob, &sealed1, &bob_contacts);
    assert_eq!(sender1, alice_id);
    assert_eq!(ack_id1, id1);
    assert_eq!(pt1, m1);
    assert!(was_prekey1, "first inbound from a brand-new session is PreKey");

    // 2) Bob → Alice, the reply is Whisper — session has flipped.
    let m2 = b"hi alice";
    let id2 = [2u8; 16];
    let sealed2 = seal(&mut bob, &alice_id, &bob_cert, &id2, m2);
    let (sender2, ack_id2, pt2, was_prekey2) = unseal(&mut alice, &sealed2, &alice_contacts);
    assert_eq!(sender2, bob_id);
    assert_eq!(ack_id2, id2);
    assert_eq!(pt2, m2);
    assert!(!was_prekey2, "session is established; Bob's reply must be Whisper");

    // 3) Alice → Bob again, now Whisper too.
    let m3 = b"received";
    let id3 = [3u8; 16];
    let sealed3 = seal(&mut alice, &bob_id, &alice_cert, &id3, m3);
    let (_, ack_id3, pt3, was_prekey3) = unseal(&mut bob, &sealed3, &bob_contacts);
    assert_eq!(ack_id3, id3);
    assert_eq!(pt3, m3);
    assert!(!was_prekey3);

    // 4) Bob → Alice.
    let m4 = b"meeting at 9";
    let id4 = [4u8; 16];
    let sealed4 = seal(&mut bob, &alice_id, &bob_cert, &id4, m4);
    let (_, ack_id4, pt4, _) = unseal(&mut alice, &sealed4, &alice_contacts);
    assert_eq!(ack_id4, id4);
    assert_eq!(pt4, m4);

    // 5) Alice → Bob.
    let m5 = b"got it";
    let id5 = [5u8; 16];
    let sealed5 = seal(&mut alice, &bob_id, &alice_cert, &id5, m5);
    let (_, ack_id5, pt5, _) = unseal(&mut bob, &sealed5, &bob_contacts);
    assert_eq!(ack_id5, id5);
    assert_eq!(pt5, m5);
}

#[test]
fn sealed_sender_rejects_cert_signed_by_a_different_identity() {
    // Mallory mints a cert claiming to be Alice but signs it with her own
    // identity. Bob's contacts list maps Alice's identity_pub to Alice's
    // pubkey; the cert won't verify against that.
    let (mut alice, mut bob, alice_id, bob_id) = paired_peers();
    let mallory = DeviceStore::fresh().unwrap();

    // Forged cert: claims Alice's identity_pub but signs with Mallory's
    // privkey at every level (trust root, server cert, sender cert). The
    // cert validates against MALLORY's pub but not Alice's.
    let mut rng = OsRng.unwrap_err();
    let mallory_kp = mallory.local_identity_keypair();
    let mallory_priv = mallory_kp.private_key();
    let mallory_pub = *mallory_kp.public_key();
    let server_cert =
        ServerCertificate::new(1, mallory_pub, mallory_priv, &mut rng).unwrap();
    let alice_id_kp = alice.local_identity_keypair();
    let forged_cert = SenderCertificate::new(
        hex(&alice_id),
        None,
        *alice_id_kp.public_key(),
        DeviceId::new(DEVICE_ID).unwrap(),
        Timestamp::from_epoch_millis(now_millis() + CERT_TTL_DAYS * 24 * 3600 * 1000),
        server_cert,
        mallory_priv,
        &mut rng,
    )
    .unwrap();

    // Use the forged cert to seal something to Bob through *Alice's* live
    // session (so the inner ratchet ciphertext is well-formed; only the
    // outer cert is bogus). Bob must reject.
    let bob_addr = address_for(&bob_id);
    let inner = {
        let alice_id_bytes = alice.identity_public_bytes();
        let store = alice.inner_mut();
        message_encrypt(
            b"phishing",
            &bob_addr,
            &address_for(&alice_id_bytes),
            &mut store.session_store,
            &mut store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .now_or_never()
        .unwrap()
        .unwrap()
    };
    let mut content = Vec::new();
    content.extend_from_slice(&[0u8; 16]);
    content.push(if inner.message_type() == CiphertextMessageType::PreKey { 1 } else { 0 });
    content.extend_from_slice(inner.serialize());
    let usmc = UnidentifiedSenderMessageContent::new(
        inner.message_type(),
        forged_cert,
        content,
        ContentHint::Default,
        None,
    )
    .unwrap();
    let sealed = {
        let store = alice.inner_mut();
        sealed_sender_encrypt_from_usmc(&bob_addr, &usmc, &store.identity_store, &mut rng)
            .now_or_never()
            .unwrap()
            .unwrap()
    };

    // Bob's contacts know only the real Alice. The cert-claim is "Alice"
    // (claimed identity_pub matches Alice) but the signature chain roots
    // in Mallory. validate() against Alice's pub must return false.
    let usmc_back =
        sealed_sender_decrypt_to_usmc(&sealed, &bob.inner_mut().identity_store)
            .now_or_never()
            .unwrap()
            .unwrap();
    let claimed_pub = usmc_back.sender().unwrap().key().unwrap();
    assert_eq!(
        IdentityKey::new(claimed_pub).serialize().as_ref(),
        alice_id.as_slice(),
        "forged cert still claims to be Alice — relay can't tell"
    );
    let alice_trust_root = IdentityKey::decode(&alice_id).unwrap();
    let valid = usmc_back
        .sender()
        .unwrap()
        .validate(
            alice_trust_root.public_key(),
            Timestamp::from_epoch_millis(now_millis()),
        )
        .unwrap();
    assert!(!valid, "self-issued cert must not validate when signed by a different identity");
}

#[test]
fn sealed_sender_state_survives_device_store_serialize_round_trip() {
    let (mut alice, mut bob, alice_id, bob_id) = paired_peers();
    let alice_cert = self_issue_cert(&alice);
    let bob_cert = self_issue_cert(&bob);

    // First exchange a PreKey/Whisper pair so Alice and Bob both have a
    // ratchet on each other.
    let pre = seal(&mut alice, &bob_id, &alice_cert, &[0xa1u8; 16], b"pre-snapshot");
    let _ = unseal(&mut bob, &pre, &[alice_id.clone()]);
    let reply = seal(&mut bob, &alice_id, &bob_cert, &[0xb1u8; 16], b"reply-pre-snapshot");
    let _ = unseal(&mut alice, &reply, &[bob_id.clone()]);

    // Snapshot Alice and rehydrate.
    let snap = alice.serialize().unwrap();
    drop(alice);
    let mut alice2 = DeviceStore::from_serialized(&snap).unwrap();
    assert_eq!(alice2.identity_public_bytes(), alice_id);

    // Issue a fresh cert post-rehydrate (the cert itself doesn't survive
    // serialize until Phase 1 caches it; the libsignal store does, which
    // is what this test verifies).
    let alice2_cert = self_issue_cert(&alice2);

    // Continue the conversation across the rehydrate boundary: must be
    // Whisper, not PreKey, because the session record was preserved.
    let m = b"after-snapshot";
    let id = [0xc1u8; 16];
    let sealed = seal(&mut alice2, &bob_id, &alice2_cert, &id, m);
    let (sender, ack_id, pt, was_prekey) = unseal(&mut bob, &sealed, &[alice_id]);
    assert_eq!(sender, alice2.identity_public_bytes());
    assert_eq!(ack_id, id);
    assert_eq!(pt, m);
    assert!(!was_prekey, "session survived snapshot — message must be Whisper");
}

// ─── helpers ──────────────────────────────────────────────────────────────

/// Build Alice and Bob, exchange bundles both ways so each store has the
/// other's identity registered. Returns the two stores plus their 33-byte
/// identity_pub bytes.
fn paired_peers() -> (DeviceStore, DeviceStore, Vec<u8>, Vec<u8>) {
    let mut alice = DeviceStore::fresh().unwrap();
    let mut bob = DeviceStore::fresh().unwrap();
    let alice_id = alice.identity_public_bytes();
    let bob_id = bob.identity_public_bytes();

    // Bob → Alice direction: Bob mints a bundle, Alice initiates.
    let bob_bundle = bob.publish_bundle().unwrap();
    alice.initiate_session(&bob_id, &bob_bundle).unwrap();

    // Bob also needs Alice in his trust list. The first message Alice
    // sends will be PreKey; libsignal's decrypt of that PreKey will
    // implicitly install a session and identity on Bob's side. We
    // pre-register the peer so the test's contact gate sees Alice as
    // known before any traffic flows.
    bob.register_peer(&alice_id);

    (alice, bob, alice_id, bob_id)
}

/// Mint a 30-day SenderCertificate self-signed by the store's
/// IdentityKeyPair. trust root, ServerCertificate.key, and SenderCertificate
/// signer all collapse onto the store's own identity — the simplest valid
/// chain through libsignal's API for a no-CA deployment.
fn self_issue_cert(store: &DeviceStore) -> SenderCertificate {
    let mut rng = OsRng.unwrap_err();
    let id_kp = store.local_identity_keypair();
    let id_pub = *id_kp.public_key();
    let id_priv = id_kp.private_key();

    let server_cert =
        ServerCertificate::new(/*key_id=*/ 1, id_pub, id_priv, &mut rng).unwrap();

    let expiration = Timestamp::from_epoch_millis(
        now_millis() + CERT_TTL_DAYS * 24 * 3600 * 1000,
    );
    SenderCertificate::new(
        hex(&store.identity_public_bytes()),
        None,
        id_pub,
        DeviceId::new(DEVICE_ID).unwrap(),
        expiration,
        server_cert,
        id_priv,
        &mut rng,
    )
    .unwrap()
}

/// Sender side: produce a sealed envelope carrying
/// `message_id || is_prekey || ratchet_ciphertext` as its inner content.
fn seal(
    sender: &mut DeviceStore,
    recipient_identity_pub: &[u8],
    cert: &SenderCertificate,
    message_id: &[u8; 16],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut rng = OsRng.unwrap_err();
    let recipient_addr = address_for(recipient_identity_pub);
    let sender_id_bytes = sender.identity_public_bytes();
    let sender_addr = address_for(&sender_id_bytes);
    let store = sender.inner_mut();

    let inner = message_encrypt(
        plaintext,
        &recipient_addr,
        &sender_addr,
        &mut store.session_store,
        &mut store.identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .now_or_never()
    .expect("in-mem store is sync")
    .expect("encrypt succeeds");
    let is_prekey: u8 = if inner.message_type() == CiphertextMessageType::PreKey { 1 } else { 0 };

    let mut content = Vec::with_capacity(16 + 1 + inner.serialize().len());
    content.extend_from_slice(message_id);
    content.push(is_prekey);
    content.extend_from_slice(inner.serialize());

    let usmc = UnidentifiedSenderMessageContent::new(
        inner.message_type(),
        cert.clone(),
        content,
        ContentHint::Default,
        None,
    )
    .expect("USMC build");

    sealed_sender_encrypt_from_usmc(&recipient_addr, &usmc, &store.identity_store, &mut rng)
        .now_or_never()
        .expect("in-mem store is sync")
        .expect("seal succeeds")
}

/// Recipient side: open the envelope, look the claimed sender up in our
/// contacts, validate the cert against that identity_pub, then decrypt the
/// inner ratchet ciphertext via the matching session.
fn unseal(
    receiver: &mut DeviceStore,
    sealed: &[u8],
    known_contacts: &[Vec<u8>],
) -> (Vec<u8>, [u8; 16], Vec<u8>, bool) {
    let receiver_id_bytes = receiver.identity_public_bytes();
    let receiver_addr = address_for(&receiver_id_bytes);
    let store = receiver.inner_mut();

    let usmc = sealed_sender_decrypt_to_usmc(sealed, &store.identity_store)
        .now_or_never()
        .expect("in-mem store is sync")
        .expect("usmc decrypt");

    let claimed_pub = usmc.sender().unwrap().key().unwrap();
    let claimed_bytes = IdentityKey::new(claimed_pub).serialize().to_vec();

    let trust_root_bytes = known_contacts
        .iter()
        .find(|c| c.as_slice() == claimed_bytes.as_slice())
        .expect("sender claim must match a known contact");
    let trust_root = IdentityKey::decode(trust_root_bytes).unwrap();
    assert!(
        usmc.sender()
            .unwrap()
            .validate(
                trust_root.public_key(),
                Timestamp::from_epoch_millis(now_millis()),
            )
            .unwrap(),
        "self-issued sender cert must validate against the contact's identity_pub"
    );

    let inner = usmc.contents().unwrap();
    assert!(inner.len() >= 17, "inner content shorter than message_id||is_prekey header");
    let mut message_id = [0u8; 16];
    message_id.copy_from_slice(&inner[..16]);
    let is_prekey = inner[16] != 0;
    let ratchet = &inner[17..];

    let parsed = if is_prekey {
        CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(ratchet).unwrap())
    } else {
        CiphertextMessage::SignalMessage(SignalMessage::try_from(ratchet).unwrap())
    };
    let mut rng = OsRng.unwrap_err();

    let sender_addr = address_for(&claimed_bytes);
    let _ = receiver_addr;
    let pt = message_decrypt(
        &parsed,
        &sender_addr,
        &address_for(&receiver_id_bytes),
        &mut store.session_store,
        &mut store.identity_store,
        &mut store.pre_key_store,
        &store.signed_pre_key_store,
        &mut store.kyber_pre_key_store,
        &mut rng,
    )
    .now_or_never()
    .expect("in-mem store is sync")
    .expect("inner decrypt");

    (claimed_bytes, message_id, pt, is_prekey)
}

fn address_for(identity_pub: &[u8]) -> ProtocolAddress {
    ProtocolAddress::new(hex(identity_pub), DeviceId::new(DEVICE_ID).unwrap())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
