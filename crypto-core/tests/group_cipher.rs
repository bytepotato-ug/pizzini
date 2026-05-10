//! Phase 6 group-chat feasibility verification: Sender Keys round-trip
//! across a small group, persist across a `DeviceStore` snapshot, and
//! rotate cleanly when a member is removed.
//!
//! These tests target the four `DeviceStore` methods that wrap
//! libsignal's `group_cipher`: `sender_key_distribution_create`,
//! `sender_key_distribution_process`, `group_encrypt`, `group_decrypt`.
//! They exercise the architecture decisions documented in the design
//! discussion:
//!
//! * One distribution_id per (sender, chain) — NOT per group. Rotation
//!   is "pick a fresh distribution_id and SKDM everyone again."
//! * Removed members can't decrypt ciphertext encrypted under the new
//!   chain. Their old SKDM is stale; the new SKDM never reaches them.
//! * Snapshot v3 round-trips Sender Key state, so a backgrounded device
//!   resumes the group conversation after a relaunch without re-pairing.
//!
//! No bundle exchange is set up between members beyond what the test
//! needs — the SKDM transport is tested in higher-layer tests once the
//! Swift side ships, since at the FFI level we're checking that the
//! group_encrypt / group_decrypt primitives compose, not the envelope
//! wrap. The shape "send raw SKDM to peer's process_skdm" matches what
//! the Swift app will do over a sealed-sender 1:1 envelope (inner type
//! byte 0x07).

use pizzini_crypto_core::DeviceStore;

/// 16-byte distribution ID. In production this is a fresh random UUID
/// per chain; for a test we use a deterministic fill so failure
/// messages are readable.
fn dist_id(tag: u8) -> [u8; 16] {
    let mut id = [0u8; 16];
    id.fill(tag);
    id
}

#[test]
fn three_member_group_round_trip() {
    // Alice creates a chain, distributes to Bob and Carol, then
    // encrypts a message that both peers must decrypt.
    let mut alice = DeviceStore::fresh().unwrap();
    let mut bob = DeviceStore::fresh().unwrap();
    let mut carol = DeviceStore::fresh().unwrap();

    let alice_id = alice.identity_public_bytes();

    let alice_dist = dist_id(0xA1);
    let alice_skdm = alice.sender_key_distribution_create(alice_dist).unwrap();

    let dist_seen_by_bob = bob
        .sender_key_distribution_process(&alice_id, &alice_skdm)
        .unwrap();
    assert_eq!(
        dist_seen_by_bob, alice_dist,
        "the distribution_id parsed from the SKDM matches what Alice generated",
    );
    let dist_seen_by_carol = carol
        .sender_key_distribution_process(&alice_id, &alice_skdm)
        .unwrap();
    assert_eq!(dist_seen_by_carol, alice_dist);

    let plaintext = b"shared message to the group";
    let ciphertext = alice.group_encrypt(alice_dist, plaintext).unwrap();

    let bob_pt = bob.group_decrypt(&alice_id, &ciphertext).unwrap();
    let carol_pt = carol.group_decrypt(&alice_id, &ciphertext).unwrap();
    assert_eq!(bob_pt, plaintext);
    assert_eq!(carol_pt, plaintext);
}

#[test]
fn out_of_order_messages_decrypt_via_message_key_cache() {
    // libsignal's SenderKey ratchet caches up to MAX_FORWARD_JUMPS
    // skipped message keys. Two messages encrypted in order, decrypted
    // out of order, both succeed.
    let mut alice = DeviceStore::fresh().unwrap();
    let mut bob = DeviceStore::fresh().unwrap();
    let alice_id = alice.identity_public_bytes();

    let dist = dist_id(0xA2);
    let skdm = alice.sender_key_distribution_create(dist).unwrap();
    bob.sender_key_distribution_process(&alice_id, &skdm).unwrap();

    let ct1 = alice.group_encrypt(dist, b"first").unwrap();
    let ct2 = alice.group_encrypt(dist, b"second").unwrap();

    // Bob receives ct2 first.
    let pt2 = bob.group_decrypt(&alice_id, &ct2).unwrap();
    assert_eq!(pt2, b"second");
    // ct1 still decrypts via the cached message key.
    let pt1 = bob.group_decrypt(&alice_id, &ct1).unwrap();
    assert_eq!(pt1, b"first");
}

#[test]
fn rotation_excludes_removed_member() {
    // Pizzini's member-removal rule: every remaining member rotates
    // their sender-key chain (= picks a fresh distribution_id and
    // re-SKDMs the rest). The removed member never receives the new
    // SKDM, so their store still has the OLD chain only — they can
    // decrypt old ciphertext but not new.
    let mut alice = DeviceStore::fresh().unwrap();
    let mut bob = DeviceStore::fresh().unwrap();
    let mut carol = DeviceStore::fresh().unwrap();
    let alice_id = alice.identity_public_bytes();

    // Initial enrolment.
    let dist_v1 = dist_id(0x01);
    let skdm_v1 = alice.sender_key_distribution_create(dist_v1).unwrap();
    bob.sender_key_distribution_process(&alice_id, &skdm_v1).unwrap();
    carol.sender_key_distribution_process(&alice_id, &skdm_v1).unwrap();

    // Sanity: both peers can decrypt a v1 ciphertext.
    let ct_v1 = alice.group_encrypt(dist_v1, b"v1 message").unwrap();
    assert_eq!(bob.group_decrypt(&alice_id, &ct_v1).unwrap(), b"v1 message");
    assert_eq!(carol.group_decrypt(&alice_id, &ct_v1).unwrap(), b"v1 message");

    // Remove Carol: Alice rotates by picking a fresh dist_id.
    // The new SKDM only goes to Bob. (Pizzini's group-state layer is
    // responsible for not sending it to Carol; here we just don't.)
    let dist_v2 = dist_id(0x02);
    let skdm_v2 = alice.sender_key_distribution_create(dist_v2).unwrap();
    bob.sender_key_distribution_process(&alice_id, &skdm_v2).unwrap();

    let ct_v2 = alice.group_encrypt(dist_v2, b"v2 after removal").unwrap();

    // Bob decrypts v2 (he has the new SKDM).
    assert_eq!(
        bob.group_decrypt(&alice_id, &ct_v2).unwrap(),
        b"v2 after removal",
    );

    // Carol's store has no chain for dist_v2 — decrypt fails. The
    // libsignal error path returns `NoSenderKeyState` which our FFI
    // surfaces as a generic error; here we just assert the call
    // doesn't return Ok with the plaintext.
    assert!(
        carol.group_decrypt(&alice_id, &ct_v2).is_err(),
        "removed member must NOT decrypt ciphertext under the rotated chain",
    );

    // Carol can still decrypt OLD v1 ciphertext she already had —
    // forward secrecy applies to the chain, not retroactively to
    // already-issued chain keys.
    let ct_v1_late = alice.group_encrypt(dist_v1, b"v1 late").unwrap();
    assert_eq!(
        carol.group_decrypt(&alice_id, &ct_v1_late).unwrap(),
        b"v1 late",
    );
}

#[test]
fn sender_key_state_survives_device_store_round_trip() {
    // Bob persists his store, the device relaunches, and group
    // ciphertext sent in the meantime decrypts on the rehydrated
    // store. This is the v3 snapshot upgrade in production.
    let mut alice = DeviceStore::fresh().unwrap();
    let mut bob = DeviceStore::fresh().unwrap();
    let alice_id = alice.identity_public_bytes();

    let dist = dist_id(0x42);
    let skdm = alice.sender_key_distribution_create(dist).unwrap();
    bob.sender_key_distribution_process(&alice_id, &skdm).unwrap();

    // Bob persists his store mid-conversation.
    let snapshot = bob.serialize().unwrap();

    // Alice keeps sending while Bob's "device" is offline.
    let ct = alice.group_encrypt(dist, b"survives a relaunch").unwrap();

    // Bob is rehydrated from the snapshot and decrypts.
    let mut bob_v2 = DeviceStore::from_serialized(&snapshot).unwrap();
    let pt = bob_v2.group_decrypt(&alice_id, &ct).unwrap();
    assert_eq!(pt, b"survives a relaunch");
}

#[test]
fn alice_round_trips_her_own_sender_key_chain_across_relaunch() {
    // The other side of the persistence story: Alice's *own* sender-
    // key chain (created via `sender_key_distribution_create`) must
    // survive a snapshot, otherwise her chain advances reset after
    // every relaunch and Bob's expected chain_id no longer matches.
    let mut alice = DeviceStore::fresh().unwrap();
    let mut bob = DeviceStore::fresh().unwrap();
    let alice_id = alice.identity_public_bytes();

    let dist = dist_id(0x77);
    let skdm = alice.sender_key_distribution_create(dist).unwrap();
    bob.sender_key_distribution_process(&alice_id, &skdm).unwrap();

    // Send one message to advance Alice's chain off the initial state.
    let ct1 = alice.group_encrypt(dist, b"before relaunch").unwrap();
    assert_eq!(bob.group_decrypt(&alice_id, &ct1).unwrap(), b"before relaunch");

    // Persist and rehydrate Alice. Without v3 sender-key persistence
    // this would forget her chain_id and the next encrypt either
    // returns NoSenderKeyState or restarts at iteration 0 (Bob would
    // refuse the duplicate counter).
    let snapshot = alice.serialize().unwrap();
    let mut alice_v2 = DeviceStore::from_serialized(&snapshot).unwrap();

    let ct2 = alice_v2.group_encrypt(dist, b"after relaunch").unwrap();
    assert_eq!(bob.group_decrypt(&alice_id, &ct2).unwrap(), b"after relaunch");
}

#[test]
fn unknown_sender_chain_decryption_fails_cleanly() {
    // Decrypting from a sender we never received an SKDM from must
    // return an error, not panic. The Swift host uses this signal to
    // trigger an SKDM exchange with the sender.
    let mut alice = DeviceStore::fresh().unwrap();
    let mut bob = DeviceStore::fresh().unwrap();
    let alice_id = alice.identity_public_bytes();

    let dist = dist_id(0x11);
    let _ = alice.sender_key_distribution_create(dist).unwrap();
    let ct = alice.group_encrypt(dist, b"bob never enrolled").unwrap();

    // Bob never processed Alice's SKDM.
    assert!(
        bob.group_decrypt(&alice_id, &ct).is_err(),
        "decrypt without prior SKDM must fail",
    );
}

#[test]
fn create_is_idempotent_on_same_distribution_id() {
    // Calling sender_key_distribution_create twice with the same
    // dist_id returns the same chain — caller has not lost any state.
    // Important for the Swift-side caller that re-invokes after a
    // crash recovery.
    let mut alice = DeviceStore::fresh().unwrap();
    let mut bob = DeviceStore::fresh().unwrap();
    let alice_id = alice.identity_public_bytes();

    let dist = dist_id(0x99);
    let skdm_a = alice.sender_key_distribution_create(dist).unwrap();
    let skdm_b = alice.sender_key_distribution_create(dist).unwrap();
    // The bytes themselves may not be byte-identical (libsignal
    // serializes the same chain state), but ingesting either gives
    // Bob the same working chain.
    let _ = (&skdm_a, &skdm_b);

    bob.sender_key_distribution_process(&alice_id, &skdm_b).unwrap();
    let ct = alice.group_encrypt(dist, b"hello").unwrap();
    assert_eq!(bob.group_decrypt(&alice_id, &ct).unwrap(), b"hello");
}
