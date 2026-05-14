//! Fix-review PoCs added during external verification of the Pizzini
//! "Private SEND v2" red-team audit fixes. Each test exercises a
//! claim that needs a positive demonstration the original audit's
//! attack no longer succeeds OR that a fix didn't introduce a new
//! vector.
//!
//! These complement (not replace) the existing `audit_probes.rs` file
//! which the prior agent flipped from bug-confirming PoCs to
//! fix-verifiers.

use pizzini_crypto_core::{
    extract_bundle_verify_key, pizzini_bundle_extract_verify_key, pizzini_store_free,
    pizzini_store_identity_public, pizzini_store_initiate_session, pizzini_store_new,
    pizzini_store_publish_bundle, pizzini_store_register_peer, pizzini_store_seal_receive,
    pizzini_store_seal_send, pizzini_verify_delivery_token, DeviceStore, DELIVERY_TOKEN_LEN,
    DELIVERY_TOKEN_VERIFY_KEY_LEN, PIZZINI_ERR_BAD_SIGNATURE, PIZZINI_ERR_BUFFER_TOO_SMALL,
    PIZZINI_OK,
};

/// Helper: pair Alice and Bob through the safe Rust-side API for use
/// by FFI tests below. Returns (alice, bob) device-store handles plus
/// their identity public keys.
fn pair_via_ffi() -> (*mut DeviceStore, *mut DeviceStore, Vec<u8>, Vec<u8>) {
    let alice = unsafe { pizzini_store_new(std::ptr::null(), 0) };
    let bob = unsafe { pizzini_store_new(std::ptr::null(), 0) };
    let mut alice_id = vec![0u8; 64];
    let mut alice_id_len = 0usize;
    unsafe {
        pizzini_store_identity_public(
            alice,
            alice_id.as_mut_ptr(),
            alice_id.len(),
            &mut alice_id_len,
        )
    };
    let alice_id = alice_id[..alice_id_len].to_vec();
    let mut bob_id = vec![0u8; 64];
    let mut bob_id_len = 0usize;
    unsafe {
        pizzini_store_identity_public(bob, bob_id.as_mut_ptr(), bob_id.len(), &mut bob_id_len)
    };
    let bob_id = bob_id[..bob_id_len].to_vec();

    let mut bundle = vec![0u8; 4096];
    let mut bundle_len = 0usize;
    unsafe {
        pizzini_store_publish_bundle(bob, bundle.as_mut_ptr(), bundle.len(), &mut bundle_len)
    };
    unsafe {
        pizzini_store_initiate_session(
            alice,
            bob_id.as_ptr(),
            bob_id.len(),
            bundle.as_ptr(),
            bundle_len,
        )
    };
    unsafe { pizzini_store_register_peer(bob, alice_id.as_ptr(), alice_id.len()) };
    (alice, bob, alice_id, bob_id)
}

/// F-101 / F-701 third-call: after a successful BUFFER_TOO_SMALL → retry
/// → OK round-trip, a THIRD call with the same sealed bytes MUST flag
/// `is_duplicate = 1`. This is the "the relay can't replay forever"
/// invariant — confirms the ratchet has indeed advanced after the
/// honest commit.
#[test]
fn f101_third_call_with_replayed_sealed_returns_duplicate() {
    let (alice, bob, _alice_id, bob_id) = pair_via_ffi();
    let plaintext = b"third-call-must-flag-duplicate";
    let msg_id = [0xCDu8; 16];
    let mut sealed = vec![0u8; 4096];
    let mut sealed_len = 0usize;
    let rc = unsafe {
        pizzini_store_seal_send(
            alice,
            bob_id.as_ptr(),
            bob_id.len(),
            msg_id.as_ptr(),
            msg_id.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            sealed.as_mut_ptr(),
            sealed.len(),
            &mut sealed_len,
        )
    };
    assert_eq!(rc, PIZZINI_OK);

    // Call 1: cap=0 → BUFFER_TOO_SMALL with non-zero size hint.
    let mut sender = vec![0u8; 64];
    let mut sender_len = 0usize;
    let mut got_msg_id = [0u8; 16];
    let mut pt_zero = [0u8; 1];
    let mut pt_zero_len = 0usize;
    let mut is_dup = 0u8;
    let rc1 = unsafe {
        pizzini_store_seal_receive(
            bob,
            sealed.as_ptr(),
            sealed_len,
            sender.as_mut_ptr(),
            sender.len(),
            &mut sender_len,
            got_msg_id.as_mut_ptr(),
            pt_zero.as_mut_ptr(),
            0,
            &mut pt_zero_len,
            &mut is_dup,
        )
    };
    assert_eq!(rc1, PIZZINI_ERR_BUFFER_TOO_SMALL);
    assert!(pt_zero_len > 0);

    // Call 2: adequate buffer → OK, plaintext matches, is_dup = 0.
    let mut pt2 = vec![0u8; pt_zero_len];
    let mut pt2_len = 0usize;
    let mut is_dup2 = 0u8;
    let rc2 = unsafe {
        pizzini_store_seal_receive(
            bob,
            sealed.as_ptr(),
            sealed_len,
            sender.as_mut_ptr(),
            sender.len(),
            &mut sender_len,
            got_msg_id.as_mut_ptr(),
            pt2.as_mut_ptr(),
            pt2.len(),
            &mut pt2_len,
            &mut is_dup2,
        )
    };
    assert_eq!(rc2, PIZZINI_OK);
    assert_eq!(is_dup2, 0);
    assert_eq!(&pt2[..pt2_len], plaintext);

    // Call 3: same sealed bytes again → is_dup = 1. The ratchet has
    // advanced past this counter; libsignal returns DuplicatedMessage,
    // which the FFI maps to (rc=OK, is_dup=1, plaintext-empty).
    let mut pt3 = vec![0u8; 4096];
    let mut pt3_len = 0usize;
    let mut is_dup3 = 0u8;
    let rc3 = unsafe {
        pizzini_store_seal_receive(
            bob,
            sealed.as_ptr(),
            sealed_len,
            sender.as_mut_ptr(),
            sender.len(),
            &mut sender_len,
            got_msg_id.as_mut_ptr(),
            pt3.as_mut_ptr(),
            pt3.len(),
            &mut pt3_len,
            &mut is_dup3,
        )
    };
    assert_eq!(rc3, PIZZINI_OK);
    assert_eq!(is_dup3, 1, "third-call replay must surface as duplicate");
    assert_eq!(pt3_len, 0, "duplicate path returns empty plaintext");

    unsafe { pizzini_store_free(alice) };
    unsafe { pizzini_store_free(bob) };
}

/// F-101 / F-701 peek non-mutation: feed `peek_sealed_lengths` a
/// MALFORMED sealed envelope. The store snapshot bytes MUST be
/// unchanged afterwards. This confirms the FFI's "size discovery is
/// non-destructive" claim under malicious input.
///
/// We exercise this via the FFI surface (the same path Swift takes):
/// the `peek` step is internal, but `pizzini_store_seal_receive` with a
/// 0-byte plaintext cap exercises ONLY the peek code path, since the
/// commit step is gated on the cap check.
#[test]
fn f101_peek_under_malformed_envelope_does_not_mutate_store() {
    use pizzini_crypto_core::pizzini_store_serialize;

    let (alice, bob, _alice_id, _bob_id) = pair_via_ffi();
    let _ = alice; // unused

    // Snapshot Bob's store BEFORE any peek.
    let mut snap_before = vec![0u8; 16384];
    let mut snap_before_len = 0usize;
    let rc = unsafe {
        pizzini_store_serialize(
            bob,
            snap_before.as_mut_ptr(),
            snap_before.len(),
            &mut snap_before_len,
        )
    };
    assert_eq!(rc, PIZZINI_OK);
    let snap_before = snap_before[..snap_before_len].to_vec();

    // Try a totally-bogus "sealed" payload (random bytes that won't
    // parse as USMC). FFI should return INTERNAL — the peek's
    // sealed_sender_decrypt_to_usmc fails to open the envelope, and
    // the function bails BEFORE calling seal_receive.
    let bogus_sealed = vec![0xDEu8; 256];
    let mut sender = vec![0u8; 64];
    let mut sender_len = 0usize;
    let mut got_msg_id = [0u8; 16];
    let mut pt = vec![0u8; 4096];
    let mut pt_len = 0usize;
    let mut is_dup = 0u8;
    let rc = unsafe {
        pizzini_store_seal_receive(
            bob,
            bogus_sealed.as_ptr(),
            bogus_sealed.len(),
            sender.as_mut_ptr(),
            sender.len(),
            &mut sender_len,
            got_msg_id.as_mut_ptr(),
            pt.as_mut_ptr(),
            pt.len(),
            &mut pt_len,
            &mut is_dup,
        )
    };
    // Either INTERNAL (peek failed) or some other non-OK — the
    // important assertion is the snapshot below.
    assert_ne!(rc, PIZZINI_OK, "bogus sealed should not decrypt cleanly");

    // Snapshot AFTER the failed peek. Must match.
    let mut snap_after = vec![0u8; 16384];
    let mut snap_after_len = 0usize;
    let rc = unsafe {
        pizzini_store_serialize(
            bob,
            snap_after.as_mut_ptr(),
            snap_after.len(),
            &mut snap_after_len,
        )
    };
    assert_eq!(rc, PIZZINI_OK);
    let snap_after = snap_after[..snap_after_len].to_vec();
    assert_eq!(
        snap_before, snap_after,
        "peek under malformed input mutated DeviceStore — bug",
    );

    unsafe { pizzini_store_free(alice) };
    unsafe { pizzini_store_free(bob) };
}

/// F-101 / F-701 peek non-mutation: now the same test with a
/// LEGITIMATE sealed envelope and `out_plaintext_cap = 0`. This is the
/// crucial path — peek opens a *valid* USMC envelope. The store must
/// be unchanged after the BUFFER_TOO_SMALL return.
#[test]
fn f101_peek_with_valid_envelope_zero_cap_does_not_mutate_store() {
    use pizzini_crypto_core::pizzini_store_serialize;

    let (alice, bob, _alice_id, bob_id) = pair_via_ffi();

    // Need a valid sealed envelope from Alice to Bob.
    let plaintext = b"peek-zero-cap-must-not-mutate";
    let msg_id = [0xACu8; 16];
    let mut sealed = vec![0u8; 4096];
    let mut sealed_len = 0usize;
    let rc = unsafe {
        pizzini_store_seal_send(
            alice,
            bob_id.as_ptr(),
            bob_id.len(),
            msg_id.as_ptr(),
            msg_id.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            sealed.as_mut_ptr(),
            sealed.len(),
            &mut sealed_len,
        )
    };
    assert_eq!(rc, PIZZINI_OK);

    // Snapshot Bob's store.
    let mut snap_before = vec![0u8; 16384];
    let mut snap_before_len = 0usize;
    unsafe {
        pizzini_store_serialize(
            bob,
            snap_before.as_mut_ptr(),
            snap_before.len(),
            &mut snap_before_len,
        )
    };
    let snap_before = snap_before[..snap_before_len].to_vec();

    // Peek with cap=0.
    let mut sender = vec![0u8; 64];
    let mut sender_len = 0usize;
    let mut got_msg_id = [0u8; 16];
    let mut pt0 = [0u8; 1];
    let mut pt0_len = 0usize;
    let mut is_dup = 0u8;
    let rc = unsafe {
        pizzini_store_seal_receive(
            bob,
            sealed.as_ptr(),
            sealed_len,
            sender.as_mut_ptr(),
            sender.len(),
            &mut sender_len,
            got_msg_id.as_mut_ptr(),
            pt0.as_mut_ptr(),
            0,
            &mut pt0_len,
            &mut is_dup,
        )
    };
    assert_eq!(rc, PIZZINI_ERR_BUFFER_TOO_SMALL);

    // Snapshot AFTER the peek. Must match.
    let mut snap_after = vec![0u8; 16384];
    let mut snap_after_len = 0usize;
    unsafe {
        pizzini_store_serialize(
            bob,
            snap_after.as_mut_ptr(),
            snap_after.len(),
            &mut snap_after_len,
        )
    };
    let snap_after = snap_after[..snap_after_len].to_vec();
    assert_eq!(
        snap_before, snap_after,
        "peek path on valid envelope still mutated the store — fix is broken",
    );

    // Sanity: the subsequent commit (with adequate buffer) DOES mutate.
    let mut pt = vec![0u8; pt0_len];
    let mut pt_len = 0usize;
    let mut is_dup2 = 0u8;
    let rc = unsafe {
        pizzini_store_seal_receive(
            bob,
            sealed.as_ptr(),
            sealed_len,
            sender.as_mut_ptr(),
            sender.len(),
            &mut sender_len,
            got_msg_id.as_mut_ptr(),
            pt.as_mut_ptr(),
            pt.len(),
            &mut pt_len,
            &mut is_dup2,
        )
    };
    assert_eq!(rc, PIZZINI_OK);
    assert_eq!(is_dup2, 0);
    assert_eq!(&pt[..pt_len], plaintext);
    let mut snap_post_commit = vec![0u8; 16384];
    let mut snap_post_commit_len = 0usize;
    unsafe {
        pizzini_store_serialize(
            bob,
            snap_post_commit.as_mut_ptr(),
            snap_post_commit.len(),
            &mut snap_post_commit_len,
        )
    };
    let snap_post_commit = snap_post_commit[..snap_post_commit_len].to_vec();
    assert_ne!(
        snap_before, snap_post_commit,
        "honest commit must mutate the store — sanity check on the snapshot helper",
    );

    unsafe { pizzini_store_free(alice) };
    unsafe { pizzini_store_free(bob) };
}

/// F-202 / F-401: the iOS handler claims batch atomicity — a single
/// invalid token must reject the WHOLE batch, not stash 1023 partials.
/// We can't run the Swift handler in Rust, but we can verify the
/// underlying primitive: `pizzini_verify_delivery_token` distinguishes
/// validly-signed tokens from forged ones using a real bundle's
/// `delivery_token_verify_key`.
#[test]
fn f202_verify_delivery_token_distinguishes_signed_from_garbage() {
    use pizzini_crypto_core::pizzini_store_mint_delivery_token;

    let (alice, bob, _alice_id, _bob_id) = pair_via_ffi();
    let _ = alice;

    // Pull Bob's bundle (the issuer's bundle) and extract the
    // delivery_token_verify_key.
    let mut bundle = vec![0u8; 4096];
    let mut bundle_len = 0usize;
    unsafe {
        pizzini_store_publish_bundle(bob, bundle.as_mut_ptr(), bundle.len(), &mut bundle_len)
    };

    // Extract via the public Rust helper (mirrors what
    // pizzini_bundle_extract_verify_key does).
    let vk = extract_bundle_verify_key(&bundle[..bundle_len]).unwrap();
    assert_eq!(vk.len(), DELIVERY_TOKEN_VERIFY_KEY_LEN);

    // Bob mints a token (just like he would in a TOKEN_ISSUE batch).
    let mut token = vec![0u8; DELIVERY_TOKEN_LEN];
    let mut token_len = 0usize;
    let rc = unsafe {
        pizzini_store_mint_delivery_token(
            bob,
            token.as_mut_ptr(),
            token.len(),
            &mut token_len,
        )
    };
    assert_eq!(rc, PIZZINI_OK);
    assert_eq!(token_len, DELIVERY_TOKEN_LEN);

    // Verify the legit token: PIZZINI_OK.
    let rc_ok = unsafe {
        pizzini_verify_delivery_token(vk.as_ptr(), vk.len(), token.as_ptr(), token.len())
    };
    assert_eq!(rc_ok, PIZZINI_OK, "legit token must verify");

    // Forge a token: keep nonce + expiry, mangle signature.
    let mut forged = token.clone();
    forged[DELIVERY_TOKEN_LEN - 1] ^= 0x01;
    let rc_bad = unsafe {
        pizzini_verify_delivery_token(vk.as_ptr(), vk.len(), forged.as_ptr(), forged.len())
    };
    assert_eq!(
        rc_bad, PIZZINI_ERR_BAD_SIGNATURE,
        "forged token must fail verification"
    );

    // All-zero token: signature won't match.
    let zero_token = vec![0u8; DELIVERY_TOKEN_LEN];
    let rc_zero = unsafe {
        pizzini_verify_delivery_token(
            vk.as_ptr(),
            vk.len(),
            zero_token.as_ptr(),
            zero_token.len(),
        )
    };
    assert_eq!(rc_zero, PIZZINI_ERR_BAD_SIGNATURE);

    unsafe { pizzini_store_free(alice) };
    unsafe { pizzini_store_free(bob) };
}

/// F-202 bundle-extract: the FFI returns the same bytes as the
/// internal helper, and the bytes match Bob's actual verify key.
#[test]
fn f202_bundle_extract_verify_key_round_trips() {
    use pizzini_crypto_core::pizzini_store_delivery_token_verify_key;

    let (alice, bob, _alice_id, _bob_id) = pair_via_ffi();
    let _ = alice;

    let mut bundle = vec![0u8; 4096];
    let mut bundle_len = 0usize;
    unsafe {
        pizzini_store_publish_bundle(bob, bundle.as_mut_ptr(), bundle.len(), &mut bundle_len)
    };

    let mut vk_from_bundle = vec![0u8; 64];
    let mut vk_from_bundle_len = 0usize;
    let rc = unsafe {
        pizzini_bundle_extract_verify_key(
            bundle.as_ptr(),
            bundle_len,
            vk_from_bundle.as_mut_ptr(),
            vk_from_bundle.len(),
            &mut vk_from_bundle_len,
        )
    };
    assert_eq!(rc, PIZZINI_OK);
    assert_eq!(vk_from_bundle_len, DELIVERY_TOKEN_VERIFY_KEY_LEN);
    let vk_from_bundle = &vk_from_bundle[..vk_from_bundle_len];

    let mut vk_from_store = vec![0u8; 64];
    let mut vk_from_store_len = 0usize;
    let rc = unsafe {
        pizzini_store_delivery_token_verify_key(
            bob,
            vk_from_store.as_mut_ptr(),
            vk_from_store.len(),
            &mut vk_from_store_len,
        )
    };
    assert_eq!(rc, PIZZINI_OK);
    let vk_from_store = &vk_from_store[..vk_from_store_len];

    assert_eq!(
        vk_from_bundle, vk_from_store,
        "bundle-extracted vk must equal store-derived vk",
    );

    unsafe { pizzini_store_free(alice) };
    unsafe { pizzini_store_free(bob) };
}
