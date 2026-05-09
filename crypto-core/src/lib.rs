//! Pizzini crypto core.
//!
//! Wraps libsignal and exposes a C ABI for the iOS app. Everything cryptographic
//! happens here — Swift never touches keys directly.
//!
//! Hard rule: no custom crypto. If a primitive isn't already in libsignal,
//! stop and ask before adding it.

#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::c_char;

use libsignal_protocol::IdentityKeyPair;
use rand::TryRngCore;
use rand::rngs::OsRng;

mod hashcash;
mod store;
pub use hashcash::{hashcash_compute, hashcash_verify, HASHCASH_DEFAULT_BITS};
pub use store::{
    DeviceStore, EncryptResult, SealReceived, DELIVERY_TOKEN_LEN, DELIVERY_TOKEN_NONCE_LEN,
    DELIVERY_TOKEN_SIG_LEN, DELIVERY_TOKEN_TTL_SECS, DELIVERY_TOKEN_VERIFY_KEY_LEN,
};

// ───── Error codes ─────────────────────────────────────────────────────
//
// Negative values denote errors; zero is success. Values are stable —
// they are part of the FFI contract.

pub const PIZZINI_OK: i32 = 0;
pub const PIZZINI_ERR_INVALID_ARG: i32 = -1;
pub const PIZZINI_ERR_BUFFER_TOO_SMALL: i32 = -2;
pub const PIZZINI_ERR_INTERNAL: i32 = -3;

// ───── Message type tags exposed across FFI ────────────────────────────

pub const PIZZINI_MSG_TYPE_PREKEY: u32 = 0;
pub const PIZZINI_MSG_TYPE_WHISPER: u32 = 1;

// ───── Version ─────────────────────────────────────────────────────────

/// Returns a static null-terminated UTF-8 string with the crate version.
/// The pointer is valid for the lifetime of the process; do not free.
#[no_mangle]
pub extern "C" fn pizzini_crypto_core_version() -> *const c_char {
    static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr() as *const c_char
}

// ───── Identity keypair ────────────────────────────────────────────────

/// Generates a fresh long-term identity keypair (libsignal IdentityKeyPair) and
/// writes its serialized form into `out_buf`.
///
/// On success returns `PIZZINI_OK` and `*out_len` is the number of bytes written.
/// If `out_buf_cap` is smaller than required, returns `PIZZINI_ERR_BUFFER_TOO_SMALL`
/// and `*out_len` is the required size — caller can retry with a larger buffer.
///
/// # Safety
/// - `out_buf` must point to at least `out_buf_cap` writable bytes.
/// - `out_len` must point to a valid `usize`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_identity_keypair_generate(
    out_buf: *mut u8,
    out_buf_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if out_buf.is_null() || out_len.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }

    // OsRng in rand 0.9 only impls TryCryptoRng. unwrap_err panics on the (effectively
    // unreachable) OS RNG failure path; on Apple platforms this is getentropy/SecRandom.
    let mut rng = OsRng.unwrap_err();
    let kp = IdentityKeyPair::generate(&mut rng);
    let bytes = kp.serialize();

    if bytes.len() > out_buf_cap {
        // SAFETY: caller asserted out_len points to a valid usize.
        unsafe { *out_len = bytes.len() };
        return PIZZINI_ERR_BUFFER_TOO_SMALL;
    }

    // SAFETY: we just verified bytes.len() <= out_buf_cap, and the caller
    // asserted that out_buf points to at least out_buf_cap writable bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
        *out_len = bytes.len();
    }

    PIZZINI_OK
}

// ───── Per-device session store ────────────────────────────────────────
//
// One `DeviceStore` per Pizzini install. The host (Swift) holds an opaque
// pointer; all libsignal state lives on the Rust side. Wire bytes (PreKey
// bundle, ciphertext) flow through `out_buf` / `out_len` pairs.

/// Creates a new device store.
///
/// If `seed_ptr` is null, a fresh identity keypair is generated. Otherwise
/// `(seed_ptr, seed_len)` must be the bytes returned by a prior
/// `pizzini_store_identity_keypair` call (libsignal's serialized
/// IdentityKeyPair) — used to rehydrate an identity from Keychain. This
/// path keeps the identity but loses session/prekey state. For full
/// continuity (sessions, ratchet) use `pizzini_store_new_from_serialized`.
///
/// Returns a non-null opaque handle on success, null on failure.
///
/// # Safety
/// `seed_ptr` must either be null or point to `seed_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_new(
    seed_ptr: *const u8,
    seed_len: usize,
) -> *mut DeviceStore {
    let result = if seed_ptr.is_null() {
        DeviceStore::fresh()
    } else {
        // SAFETY: caller asserted seed_ptr/seed_len describe a valid slice.
        let seed = unsafe { std::slice::from_raw_parts(seed_ptr, seed_len) };
        DeviceStore::from_identity(seed)
    };
    match result {
        Ok(s) => Box::into_raw(Box::new(s)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Creates a device store from a full serialized snapshot (the bytes
/// returned by `pizzini_store_serialize`). Restores identity, registration
/// id, prekeys, signed prekeys, kyber prekeys, and per-peer session state.
///
/// Returns null if the blob is malformed.
///
/// # Safety
/// `bytes` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_new_from_serialized(
    bytes: *const u8,
    len: usize,
) -> *mut DeviceStore {
    if bytes.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: caller asserted (bytes, len) describes a readable slice.
    let blob = unsafe { std::slice::from_raw_parts(bytes, len) };
    match DeviceStore::from_serialized(blob) {
        Ok(s) => Box::into_raw(Box::new(s)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Releases a device-store handle. Safe to call with null.
///
/// # Safety
/// `store` must be a pointer previously returned by `pizzini_store_new` and
/// not yet freed.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_free(store: *mut DeviceStore) {
    if !store.is_null() {
        // SAFETY: caller asserted this came from Box::into_raw.
        unsafe { drop(Box::from_raw(store)) };
    }
}

/// Writes the serialized `IdentityKeyPair` (private + public) to `out_buf`.
/// Persist these bytes in the Keychain; pass them back to `pizzini_store_new`
/// on the next launch.
///
/// # Safety
/// `store` must be a live handle. `out_buf` must point to `out_buf_cap`
/// writable bytes; `out_len` must point to a valid `usize`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_identity_keypair(
    store: *mut DeviceStore,
    out_buf: *mut u8,
    out_buf_cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: caller asserted preconditions.
    unsafe { write_blob(store, out_buf, out_buf_cap, out_len, |s| s.identity_keypair_bytes()) }
}

/// Writes the 33-byte serialized public IdentityKey. This is the routable
/// peer-id used for transport addressing and ProtocolAddress naming.
///
/// # Safety
/// Same as `pizzini_store_identity_keypair`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_identity_public(
    store: *mut DeviceStore,
    out_buf: *mut u8,
    out_buf_cap: usize,
    out_len: *mut usize,
) -> i32 {
    // SAFETY: caller asserted preconditions.
    unsafe { write_blob(store, out_buf, out_buf_cap, out_len, |s| s.identity_public_bytes()) }
}

/// Generates a fresh PreKey bundle (rotates one-time, signed, and Kyber
/// pre-keys), persists them in the store, and writes the wire-format bytes.
/// See `store.rs` for the format. Hand to a peer over QR / pairing.
///
/// # Safety
/// Same as `pizzini_store_identity_keypair`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_publish_bundle(
    store: *mut DeviceStore,
    out_buf: *mut u8,
    out_buf_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if store.is_null() || out_buf.is_null() || out_len.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted store is a live handle.
    let s = unsafe { &mut *store };
    let bytes = match s.publish_bundle() {
        Ok(b) => b,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    // SAFETY: caller asserted out_buf/out_len are valid.
    unsafe { copy_or_size_out(&bytes, out_buf, out_buf_cap, out_len) }
}

/// Processes a peer's PreKey bundle (PQXDH handshake) and stores the
/// resulting session keyed by `peer_identity` (the peer's 33-byte
/// IdentityKey bytes). After this returns OK, encrypt/decrypt may be called.
///
/// # Safety
/// All pointers must be non-null and describe valid slices.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_initiate_session(
    store: *mut DeviceStore,
    peer_identity: *const u8,
    peer_identity_len: usize,
    bundle: *const u8,
    bundle_len: usize,
) -> i32 {
    if store.is_null() || peer_identity.is_null() || bundle.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted handle + slice validity.
    let s = unsafe { &mut *store };
    let peer = unsafe { std::slice::from_raw_parts(peer_identity, peer_identity_len) };
    let b = unsafe { std::slice::from_raw_parts(bundle, bundle_len) };
    match s.initiate_session(peer, b) {
        Ok(()) => PIZZINI_OK,
        Err(_) => PIZZINI_ERR_INTERNAL,
    }
}

/// Encrypts `plaintext` for `peer_identity`. Writes the wire ciphertext to
/// `out_ciphertext` and the message type tag to `out_message_type`.
///
/// # Safety
/// All pointers must be non-null and point to memory of the declared sizes.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_encrypt(
    store: *mut DeviceStore,
    peer_identity: *const u8,
    peer_identity_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out_ciphertext: *mut u8,
    out_ciphertext_cap: usize,
    out_ciphertext_len: *mut usize,
    out_message_type: *mut u32,
) -> i32 {
    if store.is_null()
        || peer_identity.is_null()
        || plaintext.is_null()
        || out_ciphertext.is_null()
        || out_ciphertext_len.is_null()
        || out_message_type.is_null()
    {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted preconditions above.
    let s = unsafe { &mut *store };
    let peer = unsafe { std::slice::from_raw_parts(peer_identity, peer_identity_len) };
    let pt = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let r = match s.encrypt(peer, pt) {
        Ok(r) => r,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    // SAFETY: caller asserted out_message_type is valid.
    unsafe {
        *out_message_type = if r.is_prekey {
            PIZZINI_MSG_TYPE_PREKEY
        } else {
            PIZZINI_MSG_TYPE_WHISPER
        };
    }
    // SAFETY: caller asserted out_ciphertext / out_ciphertext_len are valid.
    unsafe { copy_or_size_out(&r.ciphertext, out_ciphertext, out_ciphertext_cap, out_ciphertext_len) }
}

/// Decrypts a wire ciphertext from `peer_identity`. `is_prekey` selects
/// PreKey vs Whisper parsing — the caller must communicate this out-of-band
/// (we ship it as a wire-protocol tag, not embedded in the ciphertext).
///
/// # Safety
/// All pointers must be non-null and point to memory of the declared sizes.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_decrypt(
    store: *mut DeviceStore,
    peer_identity: *const u8,
    peer_identity_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    is_prekey: u32,
    out_plaintext: *mut u8,
    out_plaintext_cap: usize,
    out_plaintext_len: *mut usize,
) -> i32 {
    if store.is_null()
        || peer_identity.is_null()
        || ciphertext.is_null()
        || out_plaintext.is_null()
        || out_plaintext_len.is_null()
    {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted preconditions.
    let s = unsafe { &mut *store };
    let peer = unsafe { std::slice::from_raw_parts(peer_identity, peer_identity_len) };
    let ct = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let pt = match s.decrypt(peer, ct, is_prekey != 0) {
        Ok(pt) => pt,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    // SAFETY: caller asserted out_plaintext/out_plaintext_len validity.
    unsafe { copy_or_size_out(&pt, out_plaintext, out_plaintext_cap, out_plaintext_len) }
}

/// Shared "copy bytes into caller buffer or report required size" tail.
///
/// # Safety
/// `out_buf` must point to `out_buf_cap` writable bytes; `out_len` must
/// point to a valid `usize`.
unsafe fn copy_or_size_out(
    bytes: &[u8],
    out_buf: *mut u8,
    out_buf_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if bytes.len() > out_buf_cap {
        // SAFETY: caller asserted out_len is valid.
        unsafe { *out_len = bytes.len() };
        return PIZZINI_ERR_BUFFER_TOO_SMALL;
    }
    // SAFETY: cap verified above; out_buf asserted valid.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
        *out_len = bytes.len();
    }
    PIZZINI_OK
}

/// Variant of `copy_or_size_out` that fetches the bytes via an accessor on
/// the store. Used for identity getters where the bytes are derived state.
///
/// # Safety
/// `store` must be a live handle. `out_buf` / `out_len` requirements as above.
unsafe fn write_blob<F: FnOnce(&DeviceStore) -> Vec<u8>>(
    store: *mut DeviceStore,
    out_buf: *mut u8,
    out_buf_cap: usize,
    out_len: *mut usize,
    accessor: F,
) -> i32 {
    if store.is_null() || out_buf.is_null() || out_len.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted store is live.
    let s = unsafe { &*store };
    let bytes = accessor(s);
    // SAFETY: out_buf/out_len asserted valid.
    unsafe { copy_or_size_out(&bytes, out_buf, out_buf_cap, out_len) }
}

/// Snapshot the entire store (identity + prekeys + sessions) to a versioned
/// binary blob. Persist this in Keychain or SQLCipher; pass it back to
/// `pizzini_store_new_from_serialized` on the next launch.
///
/// # Safety
/// `store` must be a live handle. `out_buf`/`out_len` as for the other
/// blob-returning calls.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_serialize(
    store: *mut DeviceStore,
    out_buf: *mut u8,
    out_buf_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if store.is_null() || out_buf.is_null() || out_len.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted preconditions.
    let s = unsafe { &*store };
    let bytes = match s.serialize() {
        Ok(b) => b,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    // SAFETY: out_buf/out_len asserted valid.
    unsafe { copy_or_size_out(&bytes, out_buf, out_buf_cap, out_len) }
}

/// Idempotently track an identity_pub. Called by the host right after
/// scanning a peer's QR — pre-seeds the peer so it survives serialize even
/// before the actual session handshake completes.
///
/// # Safety
/// `store` must be a live handle. `peer_identity` must point to
/// `peer_identity_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_register_peer(
    store: *mut DeviceStore,
    peer_identity: *const u8,
    peer_identity_len: usize,
) -> i32 {
    if store.is_null() || peer_identity.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: preconditions asserted.
    let s = unsafe { &mut *store };
    let peer = unsafe { std::slice::from_raw_parts(peer_identity, peer_identity_len) };
    s.register_peer(peer);
    PIZZINI_OK
}

/// Drop a peer: forget the libsignal session and remove it from the
/// serialize index. After this call, encrypting to or decrypting from the
/// peer requires re-running PQXDH from a fresh bundle.
///
/// # Safety
/// Same as `pizzini_store_register_peer`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_forget_peer(
    store: *mut DeviceStore,
    peer_identity: *const u8,
    peer_identity_len: usize,
) -> i32 {
    if store.is_null() || peer_identity.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: preconditions asserted.
    let s = unsafe { &mut *store };
    let peer = unsafe { std::slice::from_raw_parts(peer_identity, peer_identity_len) };
    s.forget_peer(peer);
    PIZZINI_OK
}

/// Writes the recipient's published delivery-token verify key (33 bytes:
/// libsignal PublicKey serialize() — 1-byte type prefix + 32-byte point).
/// Used by the relay-side token check; deterministic per IdentityKeyPair.
///
/// # Safety
/// Same as `pizzini_store_identity_keypair`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_delivery_token_verify_key(
    store: *mut DeviceStore,
    out_buf: *mut u8,
    out_buf_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if store.is_null() || out_buf.is_null() || out_len.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted store is live.
    let s = unsafe { &*store };
    let bytes = match s.delivery_token_verify_key_bytes() {
        Ok(b) => b,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    // SAFETY: out_buf/out_len asserted valid.
    unsafe { copy_or_size_out(&bytes, out_buf, out_buf_cap, out_len) }
}

/// Mints (or refreshes) the cached SenderCertificate and writes its wire
/// bytes. Production callers reach `pizzini_store_seal_send` directly
/// which calls this internally; this entry point is exposed mostly for
/// debug/logging in Swift.
///
/// # Safety
/// Same as `pizzini_store_publish_bundle`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_ensure_sender_certificate(
    store: *mut DeviceStore,
    out_buf: *mut u8,
    out_buf_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if store.is_null() || out_buf.is_null() || out_len.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted store is live.
    let s = unsafe { &mut *store };
    let bytes = match s.ensure_sender_certificate() {
        Ok(b) => b,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    // SAFETY: out_buf/out_len asserted valid.
    unsafe { copy_or_size_out(&bytes, out_buf, out_buf_cap, out_len) }
}

/// Sealed-sender SEND. Wraps `plaintext` in a libsignal ratchet
/// ciphertext, prefixes the 16-byte `message_id` and 1-byte `is_prekey`
/// at the USMC layer, seals to `peer_identity_pub`, and writes the wire
/// bytes the relay forwards verbatim. Mints the SenderCertificate
/// internally if absent.
///
/// # Safety
/// All non-null pointers must describe valid slices of the declared sizes.
/// `message_id` must point to exactly 16 readable bytes.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_seal_send(
    store: *mut DeviceStore,
    peer_identity: *const u8,
    peer_identity_len: usize,
    message_id_16: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
    out_sealed: *mut u8,
    out_sealed_cap: usize,
    out_sealed_len: *mut usize,
) -> i32 {
    if store.is_null()
        || peer_identity.is_null()
        || message_id_16.is_null()
        || plaintext.is_null()
        || out_sealed.is_null()
        || out_sealed_len.is_null()
    {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: preconditions asserted.
    let s = unsafe { &mut *store };
    let peer = unsafe { std::slice::from_raw_parts(peer_identity, peer_identity_len) };
    let pt = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let msg_id_slice = unsafe { std::slice::from_raw_parts(message_id_16, 16) };
    let mut msg_id = [0u8; 16];
    msg_id.copy_from_slice(msg_id_slice);
    let bytes = match s.seal_send(peer, &msg_id, pt) {
        Ok(b) => b,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    // SAFETY: out_sealed/out_sealed_len asserted valid.
    unsafe { copy_or_size_out(&bytes, out_sealed, out_sealed_cap, out_sealed_len) }
}

/// Mint a single delivery token: 16-byte nonce + u32 expiry + 64-byte
/// XEd25519 signature, all 84 bytes total. The recipient's peer holds a
/// stash; each SEND/ACK pops one and ships it on the wire so the relay
/// can rate-limit by recipient consent. See `pizzini_store_delivery_token_verify_key`
/// for the verify side.
///
/// # Safety
/// `out_token` must point to at least `DELIVERY_TOKEN_LEN` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_mint_delivery_token(
    store: *mut DeviceStore,
    out_token: *mut u8,
    out_token_cap: usize,
    out_token_len: *mut usize,
) -> i32 {
    if store.is_null() || out_token.is_null() || out_token_len.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted store is live.
    let s = unsafe { &*store };
    let token = match s.mint_delivery_token() {
        Ok(t) => t,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    // SAFETY: out_token/out_len asserted valid.
    unsafe { copy_or_size_out(&token, out_token, out_token_cap, out_token_len) }
}

/// BLAKE3-256 of `input`. Used by iOS to derive the hashcash challenge
/// (`BLAKE3(recipient_peer_id || hour_bucket)`) — CryptoKit doesn't
/// expose BLAKE3, and the relay's verifier hashes the same way, so the
/// iOS side reaches across the FFI rather than maintaining a parallel
/// pure-Swift implementation.
///
/// Writes 32 bytes to `out_hash_32`.
///
/// # Safety
/// `input` must point to `input_len` readable bytes; `out_hash_32`
/// must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn pizzini_blake3_hash(
    input: *const u8,
    input_len: usize,
    out_hash_32: *mut u8,
) -> i32 {
    if input.is_null() || out_hash_32.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted input/output validity.
    let bytes = unsafe { std::slice::from_raw_parts(input, input_len) };
    let hash = blake3::hash(bytes);
    unsafe {
        std::ptr::copy_nonoverlapping(hash.as_bytes().as_ptr(), out_hash_32, 32);
    }
    PIZZINI_OK
}

/// BLAKE3 hashcash prover. Brute-forces a u64 nonce such that
/// `BLAKE3(challenge || nonce_be) has at least `bits` leading zero
/// bits`. Used by iOS to compute the proof attached to a
/// BUNDLE_REQUEST; the relay verifies with a single hash.
///
/// Returns 0 on success and writes the nonce to `*out_nonce`. Returns
/// `PIZZINI_ERR_INVALID_ARG` on null pointers. There is no upper-bound
/// guard on `bits` here — the caller is responsible for picking a
/// reasonable difficulty (the relay accepts the protocol-defined
/// `HASHCASH_DEFAULT_BITS = 18`).
///
/// # Safety
/// `challenge` must point to `challenge_len` readable bytes.
/// `out_nonce` must point to a valid `u64`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_hashcash_compute(
    challenge: *const u8,
    challenge_len: usize,
    bits: u32,
    out_nonce: *mut u64,
) -> i32 {
    if challenge.is_null() || out_nonce.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted challenge slice + nonce pointer valid.
    let chal = unsafe { std::slice::from_raw_parts(challenge, challenge_len) };
    let nonce = hashcash_compute(chal, bits);
    unsafe { *out_nonce = nonce };
    PIZZINI_OK
}

/// Sealed-sender RECEIVE. Validates the embedded cert against the
/// claimed sender's identity_pub (looked up in the store's peers list),
/// decrypts the inner ratchet ciphertext, and writes four outputs:
///
/// - `out_sender` — the sender's 33-byte identity_pub.
/// - `out_message_id_16` — the 16-byte message_id from the USMC header.
/// - `out_plaintext` — the inner plaintext bytes (empty when duplicate).
/// - `out_is_duplicate` — set to 1 if libsignal's ratchet rejected the
///   inner ciphertext as a duplicate (counter already consumed). The
///   sender + message_id are still written so the host can re-emit a
///   fresh ACK to flip the sender's outbox; `out_plaintext_len` is 0.
///
/// Returns `PIZZINI_ERR_BUFFER_TOO_SMALL` when EITHER `out_sender` or
/// `out_plaintext` is too small to receive its payload, with the
/// corresponding `*_len` filled in. Caller retries with both buffers
/// sized appropriately. (We don't surface partial success — the
/// alternative is "decrypted, then refused to copy", which leaves the
/// ratchet advanced but the caller empty-handed.)
///
/// # Safety
/// All non-null pointers must describe valid slices of the declared sizes.
/// `out_message_id_16` must point to 16 writable bytes.
/// `out_is_duplicate` must point to 1 writable byte.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_seal_receive(
    store: *mut DeviceStore,
    sealed: *const u8,
    sealed_len: usize,
    out_sender: *mut u8,
    out_sender_cap: usize,
    out_sender_len: *mut usize,
    out_message_id_16: *mut u8,
    out_plaintext: *mut u8,
    out_plaintext_cap: usize,
    out_plaintext_len: *mut usize,
    out_is_duplicate: *mut u8,
) -> i32 {
    if store.is_null()
        || sealed.is_null()
        || out_sender.is_null()
        || out_sender_len.is_null()
        || out_message_id_16.is_null()
        || out_plaintext.is_null()
        || out_plaintext_len.is_null()
        || out_is_duplicate.is_null()
    {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: preconditions asserted.
    let s = unsafe { &mut *store };
    let sealed_bytes = unsafe { std::slice::from_raw_parts(sealed, sealed_len) };
    let received = match s.seal_receive(sealed_bytes) {
        Ok(r) => r,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };

    // Two-buffer copy. If either is too small we report the maximum
    // required size for that buffer, untouched, so the caller can grow
    // both and retry with one round-trip.
    let sender_len = received.sender_identity_pub.len();
    let plaintext_len = received.plaintext.len();
    if sender_len > out_sender_cap || plaintext_len > out_plaintext_cap {
        // SAFETY: lengths pointers asserted valid.
        unsafe {
            *out_sender_len = sender_len;
            *out_plaintext_len = plaintext_len;
        }
        return PIZZINI_ERR_BUFFER_TOO_SMALL;
    }
    // SAFETY: caps verified above; pointers asserted valid.
    unsafe {
        std::ptr::copy_nonoverlapping(
            received.sender_identity_pub.as_ptr(),
            out_sender,
            sender_len,
        );
        *out_sender_len = sender_len;
        std::ptr::copy_nonoverlapping(received.message_id.as_ptr(), out_message_id_16, 16);
        std::ptr::copy_nonoverlapping(
            received.plaintext.as_ptr(),
            out_plaintext,
            plaintext_len,
        );
        *out_plaintext_len = plaintext_len;
        *out_is_duplicate = if received.is_duplicate { 1 } else { 0 };
    }
    PIZZINI_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn version_is_set() {
        let ptr = pizzini_crypto_core_version();
        // SAFETY: we returned a static, null-terminated string.
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert!(!s.is_empty());
        assert_eq!(s, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn generate_identity_round_trips() {
        let mut buf = vec![0u8; 256];
        let mut len = 0usize;
        let rc = unsafe {
            pizzini_identity_keypair_generate(buf.as_mut_ptr(), buf.len(), &mut len)
        };
        assert_eq!(rc, PIZZINI_OK);
        assert!(len > 0, "wrote zero bytes");

        let kp = IdentityKeyPair::try_from(&buf[..len]).expect("deserialize");
        assert_eq!(kp.serialize().as_ref(), &buf[..len]);
    }

    #[test]
    fn two_calls_produce_different_keypairs() {
        let mut a = [0u8; 256];
        let mut a_len = 0usize;
        let mut b = [0u8; 256];
        let mut b_len = 0usize;
        unsafe {
            pizzini_identity_keypair_generate(a.as_mut_ptr(), a.len(), &mut a_len);
            pizzini_identity_keypair_generate(b.as_mut_ptr(), b.len(), &mut b_len);
        }
        assert_eq!(a_len, b_len);
        assert_ne!(a[..a_len], b[..b_len], "RNG produced identical keys");
    }

    #[test]
    fn small_buffer_reports_required_size() {
        let mut buf = [0u8; 1];
        let mut len = 0usize;
        let rc = unsafe {
            pizzini_identity_keypair_generate(buf.as_mut_ptr(), buf.len(), &mut len)
        };
        assert_eq!(rc, PIZZINI_ERR_BUFFER_TOO_SMALL);
        assert!(len > 1, "did not report required size");
    }

    #[test]
    fn null_pointers_rejected() {
        let mut len = 0usize;
        let rc = unsafe {
            pizzini_identity_keypair_generate(std::ptr::null_mut(), 0, &mut len)
        };
        assert_eq!(rc, PIZZINI_ERR_INVALID_ARG);
    }

    #[test]
    fn store_ffi_two_devices_round_trip() {
        // Mirror two_devices_round_trip from store.rs but exercising every
        // exposed C ABI symbol — these are what Swift actually calls.
        let alice = unsafe { pizzini_store_new(std::ptr::null(), 0) };
        let bob = unsafe { pizzini_store_new(std::ptr::null(), 0) };
        assert!(!alice.is_null() && !bob.is_null());

        let mut buf = vec![0u8; 64];
        let mut len = 0usize;
        let rc = unsafe {
            pizzini_store_identity_public(bob, buf.as_mut_ptr(), buf.len(), &mut len)
        };
        assert_eq!(rc, PIZZINI_OK);
        let bob_id = buf[..len].to_vec();

        let mut alice_id = vec![0u8; 64];
        let mut alen = 0usize;
        unsafe {
            pizzini_store_identity_public(alice, alice_id.as_mut_ptr(), alice_id.len(), &mut alen)
        };
        let alice_id = alice_id[..alen].to_vec();

        let mut bundle = vec![0u8; 4096];
        let mut blen = 0usize;
        let rc = unsafe {
            pizzini_store_publish_bundle(bob, bundle.as_mut_ptr(), bundle.len(), &mut blen)
        };
        assert_eq!(rc, PIZZINI_OK);
        let bundle = &bundle[..blen];

        let rc = unsafe {
            pizzini_store_initiate_session(
                alice,
                bob_id.as_ptr(), bob_id.len(),
                bundle.as_ptr(), bundle.len(),
            )
        };
        assert_eq!(rc, PIZZINI_OK);

        let plain = b"hello via store FFI";
        let mut ct = vec![0u8; 4096];
        let mut ctlen = 0usize;
        let mut mtype: u32 = 999;
        let rc = unsafe {
            pizzini_store_encrypt(
                alice,
                bob_id.as_ptr(), bob_id.len(),
                plain.as_ptr(), plain.len(),
                ct.as_mut_ptr(), ct.len(), &mut ctlen,
                &mut mtype,
            )
        };
        assert_eq!(rc, PIZZINI_OK);
        assert_eq!(mtype, PIZZINI_MSG_TYPE_PREKEY);

        let mut pt = vec![0u8; 256];
        let mut ptlen = 0usize;
        let rc = unsafe {
            pizzini_store_decrypt(
                bob,
                alice_id.as_ptr(), alice_id.len(),
                ct.as_ptr(), ctlen,
                1,
                pt.as_mut_ptr(), pt.len(), &mut ptlen,
            )
        };
        assert_eq!(rc, PIZZINI_OK);
        assert_eq!(&pt[..ptlen], plain);

        unsafe { pizzini_store_free(alice) };
        unsafe { pizzini_store_free(bob) };
    }

    #[test]
    fn store_ffi_rehydrate_from_seed() {
        let s = unsafe { pizzini_store_new(std::ptr::null(), 0) };
        let mut seed = vec![0u8; 256];
        let mut seed_len = 0usize;
        let rc = unsafe {
            pizzini_store_identity_keypair(s, seed.as_mut_ptr(), seed.len(), &mut seed_len)
        };
        assert_eq!(rc, PIZZINI_OK);

        let mut id_a = vec![0u8; 64];
        let mut id_a_len = 0usize;
        unsafe {
            pizzini_store_identity_public(s, id_a.as_mut_ptr(), id_a.len(), &mut id_a_len)
        };
        unsafe { pizzini_store_free(s) };

        let s2 = unsafe { pizzini_store_new(seed.as_ptr(), seed_len) };
        assert!(!s2.is_null());
        let mut id_b = vec![0u8; 64];
        let mut id_b_len = 0usize;
        unsafe {
            pizzini_store_identity_public(s2, id_b.as_mut_ptr(), id_b.len(), &mut id_b_len)
        };
        assert_eq!(id_a[..id_a_len], id_b[..id_b_len]);
        unsafe { pizzini_store_free(s2) };
    }

    #[test]
    fn store_ffi_serialize_round_trips() {
        // Build Alice + Bob, talk a bit, snapshot Alice via FFI, rehydrate
        // via FFI, keep talking. Mirrors the lib-level test but proves the
        // serialize/from_serialized/forget_peer C ABI symbols work.
        let alice = unsafe { pizzini_store_new(std::ptr::null(), 0) };
        let bob = unsafe { pizzini_store_new(std::ptr::null(), 0) };

        let mut bob_id = vec![0u8; 64];
        let mut bob_id_len = 0usize;
        unsafe {
            pizzini_store_identity_public(bob, bob_id.as_mut_ptr(), bob_id.len(), &mut bob_id_len)
        };
        let bob_id = bob_id[..bob_id_len].to_vec();
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

        let mut bundle = vec![0u8; 4096];
        let mut blen = 0usize;
        unsafe {
            pizzini_store_publish_bundle(bob, bundle.as_mut_ptr(), bundle.len(), &mut blen)
        };
        unsafe {
            pizzini_store_initiate_session(
                alice,
                bob_id.as_ptr(), bob_id.len(),
                bundle.as_ptr(), blen,
            )
        };

        let mut ct = vec![0u8; 4096];
        let mut ctlen = 0usize;
        let mut mt: u32 = 0;
        unsafe {
            pizzini_store_encrypt(
                alice,
                bob_id.as_ptr(), bob_id.len(),
                b"hi".as_ptr(), 2,
                ct.as_mut_ptr(), ct.len(), &mut ctlen, &mut mt,
            )
        };
        let mut pt = vec![0u8; 256];
        let mut ptlen = 0usize;
        unsafe {
            pizzini_store_decrypt(
                bob,
                alice_id.as_ptr(), alice_id.len(),
                ct.as_ptr(), ctlen, 1,
                pt.as_mut_ptr(), pt.len(), &mut ptlen,
            )
        };
        let mut bob_ct = vec![0u8; 4096];
        let mut bob_ctlen = 0usize;
        unsafe {
            pizzini_store_encrypt(
                bob,
                alice_id.as_ptr(), alice_id.len(),
                b"yo".as_ptr(), 2,
                bob_ct.as_mut_ptr(), bob_ct.len(), &mut bob_ctlen, &mut mt,
            )
        };
        let mut bob_pt = vec![0u8; 256];
        let mut bob_ptlen = 0usize;
        unsafe {
            pizzini_store_decrypt(
                alice,
                bob_id.as_ptr(), bob_id.len(),
                bob_ct.as_ptr(), bob_ctlen, 0,
                bob_pt.as_mut_ptr(), bob_pt.len(), &mut bob_ptlen,
            )
        };

        // Snapshot Alice via FFI.
        let mut snap = vec![0u8; 16384];
        let mut snaplen = 0usize;
        let rc = unsafe {
            pizzini_store_serialize(alice, snap.as_mut_ptr(), snap.len(), &mut snaplen)
        };
        assert_eq!(rc, PIZZINI_OK);
        assert!(snaplen > 0);
        unsafe { pizzini_store_free(alice) };

        // Rehydrate Alice from the snapshot.
        let alice2 = unsafe { pizzini_store_new_from_serialized(snap.as_ptr(), snaplen) };
        assert!(!alice2.is_null());

        // Continue the chat — Whisper, since the session survived.
        let mut ct3 = vec![0u8; 4096];
        let mut ct3len = 0usize;
        unsafe {
            pizzini_store_encrypt(
                alice2,
                bob_id.as_ptr(), bob_id.len(),
                b"still here".as_ptr(), 10,
                ct3.as_mut_ptr(), ct3.len(), &mut ct3len, &mut mt,
            )
        };
        assert_eq!(mt, PIZZINI_MSG_TYPE_WHISPER);
        let mut pt3 = vec![0u8; 256];
        let mut pt3len = 0usize;
        let rc = unsafe {
            pizzini_store_decrypt(
                bob,
                alice_id.as_ptr(), alice_id.len(),
                ct3.as_ptr(), ct3len, 0,
                pt3.as_mut_ptr(), pt3.len(), &mut pt3len,
            )
        };
        assert_eq!(rc, PIZZINI_OK);
        assert_eq!(&pt3[..pt3len], b"still here");

        // Forget the peer — encrypting to them must now fail.
        let rc = unsafe {
            pizzini_store_forget_peer(alice2, bob_id.as_ptr(), bob_id.len())
        };
        assert_eq!(rc, PIZZINI_OK);
        let mut ct4 = vec![0u8; 4096];
        let mut ct4len = 0usize;
        let rc = unsafe {
            pizzini_store_encrypt(
                alice2,
                bob_id.as_ptr(), bob_id.len(),
                b"ghost".as_ptr(), 5,
                ct4.as_mut_ptr(), ct4.len(), &mut ct4len, &mut mt,
            )
        };
        assert_eq!(rc, PIZZINI_ERR_INTERNAL);

        unsafe { pizzini_store_free(alice2) };
        unsafe { pizzini_store_free(bob) };
    }

    #[test]
    fn store_ffi_seal_send_receive_round_trips() {
        // Mirror seal_round_trips from store.rs but via the FFI surface
        // exclusively — these are the symbols Swift calls.
        let alice = unsafe { pizzini_store_new(std::ptr::null(), 0) };
        let bob = unsafe { pizzini_store_new(std::ptr::null(), 0) };

        // Pull both identity_pubs.
        let mut alice_id = vec![0u8; 64];
        let mut alice_id_len = 0usize;
        unsafe {
            pizzini_store_identity_public(
                alice,
                alice_id.as_mut_ptr(), alice_id.len(), &mut alice_id_len,
            )
        };
        let alice_id = alice_id[..alice_id_len].to_vec();
        let mut bob_id = vec![0u8; 64];
        let mut bob_id_len = 0usize;
        unsafe {
            pizzini_store_identity_public(
                bob,
                bob_id.as_mut_ptr(), bob_id.len(), &mut bob_id_len,
            )
        };
        let bob_id = bob_id[..bob_id_len].to_vec();

        // Bundle exchange: Alice initiates against Bob; pre-trust Alice
        // on Bob's side so the seal_receive contact-gate accepts her.
        let mut bundle = vec![0u8; 4096];
        let mut bundle_len = 0usize;
        unsafe {
            pizzini_store_publish_bundle(
                bob,
                bundle.as_mut_ptr(), bundle.len(), &mut bundle_len,
            )
        };
        unsafe {
            pizzini_store_initiate_session(
                alice,
                bob_id.as_ptr(), bob_id.len(),
                bundle.as_ptr(), bundle_len,
            )
        };
        unsafe {
            pizzini_store_register_peer(bob, alice_id.as_ptr(), alice_id.len())
        };

        // Verify-key getter works and returns the documented size.
        let mut vk = vec![0u8; 64];
        let mut vk_len = 0usize;
        let rc = unsafe {
            pizzini_store_delivery_token_verify_key(
                alice, vk.as_mut_ptr(), vk.len(), &mut vk_len,
            )
        };
        assert_eq!(rc, PIZZINI_OK);
        assert_eq!(vk_len, DELIVERY_TOKEN_VERIFY_KEY_LEN);

        // Round-trip a message.
        let plaintext = b"hello via sealed FFI";
        let msg_id = [0xAAu8; 16];
        let mut sealed = vec![0u8; 4096];
        let mut sealed_len = 0usize;
        let rc = unsafe {
            pizzini_store_seal_send(
                alice,
                bob_id.as_ptr(), bob_id.len(),
                msg_id.as_ptr(),
                plaintext.as_ptr(), plaintext.len(),
                sealed.as_mut_ptr(), sealed.len(), &mut sealed_len,
            )
        };
        assert_eq!(rc, PIZZINI_OK);
        assert!(sealed_len > 0);

        let mut sender = vec![0u8; 64];
        let mut sender_len = 0usize;
        let mut got_msg_id = [0u8; 16];
        let mut pt = vec![0u8; 1024];
        let mut pt_len = 0usize;
        let mut is_dup: u8 = 0;
        let rc = unsafe {
            pizzini_store_seal_receive(
                bob,
                sealed.as_ptr(), sealed_len,
                sender.as_mut_ptr(), sender.len(), &mut sender_len,
                got_msg_id.as_mut_ptr(),
                pt.as_mut_ptr(), pt.len(), &mut pt_len,
                &mut is_dup,
            )
        };
        assert_eq!(rc, PIZZINI_OK);
        assert_eq!(&sender[..sender_len], alice_id.as_slice());
        assert_eq!(got_msg_id, msg_id);
        assert_eq!(&pt[..pt_len], plaintext);
        assert_eq!(is_dup, 0);

        // A second receive of the same sealed bytes — the inner ratchet
        // will reject as duplicate, but the FFI must still surface the
        // sender + message_id and signal `is_duplicate=1`.
        let mut is_dup2: u8 = 0;
        let mut pt2 = vec![0u8; 1024];
        let mut pt2_len = 0usize;
        let rc = unsafe {
            pizzini_store_seal_receive(
                bob,
                sealed.as_ptr(), sealed_len,
                sender.as_mut_ptr(), sender.len(), &mut sender_len,
                got_msg_id.as_mut_ptr(),
                pt2.as_mut_ptr(), pt2.len(), &mut pt2_len,
                &mut is_dup2,
            )
        };
        assert_eq!(rc, PIZZINI_OK);
        assert_eq!(is_dup2, 1);
        assert_eq!(pt2_len, 0);
        assert_eq!(&sender[..sender_len], alice_id.as_slice());
        assert_eq!(got_msg_id, msg_id);

        // ensure_sender_certificate is idempotent.
        let mut cert = vec![0u8; 4096];
        let mut cert_len = 0usize;
        let rc = unsafe {
            pizzini_store_ensure_sender_certificate(
                alice, cert.as_mut_ptr(), cert.len(), &mut cert_len,
            )
        };
        assert_eq!(rc, PIZZINI_OK);
        assert!(cert_len > 0);

        unsafe { pizzini_store_free(alice) };
        unsafe { pizzini_store_free(bob) };
    }
}
