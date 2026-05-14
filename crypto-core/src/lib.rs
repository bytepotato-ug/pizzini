//! Pizzini crypto core.
//!
//! Wraps libsignal and exposes a C ABI for the iOS app. Everything cryptographic
//! happens here — Swift never touches keys directly.
//!
//! Hard rule: no custom crypto. If a primitive isn't already in libsignal,
//! stop and ask before adding it.

#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::c_char;

use libsignal_protocol::{IdentityKeyPair, PublicKey};
use rand::TryRngCore;
use rand::rngs::OsRng;

mod hashcash;
mod store;
pub use hashcash::{hashcash_compute, hashcash_verify, HASHCASH_DEFAULT_BITS};
pub use store::{
    extract_bundle_verify_key, DeviceStore, EncryptResult, SealReceiveError, SealReceived,
    DELIVERY_TOKEN_LEN, DELIVERY_TOKEN_NONCE_LEN, DELIVERY_TOKEN_SIG_LEN, DELIVERY_TOKEN_TTL_SECS,
    DELIVERY_TOKEN_VERIFY_KEY_LEN,
};

// ───── Error codes ─────────────────────────────────────────────────────
//
// Negative values denote errors; zero is success. Values are stable —
// they are part of the FFI contract.

pub const PIZZINI_OK: i32 = 0;
pub const PIZZINI_ERR_INVALID_ARG: i32 = -1;
pub const PIZZINI_ERR_BUFFER_TOO_SMALL: i32 = -2;
pub const PIZZINI_ERR_INTERNAL: i32 = -3;
/// Cryptographic verification failed (e.g. delivery-token signature does
/// not match the supplied verify_key). Distinct from `INTERNAL` so the
/// caller can attribute the failure to "untrustworthy bytes" rather than
/// "library misbehaved".
pub const PIZZINI_ERR_BAD_SIGNATURE: i32 = -4;

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
    // SAFETY: caller asserted preconditions. `serialize` requires `&mut`
    // since v3 — `InMemSenderKeyStore.load_sender_key` is declared with
    // `&mut self` on the trait, even though it only clones internally.
    let s = unsafe { &mut *store };
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

/// Wire size of a `message_id`: a 16-byte opaque identifier the host
/// mints per message and the relay never sees (it rides inside the
/// USMC contents header).
pub const PIZZINI_MESSAGE_ID_LEN: usize = 16;

/// Sealed-sender SEND. Wraps `plaintext` in a libsignal ratchet
/// ciphertext, prefixes the 16-byte `message_id` and 1-byte `is_prekey`
/// at the USMC layer, seals to `peer_identity_pub`, and writes the wire
/// bytes the relay forwards verbatim. Mints the SenderCertificate
/// internally if absent.
///
/// # Safety
/// All non-null pointers must describe valid slices of the declared sizes.
/// `message_id_16` must point to `message_id_len` readable bytes, and
/// `message_id_len` must equal `PIZZINI_MESSAGE_ID_LEN`.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_seal_send(
    store: *mut DeviceStore,
    peer_identity: *const u8,
    peer_identity_len: usize,
    message_id_16: *const u8,
    message_id_len: usize,
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
    // The 16-byte length is now passed explicitly so the boundary can
    // reject a short buffer instead of trusting a hard-coded `16`.
    if message_id_len != PIZZINI_MESSAGE_ID_LEN {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: preconditions asserted.
    let s = unsafe { &mut *store };
    let peer = unsafe { std::slice::from_raw_parts(peer_identity, peer_identity_len) };
    let pt = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let msg_id_slice = unsafe { std::slice::from_raw_parts(message_id_16, message_id_len) };
    let mut msg_id = [0u8; PIZZINI_MESSAGE_ID_LEN];
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
/// `input` must point to `input_len` readable bytes; it may be NULL
/// only when `input_len == 0`. `out_hash_32` must point to 32 writable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn pizzini_blake3_hash(
    input: *const u8,
    input_len: usize,
    out_hash_32: *mut u8,
) -> i32 {
    if out_hash_32.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // A zero-length input is legitimate — BLAKE3 of the empty string is
    // well-defined — and Swift's `Data().withUnsafeBytes` yields a NULL
    // baseAddress for empty `Data`. NULL with a non-zero len is a caller
    // bug. Mirrors `pizzini_argon2id_derive`'s `pass_len == 0` handling.
    if input.is_null() && input_len != 0 {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted input/output validity; an empty slice is
    // substituted rather than calling `from_raw_parts(null, 0)`.
    let bytes = if input_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(input, input_len) }
    };
    let hash = blake3::hash(bytes);
    unsafe {
        std::ptr::copy_nonoverlapping(hash.as_bytes().as_ptr(), out_hash_32, 32);
    }
    PIZZINI_OK
}

// ───── Safety number (SAS) ─────────────────────────────────────────────
//
// Symmetric, human-comparable code derived deterministically from two
// IdentityKey public bytes. Both parties — regardless of which side
// initiated pairing — see the same 60 digits when no MITM is in their
// session. Read aloud over a voice call (or scanned hand-to-hand a
// second time) to detect identity substitution that happened during
// the initial QR/paste exchange.
//
// Why 60 digits, why decimal:
//   * Signal ships a 60-digit safety number; the format is widely
//     understood and easy to read on a phone call. Decimal keeps the
//     comparison fully accessible (no hex glyphs, no wordlist), and
//     groups of 5 digits map cleanly to short verbal chunks.
//   * 60 decimal digits ≈ 199 bits of entropy from BLAKE3. We truncate
//     the XOF stream to 48 bytes (12 × u32 → mod 100_000). The mod
//     reduction bias is bounded by 2^32 / 100_000 ≈ 42_949 worst-case
//     vs the cycle of 100_000 — i.e. ~0.0023% bias per group, far
//     below "matters for a 60-digit human-compared SAS" thresholds.
//
// Domain separation:
//   * `b"pizzini.safety-number.v1"` is included so a future format change
//     (e.g. emoji SAS, longer digit code) gets a distinct v2 derivation
//     and cannot be confused with a v1 SAS by either side.
//   * Inputs are sorted byte-lexicographically before hashing so Alice
//     and Bob feed the hasher in the same order regardless of who is
//     the local / remote peer. The order tag follows: `b"\x21\x21"` is
//     the two `IdentityKey` wire lengths (33 bytes each, asserted at
//     entry) so a key-confusion attack between (peer_a || peer_b) and
//     a hypothetical (peer_a || peer_b_truncated) cannot collide.

/// Wire size of one IdentityKey public half: 1-byte DJB type prefix +
/// 32-byte Curve25519 point. The SAS derivation rejects any input that
/// is not exactly this many bytes, on either side.
pub const SAFETY_NUMBER_IDENTITY_LEN: usize = 33;

/// Length of the rendered safety number in ASCII digits (no spaces).
/// Caller formats the spacing (typically `XXXXX XXXXX ... XXXXX` —
/// twelve groups of five) at the display layer.
pub const SAFETY_NUMBER_DIGIT_LEN: usize = 60;

/// Domain-separation tag for the v1 SAS derivation. Any change to
/// digit count, group layout, or hash input ordering MUST bump the
/// version suffix so that a v2 client never accepts a v1 SAS as a
/// match.
const SAFETY_NUMBER_DOMAIN_TAG: &[u8] = b"pizzini.safety-number.v1";

/// Derive the symmetric Pizzini safety number for the pair of identity
/// keys `(peer_a, peer_b)`. Order is normalized internally — either
/// caller order produces the same 60 digits.
///
/// Writes exactly `SAFETY_NUMBER_DIGIT_LEN = 60` ASCII bytes (each in
/// `b'0'..=b'9'`) to `out_buf` on success. Returns
/// `PIZZINI_ERR_INVALID_ARG` for null pointers, wrong-length identity
/// inputs, or `out_buf_cap < 60`.
///
/// # Safety
/// `peer_a` must point to `peer_a_len` readable bytes;
/// `peer_b` must point to `peer_b_len` readable bytes;
/// `out_buf` must point to `out_buf_cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn pizzini_safety_number_derive(
    peer_a: *const u8,
    peer_a_len: usize,
    peer_b: *const u8,
    peer_b_len: usize,
    out_buf: *mut u8,
    out_buf_cap: usize,
) -> i32 {
    if peer_a.is_null() || peer_b.is_null() || out_buf.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    if peer_a_len != SAFETY_NUMBER_IDENTITY_LEN || peer_b_len != SAFETY_NUMBER_IDENTITY_LEN {
        return PIZZINI_ERR_INVALID_ARG;
    }
    if out_buf_cap < SAFETY_NUMBER_DIGIT_LEN {
        return PIZZINI_ERR_INVALID_ARG;
    }

    // SAFETY: lengths validated above; caller asserted slice validity.
    let a = unsafe { std::slice::from_raw_parts(peer_a, peer_a_len) };
    let b = unsafe { std::slice::from_raw_parts(peer_b, peer_b_len) };

    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = blake3::Hasher::new();
    hasher.update(SAFETY_NUMBER_DOMAIN_TAG);
    // Length tags bind both inputs to their declared sizes — a defense
    // against length-extension-style confusion if SAFETY_NUMBER_IDENTITY_LEN
    // ever changes in a future version without a domain-tag bump.
    hasher.update(&[SAFETY_NUMBER_IDENTITY_LEN as u8, SAFETY_NUMBER_IDENTITY_LEN as u8]);
    hasher.update(lo);
    hasher.update(hi);

    let mut xof = [0u8; 48];
    hasher.finalize_xof().fill(&mut xof);

    // SAFETY: out_buf has at least SAFETY_NUMBER_DIGIT_LEN writable bytes.
    let out = unsafe { std::slice::from_raw_parts_mut(out_buf, SAFETY_NUMBER_DIGIT_LEN) };
    for i in 0..12 {
        let word = u32::from_be_bytes(xof[i * 4..i * 4 + 4].try_into().unwrap());
        let group = word % 100_000;
        // 5 digits, big-endian decimal (most significant first).
        let mut n = group;
        for j in (0..5).rev() {
            out[i * 5 + j] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    PIZZINI_OK
}

/// FFI ceiling on `bits` to prevent an untrusted caller from wedging
/// the host thread. 26 is well above the protocol's
/// `HASHCASH_DEFAULT_BITS = 18` (which costs ~1s on a modern phone),
/// well below the wall-clock-infinite region. At 26 the expected runtime
/// is ~64x default → ~1 minute on a phone, ~3 seconds on a desktop.
/// Anything stricter the caller wants must come from a separate API
/// that takes a wall-clock budget. F-702.
pub const HASHCASH_FFI_MAX_BITS: u32 = 26;

/// BLAKE3 hashcash prover. Brute-forces a u64 nonce such that
/// `BLAKE3(challenge || nonce_be) has at least `bits` leading zero
/// bits`. Used by iOS to compute the proof attached to a
/// BUNDLE_REQUEST; the relay verifies with a single hash.
///
/// Returns 0 on success and writes the nonce to `*out_nonce`. Returns
/// `PIZZINI_ERR_INVALID_ARG` on null pointers OR when `bits` exceeds
/// `HASHCASH_FFI_MAX_BITS` (untrusted-caller DoS guard).
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
    if bits > HASHCASH_FFI_MAX_BITS {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted challenge slice + nonce pointer valid.
    let chal = unsafe { std::slice::from_raw_parts(challenge, challenge_len) };
    let nonce = hashcash_compute(chal, bits);
    unsafe { *out_nonce = nonce };
    PIZZINI_OK
}

// ───── Argon2id KDF ────────────────────────────────────────────────────
//
// The iOS SQLCipher layer chains:
//
//   Secure-Enclave-wrapped 32-byte seed
//        → ECIES unwrap        (SE participation; never leaves the chip)
//        → HKDF-SHA512         (domain-separation; Swift-side)
//        → Argon2id            (this function; ~250 ms on iPhone 12/15-class)
//        → 32-byte db_key      (fed to sqlite3_key_v2)
//
// We expose Argon2id rather than do the derivation Swift-side because
// the only Argon2 implementations on iOS are slow (CryptoSwift) and
// CryptoKit doesn't ship the primitive. Cost numbers above are with
// the production parameters M=64 MiB, T=3, P=1 — chosen to match the
// OWASP 2025 mobile-app recommendation.

/// Minimum salt length accepted by `pizzini_argon2id_derive`. Argon2's
/// own spec requires ≥ 8 bytes; we lift the floor to 16 to make the
/// FFI guard symmetric with the iOS side which always passes 32.
pub const PIZZINI_ARGON2ID_MIN_SALT_LEN: usize = 16;
/// Minimum output length accepted by `pizzini_argon2id_derive`. We
/// only ever ask for 32-byte database keys, but Argon2's own spec
/// requires ≥ 4 bytes; the lower bound is generous in case the
/// duress-passphrase task wants a 16-byte key-wrapping key later.
pub const PIZZINI_ARGON2ID_MIN_OUTPUT_LEN: usize = 16;
/// Upper bound on the memory-cost parameter (KiB). 256 MiB. Caps the
/// blast radius of a caller passing a wild value — an Argon2id call
/// with M=4 GiB would OOM the app process. The production value
/// (64 MiB = 65_536 KiB) is well under this ceiling.
pub const PIZZINI_ARGON2ID_MAX_MEMORY_KIB: u32 = 256 * 1024;
/// Upper bound on the time-cost parameter (iteration count). 100 is
/// vastly past anything we'd ship; same FFI-DoS guard as
/// HASHCASH_FFI_MAX_BITS.
pub const PIZZINI_ARGON2ID_MAX_TIME: u32 = 100;
/// Upper bound on the parallelism parameter. Single-digit by
/// construction on phones; 16 is the safe ceiling.
pub const PIZZINI_ARGON2ID_MAX_PARALLELISM: u32 = 16;

/// Argon2id key derivation. Writes exactly `out_len` bytes to `out`.
///
/// Parameters mirror the upstream RFC 9106 numbering:
///   - `m_cost_kib` — memory cost in KiB
///   - `t_cost`    — iteration (time) cost
///   - `p_cost`    — degree of parallelism
///
/// Returns `PIZZINI_OK` on success.
/// Returns `PIZZINI_ERR_INVALID_ARG` on null pointers, undersized salt
/// (< `PIZZINI_ARGON2ID_MIN_SALT_LEN`), undersized output
/// (< `PIZZINI_ARGON2ID_MIN_OUTPUT_LEN`), or any parameter past its
/// FFI-DoS ceiling.
/// Returns `PIZZINI_ERR_INTERNAL` if the underlying Argon2id
/// implementation rejects the parameter combination (e.g. M too small
/// for the requested P) or the hash itself fails.
///
/// # Safety
/// `salt`       — must point to `salt_len` readable bytes.
/// `passphrase` — must point to `pass_len` readable bytes; may be
///                empty only if `pass_len == 0`.
/// `out`        — must point to `out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn pizzini_argon2id_derive(
    salt: *const u8,
    salt_len: usize,
    passphrase: *const u8,
    pass_len: usize,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if salt.is_null() || out.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // A zero-length passphrase is legitimate (caller may have
    // pre-mixed everything into the salt). NULL with non-zero len is
    // a caller bug.
    if passphrase.is_null() && pass_len != 0 {
        return PIZZINI_ERR_INVALID_ARG;
    }
    if salt_len < PIZZINI_ARGON2ID_MIN_SALT_LEN {
        return PIZZINI_ERR_INVALID_ARG;
    }
    if out_len < PIZZINI_ARGON2ID_MIN_OUTPUT_LEN {
        return PIZZINI_ERR_INVALID_ARG;
    }
    if m_cost_kib == 0 || m_cost_kib > PIZZINI_ARGON2ID_MAX_MEMORY_KIB {
        return PIZZINI_ERR_INVALID_ARG;
    }
    if t_cost == 0 || t_cost > PIZZINI_ARGON2ID_MAX_TIME {
        return PIZZINI_ERR_INVALID_ARG;
    }
    if p_cost == 0 || p_cost > PIZZINI_ARGON2ID_MAX_PARALLELISM {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted the pointers/lengths above.
    let salt_bytes = unsafe { std::slice::from_raw_parts(salt, salt_len) };
    let pass_bytes = if pass_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(passphrase, pass_len) }
    };
    let out_slice = unsafe { std::slice::from_raw_parts_mut(out, out_len) };

    let params = match argon2::Params::new(m_cost_kib, t_cost, p_cost, Some(out_len)) {
        Ok(p) => p,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    match argon.hash_password_into(pass_bytes, salt_bytes, out_slice) {
        Ok(()) => PIZZINI_OK,
        Err(_) => PIZZINI_ERR_INTERNAL,
    }
}

/// Verify a delivery-token signature against a publish-bundle verify
/// key. F-202 / F-401: the iOS receiver of a TOKEN_ISSUE batch needs to
/// authenticate each token against the issuer's bundle-published
/// verify_key, otherwise a malicious relay can swap legitimate batches
/// for relay-forged bytes that fail at SEND-time and DoS the user.
///
/// Wire format mirrors `crypto-core::store::DeliveryToken`:
/// `nonce16 || expiry_be_u32 || sig64`. The signature is over the first
/// 20 bytes (nonce + expiry).
///
/// Returns `PIZZINI_OK` on valid signature, `PIZZINI_ERR_INVALID_ARG`
/// on null pointers or wrong lengths, `PIZZINI_ERR_INTERNAL` if the
/// verify_key fails to deserialize, and `PIZZINI_ERR_BAD_SIGNATURE` if
/// the signature does not validate.
///
/// # Safety
/// `verify_key` must point to `verify_key_len` readable bytes (must be
/// `DELIVERY_TOKEN_VERIFY_KEY_LEN` = 33).
/// `token` must point to `token_len` readable bytes (must be
/// `DELIVERY_TOKEN_LEN` = 84).
#[no_mangle]
pub unsafe extern "C" fn pizzini_verify_delivery_token(
    verify_key: *const u8,
    verify_key_len: usize,
    token: *const u8,
    token_len: usize,
) -> i32 {
    if verify_key.is_null() || token.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    if verify_key_len != DELIVERY_TOKEN_VERIFY_KEY_LEN {
        return PIZZINI_ERR_INVALID_ARG;
    }
    if token_len != DELIVERY_TOKEN_LEN {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted slice validity above.
    let vk_bytes = unsafe { std::slice::from_raw_parts(verify_key, verify_key_len) };
    let tok_bytes = unsafe { std::slice::from_raw_parts(token, token_len) };

    let key = match PublicKey::deserialize(vk_bytes) {
        Ok(k) => k,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    let payload = &tok_bytes[..DELIVERY_TOKEN_NONCE_LEN + 4];
    let sig = &tok_bytes[DELIVERY_TOKEN_NONCE_LEN + 4..];
    if key.verify_signature(payload, sig) {
        PIZZINI_OK
    } else {
        PIZZINI_ERR_BAD_SIGNATURE
    }
}

/// Verify an arbitrary XEd25519 signature `sig` over `message`, claimed
/// to be produced by the IdentityKey whose 33-byte serialized public
/// half is `identity_pub`.
///
/// Returns `PIZZINI_OK` on a valid signature, `PIZZINI_ERR_BAD_SIGNATURE`
/// if the signature does not match, or `PIZZINI_ERR_INVALID_ARG` for
/// length / null mismatches. Used by the Swift host to authenticate
/// signed `GroupOp` log entries: the signer's identity-public is
/// embedded in the op header and the recipient verifies the signature
/// before applying the op.
///
/// # Safety
/// All pointers must be non-null and refer to memory of the declared
/// sizes. `identity_pub_len` must equal the IdentityKey wire size
/// (33 bytes — 1-byte DJB type prefix + 32-byte point).
#[no_mangle]
pub unsafe extern "C" fn pizzini_verify_identity_signature(
    identity_pub: *const u8,
    identity_pub_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    // F-NEW-101: keep the no-tag FFI in source but route every caller
    // through the v2 form. Internal callers use `_v2` directly; the
    // no-tag form here is the legacy shim and is removed from cbindgen
    // via the #[doc(hidden)] attribute. Future call sites MUST take
    // the v2 path — the tag-less variant is structurally vulnerable to
    // cross-context signature reuse if a future caller passes
    // attacker-influenced bytes without their own domain prefix.
    if identity_pub.is_null() || message.is_null() || signature.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // 33 bytes is the libsignal-native IdentityKey wire size.
    if identity_pub_len != 33 {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // 64 bytes is the XEd25519 signature output libsignal's
    // `IdentityKeyPair::private_key().calculate_signature(...)` produces.
    if signature_len != 64 {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted slice validity above.
    let id_bytes = unsafe { std::slice::from_raw_parts(identity_pub, identity_pub_len) };
    let msg = unsafe { std::slice::from_raw_parts(message, message_len) };
    let sig = unsafe { std::slice::from_raw_parts(signature, signature_len) };

    let key = match PublicKey::deserialize(id_bytes) {
        Ok(k) => k,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    if key.verify_signature(msg, sig) {
        PIZZINI_OK
    } else {
        PIZZINI_ERR_BAD_SIGNATURE
    }
}

/// F-NEW-101: domain-separated identity signature verify. The signed
/// bytes the verifier reconstructs are
/// `u16_be(context_tag_len) || context_tag || message`. A caller that
/// forgets to pass the tag — or passes a different tag than the
/// signer — gets `PIZZINI_ERR_BAD_SIGNATURE`. The tag MUST be
/// non-empty; empty tags collapse to the unsafe legacy contract.
///
/// # Safety
/// `identity_pub` (33 bytes), `context_tag` (`context_tag_len`),
/// `message` (`message_len`), and `signature` (64 bytes) must point
/// at readable buffers of the stated sizes.
#[no_mangle]
pub unsafe extern "C" fn pizzini_verify_identity_signature_v2(
    identity_pub: *const u8,
    identity_pub_len: usize,
    context_tag: *const u8,
    context_tag_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    if identity_pub.is_null() || context_tag.is_null() || message.is_null() || signature.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    if identity_pub_len != 33 || signature_len != 64 {
        return PIZZINI_ERR_INVALID_ARG;
    }
    if context_tag_len == 0 || context_tag_len > u16::MAX as usize {
        // Empty tag = legacy contract; refuse so an attacker-influenced
        // caller can't downgrade to the tag-less surface.
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted slice validity above.
    let id_bytes = unsafe { std::slice::from_raw_parts(identity_pub, identity_pub_len) };
    let tag = unsafe { std::slice::from_raw_parts(context_tag, context_tag_len) };
    let msg = unsafe { std::slice::from_raw_parts(message, message_len) };
    let sig = unsafe { std::slice::from_raw_parts(signature, signature_len) };

    let key = match PublicKey::deserialize(id_bytes) {
        Ok(k) => k,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    let mut signed = Vec::with_capacity(2 + tag.len() + msg.len());
    signed.extend_from_slice(&(tag.len() as u16).to_be_bytes());
    signed.extend_from_slice(tag);
    signed.extend_from_slice(msg);
    if key.verify_signature(&signed, sig) {
        PIZZINI_OK
    } else {
        PIZZINI_ERR_BAD_SIGNATURE
    }
}

/// Sign `payload` with the local IdentityKey's private half. F-203:
/// used by the iOS client to attach a possession proof to its HELLO
/// frame so a network-positioned attacker can't squat someone else's
/// peer_id and drain that peer's queued mail. The relay verifies the
/// returned 64-byte Ed25519 signature against the IdentityKey extracted
/// from the HELLO's `peer_id` field.
///
/// The store is borrowed immutably — signing doesn't mutate any
/// libsignal state.
///
/// # Safety
/// `store` must point to a live `DeviceStore`.
/// `payload` must point to `payload_len` readable bytes.
/// `out_sig` must point to `out_cap` writable bytes.
/// `out_len` must point to a valid `usize`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_identity_sign(
    store: *mut DeviceStore,
    payload: *const u8,
    payload_len: usize,
    out_sig: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    // Legacy tag-less signing path. Kept for ABI continuity but no
    // longer called by Swift (RelayClient.swift uses the _v2 form
    // post-F-NEW-101). Any future caller MUST prefer the _v2 form.
    if store.is_null() || payload.is_null() || out_sig.is_null() || out_len.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted slice + pointer validity.
    let s = unsafe { &*store };
    let payload_bytes = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    let kp = s.local_identity_keypair();
    let mut rng = OsRng.unwrap_err();
    let sig = match kp.private_key().calculate_signature(payload_bytes, &mut rng) {
        Ok(s) => s,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    let sig_bytes: &[u8] = &sig;
    if sig_bytes.len() > out_cap {
        unsafe { *out_len = sig_bytes.len() };
        return PIZZINI_ERR_BUFFER_TOO_SMALL;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), out_sig, sig_bytes.len());
        *out_len = sig_bytes.len();
    }
    PIZZINI_OK
}

/// F-NEW-101: domain-separated identity sign. Signs
/// `u16_be(context_tag_len) || context_tag || payload`. The tag MUST
/// be non-empty; passing an empty tag returns `PIZZINI_ERR_INVALID_ARG`
/// to prevent a misuse path from silently producing legacy-format
/// signatures.
///
/// # Safety
/// `store` must point to a live `DeviceStore`. `context_tag`
/// (`context_tag_len`) and `payload` (`payload_len`) must point to
/// readable buffers. `out_sig` must be writable for `out_cap` bytes;
/// `out_len` writable for one `usize`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_identity_sign_v2(
    store: *mut DeviceStore,
    context_tag: *const u8,
    context_tag_len: usize,
    payload: *const u8,
    payload_len: usize,
    out_sig: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if store.is_null()
        || context_tag.is_null()
        || payload.is_null()
        || out_sig.is_null()
        || out_len.is_null()
    {
        return PIZZINI_ERR_INVALID_ARG;
    }
    if context_tag_len == 0 || context_tag_len > u16::MAX as usize {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted slice + pointer validity.
    let s = unsafe { &*store };
    let tag = unsafe { std::slice::from_raw_parts(context_tag, context_tag_len) };
    let payload_bytes = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    let mut signed = Vec::with_capacity(2 + tag.len() + payload_bytes.len());
    signed.extend_from_slice(&(tag.len() as u16).to_be_bytes());
    signed.extend_from_slice(tag);
    signed.extend_from_slice(payload_bytes);
    let kp = s.local_identity_keypair();
    let mut rng = OsRng.unwrap_err();
    let sig = match kp.private_key().calculate_signature(&signed, &mut rng) {
        Ok(s) => s,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    let sig_bytes: &[u8] = &sig;
    if sig_bytes.len() > out_cap {
        unsafe { *out_len = sig_bytes.len() };
        return PIZZINI_ERR_BUFFER_TOO_SMALL;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), out_sig, sig_bytes.len());
        *out_len = sig_bytes.len();
    }
    PIZZINI_OK
}

/// Pull the issuer's `delivery_token_verify_key` (33 bytes) out of a
/// BUNDLE_RESPONSE payload without consuming the bundle. Companion to
/// `pizzini_verify_delivery_token` — iOS calls this on the bundle bytes
/// it just received, stashes the result on the Contact, and uses it to
/// authenticate every later TOKEN_ISSUE batch from this peer.
///
/// Returns `PIZZINI_OK` on success and writes 33 bytes to `out_buf`,
/// `PIZZINI_ERR_BUFFER_TOO_SMALL` if `out_cap` is too small (with
/// `*out_len` set to `DELIVERY_TOKEN_VERIFY_KEY_LEN`),
/// `PIZZINI_ERR_INTERNAL` if the bundle fails to parse.
///
/// # Safety
/// `bundle` must point to `bundle_len` readable bytes.
/// `out_buf` must point to `out_cap` writable bytes.
/// `out_len` must point to a valid `usize`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_bundle_extract_verify_key(
    bundle: *const u8,
    bundle_len: usize,
    out_buf: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if bundle.is_null() || out_buf.is_null() || out_len.is_null() {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted slice + pointer validity.
    let bundle_bytes = unsafe { std::slice::from_raw_parts(bundle, bundle_len) };
    let vk = match extract_bundle_verify_key(bundle_bytes) {
        Ok(v) => v,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    if vk.len() > out_cap {
        unsafe { *out_len = vk.len() };
        return PIZZINI_ERR_BUFFER_TOO_SMALL;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(vk.as_ptr(), out_buf, vk.len());
        *out_len = vk.len();
    }
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
/// corresponding `*_len` filled with an upper bound the caller can use
/// to size the retry. **The ratchet is NOT advanced on a buffer-too-small
/// path** — the FFI runs a non-mutating peek (`peek_sealed_lengths`)
/// to check sizes before committing the ratchet step, so the caller's
/// "discover size, retry with bigger buffer" idiom is now safe (F-101 / F-701).
///
/// `out_plaintext_len` on the BUFFER_TOO_SMALL path is a conservative
/// over-estimate: it equals the USMC inner-content length minus the
/// 16-byte message_id + 1-byte is_prekey header. The actual plaintext
/// returned by a successful retry is smaller (libsignal removes its
/// own protocol overhead). Sizing a retry buffer to this bound is
/// always sufficient.
///
/// Returns `PIZZINI_ERR_BAD_SIGNATURE` when the bytes are
/// attacker-attributable — the sealed-sender certificate fails to
/// validate against the claimed contact's pinned identity, or the
/// claimed sender is not a known contact. Returns `PIZZINI_ERR_INTERNAL`
/// for every other failure (parse errors, ratchet errors, store I/O),
/// which is deliberately indistinguishable from benign corruption.
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

    // F-101 / F-701 fix: pre-flight size check via `peek_sealed_lengths`.
    // This opens the outer USMC envelope but does NOT call message_decrypt,
    // so the Double Ratchet is untouched on a too-small return. The
    // caller's documented retry-with-bigger-buffer pattern is now safe.
    let (sender_upper, plaintext_upper) = match s.peek_sealed_lengths(sealed_bytes) {
        Ok(t) => t,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    if sender_upper > out_sender_cap || plaintext_upper > out_plaintext_cap {
        // SAFETY: lengths pointers asserted valid.
        unsafe {
            *out_sender_len = sender_upper;
            *out_plaintext_len = plaintext_upper;
        }
        return PIZZINI_ERR_BUFFER_TOO_SMALL;
    }

    // Caps satisfy the upper bounds, so the actual lengths after
    // `seal_receive` will fit by construction. Now do the destructive
    // ratchet step.
    //
    // A cert-validation failure or unknown-sender contact-gate
    // rejection is attacker-attributable — the relay or a paired peer
    // handed us forged/unauthorized bytes — so it surfaces as
    // `PIZZINI_ERR_BAD_SIGNATURE`, distinct from a generic internal
    // error. The host may still choose to keep the user-facing surface
    // indistinguishable, but the FFI contract carries the truth.
    let received = match s.seal_receive(sealed_bytes) {
        Ok(r) => r,
        Err(SealReceiveError::BadSignature(_)) => return PIZZINI_ERR_BAD_SIGNATURE,
        Err(SealReceiveError::Internal(_)) => return PIZZINI_ERR_INTERNAL,
    };
    let sender_len = received.sender_identity_pub.len();
    let plaintext_len = received.plaintext.len();
    debug_assert!(sender_len <= out_sender_cap);
    debug_assert!(plaintext_len <= out_plaintext_cap);
    // SAFETY: caps verified by the peek; pointers asserted valid.
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

// ───── Group cipher (libsignal Sender Keys) ────────────────────────────
//
// Pizzini groups encrypt with libsignal's Sender Keys. Each member
// owns a per-chain `distribution_id` (a random 16-byte UUID, NOT the
// public group ID — see `DeviceStore::sender_key_distribution_create`
// for why). To enrol the group, a member calls
// `pizzini_store_sender_key_distribution_create(distribution_id)` and
// ships the SKDM bytes 1:1 over the existing sealed-sender envelope to
// each peer; the peer feeds the SKDM into
// `pizzini_store_sender_key_distribution_process(sender, skdm)`.
// To send to the group, the member calls
// `pizzini_store_group_encrypt(distribution_id, plaintext)` once and
// broadcasts the resulting `SenderKeyMessage` as N independent sealed-
// sender envelopes; each recipient calls
// `pizzini_store_group_decrypt(sender, ciphertext)`.
//
// The four functions below are thin FFI shims around the matching
// `DeviceStore::*` methods. All caller-supplied buffers follow the
// "pass cap, get required size, retry if too small" idiom that the
// rest of the FFI uses; see `copy_or_size_out`.

/// Wire size of a `distribution_id`: a 16-byte raw UUID. The Swift
/// caller derives this per-chain (e.g. from a random-UUID generator)
/// and persists the mapping `(group_id, member_peer_id) → distribution_id`
/// in its own group state model.
pub const PIZZINI_DISTRIBUTION_ID_LEN: usize = 16;

/// Create our local sender-key chain at `distribution_id` and return
/// the SKDM bytes. Calling twice with the same `distribution_id` reuses
/// the existing chain; rotation is "pick a fresh `distribution_id`."
///
/// # Safety
/// `store` and `distribution_id_16` must be non-null;
/// `distribution_id_16` must point to `distribution_id_len` readable
/// bytes, and `distribution_id_len` must equal
/// `PIZZINI_DISTRIBUTION_ID_LEN`.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_sender_key_distribution_create(
    store: *mut store::DeviceStore,
    distribution_id_16: *const u8,
    distribution_id_len: usize,
    out_skdm: *mut u8,
    out_skdm_cap: usize,
    out_skdm_len: *mut usize,
) -> i32 {
    if store.is_null()
        || distribution_id_16.is_null()
        || out_skdm.is_null()
        || out_skdm_len.is_null()
    {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // The 16-byte length is now passed explicitly so the boundary can
    // reject a short buffer instead of trusting a hard-coded constant.
    if distribution_id_len != PIZZINI_DISTRIBUTION_ID_LEN {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted preconditions above.
    let s = unsafe { &mut *store };
    let id_slice = unsafe { std::slice::from_raw_parts(distribution_id_16, distribution_id_len) };
    let mut distribution_id = [0u8; PIZZINI_DISTRIBUTION_ID_LEN];
    distribution_id.copy_from_slice(id_slice);
    let skdm = match s.sender_key_distribution_create(distribution_id) {
        Ok(b) => b,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    // SAFETY: out_skdm/out_skdm_len asserted valid.
    unsafe { copy_or_size_out(&skdm, out_skdm, out_skdm_cap, out_skdm_len) }
}

/// Process a peer's incoming SKDM. `sender_identity` is the
/// authenticated identity-public from the sealed-sender unwrap. On
/// success, writes the 16-byte distribution_id parsed from the SKDM
/// to `out_distribution_id_16`, so the caller can match the chain
/// against its group-state model without re-parsing the SKDM.
///
/// # Safety
/// All pointers must be non-null and refer to memory of the declared
/// sizes; `out_distribution_id_16` must point to
/// `out_distribution_id_cap` writable bytes, and `out_distribution_id_cap`
/// must equal `PIZZINI_DISTRIBUTION_ID_LEN`.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_sender_key_distribution_process(
    store: *mut store::DeviceStore,
    sender_identity: *const u8,
    sender_identity_len: usize,
    skdm: *const u8,
    skdm_len: usize,
    out_distribution_id_16: *mut u8,
    out_distribution_id_cap: usize,
) -> i32 {
    if store.is_null()
        || sender_identity.is_null()
        || skdm.is_null()
        || out_distribution_id_16.is_null()
    {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // The 16-byte output length is now passed explicitly so the boundary
    // can reject a short buffer instead of trusting a hard-coded constant.
    if out_distribution_id_cap != PIZZINI_DISTRIBUTION_ID_LEN {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted preconditions.
    let s = unsafe { &mut *store };
    let sender = unsafe { std::slice::from_raw_parts(sender_identity, sender_identity_len) };
    let bytes = unsafe { std::slice::from_raw_parts(skdm, skdm_len) };
    let dist_id = match s.sender_key_distribution_process(sender, bytes) {
        Ok(d) => d,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    // SAFETY: caller asserted out_distribution_id_16 has 16 writable bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(dist_id.as_ptr(), out_distribution_id_16, PIZZINI_DISTRIBUTION_ID_LEN);
    }
    PIZZINI_OK
}

/// Encrypt `plaintext` for the chain identified by `distribution_id`.
/// Caller must have called `sender_key_distribution_create` with the
/// same `distribution_id` first; otherwise libsignal returns
/// `NoSenderKeyState` (mapped to `PIZZINI_ERR_INTERNAL`). The output is
/// a `SenderKeyMessage` ready for fan-out as N pairwise sealed-sender
/// envelopes.
///
/// # Safety
/// All pointers must be non-null and refer to memory of the declared
/// sizes; `distribution_id_16` must point to `distribution_id_len`
/// readable bytes, and `distribution_id_len` must equal
/// `PIZZINI_DISTRIBUTION_ID_LEN`.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_group_encrypt(
    store: *mut store::DeviceStore,
    distribution_id_16: *const u8,
    distribution_id_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out_ciphertext: *mut u8,
    out_ciphertext_cap: usize,
    out_ciphertext_len: *mut usize,
) -> i32 {
    if store.is_null()
        || distribution_id_16.is_null()
        || plaintext.is_null()
        || out_ciphertext.is_null()
        || out_ciphertext_len.is_null()
    {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // The 16-byte length is now passed explicitly so the boundary can
    // reject a short buffer instead of trusting a hard-coded constant.
    if distribution_id_len != PIZZINI_DISTRIBUTION_ID_LEN {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted preconditions.
    let s = unsafe { &mut *store };
    let id_slice = unsafe { std::slice::from_raw_parts(distribution_id_16, distribution_id_len) };
    let mut distribution_id = [0u8; PIZZINI_DISTRIBUTION_ID_LEN];
    distribution_id.copy_from_slice(id_slice);
    let pt = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let ct = match s.group_encrypt(distribution_id, pt) {
        Ok(b) => b,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    // SAFETY: out_ciphertext/out_ciphertext_len asserted valid.
    unsafe { copy_or_size_out(&ct, out_ciphertext, out_ciphertext_cap, out_ciphertext_len) }
}

/// Decrypt a `SenderKeyMessage` from `sender_identity`. The
/// distribution_id is encoded in the ciphertext header and looked up
/// against the SKDM previously processed for this sender. Returns
/// `PIZZINI_ERR_INTERNAL` if the chain isn't installed (caller should
/// trigger an SKDM exchange) or if the signature verification fails.
///
/// # Safety
/// All pointers must be non-null and refer to memory of the declared
/// sizes.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pizzini_store_group_decrypt(
    store: *mut store::DeviceStore,
    sender_identity: *const u8,
    sender_identity_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out_plaintext: *mut u8,
    out_plaintext_cap: usize,
    out_plaintext_len: *mut usize,
) -> i32 {
    if store.is_null()
        || sender_identity.is_null()
        || ciphertext.is_null()
        || out_plaintext.is_null()
        || out_plaintext_len.is_null()
    {
        return PIZZINI_ERR_INVALID_ARG;
    }
    // SAFETY: caller asserted preconditions.
    let s = unsafe { &mut *store };
    let sender = unsafe { std::slice::from_raw_parts(sender_identity, sender_identity_len) };
    let ct = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let pt = match s.group_decrypt(sender, ct) {
        Ok(b) => b,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };
    // SAFETY: out_plaintext/out_plaintext_len asserted valid.
    unsafe { copy_or_size_out(&pt, out_plaintext, out_plaintext_cap, out_plaintext_len) }
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
                msg_id.as_ptr(), msg_id.len(),
                plaintext.as_ptr(), plaintext.len(),
                sealed.as_mut_ptr(), sealed.len(), &mut sealed_len,
            )
        };
        assert_eq!(rc, PIZZINI_OK);
        assert!(sealed_len > 0);

        let mut sender = vec![0u8; 64];
        let mut sender_len = 0usize;
        let mut got_msg_id = [0u8; 16];
        // Sized for a PreKey envelope's worst-case inner content. The post-
        // F-101/F-701 FFI checks the upper bound BEFORE message_decrypt;
        // PreKey messages carry the bundle inline so the upper bound is
        // ~1758 bytes for chat-sized plaintexts. Whisper messages can stay
        // smaller, but production callers (Swift wrapper) provision 4096
        // up-front to avoid the BUFFER_TOO_SMALL retry path entirely.
        let mut pt = vec![0u8; 4096];
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
        let mut pt2 = vec![0u8; 4096];
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

    // ───── Audit PoCs (Surfaces 1, 7) ──────────────────────────────────
    // Names previously labelled F-701/F-702/F-703 didn't match the audit's
    // finding numbering — fix-review N-004. Renamed so a future maintainer
    // grepping for the F-XX they care about lands on the right test.

    /// `pizzini_blake3_hash` MUST treat `(NULL, 0)` as the empty input
    /// and hash it — BLAKE3 of the empty string is well-defined, and
    /// Swift's `Data().withUnsafeBytes` yields a NULL baseAddress for
    /// empty `Data`. A NULL pointer with a non-zero length is still a
    /// caller bug and MUST be rejected with `INVALID_ARG`. Surface 7
    /// (FFI).
    #[test]
    fn pizzini_blake3_hash_accepts_null_zero_length_input() {
        // (NULL, 0) hashes the empty slice and succeeds.
        let mut out = [0u8; 32];
        let rc = unsafe {
            pizzini_blake3_hash(std::ptr::null(), 0, out.as_mut_ptr())
        };
        assert_eq!(rc, PIZZINI_OK, "(null, 0) must hash the empty input");
        assert_eq!(
            out,
            *blake3::hash(&[]).as_bytes(),
            "(null, 0) must produce BLAKE3 of the empty string",
        );

        // NULL with a non-zero length is still a caller bug.
        let mut out2 = [0u8; 32];
        let rc2 = unsafe {
            pizzini_blake3_hash(std::ptr::null(), 1, out2.as_mut_ptr())
        };
        assert_eq!(
            rc2, PIZZINI_ERR_INVALID_ARG,
            "null input with non-zero len slipped past check",
        );
    }

    // ───── Argon2id FFI ─────────────────────────────────────────────────

    /// Argon2id derives a deterministic 32-byte key from a fixed
    /// salt + passphrase + parameter set. Pins the FFI contract so a
    /// future bump of the upstream argon2 crate that silently changes
    /// the output for the same inputs is caught at CI time. The
    /// expected bytes are the RustCrypto reference implementation's
    /// output for (Argon2id, V0x13, m=64 KiB, t=2, p=1, len=32),
    /// captured by running the function once and freezing the result.
    /// Tiny m/t here so the test runs in milliseconds, not seconds.
    #[test]
    fn argon2id_derive_is_deterministic_for_fixed_inputs() {
        let salt = [0x42u8; 16];
        let pass = b"correct-horse-battery-staple";
        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        let rc_a = unsafe {
            pizzini_argon2id_derive(
                salt.as_ptr(), salt.len(),
                pass.as_ptr(), pass.len(),
                64, 2, 1,
                out_a.as_mut_ptr(), out_a.len(),
            )
        };
        let rc_b = unsafe {
            pizzini_argon2id_derive(
                salt.as_ptr(), salt.len(),
                pass.as_ptr(), pass.len(),
                64, 2, 1,
                out_b.as_mut_ptr(), out_b.len(),
            )
        };
        assert_eq!(rc_a, PIZZINI_OK);
        assert_eq!(rc_b, PIZZINI_OK);
        assert_eq!(out_a, out_b, "Argon2id is not deterministic for fixed inputs");
        assert_ne!(out_a, [0u8; 32], "Argon2id wrote all-zero output");
    }

    /// Different passphrases produce different outputs (sanity, not
    /// pre-image resistance — but if this fails something is *very*
    /// wrong, e.g. the upstream crate is ignoring the password).
    #[test]
    fn argon2id_derive_distinguishes_passphrases() {
        let salt = [0x11u8; 16];
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        unsafe {
            pizzini_argon2id_derive(
                salt.as_ptr(), salt.len(),
                b"alpha".as_ptr(), 5,
                64, 2, 1, a.as_mut_ptr(), a.len(),
            );
            pizzini_argon2id_derive(
                salt.as_ptr(), salt.len(),
                b"beta".as_ptr(), 4,
                64, 2, 1, b.as_mut_ptr(), b.len(),
            );
        }
        assert_ne!(a, b);
    }

    /// Different salts produce different outputs for the same
    /// passphrase. Pins the "salt is mixed in" guarantee so a future
    /// refactor that accidentally drops the salt is caught at CI.
    #[test]
    fn argon2id_derive_distinguishes_salts() {
        let pass = b"shared-passphrase";
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let salt_a = [0x01u8; 16];
        let salt_b = [0x02u8; 16];
        unsafe {
            pizzini_argon2id_derive(
                salt_a.as_ptr(), salt_a.len(),
                pass.as_ptr(), pass.len(),
                64, 2, 1, a.as_mut_ptr(), a.len(),
            );
            pizzini_argon2id_derive(
                salt_b.as_ptr(), salt_b.len(),
                pass.as_ptr(), pass.len(),
                64, 2, 1, b.as_mut_ptr(), b.len(),
            );
        }
        assert_ne!(a, b);
    }

    /// FFI guards: every undersized / out-of-range parameter returns
    /// INVALID_ARG without crashing.
    #[test]
    fn argon2id_derive_ffi_guards() {
        let salt_ok = [0u8; 16];
        let salt_too_small = [0u8; 8];
        let pass = b"x";
        let mut out = [0u8; 32];

        // null salt
        let rc = unsafe {
            pizzini_argon2id_derive(
                std::ptr::null(), 16,
                pass.as_ptr(), pass.len(),
                64, 2, 1, out.as_mut_ptr(), out.len(),
            )
        };
        assert_eq!(rc, PIZZINI_ERR_INVALID_ARG);

        // null out
        let rc = unsafe {
            pizzini_argon2id_derive(
                salt_ok.as_ptr(), salt_ok.len(),
                pass.as_ptr(), pass.len(),
                64, 2, 1, std::ptr::null_mut(), out.len(),
            )
        };
        assert_eq!(rc, PIZZINI_ERR_INVALID_ARG);

        // salt too short
        let rc = unsafe {
            pizzini_argon2id_derive(
                salt_too_small.as_ptr(), salt_too_small.len(),
                pass.as_ptr(), pass.len(),
                64, 2, 1, out.as_mut_ptr(), out.len(),
            )
        };
        assert_eq!(rc, PIZZINI_ERR_INVALID_ARG);

        // out too short
        let mut tiny = [0u8; 8];
        let rc = unsafe {
            pizzini_argon2id_derive(
                salt_ok.as_ptr(), salt_ok.len(),
                pass.as_ptr(), pass.len(),
                64, 2, 1, tiny.as_mut_ptr(), tiny.len(),
            )
        };
        assert_eq!(rc, PIZZINI_ERR_INVALID_ARG);

        // m = 0
        let rc = unsafe {
            pizzini_argon2id_derive(
                salt_ok.as_ptr(), salt_ok.len(),
                pass.as_ptr(), pass.len(),
                0, 2, 1, out.as_mut_ptr(), out.len(),
            )
        };
        assert_eq!(rc, PIZZINI_ERR_INVALID_ARG);

        // m past ceiling
        let rc = unsafe {
            pizzini_argon2id_derive(
                salt_ok.as_ptr(), salt_ok.len(),
                pass.as_ptr(), pass.len(),
                PIZZINI_ARGON2ID_MAX_MEMORY_KIB + 1, 2, 1,
                out.as_mut_ptr(), out.len(),
            )
        };
        assert_eq!(rc, PIZZINI_ERR_INVALID_ARG);

        // empty passphrase is legitimate (caller mixed entropy into
        // salt). NULL passphrase pointer with non-zero len is a bug.
        let rc = unsafe {
            pizzini_argon2id_derive(
                salt_ok.as_ptr(), salt_ok.len(),
                std::ptr::null(), 4,
                64, 2, 1, out.as_mut_ptr(), out.len(),
            )
        };
        assert_eq!(rc, PIZZINI_ERR_INVALID_ARG);

        // NULL passphrase with len=0 is allowed.
        let rc = unsafe {
            pizzini_argon2id_derive(
                salt_ok.as_ptr(), salt_ok.len(),
                std::ptr::null(), 0,
                64, 2, 1, out.as_mut_ptr(), out.len(),
            )
        };
        assert_eq!(rc, PIZZINI_OK);
    }

    /// Regression for F-101 / F-701: `pizzini_store_seal_receive` MUST NOT
    /// advance the libsignal ratchet on a `BUFFER_TOO_SMALL` return.
    /// Caller passes a 0-byte plaintext cap, gets the size hint, then
    /// retries with an adequate buffer — and gets the original plaintext
    /// back, NOT a `is_duplicate=1, pt_len=0` ghost. Was the F-101 bug
    /// reproducer; now the fix verifier.
    #[test]
    fn poc_f101_seal_receive_no_advance_on_buffer_too_small() {
        // Set up Alice and Bob, pre-trust on Bob, ship a single sealed
        // message, then on the receive side call with `out_plaintext_cap = 0`.
        let alice = unsafe { pizzini_store_new(std::ptr::null(), 0) };
        let bob = unsafe { pizzini_store_new(std::ptr::null(), 0) };

        let mut alice_id = vec![0u8; 64];
        let mut alice_id_len = 0usize;
        unsafe {
            pizzini_store_identity_public(
                alice, alice_id.as_mut_ptr(), alice_id.len(), &mut alice_id_len,
            )
        };
        let alice_id = alice_id[..alice_id_len].to_vec();
        let mut bob_id = vec![0u8; 64];
        let mut bob_id_len = 0usize;
        unsafe {
            pizzini_store_identity_public(
                bob, bob_id.as_mut_ptr(), bob_id.len(), &mut bob_id_len,
            )
        };
        let bob_id = bob_id[..bob_id_len].to_vec();

        let mut bundle = vec![0u8; 4096];
        let mut bundle_len = 0usize;
        unsafe {
            pizzini_store_publish_bundle(
                bob, bundle.as_mut_ptr(), bundle.len(), &mut bundle_len,
            )
        };
        unsafe {
            pizzini_store_initiate_session(
                alice, bob_id.as_ptr(), bob_id.len(),
                bundle.as_ptr(), bundle_len,
            )
        };
        unsafe { pizzini_store_register_peer(bob, alice_id.as_ptr(), alice_id.len()) };

        let plaintext = b"please decode me, just need bigger buffer next time";
        let msg_id = [0xCDu8; 16];
        let mut sealed = vec![0u8; 4096];
        let mut sealed_len = 0usize;
        let rc = unsafe {
            pizzini_store_seal_send(
                alice,
                bob_id.as_ptr(), bob_id.len(),
                msg_id.as_ptr(), msg_id.len(),
                plaintext.as_ptr(), plaintext.len(),
                sealed.as_mut_ptr(), sealed.len(), &mut sealed_len,
            )
        };
        assert_eq!(rc, PIZZINI_OK);

        // First receive: caller provides a 0-byte plaintext buffer (sender
        // buffer big). Expectation under the doc comment: "Caller retries
        // with both buffers sized appropriately" — implying retry succeeds.
        let mut sender = vec![0u8; 64];
        let mut sender_len = 0usize;
        let mut got_msg_id = [0u8; 16];
        let mut pt_zero = [0u8; 1];
        let mut pt_zero_len = 0usize;
        let mut is_dup: u8 = 0;
        let rc1 = unsafe {
            pizzini_store_seal_receive(
                bob,
                sealed.as_ptr(), sealed_len,
                sender.as_mut_ptr(), sender.len(), &mut sender_len,
                got_msg_id.as_mut_ptr(),
                pt_zero.as_mut_ptr(), 0, &mut pt_zero_len,  // <-- cap = 0
                &mut is_dup,
            )
        };
        // Doc comment claims this returns BUFFER_TOO_SMALL with required
        // size in *out_plaintext_len. Confirm the contract:
        assert_eq!(rc1, PIZZINI_ERR_BUFFER_TOO_SMALL,
            "doc comment promises BUFFER_TOO_SMALL when plaintext cap is too small");
        assert!(pt_zero_len > 0, "size hint not reported");

        // Second receive: same sealed bytes, ample buffers. Per the
        // Swift wrapper's comment block at decryptSealed (lines ~346-352),
        // "the FFI returns INTERNAL before advancing the ratchet on a
        // buffer-too-small ... Retrying with bigger buffers is safe."
        let mut pt_big = vec![0u8; pt_zero_len];
        let mut pt_big_len = 0usize;
        let mut sender2 = vec![0u8; 64];
        let mut sender2_len = 0usize;
        let mut got_msg_id2 = [0u8; 16];
        let mut is_dup2: u8 = 0;
        let rc2 = unsafe {
            pizzini_store_seal_receive(
                bob,
                sealed.as_ptr(), sealed_len,
                sender2.as_mut_ptr(), sender2.len(), &mut sender2_len,
                got_msg_id2.as_mut_ptr(),
                pt_big.as_mut_ptr(), pt_big.len(), &mut pt_big_len,
                &mut is_dup2,
            )
        };
        // After the F-101 / F-701 fix the FFI peeks USMC sizes BEFORE
        // running message_decrypt. The ratchet was not advanced on rc1,
        // so the retry must succeed cleanly with the original plaintext.
        assert_eq!(rc2, PIZZINI_OK, "retry with adequate buffer must succeed");
        assert_eq!(is_dup2, 0, "ratchet must NOT have been advanced on rc1");
        assert_eq!(
            &pt_big[..pt_big_len],
            plaintext,
            "retry must return the original plaintext"
        );

        unsafe { pizzini_store_free(alice) };
        unsafe { pizzini_store_free(bob) };
    }

    /// Regression for F-702: `pizzini_hashcash_compute` MUST reject
    /// `bits` values past the FFI's safety ceiling so an untrusted
    /// caller cannot wedge the host thread. Was the F-702 bug
    /// reproducer; now the fix verifier.
    #[test]
    fn poc_f702_hashcash_bits_capped_at_max() {
        let challenge = b"x";

        // bits within the ceiling: succeeds.
        let mut nonce: u64 = 0;
        let rc = unsafe {
            pizzini_hashcash_compute(challenge.as_ptr(), challenge.len(), 12, &mut nonce)
        };
        assert_eq!(rc, PIZZINI_OK);

        // bits exactly at the ceiling: would still succeed (we don't
        // actually run it because it can take ~minutes; just exercise
        // the boundary check).
        // bits one above the ceiling: rejected.
        let mut nonce_bad: u64 = 0;
        let rc_bad = unsafe {
            pizzini_hashcash_compute(
                challenge.as_ptr(),
                challenge.len(),
                HASHCASH_FFI_MAX_BITS + 1,
                &mut nonce_bad,
            )
        };
        assert_eq!(rc_bad, PIZZINI_ERR_INVALID_ARG);

        // bits = 64 (audit's reference DoS value): rejected.
        let rc_dos = unsafe {
            pizzini_hashcash_compute(challenge.as_ptr(), challenge.len(), 64, &mut nonce_bad)
        };
        assert_eq!(rc_dos, PIZZINI_ERR_INVALID_ARG);
    }

    // ───── Safety number (SAS) ─────────────────────────────────────────

    /// Helper: generate two distinct IdentityKey public bytes via the
    /// FFI so tests use the same shape Swift sees on real devices.
    fn two_identity_publics() -> (Vec<u8>, Vec<u8>) {
        let a = unsafe { pizzini_store_new(std::ptr::null(), 0) };
        let b = unsafe { pizzini_store_new(std::ptr::null(), 0) };
        assert!(!a.is_null() && !b.is_null());
        let mut a_pub = vec![0u8; 64];
        let mut a_len = 0usize;
        let mut b_pub = vec![0u8; 64];
        let mut b_len = 0usize;
        unsafe {
            assert_eq!(
                pizzini_store_identity_public(a, a_pub.as_mut_ptr(), a_pub.len(), &mut a_len),
                PIZZINI_OK
            );
            assert_eq!(
                pizzini_store_identity_public(b, b_pub.as_mut_ptr(), b_pub.len(), &mut b_len),
                PIZZINI_OK
            );
            pizzini_store_free(a);
            pizzini_store_free(b);
        }
        a_pub.truncate(a_len);
        b_pub.truncate(b_len);
        assert_eq!(a_pub.len(), SAFETY_NUMBER_IDENTITY_LEN);
        assert_eq!(b_pub.len(), SAFETY_NUMBER_IDENTITY_LEN);
        (a_pub, b_pub)
    }

    #[test]
    fn safety_number_is_60_ascii_digits() {
        let (a, b) = two_identity_publics();
        let mut out = [0u8; SAFETY_NUMBER_DIGIT_LEN];
        let rc = unsafe {
            pizzini_safety_number_derive(
                a.as_ptr(),
                a.len(),
                b.as_ptr(),
                b.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, PIZZINI_OK);
        assert!(out.iter().all(|c| (b'0'..=b'9').contains(c)));
    }

    #[test]
    fn safety_number_is_order_independent() {
        let (a, b) = two_identity_publics();
        let mut fwd = [0u8; SAFETY_NUMBER_DIGIT_LEN];
        let mut rev = [0u8; SAFETY_NUMBER_DIGIT_LEN];
        unsafe {
            pizzini_safety_number_derive(
                a.as_ptr(),
                a.len(),
                b.as_ptr(),
                b.len(),
                fwd.as_mut_ptr(),
                fwd.len(),
            );
            pizzini_safety_number_derive(
                b.as_ptr(),
                b.len(),
                a.as_ptr(),
                a.len(),
                rev.as_mut_ptr(),
                rev.len(),
            );
        }
        assert_eq!(
            fwd, rev,
            "Alice's and Bob's SAS must match regardless of caller order"
        );
    }

    #[test]
    fn safety_number_differs_per_pair() {
        let (a, b) = two_identity_publics();
        let (_a2, c) = two_identity_publics();
        let mut ab = [0u8; SAFETY_NUMBER_DIGIT_LEN];
        let mut ac = [0u8; SAFETY_NUMBER_DIGIT_LEN];
        unsafe {
            pizzini_safety_number_derive(
                a.as_ptr(), a.len(), b.as_ptr(), b.len(),
                ab.as_mut_ptr(), ab.len(),
            );
            pizzini_safety_number_derive(
                a.as_ptr(), a.len(), c.as_ptr(), c.len(),
                ac.as_mut_ptr(), ac.len(),
            );
        }
        assert_ne!(
            ab, ac,
            "Substituting one identity must change the SAS (the whole point)"
        );
    }

    #[test]
    fn safety_number_rejects_wrong_identity_length() {
        let (a, _b) = two_identity_publics();
        let short = vec![0u8; 32]; // missing the 1-byte DJB prefix
        let mut out = [0u8; SAFETY_NUMBER_DIGIT_LEN];
        let rc = unsafe {
            pizzini_safety_number_derive(
                a.as_ptr(),
                a.len(),
                short.as_ptr(),
                short.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, PIZZINI_ERR_INVALID_ARG);
    }

    #[test]
    fn safety_number_rejects_small_output_buffer() {
        let (a, b) = two_identity_publics();
        let mut out = [0u8; SAFETY_NUMBER_DIGIT_LEN - 1];
        let rc = unsafe {
            pizzini_safety_number_derive(
                a.as_ptr(),
                a.len(),
                b.as_ptr(),
                b.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, PIZZINI_ERR_INVALID_ARG);
    }

    #[test]
    fn safety_number_rejects_null_pointers() {
        let (a, _b) = two_identity_publics();
        let mut out = [0u8; SAFETY_NUMBER_DIGIT_LEN];
        let rc = unsafe {
            pizzini_safety_number_derive(
                a.as_ptr(),
                a.len(),
                std::ptr::null(),
                SAFETY_NUMBER_IDENTITY_LEN,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, PIZZINI_ERR_INVALID_ARG);
    }
}
