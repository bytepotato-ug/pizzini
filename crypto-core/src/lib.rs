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

mod loopback;
pub use loopback::{LoopbackState, RoundtripResult};

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

// ───── Loopback session (Alice ↔ Bob in one process) ───────────────────
//
// Opaque pointer pattern: Rust owns the LoopbackState; Swift holds the raw
// pointer and calls back into Rust. Free with pizzini_loopback_free.

/// Creates a new in-process loopback session. Returns a non-null opaque
/// handle, or null on internal error. Caller must release with
/// `pizzini_loopback_free`.
#[no_mangle]
pub extern "C" fn pizzini_loopback_new() -> *mut LoopbackState {
    match LoopbackState::new() {
        Ok(s) => Box::into_raw(Box::new(s)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Releases a loopback handle. Safe to call with null.
///
/// # Safety
/// `state` must be a pointer previously returned by `pizzini_loopback_new`,
/// and not yet freed. Passing any other pointer is undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn pizzini_loopback_free(state: *mut LoopbackState) {
    if !state.is_null() {
        // SAFETY: caller asserted this came from Box::into_raw above.
        unsafe { drop(Box::from_raw(state)) };
    }
}

/// Sends `plaintext` from Alice to Bob: encrypts, decrypts, and returns both
/// the wire-format ciphertext and Bob's recovered plaintext along with the
/// CiphertextMessageType (PIZZINI_MSG_TYPE_PREKEY or _WHISPER).
///
/// On `PIZZINI_ERR_BUFFER_TOO_SMALL`, the corresponding `*out_len` is set to
/// the required size; the other output's `*out_len` is unspecified. Caller
/// should retry with a buffer at least that large. Recommended caps:
///   - ciphertext: 4096 bytes (covers Kyber1024 PreKey messages comfortably)
///   - decrypted:  plaintext_len + 256
///
/// # Safety
/// All pointers must be non-null and point to memory of the declared sizes.
/// `state` must be a live handle from `pizzini_loopback_new`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_loopback_alice_send(
    state: *mut LoopbackState,
    plaintext: *const u8,
    plaintext_len: usize,
    out_ciphertext: *mut u8,
    out_ciphertext_cap: usize,
    out_ciphertext_len: *mut usize,
    out_decrypted: *mut u8,
    out_decrypted_cap: usize,
    out_decrypted_len: *mut usize,
    out_message_type: *mut u32,
) -> i32 {
    // SAFETY: caller is responsible for non-null + correctly sized pointers.
    unsafe {
        loopback_send(
            state,
            plaintext,
            plaintext_len,
            out_ciphertext,
            out_ciphertext_cap,
            out_ciphertext_len,
            out_decrypted,
            out_decrypted_cap,
            out_decrypted_len,
            out_message_type,
            Direction::AliceToBob,
        )
    }
}

/// Sends `plaintext` from Bob to Alice. Mirror of `pizzini_loopback_alice_send`.
///
/// # Safety
/// Same as `pizzini_loopback_alice_send`.
#[no_mangle]
pub unsafe extern "C" fn pizzini_loopback_bob_send(
    state: *mut LoopbackState,
    plaintext: *const u8,
    plaintext_len: usize,
    out_ciphertext: *mut u8,
    out_ciphertext_cap: usize,
    out_ciphertext_len: *mut usize,
    out_decrypted: *mut u8,
    out_decrypted_cap: usize,
    out_decrypted_len: *mut usize,
    out_message_type: *mut u32,
) -> i32 {
    // SAFETY: see pizzini_loopback_alice_send.
    unsafe {
        loopback_send(
            state,
            plaintext,
            plaintext_len,
            out_ciphertext,
            out_ciphertext_cap,
            out_ciphertext_len,
            out_decrypted,
            out_decrypted_cap,
            out_decrypted_len,
            out_message_type,
            Direction::BobToAlice,
        )
    }
}

#[derive(Copy, Clone)]
enum Direction {
    AliceToBob,
    BobToAlice,
}

#[allow(clippy::too_many_arguments)]
unsafe fn loopback_send(
    state: *mut LoopbackState,
    plaintext: *const u8,
    plaintext_len: usize,
    out_ciphertext: *mut u8,
    out_ciphertext_cap: usize,
    out_ciphertext_len: *mut usize,
    out_decrypted: *mut u8,
    out_decrypted_cap: usize,
    out_decrypted_len: *mut usize,
    out_message_type: *mut u32,
    dir: Direction,
) -> i32 {
    if state.is_null()
        || plaintext.is_null()
        || out_ciphertext.is_null()
        || out_ciphertext_len.is_null()
        || out_decrypted.is_null()
        || out_decrypted_len.is_null()
        || out_message_type.is_null()
    {
        return PIZZINI_ERR_INVALID_ARG;
    }

    // SAFETY: caller asserted state points to a valid LoopbackState owned by Rust.
    let state = unsafe { &mut *state };
    // SAFETY: caller asserted plaintext/plaintext_len describe a valid slice.
    let plain = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };

    let result = match dir {
        Direction::AliceToBob => state.alice_send(plain),
        Direction::BobToAlice => state.bob_send(plain),
    };
    let result = match result {
        Ok(r) => r,
        Err(_) => return PIZZINI_ERR_INTERNAL,
    };

    if result.ciphertext.len() > out_ciphertext_cap {
        // SAFETY: caller asserted out_ciphertext_len is valid.
        unsafe { *out_ciphertext_len = result.ciphertext.len() };
        return PIZZINI_ERR_BUFFER_TOO_SMALL;
    }
    if result.decrypted.len() > out_decrypted_cap {
        // SAFETY: caller asserted out_decrypted_len is valid.
        unsafe { *out_decrypted_len = result.decrypted.len() };
        return PIZZINI_ERR_BUFFER_TOO_SMALL;
    }

    // SAFETY: caps verified above; output pointers asserted valid.
    unsafe {
        std::ptr::copy_nonoverlapping(
            result.ciphertext.as_ptr(),
            out_ciphertext,
            result.ciphertext.len(),
        );
        *out_ciphertext_len = result.ciphertext.len();
        std::ptr::copy_nonoverlapping(
            result.decrypted.as_ptr(),
            out_decrypted,
            result.decrypted.len(),
        );
        *out_decrypted_len = result.decrypted.len();
        *out_message_type = if result.is_prekey {
            PIZZINI_MSG_TYPE_PREKEY
        } else {
            PIZZINI_MSG_TYPE_WHISPER
        };
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
    fn loopback_ffi_round_trip() {
        let h = pizzini_loopback_new();
        assert!(!h.is_null());

        let plain = b"hello from FFI";
        let mut ct = vec![0u8; 4096];
        let mut ct_len = 0usize;
        let mut pt = vec![0u8; 256];
        let mut pt_len = 0usize;
        let mut msg_type: u32 = 999;

        let rc = unsafe {
            pizzini_loopback_alice_send(
                h,
                plain.as_ptr(),
                plain.len(),
                ct.as_mut_ptr(),
                ct.len(),
                &mut ct_len,
                pt.as_mut_ptr(),
                pt.len(),
                &mut pt_len,
                &mut msg_type,
            )
        };
        assert_eq!(rc, PIZZINI_OK);
        assert!(ct_len > 0);
        assert_eq!(&pt[..pt_len], plain);
        assert_eq!(msg_type, PIZZINI_MSG_TYPE_PREKEY);

        unsafe { pizzini_loopback_free(h) };
    }
}
