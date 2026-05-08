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

// ───── Error codes ─────────────────────────────────────────────────────
//
// Negative values denote errors; zero is success. Values are stable —
// they are part of the FFI contract.

pub const PIZZINI_OK: i32 = 0;
pub const PIZZINI_ERR_INVALID_ARG: i32 = -1;
pub const PIZZINI_ERR_BUFFER_TOO_SMALL: i32 = -2;

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

        // Round-trip via libsignal: bytes we wrote must deserialize, then re-serialize
        // to the same bytes.
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
}
