//! BLAKE3 hashcash. Used as a first-contact PoW on BUNDLE_REQUEST so
//! a recipient cannot be DoS'd into a bundle exchange by anyone who
//! merely scanned their peer-id (the sender has no delivery token yet
//! at first contact, so the recipient's per-pair token gate doesn't
//! apply). The relay verifies this proof before forwarding the bundle.
//!
//! Pure BLAKE3 — no Equi-X — is a deliberate scope decision: for our
//! threat model (state-level adversary, but DoS specifically against
//! bundle exchange is a low-rate event), ASIC resistance is mostly
//! academic. Equi-X would add a non-libsignal C dep and pin a separate
//! audited primitive. BLAKE3 is already in our reproducible-build
//! manifest as a transitive dep.
//!
//! Difficulty: 18 leading zero bits ≈ 1 second of CPU on a modern
//! phone. Verifier cost: a single BLAKE3 hash, sub-microsecond.

/// Default hashcash difficulty in leading-zero bits. F-NEW-209:
/// raised from 18 → 22. Phone-side cost stays under ~1s on the
/// slowest A14-class device. A desktop-GPU attacker drops from
/// ~190 k proofs/s (at 18 bits) to ~12 proofs/s (at 22 bits) on a
/// RTX 4090 — still trivially defeats hashcash as the sole gate,
/// but the proper defense (per-recipient rate-limit on
/// BUNDLE_REQUEST at the relay) is the architectural fix. Stays
/// well under `HASHCASH_FFI_MAX_BITS = 26` so the FFI cap (F-702)
/// is unchanged.
pub const HASHCASH_DEFAULT_BITS: u32 = 22;

/// Brute-force a u64 nonce such that
/// `BLAKE3(challenge || nonce_be) starts with at least `bits` leading
/// zero bits`. Returns the first nonce that satisfies the constraint.
///
/// `challenge` is whatever input ties the proof to the verifier's
/// expectation — for our BUNDLE_REQUEST PoW this is
/// `BLAKE3(recipient_peer_id || floor(unix_time/3600))`.
pub fn hashcash_compute(challenge: &[u8], bits: u32) -> u64 {
    let mut nonce: u64 = 0;
    loop {
        if hashcash_verify(challenge, nonce, bits) {
            return nonce;
        }
        // wrapping_add so a malicious caller passing impossibly-high
        // bits doesn't loop forever undetected — the host-side prover
        // gates this externally on a wall-clock budget.
        nonce = nonce.wrapping_add(1);
    }
}

/// Verify that `BLAKE3(challenge || nonce_be)` has at least `bits`
/// leading zero bits.
pub fn hashcash_verify(challenge: &[u8], nonce: u64, bits: u32) -> bool {
    let mut hasher = blake3::Hasher::new();
    hasher.update(challenge);
    hasher.update(&nonce.to_be_bytes());
    let hash = hasher.finalize();
    leading_zero_bits(hash.as_bytes()) >= bits
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_at_easy_difficulty() {
        let challenge = b"pizzini-test-challenge";
        let nonce = hashcash_compute(challenge, 8);
        assert!(hashcash_verify(challenge, nonce, 8));
    }

    #[test]
    fn rejects_wrong_nonce() {
        let challenge = b"pizzini-test-challenge";
        let nonce = hashcash_compute(challenge, 8);
        assert!(!hashcash_verify(challenge, nonce.wrapping_add(1), 8));
    }

    #[test]
    fn rejects_at_higher_bits_than_proven() {
        let challenge = b"pizzini-test-challenge";
        let nonce = hashcash_compute(challenge, 4);
        // 4-bit proof shouldn't pass a 24-bit check.
        assert!(!hashcash_verify(challenge, nonce, 24));
    }

    #[test]
    fn leading_zeros_helper_handles_all_zero_prefix() {
        assert_eq!(leading_zero_bits(&[0, 0, 0xff]), 16);
        assert_eq!(leading_zero_bits(&[0, 0x80]), 8);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
    }
}
