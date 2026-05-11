//! Shared primitives for the relay's encrypted-at-rest persistent
//! stores (`push_token_store`, `pending_store`, and any future
//! additions).
//!
//! Three small but load-bearing capabilities:
//!
//!   1. **Sibling key file management** — `load_or_create_key` reads
//!      a 32-byte ChaCha20-Poly1305 key from disk, or generates +
//!      writes a fresh one with `0600` perms on first run. Idempotent.
//!   2. **AEAD envelope** — `encrypt` / `decrypt` wrap the actual
//!      crypto with a `[12-byte nonce || ciphertext + Poly1305 tag]`
//!      layout. Random nonce per write; the 96-bit nonce space is
//!      safe well past any realistic write count for the relay's
//!      single-digit-user scale.
//!   3. **Atomic file replacement** — `write_atomic` writes to a
//!      `<path>.tmp` sibling then renames over the canonical path,
//!      so a crash mid-write can't corrupt the prior good state.
//!      Permissions on the temp file are tightened to `0600` before
//!      the rename so the canonical path inherits the strict mode.
//!
//! Threat-model framing for the stores using this layer: the
//! encryption defends against accidental disclosure — careless
//! rsync/tarball/container-image picking up only the encrypted file
//! and not the sibling key, accidental `git add` of the state dir,
//! backups that include the encrypted blob but not the key. It does
//! NOT defend against an attacker who has the relay machine in hand;
//! both files are co-located, so anyone reading the disk can
//! decrypt. App-layer encryption with on-disk keys against same-
//! machine compromise would be theatre. We document the boundary
//! rather than pretend.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Length of the AEAD key in bytes (ChaCha20-Poly1305: 256-bit key).
pub const KEY_LEN: usize = 32;

/// Length of the AEAD nonce in bytes (ChaCha20-Poly1305: 96-bit
/// random per-write nonce).
pub const NONCE_LEN: usize = 12;

/// Load the 32-byte AEAD key from `key_path`, or generate + persist a
/// fresh one on first run. The key file's permissions are tightened
/// to `0600` immediately after write so a generous umask can't leak
/// it to other local users.
///
/// `kind_for_error` is a short human-readable name used only in the
/// "wrong length" error message — `"push-token"`, `"pending"`, etc.
/// Helps the operator localise which file is corrupt when staring at
/// the log line.
pub fn load_or_create_key(key_path: &Path, kind_for_error: &str) -> io::Result<[u8; KEY_LEN]> {
    match fs::read(key_path) {
        Ok(bytes) => {
            if bytes.len() != KEY_LEN {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "{kind_for_error} key file {} has wrong length: {} (expected {})",
                        key_path.display(),
                        bytes.len(),
                        KEY_LEN,
                    ),
                ));
            }
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let key = ChaCha20Poly1305::generate_key(&mut OsRng);
            let mut out = [0u8; KEY_LEN];
            out.copy_from_slice(key.as_slice());
            write_atomic(key_path, &out)?;
            Ok(out)
        }
        Err(e) => Err(e),
    }
}

/// Encrypt `plaintext` to a `[12-byte nonce || ciphertext + tag]`
/// envelope using ChaCha20-Poly1305 with a fresh random nonce per
/// call. Random nonces are safe well past any realistic write count
/// for this relay's scale (birthday bound on a 96-bit nonce is
/// ~2^48 writes — single-digit-user persistence will never hit that).
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| io::Error::other("ChaCha20-Poly1305 encrypt failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a `[12-byte nonce || ciphertext + tag]` envelope produced
/// by `encrypt`. Returns the plaintext or an `io::Error` if the
/// envelope is truncated, the tag doesn't verify (wrong key /
/// tampered file), or the AEAD primitive fails.
pub fn decrypt(key: &[u8; KEY_LEN], bytes: &[u8]) -> io::Result<Vec<u8>> {
    if bytes.len() < NONCE_LEN {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "encrypted file truncated before nonce",
        ));
    }
    let (nonce_bytes, ct) = bytes.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce_bytes), ct).map_err(|_| {
        io::Error::other(
            "encrypted file failed to decrypt — wrong key file, or file tampered with",
        )
    })
}

/// Write `bytes` to `path` atomically: write to `<path>.tmp`, fsync,
/// chmod 0600, rename. A crash anywhere before the rename leaves the
/// prior canonical file intact; the rename itself is atomic on POSIX
/// (and on macOS APFS / Linux ext4 / btrfs / xfs).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension(
        format!(
            "{}.tmp",
            path.extension()
                .and_then(|s| s.to_str())
                .unwrap_or("tmp"),
        ),
    );
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    restrict_permissions(&tmp, 0o600);
    fs::rename(&tmp, path)?;
    Ok(())
}

/// chmod helper. POSIX-only — on Windows / other non-Unix this is a
/// no-op (silently). The `set_permissions` call is best-effort: a
/// host that refuses (e.g. exotic filesystem) still gets correctness
/// from the persistence; the belt-and-braces is missing.
#[cfg(unix)]
pub fn restrict_permissions(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(mode)) {
        eprintln!(
            "[pizzini-relay] warn: could not chmod {}: {e}",
            path.display()
        );
    }
}

#[cfg(not(unix))]
pub fn restrict_permissions(_path: &Path, _mode: u32) {}

/// Wall-clock unix seconds. Used by stores for TTL / last-refreshed
/// timestamps that need to survive serialization (unlike `Instant`,
/// which is monotonic-process-local and not serialisable).
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ----- tiny hex helpers ------------------------------------------------
//
// Used by the JSON inner-representation of stores so binary fields
// (peer-ids, tokens, sealed envelopes) survive a JSON round-trip
// without pulling in a separate hex crate just for these helpers.

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [0xAAu8; KEY_LEN];
        let plaintext = b"hello world".to_vec();
        let ct = encrypt(&key, &plaintext).unwrap();
        let pt = decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext);
        // Each call uses a fresh nonce → ciphertexts must differ.
        let ct2 = encrypt(&key, &plaintext).unwrap();
        assert_ne!(ct, ct2);
        assert_eq!(decrypt(&key, &ct2).unwrap(), plaintext);
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let key = [0xAAu8; KEY_LEN];
        let wrong = [0xBBu8; KEY_LEN];
        let ct = encrypt(&key, b"secret").unwrap();
        assert!(decrypt(&wrong, &ct).is_err());
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = [0xAAu8; KEY_LEN];
        let mut ct = encrypt(&key, b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt(&key, &ct).is_err());
    }

    #[test]
    fn decrypt_rejects_truncated() {
        // Less than NONCE_LEN — should error cleanly, not panic.
        assert!(decrypt(&[0u8; KEY_LEN], &[0u8; 5]).is_err());
    }

    #[test]
    fn hex_round_trip() {
        let inputs: &[&[u8]] = &[
            b"",
            b"\x00",
            b"\xff",
            b"\x00\x01\x02\x7f\x80\xff",
            &[0xde, 0xad, 0xbe, 0xef],
        ];
        for &input in inputs {
            let hex = hex_encode(input);
            assert_eq!(hex_decode(&hex).unwrap().as_slice(), input);
        }
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
    }
}
