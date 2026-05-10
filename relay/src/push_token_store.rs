//! Persistent push-token store.
//!
//! The relay's primary trust posture is "minimise forensic surface" —
//! every other in-memory map (`routes`, `pending`, `verify_keys`,
//! `replays`, `hello_replays`) is deliberately wiped on restart. Push
//! tokens are the one piece of state where that posture costs the user
//! something tangible: when the relay restarts, every paired device
//! loses push delivery until the iOS app foregrounds and re-publishes
//! its APNs token. In practice this means push silently breaks for
//! days at a time after any operational event (deploy, reboot,
//! cargo-run-after-pull) — and a user who relies on push to know they
//! have a new message would have no signal that anything went wrong.
//!
//! This module gives push tokens persistence across restarts, with
//! three guard-rails baked in to keep the privacy trade-off honest:
//!
//!   1. **Encryption at rest.** The on-disk file is a ChaCha20-
//!      Poly1305 envelope over the JSON inner state, keyed by 32
//!      random bytes generated on first run and stored in a sibling
//!      file. The realistic threat this defends against is *accidental
//!      exposure*: a tarball, an rsync, a container image build, a
//!      careless `cp -r state-dir/` that picks up the encrypted file
//!      but not the key. It does NOT defend against an attacker who
//!      has the relay machine in hand — both files are co-located, so
//!      anyone who can read the disk can decrypt. That's not a defect;
//!      app-layer encryption against same-machine compromise is
//!      theatre. We document the boundary instead of pretending.
//!   2. **Restrictive POSIX permissions.** State directory is `0700`,
//!      both files are `0600`. Best-effort: a non-POSIX host (Windows)
//!      just logs a warning and continues — the persistence still
//!      works, only the permission belt is missing.
//!   3. **TTL purge.** Every entry carries `last_refreshed_unix`.
//!      Entries older than `MAX_TOKEN_AGE` (30 days) are dropped on
//!      load. A device that hasn't foregrounded its app in a month
//!      almost certainly has a stale token anyway (APNs rotates them
//!      eventually); the bounded retention keeps the persistent map
//!      from drifting indefinitely.
//!
//! On every TOKEN_REGISTER frame the store is updated and the file is
//! atomically rewritten (write-to-temp + rename). That's heavier than
//! the previous "HashMap insert" path, but TOKEN_REGISTER is a
//! once-per-app-foreground event — not on the hot send path — so the
//! cost is amortised away.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default state directory if `PIZZINI_RELAY_STATE_DIR` is unset. A
/// relative path — created in the relay process's current working
/// directory on first run. Operators who care can set the env var
/// to a path outside the repo / outside the container's writable
/// volume.
pub const DEFAULT_STATE_DIR: &str = "./pizzini-relay-state";

const TOKENS_FILE_NAME: &str = "push_tokens.bin";
const KEY_FILE_NAME: &str = "push_tokens.key";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// Maximum time we'll keep a token alive without a refresh.
/// 30 days picked to be longer than typical APNs token-rotation
/// cadence (Apple doesn't publish a number, but device tokens are
/// stable for weeks to months under normal use) and short enough
/// that an abandoned device's token doesn't sit in the file
/// indefinitely. Re-evaluated on every load; entries are only ever
/// dropped, never resurrected.
pub const MAX_TOKEN_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// One entry in the persistent map: the APNs device token plus the
/// unix timestamp of the most recent TOKEN_REGISTER. Timestamp drives
/// the TTL purge on next load; without it a token that the device
/// has long since rotated would sit in the store forever.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    /// Hex-encoded APNs token. JSON-safe; the inline `hex_encode` /
    /// `hex_decode` helpers below avoid pulling in a hex crate.
    token_hex: String,
    last_refreshed_unix: u64,
}

/// Inner JSON document. A single `entries` map keyed by hex-encoded
/// peer-id so the file is human-inspectable during dev — encryption
/// in-flight to the disk is the secrecy mechanism, JSON readability
/// is for the operator's debugging convenience.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct StoreDoc {
    entries: HashMap<String, StoredEntry>,
}

/// The persistent push-token store. Owns the path the encrypted file
/// lives at, the in-memory decrypted map, and the encryption key.
///
/// Constructed by `load_or_create`; every mutator persists
/// synchronously (atomic rename) so a crash mid-write can never
/// leave the on-disk state inconsistent with what the relay thinks
/// it has. Lookups are zero-I/O — just a HashMap probe.
pub struct PushTokenStore {
    tokens_path: PathBuf,
    key: [u8; KEY_LEN],
    map: HashMap<Vec<u8>, (Vec<u8>, u64)>,
}

// Manual `Debug` rather than `#[derive]` — a derived impl would print
// the raw encryption key inside any `dbg!(&store)` or
// `eprintln!("{store:?}")` call site, which would leak it through
// stdout/stderr into journalctl / Console.app / whatever logging
// pipeline the operator has set up. The redacted form here keeps
// `Result::unwrap_err` (used in unit tests) compiling without
// turning every future log line into a key-exposure hazard.
impl std::fmt::Debug for PushTokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushTokenStore")
            .field("tokens_path", &self.tokens_path)
            .field("key", &"[redacted 32 bytes]")
            .field("entries", &self.map.len())
            .finish()
    }
}

impl PushTokenStore {
    /// Resolve the state directory from `PIZZINI_RELAY_STATE_DIR`
    /// (or `DEFAULT_STATE_DIR` if unset). Used by `main.rs` to pass
    /// to `load_or_create` and to print a startup line so the
    /// operator can see exactly where state is being written.
    pub fn resolve_state_dir() -> PathBuf {
        match std::env::var_os("PIZZINI_RELAY_STATE_DIR") {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => PathBuf::from(DEFAULT_STATE_DIR),
        }
    }

    /// Load the store from `state_dir`, or create an empty one if the
    /// files don't exist yet. Creates `state_dir` if missing.
    /// Performs the TTL purge on load — entries past `MAX_TOKEN_AGE`
    /// since their last refresh are dropped silently.
    ///
    /// Fails (returns an `io::Error`) if the files exist but are
    /// corrupt / unreadable / decrypt-fails — refusing to start is the
    /// right call there: continuing with an empty map after a partial
    /// failure could silently break push for every paired device.
    pub fn load_or_create(state_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(state_dir)?;
        restrict_permissions(state_dir, 0o700);
        let tokens_path = state_dir.join(TOKENS_FILE_NAME);
        let key_path = state_dir.join(KEY_FILE_NAME);

        let key = load_or_create_key(&key_path)?;

        let map: HashMap<Vec<u8>, (Vec<u8>, u64)> = match fs::read(&tokens_path) {
            Ok(bytes) => decrypt_and_load(&bytes, &key, MAX_TOKEN_AGE)?,
            Err(e) if e.kind() == ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };

        Ok(PushTokenStore {
            tokens_path,
            key,
            map,
        })
    }

    /// Total live entries. Used by main.rs at startup to log "loaded
    /// N tokens" so the operator can see the persistence is working.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Insert / update an entry for `peer_id` and persist. The
    /// timestamp is captured from the system clock at call time
    /// (not from the wire frame — peers shouldn't be able to set
    /// `last_refreshed` retroactively to extend their own retention).
    pub fn insert(&mut self, peer_id: Vec<u8>, token: Vec<u8>) -> io::Result<()> {
        let now = unix_now();
        self.map.insert(peer_id, (token, now));
        self.persist()
    }

    /// Look up a token by peer-id. Returns a cloned `Vec<u8>` because
    /// the relay's send-push path needs an owned copy to hand to the
    /// APNs client running on a different task — a borrow tied to
    /// the store's lock would force us to hold the lock across the
    /// HTTP round-trip.
    pub fn get_cloned(&self, peer_id: &[u8]) -> Option<Vec<u8>> {
        self.map.get(peer_id).map(|(token, _)| token.clone())
    }

    /// Serialize the in-memory map, encrypt, and atomically replace
    /// the file. Uses write-to-temp + rename so a crash mid-write
    /// can never corrupt the canonical file — the rename is the
    /// commit point.
    fn persist(&self) -> io::Result<()> {
        let mut doc = StoreDoc::default();
        for (peer_id, (token, ts)) in &self.map {
            doc.entries.insert(
                hex_encode(peer_id),
                StoredEntry {
                    token_hex: hex_encode(token),
                    last_refreshed_unix: *ts,
                },
            );
        }
        let plaintext = serde_json::to_vec(&doc).map_err(io::Error::other)?;
        let ciphertext = encrypt(&self.key, &plaintext)?;

        let tmp_path = self.tokens_path.with_extension("bin.tmp");
        {
            let mut f = fs::File::create(&tmp_path)?;
            f.write_all(&ciphertext)?;
            f.sync_all()?;
        }
        restrict_permissions(&tmp_path, 0o600);
        fs::rename(&tmp_path, &self.tokens_path)?;
        Ok(())
    }
}

// ----- internals -------------------------------------------------------

/// Load the 32-byte encryption key from `key_path`, or generate +
/// persist a fresh one on first run. The key file's permissions are
/// hardened to 0600 immediately after write so a generous umask can't
/// leak it to other local users. On a non-POSIX host the chmod call
/// fails silently — persistence still works, just without the belt.
fn load_or_create_key(key_path: &Path) -> io::Result<[u8; KEY_LEN]> {
    match fs::read(key_path) {
        Ok(bytes) => {
            if bytes.len() != KEY_LEN {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "push-token key file {} has wrong length: {} (expected {})",
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
            let tmp = key_path.with_extension("key.tmp");
            {
                let mut f = fs::File::create(&tmp)?;
                f.write_all(&out)?;
                f.sync_all()?;
            }
            restrict_permissions(&tmp, 0o600);
            fs::rename(&tmp, key_path)?;
            Ok(out)
        }
        Err(e) => Err(e),
    }
}

/// Encrypt `plaintext` to `[12-byte nonce || ciphertext+tag]` using
/// ChaCha20-Poly1305 with a fresh random nonce per write. Random
/// nonce + per-write reuse is safe for ChaCha20-Poly1305 well past
/// any realistic write count (birthday bound on a 96-bit nonce is
/// ~2^48 writes — we'll never get there).
fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> io::Result<Vec<u8>> {
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

/// Decrypt a `[12-byte nonce || ciphertext+tag]` envelope, parse the
/// inner JSON, drop entries past TTL, and return the survivors as
/// the live HashMap representation. A bad nonce, a bad tag, or a bad
/// JSON body all surface as `io::Error` — see `load_or_create` for
/// why we refuse to start rather than swallow.
fn decrypt_and_load(
    bytes: &[u8],
    key: &[u8; KEY_LEN],
    max_age: Duration,
) -> io::Result<HashMap<Vec<u8>, (Vec<u8>, u64)>> {
    if bytes.len() < NONCE_LEN {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "push-token file truncated before nonce",
        ));
    }
    let (nonce_bytes, ct) = bytes.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| {
            io::Error::other(
                "push-token file failed to decrypt — wrong key file, or file tampered with",
            )
        })?;
    let doc: StoreDoc = serde_json::from_slice(&plaintext).map_err(io::Error::other)?;

    let now = unix_now();
    let cutoff = now.saturating_sub(max_age.as_secs());
    let mut map = HashMap::with_capacity(doc.entries.len());
    for (peer_hex, entry) in doc.entries {
        if entry.last_refreshed_unix < cutoff {
            continue; // TTL purge
        }
        let peer_id = match hex_decode(&peer_hex) {
            Some(p) => p,
            None => continue, // skip malformed entry rather than refuse the whole file
        };
        let token = match hex_decode(&entry.token_hex) {
            Some(t) => t,
            None => continue,
        };
        map.insert(peer_id, (token, entry.last_refreshed_unix));
    }
    Ok(map)
}

/// chmod helper. POSIX-only — on Windows / other non-Unix this is a
/// no-op (silently). The `set_permissions` call is best-effort: a
/// host that refuses (e.g. exotic filesystem) still gets correctness
/// from the persistence; the belt-and-braces is missing.
#[cfg(unix)]
fn restrict_permissions(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(mode)) {
        eprintln!(
            "[pizzini-relay] warn: could not chmod {}: {e}",
            path.display()
        );
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path, _mode: u32) {}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ----- tiny hex helpers ------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
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
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Build a temp dir unique to the test name. We don't pull in the
    /// `tempfile` crate just for this — `std::env::temp_dir()` plus a
    /// per-test subdirectory keyed off a high-entropy unix-nano stamp
    /// is enough isolation for unit tests, and avoids touching the
    /// dependency tree for a test-only convenience.
    fn fresh_state_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("pizzini-push-test-{label}-{nanos}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn round_trip_persist_and_reload() {
        let dir = fresh_state_dir("roundtrip");
        let peer = vec![0xAA; 33];
        let token = vec![0xBB; 32];
        {
            let mut store = PushTokenStore::load_or_create(&dir).unwrap();
            store.insert(peer.clone(), token.clone()).unwrap();
            assert_eq!(store.get_cloned(&peer), Some(token.clone()));
        }
        // Re-open: the second store reads from disk, so an
        // entry surviving the close-and-reopen means persistence is
        // wired correctly.
        {
            let store = PushTokenStore::load_or_create(&dir).unwrap();
            assert_eq!(store.get_cloned(&peer), Some(token));
            assert_eq!(store.len(), 1);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn second_insert_overwrites_first() {
        let dir = fresh_state_dir("overwrite");
        let peer = vec![0xCC; 33];
        let mut store = PushTokenStore::load_or_create(&dir).unwrap();
        store.insert(peer.clone(), vec![0x01; 32]).unwrap();
        store.insert(peer.clone(), vec![0x02; 32]).unwrap();
        assert_eq!(store.get_cloned(&peer), Some(vec![0x02; 32]));
        assert_eq!(store.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_key_length_refuses_to_load() {
        // Operator hand-edited the key file to the wrong size — that's
        // a misconfiguration we should surface rather than silently
        // "recover" by ignoring (which would silently invalidate
        // every device's push registration).
        let dir = fresh_state_dir("badkey");
        fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join(KEY_FILE_NAME);
        fs::write(&key_path, b"too short").unwrap();
        let err = PushTokenStore::load_or_create(&dir).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_tokens_file_refuses_to_load() {
        // ChaCha20-Poly1305 tag mismatch — refuse to start rather
        // than "recover" by treating the map as empty, which would
        // silently lose every paired device's push.
        let dir = fresh_state_dir("tampered");
        {
            let mut store = PushTokenStore::load_or_create(&dir).unwrap();
            store.insert(vec![0xDD; 33], vec![0xEE; 32]).unwrap();
        }
        // Flip one byte inside the ciphertext region (after the 12-byte
        // nonce).
        let tokens_path = dir.join(TOKENS_FILE_NAME);
        let mut bytes = fs::read(&tokens_path).unwrap();
        let mid = (bytes.len() - 1).max(NONCE_LEN);
        bytes[mid] ^= 0x01;
        fs::write(&tokens_path, bytes).unwrap();

        let err = PushTokenStore::load_or_create(&dir).unwrap_err();
        // Surfaces as InvalidData / Other — main.rs treats either as
        // refuse-to-start, which is the behaviour we want.
        assert!(
            err.to_string().contains("decrypt") || err.kind() == ErrorKind::InvalidData,
            "unexpected error: {err}",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ttl_drops_entries_past_max_age_on_load() {
        // Build a store, then hand-edit a single entry's timestamp
        // to be older than MAX_TOKEN_AGE. After reload the entry
        // should be gone; a fresh entry should survive.
        let dir = fresh_state_dir("ttl");
        let stale_peer = vec![0x11; 33];
        let fresh_peer = vec![0x22; 33];
        {
            let mut store = PushTokenStore::load_or_create(&dir).unwrap();
            store.insert(stale_peer.clone(), vec![0xAA; 32]).unwrap();
            store.insert(fresh_peer.clone(), vec![0xBB; 32]).unwrap();
            // Reach in and rewrite the stale entry's timestamp to
            // MAX_TOKEN_AGE + 1h in the past, then re-persist.
            let stale_unix = unix_now() - MAX_TOKEN_AGE.as_secs() - 3600;
            if let Some(slot) = store.map.get_mut(&stale_peer) {
                slot.1 = stale_unix;
            }
            store.persist().unwrap();
        }
        let reopened = PushTokenStore::load_or_create(&dir).unwrap();
        assert_eq!(reopened.get_cloned(&stale_peer), None);
        assert_eq!(reopened.get_cloned(&fresh_peer), Some(vec![0xBB; 32]));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_dir_starts_empty() {
        let dir = fresh_state_dir("empty");
        let store = PushTokenStore::load_or_create(&dir).unwrap();
        assert_eq!(store.len(), 0);
        // Key file should now exist (it's generated lazily on first
        // load-or-create), tokens file should NOT (no writes yet).
        assert!(dir.join(KEY_FILE_NAME).exists());
        assert!(!dir.join(TOKENS_FILE_NAME).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hex_round_trip() {
        // Spot-check the inline hex helpers — they're tiny but
        // load-bearing for the JSON encoding of binary peer-ids and
        // tokens.
        let inputs: &[&[u8]] = &[
            b"",
            b"\x00",
            b"\xff",
            b"\x00\x01\x02\x7f\x80\xff",
            &[0xde, 0xad, 0xbe, 0xef],
        ];
        for &input in inputs {
            let hex = hex_encode(input);
            let decoded = hex_decode(&hex).unwrap();
            assert_eq!(decoded.as_slice(), input);
        }
        // Reject malformed inputs.
        assert_eq!(hex_decode("abc"), None); // odd length
        assert_eq!(hex_decode("zz"), None); // non-hex char
    }
}
