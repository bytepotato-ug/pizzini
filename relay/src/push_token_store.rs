//! Persistent push-token store.
//!
//! The relay's primary trust posture is "minimise forensic surface" —
//! several in-memory maps (`routes`, `verify_keys`, `replays`,
//! `hello_replays`) are still deliberately wiped on restart. Push
//! tokens are one of two places where that posture costs the user
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
//!   1. **Encryption at rest** via the shared `encrypted_file` layer.
//!      See that module's header for the threat-model framing — in
//!      short, the encryption defends against accidental disclosure
//!      (rsync / tarball / container image picking up one file but
//!      not the sibling key), NOT against an attacker with disk
//!      access to the relay machine.
//!   2. **Restrictive POSIX permissions** — directory `0700`, files
//!      `0600`. Best-effort; a non-POSIX host logs a warning and
//!      continues.
//!   3. **TTL purge.** Every entry carries `last_refreshed_unix`.
//!      Entries older than `MAX_TOKEN_AGE` (30 days) are dropped on
//!      load. A device that hasn't foregrounded its app in a month
//!      almost certainly has a stale token anyway (APNs rotates them
//!      eventually); the bounded retention keeps the persistent map
//!      from drifting indefinitely.
//!
//! On every TOKEN_REGISTER frame the store is updated and the file
//! is atomically rewritten (write-to-temp + rename). That's heavier
//! than the previous "HashMap insert" path, but TOKEN_REGISTER is a
//! once-per-app-foreground event — not on the hot send path — so
//! the cost is amortised away.

use crate::encrypted_file;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default state directory if `PIZZINI_RELAY_STATE_DIR` is unset. A
/// relative path — created in the relay process's current working
/// directory on first run. Operators who care can set the env var
/// to a path outside the repo / outside the container's writable
/// volume.
pub const DEFAULT_STATE_DIR: &str = "./pizzini-relay-state";

const TOKENS_FILE_NAME: &str = "push_tokens.bin";
const KEY_FILE_NAME: &str = "push_tokens.key";

/// Per-store AAD. F-NEW-206: domain-separates this store's
/// ciphertext from siblings' even when keys collide. The version
/// suffix is bumped if the inner JSON shape ever changes
/// incompatibly.
const AAD: &[u8] = b"pizzini.relay.push-tokens.v1";

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
    /// `hex_decode` helpers in `encrypted_file` avoid pulling in a
    /// hex crate.
    token_hex: String,
    last_refreshed_unix: u64,
}

/// Inner JSON document. A single `entries` map keyed by hex-encoded
/// peer-id so the file is human-inspectable during dev — encryption
/// in-flight to the disk is the secrecy mechanism, JSON readability
/// is for the operator's debugging convenience after decryption.
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
    key: [u8; encrypted_file::KEY_LEN],
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

    /// Load the store from `state_dir`, or create an empty one if
    /// the files don't exist yet. Creates `state_dir` if missing.
    /// Performs the TTL purge on load — entries past `MAX_TOKEN_AGE`
    /// since their last refresh are dropped silently.
    ///
    /// Fails (returns an `io::Error`) if the files exist but are
    /// corrupt / unreadable / decrypt-fails — refusing to start is
    /// the right call there: continuing with an empty map after a
    /// partial failure could silently break push for every paired
    /// device.
    pub fn load_or_create(state_dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(state_dir)?;
        encrypted_file::restrict_permissions(state_dir, 0o700);
        let tokens_path = state_dir.join(TOKENS_FILE_NAME);
        let key_path = state_dir.join(KEY_FILE_NAME);

        let key = encrypted_file::load_or_create_key(&key_path, "push-token")?;

        let map = match fs::read(&tokens_path) {
            Ok(bytes) => {
                // Try the domain-AAD decrypt first; on failure (pre-
                // F-NEW-206 file written without AAD), fall back to
                // the no-AAD decrypt. Either way, the next persist
                // writes the file back with AAD so subsequent reads
                // take the fast path.
                let plaintext = encrypted_file::decrypt_with_aad(&key, &bytes, AAD)
                    .or_else(|_| encrypted_file::decrypt(&key, &bytes))?;
                let doc: StoreDoc = serde_json::from_slice(&plaintext).map_err(io::Error::other)?;
                purge_stale(doc, MAX_TOKEN_AGE)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };

        Ok(PushTokenStore {
            tokens_path,
            key,
            map,
        })
    }

    /// Total live entries. Used by main.rs at startup to log
    /// "loaded N tokens" so the operator can see persistence is
    /// working.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Insert / update an entry for `peer_id` and persist. The
    /// timestamp is captured from the system clock at call time
    /// (not from the wire frame — peers shouldn't be able to set
    /// `last_refreshed` retroactively to extend their own
    /// retention).
    pub fn insert(&mut self, peer_id: Vec<u8>, token: Vec<u8>) -> io::Result<()> {
        let now = encrypted_file::unix_now();
        self.map.insert(peer_id, (token, now));
        self.persist()
    }

    /// Remove an entry for `peer_id` and persist. Returns `true` if
    /// an entry existed and was removed, `false` if the peer was
    /// already absent. Used by the DEREGISTER_PUSH frame so a
    /// client that elected a new push-primary can release the old
    /// relay's claim — without this, after a primary reshuffle
    /// every relay that was ever primary still holds a token and
    /// `maybe_send_push` fires duplicates on every inbound SEND.
    pub fn remove(&mut self, peer_id: &[u8]) -> io::Result<bool> {
        if self.map.remove(peer_id).is_some() {
            self.persist()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Drop entries whose `last_refreshed_unix` is older than
    /// `max_age` from now. Persists if any were dropped. Returns the
    /// count of dropped entries for logging. F-NEW-208 — the previous
    /// design only purged on load, so a long-running relay
    /// accumulated tokens indefinitely between restarts.
    pub fn gc_expired(&mut self, max_age: Duration) -> io::Result<usize> {
        let now = encrypted_file::unix_now();
        let cutoff = now.saturating_sub(max_age.as_secs());
        let before = self.map.len();
        self.map.retain(|_, (_, ts)| *ts > cutoff);
        let removed = before - self.map.len();
        if removed > 0 {
            self.persist()?;
        }
        Ok(removed)
    }

    /// Look up a token by peer-id. Returns a cloned `Vec<u8>`
    /// because the relay's send-push path needs an owned copy to
    /// hand to the APNs client running on a different task — a
    /// borrow tied to the store's lock would force us to hold the
    /// lock across the HTTP round-trip.
    pub fn get_cloned(&self, peer_id: &[u8]) -> Option<Vec<u8>> {
        self.map.get(peer_id).map(|(token, _)| token.clone())
    }

    /// Serialize the in-memory map, encrypt, and atomically replace
    /// the file. Uses `encrypted_file::write_atomic` so a crash
    /// mid-write can never corrupt the canonical file — the rename
    /// is the commit point.
    fn persist(&self) -> io::Result<()> {
        let mut doc = StoreDoc::default();
        for (peer_id, (token, ts)) in &self.map {
            doc.entries.insert(
                encrypted_file::hex_encode(peer_id),
                StoredEntry {
                    token_hex: encrypted_file::hex_encode(token),
                    last_refreshed_unix: *ts,
                },
            );
        }
        let plaintext = serde_json::to_vec(&doc).map_err(io::Error::other)?;
        let ciphertext = encrypted_file::encrypt_with_aad(&self.key, &plaintext, AAD)?;
        encrypted_file::write_atomic(&self.tokens_path, &ciphertext)
    }
}

/// Drop any entries older than `max_age` since their last refresh,
/// and decode the hex-encoded inner representation back into the
/// live `HashMap<Vec<u8>, (Vec<u8>, u64)>` shape.
///
/// A malformed entry (non-hex peer-id or token) is silently skipped
/// rather than failing the whole load — a corrupt single row is
/// less destructive than refusing to start, and the persist on next
/// insert overwrites the corruption.
fn purge_stale(doc: StoreDoc, max_age: Duration) -> HashMap<Vec<u8>, (Vec<u8>, u64)> {
    let now = encrypted_file::unix_now();
    let cutoff = now.saturating_sub(max_age.as_secs());
    let mut map = HashMap::with_capacity(doc.entries.len());
    for (peer_hex, entry) in doc.entries {
        if entry.last_refreshed_unix < cutoff {
            continue;
        }
        let peer_id = match encrypted_file::hex_decode(&peer_hex) {
            Some(p) => p,
            None => continue,
        };
        let token = match encrypted_file::hex_decode(&entry.token_hex) {
            Some(t) => t,
            None => continue,
        };
        map.insert(peer_id, (token, entry.last_refreshed_unix));
    }
    map
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let dir = fresh_state_dir("tampered");
        {
            let mut store = PushTokenStore::load_or_create(&dir).unwrap();
            store.insert(vec![0xDD; 33], vec![0xEE; 32]).unwrap();
        }
        let tokens_path = dir.join(TOKENS_FILE_NAME);
        let mut bytes = fs::read(&tokens_path).unwrap();
        let mid = (bytes.len() - 1).max(encrypted_file::NONCE_LEN);
        bytes[mid] ^= 0x01;
        fs::write(&tokens_path, bytes).unwrap();

        let err = PushTokenStore::load_or_create(&dir).unwrap_err();
        assert!(
            err.to_string().contains("decrypt") || err.kind() == ErrorKind::InvalidData,
            "unexpected error: {err}",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ttl_drops_entries_past_max_age_on_load() {
        let dir = fresh_state_dir("ttl");
        let stale_peer = vec![0x11; 33];
        let fresh_peer = vec![0x22; 33];
        {
            let mut store = PushTokenStore::load_or_create(&dir).unwrap();
            store.insert(stale_peer.clone(), vec![0xAA; 32]).unwrap();
            store.insert(fresh_peer.clone(), vec![0xBB; 32]).unwrap();
            let stale_unix =
                encrypted_file::unix_now() - MAX_TOKEN_AGE.as_secs() - 3600;
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
        assert!(dir.join(KEY_FILE_NAME).exists());
        assert!(!dir.join(TOKENS_FILE_NAME).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_drops_entry_and_persists() {
        let dir = fresh_state_dir("remove");
        let peer = vec![0xEE; 33];
        {
            let mut store = PushTokenStore::load_or_create(&dir).unwrap();
            store.insert(peer.clone(), vec![0xFF; 32]).unwrap();
            let removed = store.remove(&peer).unwrap();
            assert!(removed, "remove should return true for existing entry");
            assert_eq!(store.get_cloned(&peer), None);
            assert_eq!(store.len(), 0);
        }
        // Reopen — removal must be persisted, not in-memory only.
        let store = PushTokenStore::load_or_create(&dir).unwrap();
        assert_eq!(store.get_cloned(&peer), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_missing_returns_false() {
        let dir = fresh_state_dir("remove-missing");
        let mut store = PushTokenStore::load_or_create(&dir).unwrap();
        let removed = store.remove(&[0x00; 33]).unwrap();
        assert!(!removed, "remove should return false for absent entry");
        let _ = fs::remove_dir_all(&dir);
    }
}
