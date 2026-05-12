//! Persistent token-replay store.
//!
//! F-NEW-203 fix. Before this module the `Replays` table — the set of
//! `(recipient_peer_id, token_nonce)` keys we've already accepted —
//! lived in an in-memory `HashMap` that was wiped on every process
//! restart. Combined with the now-persistent `PendingStore`, that
//! created a critical asymmetry: a captured SEND frame's
//! `delivery_token` still verified after a relay bounce, but the
//! replay-set lookup missed (it was reset) → the relay re-accepted
//! the same SEND. An attacker on-path (clearnet dev build) or a
//! malicious relay-restarter could replay up to 100 captured frames
//! at an offline recipient, evicting legitimate not-yet-delivered
//! SENDs from the `drop-oldest` pending queue.
//!
//! This module persists the replay set with the same shape as
//! `pending_store` and `push_token_store`:
//!
//!   • Encryption-at-rest via the shared `encrypted_file` layer. The
//!     threat-model framing in `encrypted_file`'s header applies
//!     here too — defence against accidental disclosure, not against
//!     a disk-access adversary.
//!   • Atomic write on every mutation (write-to-temp + rename).
//!   • TTL respected on load. Entries past `TOKEN_REPLAY_WINDOW` are
//!     dropped, so a restart-after-30d doesn't pin stale nonces.
//!
//! Wall-clock seconds are used rather than `Instant` because
//! `Instant` is monotonic-process-local — a set persisted by one
//! process cannot translate its Instants to another's clock.

use crate::encrypted_file;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::Duration;

const REPLAY_FILE_NAME: &str = "replays.bin";
const KEY_FILE_NAME: &str = "replays.key";

/// Per-store AAD. F-NEW-206 defense-in-depth domain separation.
const AAD: &[u8] = b"pizzini.relay.replays.v1";

/// One persisted replay entry. Stores when the nonce was first
/// observed, in wall-clock seconds, so the GC pass can drop it once
/// `TOKEN_REPLAY_WINDOW` has elapsed from that point.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    /// `(peer_id_hex, nonce_hex)` joined by `:` so the serde JSON
    /// representation stays a flat HashMap<String, _>. The inline
    /// encoding is read by `decompose_key`.
    first_seen_unix: u64,
}

/// Inner JSON document. Single `entries` map keyed by
/// `peer_id_hex:nonce_hex` — the same JSON-safe shape as the sibling
/// stores so operators can inspect under decryption.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct StoreDoc {
    entries: HashMap<String, StoredEntry>,
}

/// The persistent replay store. Owns the file path, the in-memory
/// decrypted map, and the encryption key. Constructed by
/// `load_or_create`; every mutator persists synchronously so a crash
/// mid-write can never leave the on-disk state inconsistent.
pub struct ReplayStore {
    replays_path: PathBuf,
    key: [u8; encrypted_file::KEY_LEN],
    /// `(peer_id_bytes, nonce_bytes) → first_seen_unix`
    map: HashMap<(Vec<u8>, Vec<u8>), u64>,
}

impl std::fmt::Debug for ReplayStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayStore")
            .field("replays_path", &self.replays_path)
            .field("key", &"[redacted 32 bytes]")
            .field("entries", &self.map.len())
            .finish()
    }
}

impl ReplayStore {
    /// Load the store from `state_dir`, or create an empty one if
    /// the files don't exist yet. Performs the TTL purge on load —
    /// entries past `max_age` since their `first_seen_unix` are
    /// dropped silently.
    pub fn load_or_create(state_dir: &Path, max_age: Duration) -> io::Result<Self> {
        fs::create_dir_all(state_dir)?;
        encrypted_file::restrict_permissions(state_dir, 0o700);
        let replays_path = state_dir.join(REPLAY_FILE_NAME);
        let key_path = state_dir.join(KEY_FILE_NAME);

        let key = encrypted_file::load_or_create_key(&key_path, "replay")?;

        let map = match fs::read(&replays_path) {
            Ok(bytes) => {
                let plaintext = encrypted_file::decrypt_with_aad(&key, &bytes, AAD)
                    .or_else(|_| encrypted_file::decrypt(&key, &bytes))?;
                let doc: StoreDoc = serde_json::from_slice(&plaintext).map_err(io::Error::other)?;
                purge_stale(doc, max_age)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };

        Ok(ReplayStore {
            replays_path,
            key,
            map,
        })
    }

    /// Current entry count.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True if `(peer_id, nonce)` is already in the replay set —
    /// caller should refuse the frame as a replay.
    ///
    /// Fires on every accepted SEND/ACK and is therefore the hottest
    /// read on the relay. Previously this was an O(n) linear scan
    /// across `map.keys()` because `HashMap<(Vec<u8>, Vec<u8>), _>`
    /// doesn't admit a `(&[u8], &[u8])` probe. At 30-day TTL the set
    /// reaches multi-million entries on any active fleet; a single
    /// SEND was paying tens-of-microseconds per match. The owned-key
    /// build below allocates ~80 bytes per probe and replaces a
    /// million-iter scan with one hash lookup — net win at any
    /// realistic load.
    pub fn contains(&self, peer_id: &[u8], nonce: &[u8]) -> bool {
        let key = (peer_id.to_vec(), nonce.to_vec());
        self.map.contains_key(&key)
    }

    /// Insert `(peer_id, nonce)` with `first_seen_unix = now` and
    /// persist. Idempotent — re-inserting the same key updates the
    /// timestamp but doesn't otherwise change behaviour (a replay
    /// would have been rejected by `contains` before reaching here).
    pub fn insert(&mut self, peer_id: Vec<u8>, nonce: Vec<u8>) -> io::Result<()> {
        let now = encrypted_file::unix_now();
        self.map.insert((peer_id, nonce), now);
        self.persist()
    }

    /// Drop entries older than `max_age` from now. Persists if any
    /// were dropped. Returns the count of dropped entries for
    /// logging by the GC task.
    pub fn gc_expired(&mut self, max_age: Duration) -> io::Result<usize> {
        let now = encrypted_file::unix_now();
        let cutoff = now.saturating_sub(max_age.as_secs());
        let before = self.map.len();
        self.map.retain(|_, ts| *ts > cutoff);
        let removed = before - self.map.len();
        if removed > 0 {
            self.persist()?;
        }
        Ok(removed)
    }

    fn persist(&self) -> io::Result<()> {
        let mut doc = StoreDoc::default();
        for ((peer_id, nonce), ts) in &self.map {
            let composite = format!(
                "{}:{}",
                encrypted_file::hex_encode(peer_id),
                encrypted_file::hex_encode(nonce),
            );
            doc.entries.insert(
                composite,
                StoredEntry {
                    first_seen_unix: *ts,
                },
            );
        }
        let plaintext = serde_json::to_vec(&doc).map_err(io::Error::other)?;
        let ciphertext = encrypted_file::encrypt_with_aad(&self.key, &plaintext, AAD)?;
        encrypted_file::write_atomic(&self.replays_path, &ciphertext)
    }
}

/// Drop entries older than `max_age`, decode hex back into bytes.
/// Malformed entries are silently skipped — a corrupt single row is
/// less destructive than refusing to start; the persist on next
/// mutation drops the corrupt row from disk.
fn purge_stale(doc: StoreDoc, max_age: Duration) -> HashMap<(Vec<u8>, Vec<u8>), u64> {
    let now = encrypted_file::unix_now();
    let cutoff = now.saturating_sub(max_age.as_secs());
    let mut out: HashMap<(Vec<u8>, Vec<u8>), u64> = HashMap::new();
    for (composite, entry) in doc.entries {
        if entry.first_seen_unix <= cutoff {
            continue;
        }
        let Some((peer_hex, nonce_hex)) = composite.split_once(':') else {
            continue;
        };
        let Some(peer) = encrypted_file::hex_decode(peer_hex) else {
            continue;
        };
        let Some(nonce) = encrypted_file::hex_decode(nonce_hex) else {
            continue;
        };
        out.insert((peer, nonce), entry.first_seen_unix);
    }
    out
}
