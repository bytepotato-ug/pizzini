//! Persistent per-(recipient, hour) BUNDLE_REQUEST acceptance counter.
//!
//! The relay enforces `BUNDLE_REQ_PER_RECIPIENT_PER_HOUR` accepted
//! `BUNDLE_REQUEST` frames per recipient per wall-clock hour. That cap
//! is the load-bearing flood control on a victim's first-contact
//! bundle channel — hashcash only gates the *cost* of one proof, not
//! how many valid proofs a Sybil swarm can land.
//!
//! Pre-this-module the counter lived in an in-memory
//! `HashMap<(PeerId, u64), u32>` that was rebuilt empty on every
//! process restart. Any benign relay bounce (deploy, crash, OOM,
//! `systemctl restart`) silently handed every recipient's hour bucket
//! a fresh full budget mid-hour, and a malicious operator could
//! nullify the cap entirely by restarting their own process. The
//! "8/hour, a swarm cannot drown a target" guarantee did not hold
//! across the most ordinary operational event.
//!
//! This module gives the counter persistence across restarts, with
//! the same shape as `push_token_store` / `pending_store`:
//!
//!   • Encryption at rest via the shared `encrypted_file` layer.
//!   • Atomic write on every increment (write-to-temp + rename).
//!     `BUNDLE_REQUEST` is a first-contact event, not on the hot send
//!     path, so the per-increment persist cost is amortised away.
//!   • Hour-bucket TTL purge on load: a bucket older than the current
//!     hour minus `BUCKET_RETENTION_HOURS` is dropped, so the file
//!     does not accumulate dead buckets across long uptimes.
//!
//! Fails (returns `Err`) on a corrupt key file or a tampered blob —
//! refusing to start is the right call. Continuing with an empty map
//! after partial corruption would reopen the full per-recipient
//! budget, which is exactly the gap this module closes.

use crate::encrypted_file;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

const FILE_NAME: &str = "bundle_req_rate.bin";
const KEY_FILE_NAME: &str = "bundle_req_rate.key";

/// Per-store AAD. Domain-separates this store's ciphertext from
/// sibling stores' so a swap attack fails at AEAD verify.
const AAD: &[u8] = b"pizzini.relay.bundle-req-rate.v1";

/// How many past hour buckets to retain on load. The rate limiter
/// only ever consults the current bucket, but a small retention
/// window keeps the file stable across a sub-hour restart without
/// the counter visibly jumping, and absorbs clock skew. Anything
/// older is dead weight and dropped.
const BUCKET_RETENTION_HOURS: u64 = 2;

/// Inner JSON document: a single `counts` map keyed by
/// `"{recipient_peer_id_hex}:{hour_bucket}"` for JSON flatness.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct StoreDoc {
    counts: HashMap<String, u32>,
}

/// Persistent per-(recipient, hour) BUNDLE_REQUEST acceptance counter.
///
/// Thread-safety is the caller's responsibility — `main.rs` wraps it
/// in `Arc<Mutex<_>>` so concurrent BUNDLE_REQUEST handlers and the
/// GC task serialize through one lock.
pub struct BundleReqRateStore {
    path: PathBuf,
    key: [u8; encrypted_file::KEY_LEN],
    /// `(recipient_peer_id, hour_bucket) → accepted count`.
    counts: HashMap<(Vec<u8>, u64), u32>,
}

// Manual `Debug` to redact the key — same reasoning as the sibling
// stores: a derived impl would print the raw encryption key through
// any `{store:?}` log line.
impl std::fmt::Debug for BundleReqRateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleReqRateStore")
            .field("path", &self.path)
            .field("key", &"[redacted 32 bytes]")
            .field("buckets", &self.counts.len())
            .finish()
    }
}

impl BundleReqRateStore {
    /// Load (or create) the store at `state_dir`. Buckets older than
    /// `current_hour - BUCKET_RETENTION_HOURS` are dropped on load.
    /// `current_hour` is passed in (rather than read here) so the
    /// caller's single `current_hour_bucket()` helper stays the one
    /// source of truth for the hour coordinate.
    pub fn load_or_create(state_dir: &Path, current_hour: u64) -> io::Result<Self> {
        fs::create_dir_all(state_dir)?;
        encrypted_file::restrict_permissions(state_dir, 0o700);
        let path = state_dir.join(FILE_NAME);
        let key_path = state_dir.join(KEY_FILE_NAME);

        let key = encrypted_file::load_or_create_key(&key_path, "bundle-req-rate")?;

        let counts = match fs::read(&path) {
            Ok(bytes) => {
                let plaintext = encrypted_file::decrypt_with_aad(&key, &bytes, AAD)
                    .or_else(|_| encrypted_file::decrypt(&key, &bytes))?;
                let doc: StoreDoc =
                    serde_json::from_slice(&plaintext).map_err(io::Error::other)?;
                purge_stale(doc, current_hour)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };

        Ok(BundleReqRateStore { path, key, counts })
    }

    /// Distinct live `(recipient, hour)` buckets. Drives the startup
    /// banner.
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// Increment the accepted-count for `(recipient, hour)` and
    /// persist. Returns the post-increment count so the caller can
    /// compare it against the cap with the same atomic-under-lock
    /// semantics the in-memory version had.
    ///
    /// `persist()` runs before the count is returned, so any count the
    /// caller acts on is already durable on disk. A crash *during* the
    /// atomic write leaves the previous (pre-increment) file in place
    /// — but the in-flight request that triggered this increment also
    /// died with the process and was never served, so the bucket on
    /// the next load is consistent with "that request never happened".
    /// This is a vastly smaller window than the old
    /// wipe-the-whole-table-on-restart behaviour, which handed every
    /// recipient a fresh full budget on every bounce.
    pub fn increment(&mut self, recipient: Vec<u8>, hour: u64) -> io::Result<u32> {
        let entry = self.counts.entry((recipient, hour)).or_insert(0);
        *entry = entry.saturating_add(1);
        let count = *entry;
        self.persist()?;
        Ok(count)
    }

    /// Drop buckets older than `current_hour - BUCKET_RETENTION_HOURS`.
    /// Persists if any were dropped. Returns the count of dropped
    /// buckets for logging.
    pub fn gc_stale(&mut self, current_hour: u64) -> io::Result<usize> {
        let cutoff = current_hour.saturating_sub(BUCKET_RETENTION_HOURS);
        let before = self.counts.len();
        self.counts.retain(|(_, hour), _| *hour >= cutoff);
        let removed = before - self.counts.len();
        if removed > 0 {
            self.persist()?;
        }
        Ok(removed)
    }

    /// Serialize the in-memory map, encrypt, atomically replace the
    /// file. The rename inside `write_atomic` is the commit point.
    fn persist(&self) -> io::Result<()> {
        let mut doc = StoreDoc::default();
        for ((recipient, hour), count) in &self.counts {
            let composite = format!("{}:{}", encrypted_file::hex_encode(recipient), hour);
            doc.counts.insert(composite, *count);
        }
        let plaintext = serde_json::to_vec(&doc).map_err(io::Error::other)?;
        let ciphertext = encrypted_file::encrypt_with_aad(&self.key, &plaintext, AAD)?;
        encrypted_file::write_atomic(&self.path, &ciphertext)
    }
}

/// Drop buckets older than the retention window and decode the
/// composite hex keys back into the live map shape. A malformed key
/// is silently skipped (a corrupt single row is less destructive
/// than refusing to start; the next increment overwrites it).
fn purge_stale(doc: StoreDoc, current_hour: u64) -> HashMap<(Vec<u8>, u64), u32> {
    let cutoff = current_hour.saturating_sub(BUCKET_RETENTION_HOURS);
    let mut map = HashMap::with_capacity(doc.counts.len());
    for (composite, count) in doc.counts {
        let Some((recipient_hex, hour_str)) = composite.rsplit_once(':') else {
            continue;
        };
        let Ok(hour) = hour_str.parse::<u64>() else {
            continue;
        };
        if hour < cutoff {
            continue;
        }
        let Some(recipient) = encrypted_file::hex_decode(recipient_hex) else {
            continue;
        };
        map.insert((recipient, hour), count);
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
        let dir = std::env::temp_dir().join(format!("pizzini-bundlerate-test-{label}-{nanos}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn increment_persists_across_reload() {
        // The core F-S4-02 property: the per-(recipient, hour) count
        // survives a process restart.
        let dir = fresh_state_dir("persist");
        let victim = vec![0xAA; 33];
        let hour = 480_000u64;
        {
            let mut store = BundleReqRateStore::load_or_create(&dir, hour).unwrap();
            assert_eq!(store.increment(victim.clone(), hour).unwrap(), 1);
            assert_eq!(store.increment(victim.clone(), hour).unwrap(), 2);
            assert_eq!(store.increment(victim.clone(), hour).unwrap(), 3);
        }
        // Reopen in the same hour — the counter is NOT reset.
        let mut store = BundleReqRateStore::load_or_create(&dir, hour).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.increment(victim.clone(), hour).unwrap(), 4);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_buckets_purged_on_load() {
        let dir = fresh_state_dir("ttl");
        let victim = vec![0xBB; 33];
        let old_hour = 100u64;
        {
            let mut store = BundleReqRateStore::load_or_create(&dir, old_hour).unwrap();
            store.increment(victim.clone(), old_hour).unwrap();
        }
        // Reopen many hours later — the old bucket is past the
        // retention window and dropped.
        let now_hour = old_hour + BUCKET_RETENTION_HOURS + 5;
        let store = BundleReqRateStore::load_or_create(&dir, now_hour).unwrap();
        assert_eq!(store.len(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recent_bucket_kept_across_subhour_restart() {
        // A restart inside the retention window keeps the bucket.
        let dir = fresh_state_dir("recent");
        let victim = vec![0xCC; 33];
        let hour = 9000u64;
        {
            let mut store = BundleReqRateStore::load_or_create(&dir, hour).unwrap();
            store.increment(victim.clone(), hour).unwrap();
            store.increment(victim.clone(), hour).unwrap();
        }
        // One hour later — within BUCKET_RETENTION_HOURS — bucket
        // for `hour` is still present.
        let store = BundleReqRateStore::load_or_create(&dir, hour + 1).unwrap();
        assert_eq!(store.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn gc_stale_drops_old_buckets() {
        let dir = fresh_state_dir("gc");
        let victim = vec![0xDD; 33];
        let mut store = BundleReqRateStore::load_or_create(&dir, 1000).unwrap();
        store.increment(victim.clone(), 1000).unwrap();
        store.increment(victim.clone(), 1001).unwrap();
        // GC at hour 1010: both 1000 and 1001 are older than
        // 1010 - BUCKET_RETENTION_HOURS, so both drop.
        let dropped = store.gc_stale(1010).unwrap();
        assert_eq!(dropped, 2);
        assert_eq!(store.len(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_key_length_refuses_to_load() {
        let dir = fresh_state_dir("badkey");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(KEY_FILE_NAME), b"too short").unwrap();
        let err = BundleReqRateStore::load_or_create(&dir, 0).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_file_refuses_to_load() {
        let dir = fresh_state_dir("tampered");
        {
            let mut store = BundleReqRateStore::load_or_create(&dir, 5).unwrap();
            store.increment(vec![0x11; 33], 5).unwrap();
        }
        let path = dir.join(FILE_NAME);
        let mut bytes = fs::read(&path).unwrap();
        let mid = (bytes.len() - 1).max(encrypted_file::NONCE_LEN);
        bytes[mid] ^= 0x01;
        fs::write(&path, bytes).unwrap();
        let err = BundleReqRateStore::load_or_create(&dir, 5).unwrap_err();
        assert!(
            err.to_string().contains("decrypt") || err.kind() == ErrorKind::InvalidData,
            "unexpected error: {err}",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_dir_starts_empty() {
        let dir = fresh_state_dir("empty");
        let store = BundleReqRateStore::load_or_create(&dir, 0).unwrap();
        assert_eq!(store.len(), 0);
        assert!(dir.join(KEY_FILE_NAME).exists());
        assert!(!dir.join(FILE_NAME).exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
