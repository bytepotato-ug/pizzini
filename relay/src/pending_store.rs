//! Persistent offline-message queue.
//!
//! When a SEND or ACK arrives for a peer who isn't currently
//! connected, the relay queues the frame for delivery on the
//! recipient's next HELLO. Pre-this-module the queue lived in an
//! in-memory `HashMap<PeerId, VecDeque<PendingFrame>>` that was
//! wiped on every process restart — meaning a relay bounce (deploy,
//! crash, Mac reboot, `cargo run` after a code change) silently
//! lost every in-flight message destined for an offline recipient.
//! The sender's outbox sees only the relay's "accepted" ACK, so the
//! lost-on-restart frames flip to ✓ on the sender's UI and stay
//! there forever — exactly the failure mode that lost the "dde"
//! message during the push-token-persistence rollout.
//!
//! Professional messengers (Signal, WhatsApp, iMessage) all persist
//! the offline queue. The "in-memory only" pattern is a dev-time
//! shortcut. This module fills the gap with the same shape as
//! `push_token_store`:
//!
//!   • Encryption-at-rest via `encrypted_file::encrypt` + a sibling
//!     key file. The threat-model framing (defends against
//!     accidental disclosure, not against an attacker with disk
//!     access) lives in the `encrypted_file` header.
//!   • Atomic write on every mutation. A crash mid-write leaves the
//!     prior good state intact.
//!   • TTL respected on load. Each queued frame carries its absolute
//!     unix-seconds expiry — entries past their TTL are dropped
//!     when the file is read, so a restart-after-7d doesn't surface
//!     ghost frames to a freshly-reconnected peer.
//!   • Per-peer cap (`max_per_peer`) enforced on enqueue — DoS
//!     safeguard against a malicious sender spraying frames at a
//!     single long-offline recipient.
//!   • Global caps (`max_distinct_peers`, `max_total_frames`,
//!     `max_total_bytes`) enforced on enqueue — DoS safeguard against
//!     a malicious sender spraying frames at *many* fabricated
//!     `to_id`s (the no-token CHAIN_SEED_DELIVERY pipe makes `to_id`
//!     attacker-chosen). The per-peer cap alone does not bound the
//!     store when `to_id` cardinality is unbounded. When a global
//!     cap would be exceeded the enqueue fails closed — the frame is
//!     refused, never another peer's frame evicted — so an attacker
//!     cannot displace a legitimate recipient's queued messages.
//!
//! On-disk footprint is hard-bounded by `max_total_frames` /
//! `max_total_bytes` regardless of `to_id` cardinality.
//!
//! What this module is NOT doing: distinguishing between "delivered
//! to the relay" (frame is in the disk queue) and "actually reached
//! the recipient" (frame was forwarded and the recipient sent an
//! ACK upstream). The send-side ACK is the recipient's
//! responsibility, propagated through the relay's normal route table
//! once they reconnect.

use crate::encrypted_file;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

const PENDING_FILE_NAME: &str = "pending.bin";
const KEY_FILE_NAME: &str = "pending.key";

/// Per-store AAD. F-NEW-206: domain-separates this store's
/// ciphertext from siblings'. Bumping the version suffix triggers a
/// one-shot legacy decrypt on the next load.
const AAD: &[u8] = b"pizzini.relay.pending.v1";

/// One queued routing frame. Mirrors the previous in-memory
/// `PendingFrame` but with `expires_at_unix` (wall-clock seconds)
/// instead of `Instant` so it survives serialization. `Instant` is
/// monotonic-process-local; a queue persisted under one process can't
/// translate its Instants for another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingFrame {
    /// The entire wire frame as it would have been forwarded —
    /// frame_type byte + recipient header + payload — so it can be
    /// handed verbatim to the recipient's writer task on reconnect.
    /// Hex-encoded for JSON-safety.
    pub bytes_hex: String,
    /// Absolute expiry as unix-epoch seconds. The pre-persistence
    /// implementation used `Instant`, which doesn't survive process
    /// bounds; this is wall-clock so a queued frame survives a
    /// restart with its original TTL intact.
    pub expires_at_unix: u64,
}

impl PendingFrame {
    /// Construct from raw frame bytes + absolute expiry seconds.
    /// Callers that have a `Duration` ttl should add it to
    /// `encrypted_file::unix_now()` first.
    pub fn new(bytes: Vec<u8>, expires_at_unix: u64) -> Self {
        Self {
            bytes_hex: encrypted_file::hex_encode(&bytes),
            expires_at_unix,
        }
    }

    /// Decoded raw frame bytes. Returns an empty Vec on hex-decode
    /// failure — a corrupt single row is silently skipped on load,
    /// so this case shouldn't normally fire post-load. Defensive
    /// fallback rather than a panic.
    pub fn bytes(&self) -> Vec<u8> {
        encrypted_file::hex_decode(&self.bytes_hex).unwrap_or_default()
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expires_at_unix <= now_unix
    }

    /// Decoded frame length in bytes. The stored form is hex, so the
    /// raw length is half the hex string's length — computed without
    /// allocating a decode buffer, since the global byte-count cap
    /// in `PendingStore::enqueue` calls this on every queued frame.
    pub fn byte_len(&self) -> usize {
        self.bytes_hex.len() / 2
    }
}

/// Inner JSON document. A single `queues` map keyed by hex-encoded
/// peer-id. Operator can decrypt-and-`jq` the file during dev for
/// "what's queued for whom" debugging.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct StoreDoc {
    queues: HashMap<String, VecDeque<PendingFrame>>,
}

/// Persistent offline-queue store. Wraps the in-memory `HashMap<
/// PeerId, VecDeque<PendingFrame>>` with disk persistence + TTL
/// enforcement + per-peer cap.
///
/// Thread-safety is the caller's responsibility — `main.rs` wraps
/// it in `Arc<Mutex<PendingStore>>` so concurrent SEND handlers and
/// the GC task serialize through one lock.
pub struct PendingStore {
    pending_path: PathBuf,
    key: [u8; encrypted_file::KEY_LEN],
    queues: HashMap<Vec<u8>, VecDeque<PendingFrame>>,
    /// Per-peer queue cap, applied on `enqueue`. Passed in by the
    /// caller so `main.rs` retains it as the single source of truth.
    max_per_peer: usize,
    /// Global cap on the number of distinct peer queues.
    max_distinct_peers: usize,
    /// Global cap on the total frame count across all queues.
    max_total_frames: usize,
    /// Global cap on the total queued-frame byte count across all
    /// queues (measured on the decoded frame bytes).
    max_total_bytes: usize,
}

/// Outcome of an `enqueue`. `Stored` means the frame was queued and
/// persisted; `RejectedGlobalCap` means a global ceiling
/// (`max_distinct_peers` / `max_total_frames` / `max_total_bytes`)
/// would have been exceeded, so the frame was refused and nothing
/// was mutated — failing closed rather than evicting another peer's
/// frames on an attacker's behalf.
#[derive(Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Stored,
    RejectedGlobalCap,
}

// Manual `Debug` to redact the key — same reasoning as
// `PushTokenStore`.
impl std::fmt::Debug for PendingStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total: usize = self.queues.values().map(|q| q.len()).sum();
        f.debug_struct("PendingStore")
            .field("pending_path", &self.pending_path)
            .field("key", &"[redacted 32 bytes]")
            .field("peers_with_queues", &self.queues.len())
            .field("total_frames", &total)
            .finish()
    }
}

impl PendingStore {
    /// Load (or create) the persistent store at `state_dir`. Frames
    /// past their TTL are dropped at load time. `max_per_peer` is
    /// the per-peer queue cap; `max_distinct_peers` /
    /// `max_total_frames` / `max_total_bytes` are the global
    /// ceilings — all enforced on subsequent `enqueue` calls.
    ///
    /// Fails (returns `Err`) on a corrupt key file or a tampered
    /// pending blob — refusing to start is the right call there.
    /// Continuing with an empty queue after partial corruption
    /// would silently lose every paired peer's in-flight messages.
    pub fn load_or_create(
        state_dir: &Path,
        max_per_peer: usize,
        max_distinct_peers: usize,
        max_total_frames: usize,
        max_total_bytes: usize,
    ) -> io::Result<Self> {
        fs::create_dir_all(state_dir)?;
        encrypted_file::restrict_permissions(state_dir, 0o700);
        let pending_path = state_dir.join(PENDING_FILE_NAME);
        let key_path = state_dir.join(KEY_FILE_NAME);

        let key = encrypted_file::load_or_create_key(&key_path, "pending-queue")?;

        let queues = match fs::read(&pending_path) {
            Ok(bytes) => {
                // Domain-AAD decrypt with legacy-no-AAD fallback for
                // files written before F-NEW-206. The next persist
                // rewrites with the AAD path.
                let plaintext = encrypted_file::decrypt_with_aad(&key, &bytes, AAD)
                    .or_else(|_| encrypted_file::decrypt(&key, &bytes))?;
                let doc: StoreDoc = serde_json::from_slice(&plaintext).map_err(io::Error::other)?;
                drop_expired(doc, encrypted_file::unix_now())
            }
            Err(e) if e.kind() == ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };

        Ok(PendingStore {
            pending_path,
            key,
            queues,
            max_per_peer,
            max_distinct_peers,
            max_total_frames,
            max_total_bytes,
        })
    }

    /// Total queued frames across all peers. Drives the startup
    /// banner so the operator can see "loaded N frames from the
    /// pending store".
    pub fn total_frames(&self) -> usize {
        self.queues.values().map(|q| q.len()).sum()
    }

    /// Distinct peers with at least one queued frame.
    pub fn peers_with_queues(&self) -> usize {
        self.queues.len()
    }

    /// Total decoded-frame bytes queued across all peers. Used by the
    /// global byte-count cap in `enqueue`.
    fn total_bytes(&self) -> usize {
        self.queues
            .values()
            .flat_map(|q| q.iter())
            .map(|f| f.byte_len())
            .sum()
    }

    /// Append a frame to `peer_id`'s queue, evicting the oldest
    /// frame first if doing so would exceed the per-peer cap.
    /// Persists atomically before returning `EnqueueOutcome::Stored`.
    ///
    /// Fails closed with `EnqueueOutcome::RejectedGlobalCap` (no
    /// mutation, no persist) if storing the frame would push the
    /// store past any global ceiling: the number of distinct peer
    /// queues, the total frame count, or the total byte count.
    /// Refusing — rather than evicting some other peer's frames —
    /// keeps a malicious sender spraying fabricated `to_id`s from
    /// either growing the store without bound or displacing a
    /// legitimate recipient's queued messages.
    ///
    /// The per-peer eviction strategy ("drop oldest") matches the
    /// pre-persistence implementation: a recipient reconnecting
    /// after a long absence should see the most recent messages,
    /// even at the cost of dropping the oldest. Sender-side TTL
    /// + retry caps already bound how long a sender keeps trying;
    /// this just decides which N of M to keep.
    pub fn enqueue(
        &mut self,
        peer_id: Vec<u8>,
        frame: PendingFrame,
    ) -> io::Result<EnqueueOutcome> {
        let is_new_peer = !self.queues.contains_key(&peer_id);
        // Global distinct-peer cap: a frame to a not-yet-seen `to_id`
        // is refused once the store already holds the maximum number
        // of distinct queues.
        if is_new_peer && self.queues.len() >= self.max_distinct_peers {
            return Ok(EnqueueOutcome::RejectedGlobalCap);
        }
        // Global frame-count cap. The per-peer eviction below can
        // free a slot, so this is only a hard reject when the
        // recipient's own queue is not already at its per-peer cap
        // (i.e. accepting the frame genuinely adds to the total).
        let queue_len = self.queues.get(&peer_id).map(|q| q.len()).unwrap_or(0);
        let per_peer_eviction = queue_len >= self.max_per_peer;
        let total_frames = self.total_frames();
        if !per_peer_eviction && total_frames >= self.max_total_frames {
            return Ok(EnqueueOutcome::RejectedGlobalCap);
        }
        // Global byte-count cap. Account for the bytes the per-peer
        // eviction would reclaim so a steady-state full per-peer
        // queue can still rotate without tripping the global cap.
        let incoming = frame.byte_len();
        let reclaimed = if per_peer_eviction {
            self.queues
                .get(&peer_id)
                .and_then(|q| q.front())
                .map(|f| f.byte_len())
                .unwrap_or(0)
        } else {
            0
        };
        if self.total_bytes() + incoming > self.max_total_bytes + reclaimed {
            return Ok(EnqueueOutcome::RejectedGlobalCap);
        }

        let queue = self.queues.entry(peer_id).or_default();
        while queue.len() >= self.max_per_peer {
            queue.pop_front();
        }
        queue.push_back(frame);
        self.persist()?;
        Ok(EnqueueOutcome::Stored)
    }

    /// Remove and return `peer_id`'s entire queue (typically called
    /// by `drain_pending` on a fresh HELLO). Drops expired frames
    /// during the drain so the caller never forwards a stale
    /// envelope. Persists if anything was removed.
    pub fn drain(&mut self, peer_id: &[u8]) -> io::Result<VecDeque<PendingFrame>> {
        let Some(queue) = self.queues.remove(peer_id) else {
            return Ok(VecDeque::new());
        };
        let now = encrypted_file::unix_now();
        let live: VecDeque<PendingFrame> =
            queue.into_iter().filter(|f| !f.is_expired(now)).collect();
        // `remove` already mutated `queues` — persist the new state
        // unconditionally so the recipient doesn't re-receive frames
        // after a subsequent relay restart.
        self.persist()?;
        Ok(live)
    }

    /// Walk every per-peer queue and drop expired frames in place.
    /// Returns the number of frames removed. Run periodically by
    /// the GC task. Persists only if something was actually dropped
    /// — keeps the steady-state idle relay from rewriting the file
    /// every 5 minutes for no reason.
    pub fn gc_expired(&mut self) -> io::Result<usize> {
        let now = encrypted_file::unix_now();
        let mut dropped = 0usize;
        self.queues.retain(|_, queue| {
            let before = queue.len();
            queue.retain(|f| !f.is_expired(now));
            dropped += before - queue.len();
            !queue.is_empty()
        });
        if dropped > 0 {
            self.persist()?;
        }
        Ok(dropped)
    }

    /// Serialize the in-memory queues, encrypt, atomically replace
    /// the file. Same shape as `PushTokenStore::persist` — the
    /// `encrypted_file::write_atomic` call is the commit point.
    fn persist(&self) -> io::Result<()> {
        let mut doc = StoreDoc::default();
        for (peer_id, queue) in &self.queues {
            if queue.is_empty() {
                continue;
            }
            doc.queues
                .insert(encrypted_file::hex_encode(peer_id), queue.clone());
        }
        let plaintext = serde_json::to_vec(&doc).map_err(io::Error::other)?;
        let ciphertext = encrypted_file::encrypt_with_aad(&self.key, &plaintext, AAD)?;
        encrypted_file::write_atomic(&self.pending_path, &ciphertext)
    }
}

/// Drop expired frames + decode hex peer-id keys back into the
/// live `HashMap<Vec<u8>, VecDeque<PendingFrame>>` shape used by the
/// store. A malformed peer-id key is silently skipped (corrupt
/// single row < refuse-to-start).
fn drop_expired(
    doc: StoreDoc,
    now: u64,
) -> HashMap<Vec<u8>, VecDeque<PendingFrame>> {
    let mut map = HashMap::with_capacity(doc.queues.len());
    for (peer_hex, queue) in doc.queues {
        let peer_id = match encrypted_file::hex_decode(&peer_hex) {
            Some(p) => p,
            None => continue,
        };
        let live: VecDeque<PendingFrame> = queue.into_iter().filter(|f| !f.is_expired(now)).collect();
        if !live.is_empty() {
            map.insert(peer_id, live);
        }
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

    const TEST_CAP: usize = 5;
    // Generous global caps for tests that aren't exercising them —
    // high enough that only the per-peer cap is in play.
    const TEST_MAX_PEERS: usize = 1024;
    const TEST_MAX_FRAMES: usize = 16_384;
    const TEST_MAX_BYTES: usize = 64 * 1024 * 1024;

    fn fresh_state_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("pizzini-pending-test-{label}-{nanos}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// `load_or_create` with the per-test per-peer `cap` and the
    /// generous global caps above — keeps the bulk of the tests on
    /// the original two-arg shape.
    fn open(dir: &Path, cap: usize) -> PendingStore {
        PendingStore::load_or_create(dir, cap, TEST_MAX_PEERS, TEST_MAX_FRAMES, TEST_MAX_BYTES)
            .unwrap()
    }

    fn frame_with_ttl(body: u8, ttl_secs: u64) -> PendingFrame {
        PendingFrame::new(
            vec![body; 64],
            encrypted_file::unix_now() + ttl_secs,
        )
    }

    #[test]
    fn round_trip_persist_and_reload() {
        let dir = fresh_state_dir("roundtrip");
        let alice = vec![0xAA; 33];
        let bob = vec![0xBB; 33];
        {
            let mut store = open(&dir, TEST_CAP);
            store.enqueue(alice.clone(), frame_with_ttl(0x11, 3600)).unwrap();
            store.enqueue(alice.clone(), frame_with_ttl(0x22, 3600)).unwrap();
            store.enqueue(bob.clone(), frame_with_ttl(0x33, 3600)).unwrap();
        }
        {
            // Re-open: persistence survived the close, queues retain
            // arrival order, hex round-trip is symmetric.
            let mut store = open(&dir, TEST_CAP);
            assert_eq!(store.total_frames(), 3);
            assert_eq!(store.peers_with_queues(), 2);
            let drained = store.drain(&alice).unwrap();
            assert_eq!(drained.len(), 2);
            assert_eq!(drained[0].bytes(), vec![0x11; 64]);
            assert_eq!(drained[1].bytes(), vec![0x22; 64]);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn drain_removes_peer_queue_from_store() {
        let dir = fresh_state_dir("drainremoves");
        let alice = vec![0x11; 33];
        let mut store = open(&dir, TEST_CAP);
        store.enqueue(alice.clone(), frame_with_ttl(1, 3600)).unwrap();
        assert_eq!(store.total_frames(), 1);
        let drained = store.drain(&alice).unwrap();
        assert_eq!(drained.len(), 1);
        // After drain the peer's row is gone — a subsequent drain
        // returns empty (NOT a re-delivery of the same frame).
        assert_eq!(store.drain(&alice).unwrap().len(), 0);
        assert_eq!(store.total_frames(), 0);
        // And the persisted state agrees: reloaded store sees the
        // empty queue too.
        drop(store);
        let reopened = open(&dir, TEST_CAP);
        assert_eq!(reopened.total_frames(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_peer_cap_evicts_oldest() {
        let dir = fresh_state_dir("cap");
        let alice = vec![0xCC; 33];
        let mut store = open(&dir, 3);
        for i in 0..6u8 {
            store
                .enqueue(alice.clone(), frame_with_ttl(0x10 + i, 3600))
                .unwrap();
        }
        let drained = store.drain(&alice).unwrap();
        // Cap=3 with 6 inserts → keep newest 3 (the entries with body
        // 0x13, 0x14, 0x15 — bodies 0x10/0x11/0x12 evicted).
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].bytes()[0], 0x13);
        assert_eq!(drained[1].bytes()[0], 0x14);
        assert_eq!(drained[2].bytes()[0], 0x15);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_frames_dropped_on_load() {
        let dir = fresh_state_dir("expired");
        let alice = vec![0xAA; 33];
        {
            let mut store = open(&dir, TEST_CAP);
            // Fresh frame survives; "expired 1h ago" frame dropped.
            let now = encrypted_file::unix_now();
            store
                .enqueue(
                    alice.clone(),
                    PendingFrame::new(vec![0xFE; 64], now.saturating_sub(3600)),
                )
                .unwrap();
            store.enqueue(alice.clone(), frame_with_ttl(0xAB, 3600)).unwrap();
        }
        let mut reopened = open(&dir, TEST_CAP);
        assert_eq!(reopened.total_frames(), 1);
        let drained = reopened.drain(&alice).unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].bytes()[0], 0xAB);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn gc_expired_drops_in_place() {
        let dir = fresh_state_dir("gc");
        let alice = vec![0xAA; 33];
        let bob = vec![0xBB; 33];
        let mut store = open(&dir, TEST_CAP);
        let now = encrypted_file::unix_now();
        store.enqueue(alice.clone(), PendingFrame::new(vec![1; 8], now.saturating_sub(60))).unwrap();
        store.enqueue(alice.clone(), frame_with_ttl(2, 3600)).unwrap();
        store.enqueue(bob.clone(), PendingFrame::new(vec![3; 8], now.saturating_sub(60))).unwrap();
        let dropped = store.gc_expired().unwrap();
        assert_eq!(dropped, 2);
        // Alice keeps 1 live frame; Bob's row is gone (queue emptied).
        assert_eq!(store.total_frames(), 1);
        assert_eq!(store.peers_with_queues(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_key_length_refuses_to_load() {
        let dir = fresh_state_dir("badkey");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(KEY_FILE_NAME), b"too short").unwrap();
        let err = PendingStore::load_or_create(
            &dir,
            TEST_CAP,
            TEST_MAX_PEERS,
            TEST_MAX_FRAMES,
            TEST_MAX_BYTES,
        )
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_pending_file_refuses_to_load() {
        let dir = fresh_state_dir("tampered");
        {
            let mut store = open(&dir, TEST_CAP);
            store.enqueue(vec![0x11; 33], frame_with_ttl(0xAA, 3600)).unwrap();
        }
        let path = dir.join(PENDING_FILE_NAME);
        let mut bytes = fs::read(&path).unwrap();
        let mid = (bytes.len() - 1).max(encrypted_file::NONCE_LEN);
        bytes[mid] ^= 0x01;
        fs::write(&path, bytes).unwrap();
        let err = PendingStore::load_or_create(
            &dir,
            TEST_CAP,
            TEST_MAX_PEERS,
            TEST_MAX_FRAMES,
            TEST_MAX_BYTES,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("decrypt") || err.kind() == ErrorKind::InvalidData,
            "unexpected error: {err}",
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_dir_starts_empty() {
        let dir = fresh_state_dir("empty");
        let store = open(&dir, TEST_CAP);
        assert_eq!(store.total_frames(), 0);
        assert!(dir.join(KEY_FILE_NAME).exists());
        assert!(!dir.join(PENDING_FILE_NAME).exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn global_distinct_peer_cap_refuses_new_to_ids() {
        // An attacker picking a fresh fabricated `to_id` per frame is
        // bounded by the distinct-peer cap regardless of how few
        // frames each queue holds.
        let dir = fresh_state_dir("globalpeers");
        let mut store =
            PendingStore::load_or_create(&dir, TEST_CAP, 3, TEST_MAX_FRAMES, TEST_MAX_BYTES)
                .unwrap();
        for i in 0..3u8 {
            assert_eq!(
                store
                    .enqueue(vec![i; 33], frame_with_ttl(i, 3600))
                    .unwrap(),
                EnqueueOutcome::Stored,
            );
        }
        // 4th distinct peer is refused — fail closed, store unchanged.
        assert_eq!(
            store
                .enqueue(vec![0xFF; 33], frame_with_ttl(0xFF, 3600))
                .unwrap(),
            EnqueueOutcome::RejectedGlobalCap,
        );
        assert_eq!(store.peers_with_queues(), 3);
        // An already-known peer can still enqueue (up to its per-peer
        // cap) — the distinct-peer cap only gates *new* queues.
        assert_eq!(
            store.enqueue(vec![0u8; 33], frame_with_ttl(1, 3600)).unwrap(),
            EnqueueOutcome::Stored,
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn global_frame_count_cap_refuses_overflow() {
        // Total frame count is hard-bounded even when no single
        // per-peer queue is full.
        let dir = fresh_state_dir("globalframes");
        let mut store =
            PendingStore::load_or_create(&dir, TEST_CAP, TEST_MAX_PEERS, 4, TEST_MAX_BYTES)
                .unwrap();
        // Two peers, two frames each — exactly fills the global cap.
        for p in 0..2u8 {
            for f in 0..2u8 {
                assert_eq!(
                    store
                        .enqueue(vec![p; 33], frame_with_ttl(f, 3600))
                        .unwrap(),
                    EnqueueOutcome::Stored,
                );
            }
        }
        assert_eq!(store.total_frames(), 4);
        // One more frame to an existing peer (not at its per-peer
        // cap) is refused by the global frame-count cap.
        assert_eq!(
            store.enqueue(vec![0u8; 33], frame_with_ttl(9, 3600)).unwrap(),
            EnqueueOutcome::RejectedGlobalCap,
        );
        assert_eq!(store.total_frames(), 4);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn global_byte_cap_refuses_overflow() {
        // Total queued bytes are hard-bounded. `frame_with_ttl`
        // produces 64-byte frames; a 200-byte cap admits 3 of them.
        let dir = fresh_state_dir("globalbytes");
        let mut store =
            PendingStore::load_or_create(&dir, TEST_CAP, TEST_MAX_PEERS, TEST_MAX_FRAMES, 200)
                .unwrap();
        for i in 0..3u8 {
            assert_eq!(
                store
                    .enqueue(vec![i; 33], frame_with_ttl(i, 3600))
                    .unwrap(),
                EnqueueOutcome::Stored,
            );
        }
        // 4th 64-byte frame would push past 200 bytes — refused.
        assert_eq!(
            store
                .enqueue(vec![0xAB; 33], frame_with_ttl(0xAB, 3600))
                .unwrap(),
            EnqueueOutcome::RejectedGlobalCap,
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_peer_rotation_still_works_at_global_byte_cap() {
        // A peer whose own queue is full can still rotate (evict
        // oldest, push newest) without tripping the global byte cap —
        // the reclaimed bytes are accounted for.
        let dir = fresh_state_dir("globalrotate");
        // per-peer cap 2, byte cap exactly 2 frames' worth (128).
        let mut store =
            PendingStore::load_or_create(&dir, 2, TEST_MAX_PEERS, TEST_MAX_FRAMES, 128).unwrap();
        let alice = vec![0xAA; 33];
        assert_eq!(
            store.enqueue(alice.clone(), frame_with_ttl(1, 3600)).unwrap(),
            EnqueueOutcome::Stored,
        );
        assert_eq!(
            store.enqueue(alice.clone(), frame_with_ttl(2, 3600)).unwrap(),
            EnqueueOutcome::Stored,
        );
        // Queue is at its per-peer cap and the store is at the byte
        // cap — but this enqueue evicts the oldest first, so it is
        // a rotation, not growth: it must still succeed.
        assert_eq!(
            store.enqueue(alice.clone(), frame_with_ttl(3, 3600)).unwrap(),
            EnqueueOutcome::Stored,
        );
        let drained = store.drain(&alice).unwrap();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].bytes()[0], 2);
        assert_eq!(drained[1].bytes()[0], 3);
        let _ = fs::remove_dir_all(&dir);
    }
}
