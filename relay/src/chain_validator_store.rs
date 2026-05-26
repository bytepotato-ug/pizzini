//! Persistent per-(recipient, chain_id) hash-chain validator state.
//!
//! Stage-3b of the delivery-token v2 rollout. Replaces the v1
//! Ed25519-signed-token replay-set with hash-chained validation:
//!
//!   * Recipient mints a chain `(seed, root = H^n(seed))`, ships the
//!     seed to the sender via the sealed Double Ratchet, registers
//!     `(chain_id, root, length)` with this relay via `REGISTER_CHAIN`.
//!   * Sender presents `(chain_id, index, value)` where
//!     `value == H^(length − index)(seed)` on every SEND.
//!   * Relay validates a presentation by hashing `value` forward
//!     `(index − last_index)` times and comparing to `last_value`;
//!     on success, `last_index := index` and `last_value := value`.
//!     Replays and out-of-order presentations are rejected.
//!
//! Persistence shape mirrors `replay_store.rs` and `pending_store.rs`:
//! encrypted-at-rest via `encrypted_file`, atomic-write on every
//! mutation, TTL purge on load. Wall-clock seconds for `last_used`
//! so a process restart can correctly age out abandoned chains.

use crate::encrypted_file;
use serde::{Deserialize, Serialize};
// Chain primitive is BLAKE3 — keeps the app-code hash audit surface
// to a single algorithm (the same one used by hashcash, group-op
// digests, and the iOS challenge derivation). The Swift side's
// `HashChainToken.applyHash` must use the same primitive bit-for-bit.
use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::Duration;

const FILE_NAME: &str = "chain_validators.bin";
const KEY_FILE_NAME: &str = "chain_validators.key";

/// Per-store AAD. Domain-separated from sibling stores so a swap
/// attack (replacing one store's ciphertext with another's) fails
/// at AEAD verify.
const AAD: &[u8] = b"pizzini.relay.chain_validators.v1";

/// PZ-H2: append-only journal alongside the snapshot. Each replay-cursor
/// advance (and chain registration) appends one small encrypted,
/// length-prefixed record here and fsyncs it — O(1) — instead of
/// re-encrypting the WHOLE snapshot + double-fsync on every mutation
/// (the write-amplification DoS). The snapshot is the periodically
/// compacted base; the journal holds mutations since the last compaction.
const JOURNAL_FILE_NAME: &str = "chain_validators.journal";

/// Domain-separated AAD for journal records, distinct from the snapshot's
/// `AAD`, so a snapshot blob can't be replayed as a journal record (or
/// vice-versa) under the shared key.
const JOURNAL_AAD: &[u8] = b"pizzini.relay.chain_validators.journal.v1";

/// Compact (rewrite snapshot + truncate journal) once this many records
/// have been appended since the last compaction. Bounds journal size and
/// startup replay cost while keeping the per-advance write O(1) amortized.
const JOURNAL_COMPACT_THRESHOLD: u64 = 4096;

pub const CHAIN_ID_LEN: usize = 16;
pub const CHAIN_VALUE_LEN: usize = 32;

/// Hard cap on chain length so a malicious recipient can't register
/// a chain with `length = u32::MAX` and force linear-in-length work
/// on every validation. Chains longer than this are refused at
/// registration. 2^20 (~1 M presentations) is well above any
/// realistic user's lifetime traffic to one peer.
pub const MAX_CHAIN_LENGTH: u32 = 1 << 20;

/// F-MEM-07 / F-RP-02: cap on how far a single presentation may advance
/// the chain index in one `validate` call. The validator walks
/// `delta = index - last_index` BLAKE3 steps under the global validator
/// lock; without a cap a presentation claiming `index = length` forces up
/// to `MAX_CHAIN_LENGTH` (~1M) hashes — and on a `BadChainValue` the cursor
/// is NOT advanced, so a wrong-value flood re-pays the full walk on every
/// frame, head-of-line-blocking all peers. Legitimate senders advance one
/// step at a time; 64 leaves generous slack for lost-ACK / dropped-frame
/// catch-up while bounding per-frame work to a small constant. A larger
/// jump is rejected as out-of-range before any hashing.
pub const MAX_VALIDATE_STEPS: u32 = 64;

/// F-RP-01: per-peer cap on distinct registered chains. A peer_id is a
/// free-to-mint HELLO identity, so without this one identity could
/// register unbounded `(peer, chain)` entries (REGISTER_CHAIN has no rate
/// limit) and grow the persistent store + its O(n) re-encrypt cost without
/// bound. 32 distinct chains per peer is far above any realistic per-contact
/// rotation rate.
pub const MAX_CHAINS_PER_PEER: usize = 32;
/// F-RP-01: global cap on total distinct `(peer, chain)` entries — the
/// backstop against a Sybil flood that rotates peer_id for every chain to
/// defeat the per-peer cap. New registrations past this are refused; the
/// idle-TTL GC reclaims space.
pub const MAX_TOTAL_CHAINS: usize = 100_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    /// Composite hex key: `{peer_id_hex}:{chain_id_hex}` for JSON
    /// flatness; decoded back to bytes on load via `decompose_key`.
    root_hex: String,
    length: u32,
    last_index: u32,
    last_value_hex: String,
    registered_unix: u64,
    last_used_unix: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct StoreDoc {
    entries: HashMap<String, StoredEntry>,
}

/// One appended mutation (PZ-H2): the full authoritative `StoredEntry`
/// for a composite key. GC removals do NOT append a tombstone —
/// `gc_expired` compacts instead — so every journal record is an upsert.
/// Replay is monotonic (see `apply_monotonic`), so a stale record left
/// behind by a crash between snapshot-write and journal-truncate can
/// never regress a cursor.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalRecord {
    key: String,
    entry: StoredEntry,
}

/// Outcome of a validation attempt. `Accepted` means state was
/// advanced and persisted; `Rejected` means nothing changed.
#[derive(Debug, PartialEq, Eq)]
pub enum ValidateOutcome {
    Accepted,
    /// Recipient or chain isn't registered.
    UnknownChain,
    /// `index <= last_index` (replay) or `index > length` (past end).
    OutOfRange,
    /// Hash chain didn't verify — the presented value is not on the
    /// recipient's chain.
    BadChainValue,
}

#[derive(Debug, Clone, Copy)]
pub struct ChainRegistration {
    pub peer_id: [u8; 33],
    pub chain_id: [u8; CHAIN_ID_LEN],
    pub root: [u8; CHAIN_VALUE_LEN],
    pub length: u32,
}

pub struct ChainValidatorStore {
    path: PathBuf,
    journal_path: PathBuf,
    key: [u8; encrypted_file::KEY_LEN],
    /// `(peer_id, chain_id) → state`.
    map: HashMap<(Vec<u8>, [u8; CHAIN_ID_LEN]), ChainState>,
    /// Records appended to the journal since the last compaction; drives
    /// the `JOURNAL_COMPACT_THRESHOLD` compaction trigger.
    journal_len: u64,
}

#[derive(Debug, Clone)]
struct ChainState {
    root: [u8; CHAIN_VALUE_LEN],
    length: u32,
    last_index: u32,
    last_value: [u8; CHAIN_VALUE_LEN],
    registered_unix: u64,
    last_used_unix: u64,
}

impl std::fmt::Debug for ChainValidatorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainValidatorStore")
            .field("path", &self.path)
            .field("key", &"[redacted 32 bytes]")
            .field("entries", &self.map.len())
            .finish()
    }
}

#[allow(dead_code)] // `len` / `gc_expired` wired into main.rs in the next commit.
impl ChainValidatorStore {
    pub fn load_or_create(state_dir: &Path, max_age: Duration) -> io::Result<Self> {
        fs::create_dir_all(state_dir)?;
        encrypted_file::restrict_permissions(state_dir, 0o700);
        let path = state_dir.join(FILE_NAME);
        let key_path = state_dir.join(KEY_FILE_NAME);
        let key = encrypted_file::load_or_create_key(&key_path, "chain-validator")?;

        let mut map = match fs::read(&path) {
            Ok(bytes) => {
                let plaintext = encrypted_file::decrypt_with_aad(&key, &bytes, AAD)
                    .or_else(|_| encrypted_file::decrypt(&key, &bytes))?;
                let doc: StoreDoc =
                    serde_json::from_slice(&plaintext).map_err(io::Error::other)?;
                purge_stale(doc, max_age)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };

        // PZ-H2: fold the append-only journal over the snapshot. Monotonic
        // apply means a record can only advance a cursor, never regress it,
        // so a crash between a compaction's snapshot-write and journal-
        // truncate is safe (the stale records are <= the snapshot and are
        // ignored).
        let journal_path = state_dir.join(JOURNAL_FILE_NAME);
        let replayed = replay_journal(&journal_path, &key, max_age, &mut map)?;

        let mut store = ChainValidatorStore {
            path,
            journal_path,
            key,
            map,
            journal_len: replayed,
        };
        // Make the journal file exist with a durable directory entry, so
        // every subsequent append needs only a file fsync (not a parent-dir
        // fsync) on the hot path.
        store.ensure_journal_durable_exists()?;
        // If we just folded a non-empty journal, compact once at startup so
        // the snapshot is current and the journal starts small.
        if replayed > 0 {
            store.compact()?;
        }
        Ok(store)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Register a fresh chain. Idempotent on `(peer_id, chain_id)`:
    /// re-registering the same key with the same root/length is a
    /// no-op; conflicting registrations (same key, different root)
    /// are refused so a relay-MITM can't quietly swap chains.
    pub fn register(&mut self, reg: ChainRegistration) -> io::Result<RegisterOutcome> {
        if reg.length == 0 || reg.length > MAX_CHAIN_LENGTH {
            return Ok(RegisterOutcome::BadLength);
        }
        let now = encrypted_file::unix_now();
        let key = (reg.peer_id.to_vec(), reg.chain_id);
        if let Some(existing) = self.map.get(&key) {
            if existing.root == reg.root && existing.length == reg.length {
                return Ok(RegisterOutcome::AlreadyRegistered);
            }
            return Ok(RegisterOutcome::Conflict);
        }
        // F-RP-01: bound store growth before inserting a NEW key. Existing
        // keys took the idempotent/conflict path above and are unaffected, so
        // legitimate re-registration always succeeds even at the cap.
        if self.map.len() >= MAX_TOTAL_CHAINS {
            return Ok(RegisterOutcome::RejectedCap);
        }
        let per_peer = self
            .map
            .keys()
            .filter(|(p, _)| p.as_slice() == reg.peer_id.as_slice())
            .take(MAX_CHAINS_PER_PEER)
            .count();
        if per_peer >= MAX_CHAINS_PER_PEER {
            return Ok(RegisterOutcome::RejectedCap);
        }
        let state = ChainState {
            root: reg.root,
            length: reg.length,
            last_index: 0,
            last_value: reg.root,
            registered_unix: now,
            last_used_unix: now,
        };
        self.map.insert(key, state.clone());
        self.append_journal(&reg.peer_id, &reg.chain_id, &state)?;
        Ok(RegisterOutcome::Registered)
    }

    /// Validate a presentation. On `Accepted`, the state is advanced
    /// AND persisted atomically (write-then-rename) so a crash mid-
    /// validation can never leave the on-disk state ahead of the
    /// in-memory state.
    pub fn validate(
        &mut self,
        peer_id: &[u8],
        chain_id: &[u8; CHAIN_ID_LEN],
        index: u32,
        value: &[u8; CHAIN_VALUE_LEN],
    ) -> io::Result<ValidateOutcome> {
        let key = (peer_id.to_vec(), *chain_id);
        let Some(state) = self.map.get_mut(&key) else {
            return Ok(ValidateOutcome::UnknownChain);
        };
        if index == 0 || index <= state.last_index || index > state.length {
            return Ok(ValidateOutcome::OutOfRange);
        }
        let delta = index - state.last_index;
        // F-MEM-07 / F-RP-02: bound the forward walk to a small constant so a
        // single presentation cannot force a multi-hundred-thousand BLAKE3
        // loop under the global lock. Reject an oversized jump before hashing.
        if delta > MAX_VALIDATE_STEPS {
            return Ok(ValidateOutcome::OutOfRange);
        }
        let mut current = *value;
        for _ in 0..delta {
            // AUDIT-DECISION-NEEDED: the chain step is a bare
            // `BLAKE3(value)` with no domain-separation tag and no
            // `chain_id` binding, so chain isolation rests on seed
            // entropy rather than on the hash construction. The
            // audited remediation is a wire-format change to
            // `BLAKE3(b"pizzini.chain-token.v2" || chain_id ||
            // value)` — but it MUST match the iOS prover
            // (`HashChainToken.applyHash`) bit-for-bit, and there is
            // currently NO chain-version field anywhere in the wire
            // token (`parse_v2_token`), the registration
            // (`ChainRegistration`), or the stored state
            // (`StoredEntry`) to gate old vs. new chains on. Changing
            // the step unconditionally would invalidate every
            // already-registered chain on both sides. This needs a
            // versioning hook designed in first — do not change the
            // hash step here without that.
            let out = blake3::hash(&current);
            current.copy_from_slice(out.as_bytes());
        }
        // Constant-time compare on the 32-byte chain value. Without
        // this a relay implementation under timing observation could
        // leak the number of matching prefix bytes — see Swift's
        // `constantTimeEquals` in `HashChainToken.swift`.
        let mut diff: u8 = 0;
        for i in 0..CHAIN_VALUE_LEN {
            diff |= current[i] ^ state.last_value[i];
        }
        if diff != 0 {
            return Ok(ValidateOutcome::BadChainValue);
        }
        state.last_index = index;
        state.last_value = *value;
        state.last_used_unix = encrypted_file::unix_now();
        // Clone the advanced state so the `&mut self.map` borrow held by
        // `state` ends before `append_journal` reborrows `&mut self`.
        let advanced = state.clone();
        // PZ-H2: persist the advance via an O(1) fsync'd journal append.
        // The append is durable BEFORE we return `Accepted` — that is the
        // replay guarantee (a crash after the OK can't roll the cursor back).
        self.append_journal(peer_id, chain_id, &advanced)?;
        Ok(ValidateOutcome::Accepted)
    }

    /// Drop entries whose `last_used_unix` is older than `max_age`.
    /// A chain whose sender hasn't sent for `max_age` is presumed
    /// rotated (or the contact unpaired); the relay isn't the
    /// authority on contact lifetime, but holding stale chain state
    /// forever isn't free.
    pub fn gc_expired(&mut self, max_age: Duration) -> io::Result<usize> {
        let now = encrypted_file::unix_now();
        let cutoff = now.saturating_sub(max_age.as_secs());
        let before = self.map.len();
        self.map.retain(|_, state| state.last_used_unix > cutoff);
        let removed = before - self.map.len();
        if removed > 0 {
            // Compaction rewrites the snapshot without the removed entries
            // and truncates the journal, so the removals are durable and the
            // journal can't re-introduce a purged chain on the next load.
            self.compact()?;
        }
        Ok(removed)
    }

    /// Append one mutation to the journal and fsync it. O(1) in the store
    /// size — this is the hot-path replacement for a full snapshot rewrite.
    /// The fsync makes the record durable BEFORE the caller treats the
    /// advance/registration as committed (the replay guarantee). Triggers a
    /// compaction once the journal passes `JOURNAL_COMPACT_THRESHOLD`.
    fn append_journal(
        &mut self,
        peer_id: &[u8],
        chain_id: &[u8; CHAIN_ID_LEN],
        state: &ChainState,
    ) -> io::Result<()> {
        let rec = JournalRecord {
            key: composite_key(peer_id, chain_id),
            entry: stored_entry_of(state),
        };
        let plaintext = serde_json::to_vec(&rec).map_err(io::Error::other)?;
        let ciphertext = encrypted_file::encrypt_with_aad(&self.key, &plaintext, JOURNAL_AAD)?;
        let len: u32 = ciphertext
            .len()
            .try_into()
            .map_err(|_| io::Error::other("journal record too large"))?;
        let mut framed = Vec::with_capacity(4 + ciphertext.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&ciphertext);
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.journal_path)?;
            f.write_all(&framed)?;
            // sync_all flushes the appended bytes + the file-size metadata.
            // The directory entry is already durable (ensure_journal_durable_
            // exists), so no parent-dir fsync is needed on the hot path.
            f.sync_all()?;
        }
        self.journal_len += 1;
        if self.journal_len >= JOURNAL_COMPACT_THRESHOLD {
            self.compact()?;
        }
        Ok(())
    }

    /// Rewrite the snapshot from the in-memory map, then truncate the
    /// journal. Order matters: the snapshot (which subsumes every journal
    /// record) is made durable FIRST, so a crash before truncation just
    /// leaves stale journal records that monotonic replay ignores.
    fn compact(&mut self) -> io::Result<()> {
        self.write_snapshot()?;
        self.truncate_journal()?;
        self.journal_len = 0;
        Ok(())
    }

    /// Serialize the whole map and atomically replace the snapshot file.
    /// This is the (now rare) O(n) write; the per-mutation hot path is
    /// `append_journal`.
    fn write_snapshot(&self) -> io::Result<()> {
        let mut doc = StoreDoc::default();
        for ((peer_id, chain_id), state) in &self.map {
            doc.entries
                .insert(composite_key(peer_id, chain_id), stored_entry_of(state));
        }
        let plaintext = serde_json::to_vec(&doc).map_err(io::Error::other)?;
        let ciphertext = encrypted_file::encrypt_with_aad(&self.key, &plaintext, AAD)?;
        encrypted_file::write_atomic(&self.path, &ciphertext)
    }

    /// Empty the journal (O_TRUNC keeps the same inode + directory entry, so
    /// no parent-dir fsync is needed) and fsync so the truncation is durable
    /// before the next append starts a fresh sequence.
    fn truncate_journal(&self) -> io::Result<()> {
        let f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.journal_path)?;
        encrypted_file::restrict_permissions(&self.journal_path, 0o600);
        f.sync_all()
    }

    /// Create the journal file (empty) if it doesn't exist yet, tighten its
    /// permissions, and fsync the parent directory so the new file's
    /// directory entry is durable. After this, an append's `sync_all` alone
    /// makes the appended record durable.
    fn ensure_journal_durable_exists(&self) -> io::Result<()> {
        if self.journal_path.exists() {
            return Ok(());
        }
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)?;
        encrypted_file::restrict_permissions(&self.journal_path, 0o600);
        if let Some(parent) = self.journal_path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Ok(dir) = fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// Fresh chain stored.
    Registered,
    /// Same `(peer_id, chain_id)` already present with identical
    /// root + length. No-op; safe to retry registrations after a
    /// reconnect.
    AlreadyRegistered,
    /// Same `(peer_id, chain_id)` present with a different root or
    /// length. Refused so a relay-side adversary can't quietly swap.
    Conflict,
    /// `length == 0` or `length > MAX_CHAIN_LENGTH`.
    BadLength,
    /// F-RP-01: refused because the per-peer (`MAX_CHAINS_PER_PEER`) or
    /// global (`MAX_TOTAL_CHAINS`) chain cap is already reached. Bounds
    /// flooding of the persistent store by a free HELLO identity / Sybil.
    RejectedCap,
}

/// Composite hex key `{peer_hex}:{chain_hex}` used in the JSON snapshot
/// and journal records.
fn composite_key(peer_id: &[u8], chain_id: &[u8]) -> String {
    format!(
        "{}:{}",
        encrypted_file::hex_encode(peer_id),
        encrypted_file::hex_encode(chain_id),
    )
}

/// Project an in-memory `ChainState` to its serializable form.
fn stored_entry_of(state: &ChainState) -> StoredEntry {
    StoredEntry {
        root_hex: encrypted_file::hex_encode(&state.root),
        length: state.length,
        last_index: state.last_index,
        last_value_hex: encrypted_file::hex_encode(&state.last_value),
        registered_unix: state.registered_unix,
        last_used_unix: state.last_used_unix,
    }
}

/// Decode a `(composite, StoredEntry)` back to a map key + `ChainState`.
/// Returns `None` on any malformed field so the caller skips that entry
/// rather than failing the whole load. Shared by snapshot purge + journal
/// replay so both decode identically.
fn decode_entry(
    composite: &str,
    entry: &StoredEntry,
) -> Option<((Vec<u8>, [u8; CHAIN_ID_LEN]), ChainState)> {
    let (peer_hex, chain_hex) = composite.split_once(':')?;
    let peer = encrypted_file::hex_decode(peer_hex)?;
    let chain_id_vec = encrypted_file::hex_decode(chain_hex)?;
    if chain_id_vec.len() != CHAIN_ID_LEN {
        return None;
    }
    let root_vec = encrypted_file::hex_decode(&entry.root_hex)?;
    let last_val_vec = encrypted_file::hex_decode(&entry.last_value_hex)?;
    if root_vec.len() != CHAIN_VALUE_LEN || last_val_vec.len() != CHAIN_VALUE_LEN {
        return None;
    }
    let mut chain_id = [0u8; CHAIN_ID_LEN];
    chain_id.copy_from_slice(&chain_id_vec);
    let mut root = [0u8; CHAIN_VALUE_LEN];
    root.copy_from_slice(&root_vec);
    let mut last_value = [0u8; CHAIN_VALUE_LEN];
    last_value.copy_from_slice(&last_val_vec);
    Some((
        (peer, chain_id),
        ChainState {
            root,
            length: entry.length,
            last_index: entry.last_index,
            last_value,
            registered_unix: entry.registered_unix,
            last_used_unix: entry.last_used_unix,
        },
    ))
}

fn purge_stale(
    doc: StoreDoc,
    max_age: Duration,
) -> HashMap<(Vec<u8>, [u8; CHAIN_ID_LEN]), ChainState> {
    let now = encrypted_file::unix_now();
    let cutoff = now.saturating_sub(max_age.as_secs());
    let mut out: HashMap<(Vec<u8>, [u8; CHAIN_ID_LEN]), ChainState> = HashMap::new();
    for (composite, entry) in &doc.entries {
        if entry.last_used_unix <= cutoff {
            continue;
        }
        if let Some((k, state)) = decode_entry(composite, entry) {
            out.insert(k, state);
        }
    }
    out
}

/// Replay the append-only journal over `map`. Each `[u32 len][ciphertext]`
/// record is decrypted, decoded, and applied monotonically. A truncated or
/// undecryptable trailing record (a crash mid-append, before the advance
/// was fsync'd and thus before the caller ever saw `Accepted`) ends replay
/// cleanly. Stale-by-TTL records are skipped but still counted, so a
/// startup compaction reclaims them. Returns the number of records read.
fn replay_journal(
    path: &Path,
    key: &[u8; encrypted_file::KEY_LEN],
    max_age: Duration,
    map: &mut HashMap<(Vec<u8>, [u8; CHAIN_ID_LEN]), ChainState>,
) -> io::Result<u64> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let now = encrypted_file::unix_now();
    let cutoff = now.saturating_sub(max_age.as_secs());
    let mut applied = 0u64;
    let mut off = 0usize;
    while off + 4 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if len == 0 || off + len > bytes.len() {
            break; // truncated trailing record — never durably committed
        }
        let ct = &bytes[off..off + len];
        off += len;
        let Ok(plaintext) = encrypted_file::decrypt_with_aad(key, ct, JOURNAL_AAD) else {
            break; // corrupt trailing record — stop, don't fail the load
        };
        let Ok(rec) = serde_json::from_slice::<JournalRecord>(&plaintext) else {
            break;
        };
        applied += 1;
        if rec.entry.last_used_unix <= cutoff {
            continue;
        }
        if let Some((k, state)) = decode_entry(&rec.key, &rec.entry) {
            apply_monotonic(map, k, state);
        }
    }
    Ok(applied)
}

/// Insert/overwrite only if it does not regress an existing cursor. This is
/// what makes a stale post-compaction journal harmless: a record whose
/// `last_index` is below what the snapshot already holds is ignored, so a
/// consumed token can never be replayed after a crash.
fn apply_monotonic(
    map: &mut HashMap<(Vec<u8>, [u8; CHAIN_ID_LEN]), ChainState>,
    k: (Vec<u8>, [u8; CHAIN_ID_LEN]),
    state: ChainState,
) {
    match map.get(&k) {
        Some(existing) if state.last_index < existing.last_index => { /* stale: keep current */ }
        _ => {
            map.insert(k, state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_chain(seed: [u8; 32], length: u32) -> ([u8; 32], Vec<[u8; 32]>) {
        // Returns (root, chain values at positions 0..=length).
        // Position i = H^i(seed). Token at sender-side index `j`
        // (1-indexed) is position `length − j`. Root = position
        // `length`.
        let mut positions = Vec::with_capacity(length as usize + 1);
        let mut current = seed;
        positions.push(current);
        for _ in 0..length {
            let out = blake3::hash(&current);
            let mut next = [0u8; 32];
            next.copy_from_slice(out.as_bytes());
            positions.push(next);
            current = next;
        }
        let root = positions[length as usize];
        (root, positions)
    }

    fn token_at(positions: &[[u8; 32]], length: u32, sender_index: u32) -> [u8; 32] {
        // token[i] = position (length − i)
        positions[(length - sender_index) as usize]
    }

    fn make_store(dir: &Path) -> ChainValidatorStore {
        ChainValidatorStore::load_or_create(dir, Duration::from_secs(86_400)).unwrap()
    }

    #[test]
    fn round_trip_register_and_validate() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let seed = [0x11u8; 32];
        let (root, positions) = fresh_chain(seed, 16);
        let reg = ChainRegistration {
            peer_id: [0xAA; 33],
            chain_id: [0xBB; 16],
            root,
            length: 16,
        };
        assert_eq!(store.register(reg).unwrap(), RegisterOutcome::Registered);
        // Present token at index 1: value = position 15.
        let t1 = token_at(&positions, 16, 1);
        assert_eq!(
            store.validate(&reg.peer_id, &reg.chain_id, 1, &t1).unwrap(),
            ValidateOutcome::Accepted,
        );
        // Replay must fail.
        assert_eq!(
            store.validate(&reg.peer_id, &reg.chain_id, 1, &t1).unwrap(),
            ValidateOutcome::OutOfRange,
        );
        // Token at index 2 must verify against the now-advanced state.
        let t2 = token_at(&positions, 16, 2);
        assert_eq!(
            store.validate(&reg.peer_id, &reg.chain_id, 2, &t2).unwrap(),
            ValidateOutcome::Accepted,
        );
    }

    #[test]
    fn register_rejects_zero_length() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let reg = ChainRegistration {
            peer_id: [0; 33],
            chain_id: [0; 16],
            root: [0; 32],
            length: 0,
        };
        assert_eq!(store.register(reg).unwrap(), RegisterOutcome::BadLength);
    }

    #[test]
    fn register_rejects_oversize_length() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let reg = ChainRegistration {
            peer_id: [0; 33],
            chain_id: [0; 16],
            root: [0; 32],
            length: MAX_CHAIN_LENGTH + 1,
        };
        assert_eq!(store.register(reg).unwrap(), RegisterOutcome::BadLength);
    }

    #[test]
    fn register_enforces_per_peer_cap() {
        // F-RP-01: a single peer_id may register at most MAX_CHAINS_PER_PEER
        // distinct chains; the next is RejectedCap, but a different peer is
        // still fine and idempotent re-registration of an existing key works.
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let (root, _) = fresh_chain([0x01; 32], 8);
        let peer = [0xAB; 33];
        for i in 0..MAX_CHAINS_PER_PEER {
            let mut chain_id = [0u8; 16];
            chain_id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let reg = ChainRegistration { peer_id: peer, chain_id, root, length: 8 };
            assert_eq!(store.register(reg).unwrap(), RegisterOutcome::Registered, "i={i}");
        }
        // The (cap+1)th distinct chain for the same peer is refused.
        let mut over = [0u8; 16];
        over[..8].copy_from_slice(&(MAX_CHAINS_PER_PEER as u64).to_be_bytes());
        let reg_over = ChainRegistration { peer_id: peer, chain_id: over, root, length: 8 };
        assert_eq!(store.register(reg_over).unwrap(), RegisterOutcome::RejectedCap);
        // Re-registering an EXISTING key for the capped peer still succeeds.
        let mut existing = [0u8; 16];
        existing[..8].copy_from_slice(&0u64.to_be_bytes());
        let reg_existing = ChainRegistration { peer_id: peer, chain_id: existing, root, length: 8 };
        assert_eq!(store.register(reg_existing).unwrap(), RegisterOutcome::AlreadyRegistered);
        // A different peer is unaffected by another peer's cap.
        let reg_other = ChainRegistration { peer_id: [0xCD; 33], chain_id: [0xFF; 16], root, length: 8 };
        assert_eq!(store.register(reg_other).unwrap(), RegisterOutcome::Registered);
    }

    #[test]
    fn idempotent_re_registration() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let (root, _) = fresh_chain([0x22; 32], 8);
        let reg = ChainRegistration {
            peer_id: [0x33; 33],
            chain_id: [0x44; 16],
            root,
            length: 8,
        };
        assert_eq!(store.register(reg).unwrap(), RegisterOutcome::Registered);
        assert_eq!(
            store.register(reg).unwrap(),
            RegisterOutcome::AlreadyRegistered,
        );
    }

    #[test]
    fn conflicting_registration_refused() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let (root_a, _) = fresh_chain([0x55; 32], 8);
        let (root_b, _) = fresh_chain([0x66; 32], 8);
        let peer = [0x77; 33];
        let chain_id = [0x88; 16];
        store
            .register(ChainRegistration {
                peer_id: peer,
                chain_id,
                root: root_a,
                length: 8,
            })
            .unwrap();
        assert_eq!(
            store
                .register(ChainRegistration {
                    peer_id: peer,
                    chain_id,
                    root: root_b,
                    length: 8,
                })
                .unwrap(),
            RegisterOutcome::Conflict,
        );
    }

    #[test]
    fn validate_rejects_unknown_chain() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        assert_eq!(
            store
                .validate(&[0; 33], &[0; 16], 1, &[0; 32])
                .unwrap(),
            ValidateOutcome::UnknownChain,
        );
    }

    #[test]
    fn validate_rejects_bad_value() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let (root, _) = fresh_chain([0x99; 32], 8);
        let reg = ChainRegistration {
            peer_id: [0xAA; 33],
            chain_id: [0xBB; 16],
            root,
            length: 8,
        };
        store.register(reg).unwrap();
        assert_eq!(
            store
                .validate(&reg.peer_id, &reg.chain_id, 1, &[0xFF; 32])
                .unwrap(),
            ValidateOutcome::BadChainValue,
        );
    }

    #[test]
    fn validate_tolerates_gap_in_index_sequence() {
        // The network can drop or reorder a SEND. The validator must
        // accept token[5] after token[2] (without seeing 3 or 4)
        // because the chain math `H^(5−2)(value_5) == value_2` holds.
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let (root, positions) = fresh_chain([0xCC; 32], 32);
        let reg = ChainRegistration {
            peer_id: [0xDD; 33],
            chain_id: [0xEE; 16],
            root,
            length: 32,
        };
        store.register(reg).unwrap();
        let t2 = token_at(&positions, 32, 2);
        let t5 = token_at(&positions, 32, 5);
        assert_eq!(
            store.validate(&reg.peer_id, &reg.chain_id, 2, &t2).unwrap(),
            ValidateOutcome::Accepted,
        );
        assert_eq!(
            store.validate(&reg.peer_id, &reg.chain_id, 5, &t5).unwrap(),
            ValidateOutcome::Accepted,
        );
    }

    #[test]
    fn validate_caps_forward_walk_steps() {
        // F-MEM-07 / F-RP-02: a single presentation may advance the index by
        // at most MAX_VALIDATE_STEPS. A larger jump is rejected as OutOfRange
        // BEFORE any BLAKE3 walk; a jump exactly at the cap still validates.
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let length = 200u32; // > MAX_VALIDATE_STEPS, < MAX_CHAIN_LENGTH
        let (root, positions) = fresh_chain([0x5A; 32], length);
        let reg = ChainRegistration {
            peer_id: [0x10; 33],
            chain_id: [0x20; 16],
            root,
            length,
        };
        store.register(reg).unwrap();

        // Jump of MAX_VALIDATE_STEPS + 1 from a fresh chain (last_index = 0)
        // is rejected without walking; state stays at last_index = 0.
        let over = MAX_VALIDATE_STEPS + 1;
        let t_over = token_at(&positions, length, over);
        assert_eq!(
            store.validate(&reg.peer_id, &reg.chain_id, over, &t_over).unwrap(),
            ValidateOutcome::OutOfRange,
        );

        // A jump of exactly MAX_VALIDATE_STEPS is within budget and validates.
        let at_cap = MAX_VALIDATE_STEPS;
        let t_cap = token_at(&positions, length, at_cap);
        assert_eq!(
            store.validate(&reg.peer_id, &reg.chain_id, at_cap, &t_cap).unwrap(),
            ValidateOutcome::Accepted,
        );
    }

    #[test]
    fn validate_rejects_past_end() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let (root, _) = fresh_chain([0x12; 32], 4);
        let reg = ChainRegistration {
            peer_id: [0x34; 33],
            chain_id: [0x56; 16],
            root,
            length: 4,
        };
        store.register(reg).unwrap();
        assert_eq!(
            store
                .validate(&reg.peer_id, &reg.chain_id, 5, &[0; 32])
                .unwrap(),
            ValidateOutcome::OutOfRange,
        );
    }

    #[test]
    fn persistence_round_trip_across_load() {
        let tmp = TempDir::new().unwrap();
        let (root, positions) = fresh_chain([0x77; 32], 16);
        let reg = ChainRegistration {
            peer_id: [0x88; 33],
            chain_id: [0x99; 16],
            root,
            length: 16,
        };
        {
            let mut store = make_store(tmp.path());
            store.register(reg).unwrap();
            let t1 = token_at(&positions, 16, 1);
            store.validate(&reg.peer_id, &reg.chain_id, 1, &t1).unwrap();
        }
        let mut store2 = make_store(tmp.path());
        // After reload, state must remember last_index = 1, so a
        // replay of index 1 still fails.
        let t1 = token_at(&positions, 16, 1);
        assert_eq!(
            store2.validate(&reg.peer_id, &reg.chain_id, 1, &t1).unwrap(),
            ValidateOutcome::OutOfRange,
        );
        // And token at index 2 still verifies against the persisted
        // last_value.
        let t2 = token_at(&positions, 16, 2);
        assert_eq!(
            store2.validate(&reg.peer_id, &reg.chain_id, 2, &t2).unwrap(),
            ValidateOutcome::Accepted,
        );
    }

    /// PZ-H2 crash-safety: an advance is durable via the append-only
    /// journal BEFORE `validate` returns `Accepted`, even if the process
    /// "crashes" before any compaction folds the journal into the
    /// snapshot. On reload the folded cursor must NOT regress — a replay of
    /// a consumed index stays rejected, and the next forward index still
    /// verifies. This is the core replay-monotonicity guarantee the journal
    /// must never break.
    #[test]
    fn replay_cursor_survives_crash_before_compaction() {
        let tmp = TempDir::new().unwrap();
        let length: u32 = 16;
        let (root, positions) = fresh_chain([0x5A; 32], length);
        let reg = ChainRegistration {
            peer_id: [0x1B; 33],
            chain_id: [0x2C; 16],
            root,
            length,
        };
        {
            let mut store = make_store(tmp.path());
            assert_eq!(store.register(reg).unwrap(), RegisterOutcome::Registered);
            // Advance the cursor to index 3. These advances live ONLY in the
            // journal — well under JOURNAL_COMPACT_THRESHOLD, so no snapshot
            // rewrite happened and the snapshot file isn't even created yet.
            for i in 1..=3u32 {
                let ti = token_at(&positions, length, i);
                assert_eq!(
                    store.validate(&reg.peer_id, &reg.chain_id, i, &ti).unwrap(),
                    ValidateOutcome::Accepted,
                );
            }
            // The snapshot must NOT yet reflect the advances — proving the
            // durability came from the fsync'd journal, not a snapshot write.
            let snapshot = tmp.path().join(FILE_NAME);
            assert!(
                !snapshot.exists(),
                "no full-store snapshot should have been written on the advance hot path"
            );
            // Drop without compaction — simulates a crash. Only the fsync'd
            // journal survives.
        }
        // Reload: the journal must be folded so the cursor is back at 3.
        let mut reloaded = make_store(tmp.path());
        // Replay of an already-consumed index is rejected (no regression).
        let t3 = token_at(&positions, length, 3);
        assert_eq!(
            reloaded.validate(&reg.peer_id, &reg.chain_id, 3, &t3).unwrap(),
            ValidateOutcome::OutOfRange,
        );
        // The next forward index still verifies → the cursor really is at 3.
        let t4 = token_at(&positions, length, 4);
        assert_eq!(
            reloaded.validate(&reg.peer_id, &reg.chain_id, 4, &t4).unwrap(),
            ValidateOutcome::Accepted,
        );
    }

    /// Audit M1 + M2 negative case: walking the chain all the way to
    /// `length` succeeds for the last token, then any further token
    /// (regardless of value) is rejected as `OutOfRange`. After that,
    /// re-registering with a fresh chain under a NEW `chain_id`
    /// recovers — the sender resumes sending against the new chain
    /// while the exhausted one stays dead in the store.
    #[test]
    fn chain_exhaustion_then_recovery_via_new_chain_id() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let seed = [0xEEu8; 32];
        let length: u32 = 6;
        let (root, positions) = fresh_chain(seed, length);
        let reg = ChainRegistration {
            peer_id: [0xCC; 33],
            chain_id: [0xDD; 16],
            root,
            length,
        };
        assert_eq!(store.register(reg).unwrap(), RegisterOutcome::Registered);
        // Walk all `length` tokens — every one must Accept.
        for i in 1..=length {
            let ti = token_at(&positions, length, i);
            assert_eq!(
                store.validate(&reg.peer_id, &reg.chain_id, i, &ti).unwrap(),
                ValidateOutcome::Accepted,
                "token at index {i} must accept",
            );
        }
        // One past the end must fail with OutOfRange, even with a
        // structurally valid-shaped token value.
        let bogus = [0u8; 32];
        assert_eq!(
            store
                .validate(&reg.peer_id, &reg.chain_id, length + 1, &bogus)
                .unwrap(),
            ValidateOutcome::OutOfRange,
        );
        // Recovery: register a fresh chain under a NEW chain_id. The
        // exhausted entry stays in the map (it has not aged out) but
        // the new one is independently usable.
        let seed_b = [0x55u8; 32];
        let (root_b, positions_b) = fresh_chain(seed_b, length);
        let reg_b = ChainRegistration {
            peer_id: reg.peer_id,
            chain_id: [0xAA; 16],
            root: root_b,
            length,
        };
        assert_eq!(store.register(reg_b).unwrap(), RegisterOutcome::Registered);
        let t1_b = token_at(&positions_b, length, 1);
        assert_eq!(
            store
                .validate(&reg_b.peer_id, &reg_b.chain_id, 1, &t1_b)
                .unwrap(),
            ValidateOutcome::Accepted,
        );
    }

    /// Audit H1 sanity check: the validator's hash primitive is
    /// BLAKE3, not SHA-256. Reproduce the chain root via the public
    /// crate API (so a future swap to a different hash would break
    /// this test loudly rather than silently desynchronising from
    /// the iOS side).
    #[test]
    fn chain_primitive_is_blake3() {
        let seed = [0x42u8; 32];
        let h1 = blake3::hash(&seed);
        let h2 = blake3::hash(h1.as_bytes());
        // fresh_chain(seed, 2) MUST produce the same root as two
        // explicit blake3 applications.
        let (root, _) = fresh_chain(seed, 2);
        assert_eq!(&root, h2.as_bytes());
    }
}
