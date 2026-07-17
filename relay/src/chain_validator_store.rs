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
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;

const FILE_NAME: &str = "chain_validators.bin";
const KEY_FILE_NAME: &str = "chain_validators.key";

/// Per-store AAD. Domain-separated from sibling stores so a swap
/// attack (replacing one store's ciphertext with another's) fails
/// at AEAD verify.
const AAD: &[u8] = b"pizzini.relay.chain_validators.v1";

pub const CHAIN_ID_LEN: usize = 16;
pub const CHAIN_VALUE_LEN: usize = 32;

/// S4-05: domain-separation tag for one hash-chain step. The step was
/// previously a bare `BLAKE3(value)` with no domain tag / version, so
/// the chain construction was not domain-separated from any other
/// BLAKE3 use and had no migration hook. The step is now
/// `BLAKE3(CHAIN_STEP_DOMAIN || value)`. The `v2` in the tag IS the
/// version field: a future construction change bumps this string,
/// which (by design) makes every value computed under the old tag stop
/// validating — a clean, loud migration boundary. This MUST match the
/// iOS prover (`HashChainToken.applyHash`) byte-for-byte; both sides
/// prepend exactly these bytes before each BLAKE3 step.
///
/// Note on chain_id binding: the tag deliberately does NOT mix in
/// `chain_id`. The chain values are derived once by the recipient from
/// the seed (with no relay context), while the relay stores/looks them
/// up under the per-relay `relayScopedChainID`; binding the lookup
/// chain_id into the step would force one distinct value-chain per
/// relay and break the "one chain, many relays" design
/// (`relayScopedChainID`). Domain separation via a fixed versioned tag
/// gives the migratability the finding asks for without that
/// regression.
pub const CHAIN_STEP_DOMAIN: &[u8] = b"pizzini-v2-delivery-token-chain";

/// One forward hash-chain step: `BLAKE3(CHAIN_STEP_DOMAIN || value)`.
/// Used by `validate` (relay hot path) and the test chain generator.
/// The iOS side computes the identical bytes in `applyHash`.
fn chain_step(value: &[u8; CHAIN_VALUE_LEN]) -> [u8; CHAIN_VALUE_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHAIN_STEP_DOMAIN);
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

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
    key: [u8; encrypted_file::KEY_LEN],
    /// `(peer_id, chain_id) → state`.
    map: HashMap<(Vec<u8>, [u8; CHAIN_ID_LEN]), ChainState>,
    /// S4-01: off-hot-lock persistence coordinator. The in-memory
    /// advance (and the cheap serialize+encrypt to build a snapshot)
    /// happens under the outer `Mutex<ChainValidatorStore>`; the blocking
    /// `write_atomic` fsync is committed via this coordinator AFTER the
    /// outer lock is released, so concurrent token validations no longer
    /// head-of-line-block behind a per-SEND fsync.
    persist: Arc<PersistCoordinator>,
    /// Monotonic generation counter. Bumped on every mutation; a higher
    /// generation's snapshot supersedes any lower one in the coordinator.
    generation: u64,
}

/// S4-01: serializes and de-duplicates the blocking disk writes for the
/// chain-validator store so they happen OFF the hot `chain_validators`
/// mutex. Each mutation builds a full-map ciphertext snapshot tagged
/// with a monotonic generation (cheap, under the outer lock) and stages
/// it here; `commit` then performs the actual `write_atomic` (a blocking
/// fsync) under THIS coordinator's async mutex — never the validator
/// mutex — and coalesces: a request only needs to observe
/// `committed >= its generation`, and because the map is cumulative the
/// highest staged snapshot already contains every lower advance. A
/// stale snapshot is never written over a newer one.
struct PersistCoordinator {
    path: PathBuf,
    inner: AsyncMutex<PersistInner>,
}

struct PersistInner {
    /// Highest generation whose snapshot is durable on disk.
    committed: u64,
    /// Newest staged-but-not-yet-written snapshot, if any.
    pending: Option<(u64, Vec<u8>)>,
}

/// Handle returned by a mutating call describing the durable write it
/// requires. `commit().await` blocks (off the validator lock) until the
/// store's on-disk state reflects at least this mutation. A handle from
/// a no-op outcome (e.g. a rejected validation) commits trivially.
/// Callers on a request path MUST `commit().await` before acting on an
/// `Accepted`/`Registered` outcome so a crash cannot lose the
/// replay-cursor advance (no lost cursor across restart).
///
/// The inner coordinator type is intentionally private — callers only
/// ever construct this via `validate`/`register` and consume it via
/// `commit`.
#[must_use = "a Persist handle must be committed (or explicitly ignored) to make the mutation durable"]
pub struct Persist {
    pending: Option<(Arc<PersistCoordinator>, u64)>,
}

impl Persist {
    const NOOP: Persist = Persist { pending: None };

    fn pending(coordinator: Arc<PersistCoordinator>, generation: u64) -> Persist {
        Persist {
            pending: Some((coordinator, generation)),
        }
    }

    /// Make the staged mutation durable (off the validator lock). On a
    /// no-op handle this is a no-op. Returns the underlying
    /// `write_atomic` error if the disk write failed.
    pub async fn commit(self) -> io::Result<()> {
        match self.pending {
            None => Ok(()),
            Some((coordinator, generation)) => coordinator.commit(generation).await,
        }
    }
}

impl PersistCoordinator {
    /// Stage `ciphertext` for generation `gen` (keeping only the newest)
    /// and bump nothing else. Called under the validator lock; cheap.
    async fn stage(&self, generation: u64, ciphertext: Vec<u8>) {
        let mut inner = self.inner.lock().await;
        match &inner.pending {
            Some((g, _)) if *g >= generation => {}
            _ => inner.pending = Some((generation, ciphertext)),
        }
    }

    /// Ensure the on-disk state reflects at least `generation`. Performs
    /// the blocking `write_atomic` under this coordinator's mutex (NOT
    /// the validator mutex), coalescing concurrent waiters onto the
    /// newest staged snapshot.
    async fn commit(&self, generation: u64) -> io::Result<()> {
        let mut inner = self.inner.lock().await;
        if inner.committed >= generation {
            return Ok(()); // a newer (or equal) snapshot already landed.
        }
        let Some((gen, ciphertext)) = inner.pending.take() else {
            // Nothing staged but we owe `generation` — should not happen
            // because the staging always precedes the commit for the same
            // mutation, but treat as satisfied rather than spin.
            inner.committed = inner.committed.max(generation);
            return Ok(());
        };
        // Write the newest staged snapshot. `write_atomic` is blocking
        // (fsync); we hold only the persist mutex here, not the
        // validator mutex, so other token validations proceed.
        let path = self.path.clone();
        let result =
            tokio::task::spawn_blocking(move || encrypted_file::write_atomic(&path, &ciphertext))
                .await
                .unwrap_or_else(|e| Err(io::Error::other(format!("persist task panicked: {e}"))));
        match result {
            Ok(()) => {
                inner.committed = inner.committed.max(gen);
                Ok(())
            }
            Err(e) => {
                // Re-stage so a later commit retries rather than silently
                // dropping the snapshot.
                if inner.pending.is_none() {
                    // Nothing newer arrived; nothing to re-stage from here
                    // (the ciphertext was moved into spawn_blocking). The
                    // next mutation will stage a fresh snapshot.
                }
                Err(e)
            }
        }
    }
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
            .field("path", &self.persist.path)
            .field("entries", &self.map.len())
            .field("generation", &self.generation)
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

        let map = match fs::read(&path) {
            Ok(bytes) => {
                // S4-07: AAD-only decrypt. The unconditional no-AAD
                // fallback was a one-time migration shim for files
                // written before this store adopted per-store AAD; all
                // four stores now persist with AAD, so the fallback only
                // weakened AEAD domain separation for the binary's
                // lifetime. Removed — a file that does not verify under
                // this store's AAD now fails the load (refuse to start)
                // exactly like a tampered/wrong-key file.
                let plaintext = encrypted_file::decrypt_with_aad(&key, &bytes, AAD)?;
                let doc: StoreDoc =
                    serde_json::from_slice(&plaintext).map_err(io::Error::other)?;
                purge_stale(doc, max_age)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };

        Ok(ChainValidatorStore {
            key,
            map,
            persist: Arc::new(PersistCoordinator {
                path,
                inner: AsyncMutex::new(PersistInner {
                    committed: 0,
                    pending: None,
                }),
            }),
            generation: 0,
        })
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// S4-01: build the full-map ciphertext snapshot for the CURRENT
    /// in-memory state, bump the generation, and stage it on the
    /// coordinator. Returns a `Persist` the caller commits off the
    /// validator lock. Cheap relative to the fsync: serialize + encrypt
    /// only. Must be called under the validator lock (it mutates
    /// `self.generation`).
    async fn stage_persist(&mut self) -> io::Result<Persist> {
        let ciphertext = self.encrypt_snapshot()?;
        self.generation += 1;
        let generation = self.generation;
        self.persist.stage(generation, ciphertext).await;
        Ok(Persist::pending(self.persist.clone(), generation))
    }

    /// Serialize the in-memory map and encrypt it (no disk I/O). The
    /// blocking write is done separately by the coordinator.
    fn encrypt_snapshot(&self) -> io::Result<Vec<u8>> {
        let mut doc = StoreDoc::default();
        for ((peer_id, chain_id), state) in &self.map {
            let composite = format!(
                "{}:{}",
                encrypted_file::hex_encode(peer_id),
                encrypted_file::hex_encode(chain_id),
            );
            doc.entries.insert(
                composite,
                StoredEntry {
                    root_hex: encrypted_file::hex_encode(&state.root),
                    length: state.length,
                    last_index: state.last_index,
                    last_value_hex: encrypted_file::hex_encode(&state.last_value),
                    registered_unix: state.registered_unix,
                    last_used_unix: state.last_used_unix,
                },
            );
        }
        let plaintext = serde_json::to_vec(&doc).map_err(io::Error::other)?;
        encrypted_file::encrypt_with_aad(&self.key, &plaintext, AAD)
    }

    /// Register a fresh chain. Idempotent on `(peer_id, chain_id)`:
    /// re-registering the same key with the same root/length is a
    /// no-op; conflicting registrations (same key, different root)
    /// are refused so a relay-MITM can't quietly swap chains.
    ///
    /// S4-01: on a real insert this stages a snapshot and returns a
    /// `Persist` the caller commits AFTER releasing the validator lock,
    /// so the per-registration fsync no longer head-of-line-blocks
    /// concurrent token validation. The no-op / refused outcomes return
    /// `Persist::NOOP` (nothing to flush).
    pub async fn register(
        &mut self,
        reg: ChainRegistration,
    ) -> io::Result<(RegisterOutcome, Persist)> {
        if reg.length == 0 || reg.length > MAX_CHAIN_LENGTH {
            return Ok((RegisterOutcome::BadLength, Persist::NOOP));
        }
        let now = encrypted_file::unix_now();
        let key = (reg.peer_id.to_vec(), reg.chain_id);
        if let Some(existing) = self.map.get(&key) {
            if existing.root == reg.root && existing.length == reg.length {
                return Ok((RegisterOutcome::AlreadyRegistered, Persist::NOOP));
            }
            return Ok((RegisterOutcome::Conflict, Persist::NOOP));
        }
        // F-RP-01: bound store growth before inserting a NEW key. Existing
        // keys took the idempotent/conflict path above and are unaffected, so
        // legitimate re-registration always succeeds even at the cap.
        if self.map.len() >= MAX_TOTAL_CHAINS {
            return Ok((RegisterOutcome::RejectedCap, Persist::NOOP));
        }
        let per_peer = self
            .map
            .keys()
            .filter(|(p, _)| p.as_slice() == reg.peer_id.as_slice())
            .take(MAX_CHAINS_PER_PEER)
            .count();
        if per_peer >= MAX_CHAINS_PER_PEER {
            return Ok((RegisterOutcome::RejectedCap, Persist::NOOP));
        }
        self.map.insert(
            key,
            ChainState {
                root: reg.root,
                length: reg.length,
                last_index: 0,
                last_value: reg.root,
                registered_unix: now,
                last_used_unix: now,
            },
        );
        let persist = self.stage_persist().await?;
        Ok((RegisterOutcome::Registered, persist))
    }

    /// Validate a presentation. On `Accepted`, the state is advanced
    /// in-memory and a snapshot is staged; the returned `Persist` MUST
    /// be committed by the caller (after releasing the validator lock)
    /// BEFORE the SEND is forwarded/queued, so a crash can never leave
    /// the cursor un-advanced on disk and re-open a replay window
    /// (S4-01 keeps correctness: no lost replay/cursor state across
    /// restart). Non-`Accepted` outcomes return `Persist::NOOP` —
    /// importantly, a `BadChainValue`/`OutOfRange`/`UnknownChain` does
    /// NOT touch disk, so garbage-token spam costs no persist.
    pub async fn validate(
        &mut self,
        peer_id: &[u8],
        chain_id: &[u8; CHAIN_ID_LEN],
        index: u32,
        value: &[u8; CHAIN_VALUE_LEN],
    ) -> io::Result<(ValidateOutcome, Persist)> {
        let key = (peer_id.to_vec(), *chain_id);
        let Some(state) = self.map.get_mut(&key) else {
            return Ok((ValidateOutcome::UnknownChain, Persist::NOOP));
        };
        if index == 0 || index <= state.last_index || index > state.length {
            return Ok((ValidateOutcome::OutOfRange, Persist::NOOP));
        }
        let delta = index - state.last_index;
        // F-MEM-07 / F-RP-02: bound the forward walk to a small constant so a
        // single presentation cannot force a multi-hundred-thousand BLAKE3
        // loop under the global lock. Reject an oversized jump before hashing.
        if delta > MAX_VALIDATE_STEPS {
            return Ok((ValidateOutcome::OutOfRange, Persist::NOOP));
        }
        let mut current = *value;
        for _ in 0..delta {
            // S4-05: domain-separated, versioned chain step
            // `BLAKE3(CHAIN_STEP_DOMAIN || value)` (see `chain_step` /
            // `CHAIN_STEP_DOMAIN`). Matches `HashChainToken.applyHash`
            // on iOS byte-for-byte. This is a wire/format change
            // (acceptable in beta): a chain whose tokens were produced
            // with the old bare-`BLAKE3(value)` step no longer chains to
            // its registered root and is rejected as `BadChainValue`.
            current = chain_step(&current);
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
            return Ok((ValidateOutcome::BadChainValue, Persist::NOOP));
        }
        state.last_index = index;
        state.last_value = *value;
        state.last_used_unix = encrypted_file::unix_now();
        let persist = self.stage_persist().await?;
        Ok((ValidateOutcome::Accepted, persist))
    }

    /// Drop entries whose `last_used_unix` is older than `max_age`.
    /// A chain whose sender hasn't sent for `max_age` is presumed
    /// rotated (or the contact unpaired); the relay isn't the
    /// authority on contact lifetime, but holding stale chain state
    /// forever isn't free.
    pub async fn gc_expired(&mut self, max_age: Duration) -> io::Result<usize> {
        let now = encrypted_file::unix_now();
        let cutoff = now.saturating_sub(max_age.as_secs());
        let before = self.map.len();
        self.map.retain(|_, state| state.last_used_unix > cutoff);
        let removed = before - self.map.len();
        if removed > 0 {
            // GC runs on its own sparse task, not the hot path. Stage +
            // commit through the same coordinator so the generation
            // ordering holds (a GC write never clobbers a newer accepted
            // SEND's snapshot, nor vice-versa).
            self.stage_persist().await?.commit().await?;
        }
        Ok(removed)
    }

    /// Test helper: register and commit, returning just the outcome.
    #[cfg(test)]
    async fn register_committed(&mut self, reg: ChainRegistration) -> io::Result<RegisterOutcome> {
        let (outcome, persist) = self.register(reg).await?;
        persist.commit().await?;
        Ok(outcome)
    }

    /// Test helper: validate and commit, returning just the outcome.
    #[cfg(test)]
    async fn validate_committed(
        &mut self,
        peer_id: &[u8],
        chain_id: &[u8; CHAIN_ID_LEN],
        index: u32,
        value: &[u8; CHAIN_VALUE_LEN],
    ) -> io::Result<ValidateOutcome> {
        let (outcome, persist) = self.validate(peer_id, chain_id, index, value).await?;
        persist.commit().await?;
        Ok(outcome)
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

fn purge_stale(
    doc: StoreDoc,
    max_age: Duration,
) -> HashMap<(Vec<u8>, [u8; CHAIN_ID_LEN]), ChainState> {
    let now = encrypted_file::unix_now();
    let cutoff = now.saturating_sub(max_age.as_secs());
    let mut out: HashMap<(Vec<u8>, [u8; CHAIN_ID_LEN]), ChainState> = HashMap::new();
    // S4-08: count rows skipped because the row itself is malformed
    // (corrupt on-disk state that still passed the whole-file AEAD tag),
    // as distinct from rows aged out by TTL. Surfaced once at the end as
    // an operator-visible count — no peer-id / secret, just a number.
    let mut corrupt = 0usize;
    for (composite, entry) in doc.entries {
        if entry.last_used_unix <= cutoff {
            continue;
        }
        let Some((peer_hex, chain_hex)) = composite.split_once(':') else {
            corrupt += 1;
            continue;
        };
        let Some(peer) = encrypted_file::hex_decode(peer_hex) else {
            corrupt += 1;
            continue;
        };
        let Some(chain_id_vec) = encrypted_file::hex_decode(chain_hex) else {
            corrupt += 1;
            continue;
        };
        if chain_id_vec.len() != CHAIN_ID_LEN {
            corrupt += 1;
            continue;
        }
        let Some(root_vec) = encrypted_file::hex_decode(&entry.root_hex) else {
            corrupt += 1;
            continue;
        };
        let Some(last_val_vec) = encrypted_file::hex_decode(&entry.last_value_hex) else {
            corrupt += 1;
            continue;
        };
        if root_vec.len() != CHAIN_VALUE_LEN || last_val_vec.len() != CHAIN_VALUE_LEN {
            corrupt += 1;
            continue;
        }
        let mut chain_id = [0u8; CHAIN_ID_LEN];
        chain_id.copy_from_slice(&chain_id_vec);
        let mut root = [0u8; CHAIN_VALUE_LEN];
        root.copy_from_slice(&root_vec);
        let mut last_value = [0u8; CHAIN_VALUE_LEN];
        last_value.copy_from_slice(&last_val_vec);
        out.insert(
            (peer, chain_id),
            ChainState {
                root,
                length: entry.length,
                last_index: entry.last_index,
                last_value,
                registered_unix: entry.registered_unix,
                last_used_unix: entry.last_used_unix,
            },
        );
    }
    encrypted_file::warn_dropped_rows("chain-validator", corrupt);
    out
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
            // Must use the SAME domain-separated step the validator and
            // the iOS prover use (S4-05), or the generated chain won't
            // validate.
            let next = chain_step(&current);
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

    #[tokio::test]
    async fn round_trip_register_and_validate() {
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
        assert_eq!(store.register_committed(reg).await.unwrap(), RegisterOutcome::Registered);
        // Present token at index 1: value = position 15.
        let t1 = token_at(&positions, 16, 1);
        assert_eq!(
            store.validate_committed(&reg.peer_id, &reg.chain_id, 1, &t1).await.unwrap(),
            ValidateOutcome::Accepted,
        );
        // Replay must fail.
        assert_eq!(
            store.validate_committed(&reg.peer_id, &reg.chain_id, 1, &t1).await.unwrap(),
            ValidateOutcome::OutOfRange,
        );
        // Token at index 2 must verify against the now-advanced state.
        let t2 = token_at(&positions, 16, 2);
        assert_eq!(
            store.validate_committed(&reg.peer_id, &reg.chain_id, 2, &t2).await.unwrap(),
            ValidateOutcome::Accepted,
        );
    }

    #[tokio::test]
    async fn register_rejects_zero_length() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let reg = ChainRegistration {
            peer_id: [0; 33],
            chain_id: [0; 16],
            root: [0; 32],
            length: 0,
        };
        assert_eq!(store.register_committed(reg).await.unwrap(), RegisterOutcome::BadLength);
    }

    #[tokio::test]
    async fn register_rejects_oversize_length() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let reg = ChainRegistration {
            peer_id: [0; 33],
            chain_id: [0; 16],
            root: [0; 32],
            length: MAX_CHAIN_LENGTH + 1,
        };
        assert_eq!(store.register_committed(reg).await.unwrap(), RegisterOutcome::BadLength);
    }

    #[tokio::test]
    async fn register_enforces_per_peer_cap() {
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
            assert_eq!(store.register_committed(reg).await.unwrap(), RegisterOutcome::Registered, "i={i}");
        }
        // The (cap+1)th distinct chain for the same peer is refused.
        let mut over = [0u8; 16];
        over[..8].copy_from_slice(&(MAX_CHAINS_PER_PEER as u64).to_be_bytes());
        let reg_over = ChainRegistration { peer_id: peer, chain_id: over, root, length: 8 };
        assert_eq!(store.register_committed(reg_over).await.unwrap(), RegisterOutcome::RejectedCap);
        // Re-registering an EXISTING key for the capped peer still succeeds.
        let mut existing = [0u8; 16];
        existing[..8].copy_from_slice(&0u64.to_be_bytes());
        let reg_existing = ChainRegistration { peer_id: peer, chain_id: existing, root, length: 8 };
        assert_eq!(store.register_committed(reg_existing).await.unwrap(), RegisterOutcome::AlreadyRegistered);
        // A different peer is unaffected by another peer's cap.
        let reg_other = ChainRegistration { peer_id: [0xCD; 33], chain_id: [0xFF; 16], root, length: 8 };
        assert_eq!(store.register_committed(reg_other).await.unwrap(), RegisterOutcome::Registered);
    }

    #[tokio::test]
    async fn idempotent_re_registration() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let (root, _) = fresh_chain([0x22; 32], 8);
        let reg = ChainRegistration {
            peer_id: [0x33; 33],
            chain_id: [0x44; 16],
            root,
            length: 8,
        };
        assert_eq!(store.register_committed(reg).await.unwrap(), RegisterOutcome::Registered);
        assert_eq!(
            store.register_committed(reg).await.unwrap(),
            RegisterOutcome::AlreadyRegistered,
        );
    }

    #[tokio::test]
    async fn conflicting_registration_refused() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let (root_a, _) = fresh_chain([0x55; 32], 8);
        let (root_b, _) = fresh_chain([0x66; 32], 8);
        let peer = [0x77; 33];
        let chain_id = [0x88; 16];
        store
            .register_committed(ChainRegistration {
                peer_id: peer,
                chain_id,
                root: root_a,
                length: 8,
            })
            .await
            .unwrap();
        assert_eq!(
            store
                .register_committed(ChainRegistration {
                    peer_id: peer,
                    chain_id,
                    root: root_b,
                    length: 8,
                })
                .await
                .unwrap(),
            RegisterOutcome::Conflict,
        );
    }

    #[tokio::test]
    async fn validate_rejects_unknown_chain() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        assert_eq!(
            store
                .validate_committed(&[0; 33], &[0; 16], 1, &[0; 32])
                .await
                .unwrap(),
            ValidateOutcome::UnknownChain,
        );
    }

    #[tokio::test]
    async fn validate_rejects_bad_value() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let (root, _) = fresh_chain([0x99; 32], 8);
        let reg = ChainRegistration {
            peer_id: [0xAA; 33],
            chain_id: [0xBB; 16],
            root,
            length: 8,
        };
        store.register_committed(reg).await.unwrap();
        assert_eq!(
            store
                .validate_committed(&reg.peer_id, &reg.chain_id, 1, &[0xFF; 32])
                .await
                .unwrap(),
            ValidateOutcome::BadChainValue,
        );
    }

    #[tokio::test]
    async fn validate_tolerates_gap_in_index_sequence() {
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
        store.register_committed(reg).await.unwrap();
        let t2 = token_at(&positions, 32, 2);
        let t5 = token_at(&positions, 32, 5);
        assert_eq!(
            store.validate_committed(&reg.peer_id, &reg.chain_id, 2, &t2).await.unwrap(),
            ValidateOutcome::Accepted,
        );
        assert_eq!(
            store.validate_committed(&reg.peer_id, &reg.chain_id, 5, &t5).await.unwrap(),
            ValidateOutcome::Accepted,
        );
    }

    #[tokio::test]
    async fn validate_caps_forward_walk_steps() {
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
        store.register_committed(reg).await.unwrap();

        // Jump of MAX_VALIDATE_STEPS + 1 from a fresh chain (last_index = 0)
        // is rejected without walking; state stays at last_index = 0.
        let over = MAX_VALIDATE_STEPS + 1;
        let t_over = token_at(&positions, length, over);
        assert_eq!(
            store.validate_committed(&reg.peer_id, &reg.chain_id, over, &t_over).await.unwrap(),
            ValidateOutcome::OutOfRange,
        );

        // A jump of exactly MAX_VALIDATE_STEPS is within budget and validates.
        let at_cap = MAX_VALIDATE_STEPS;
        let t_cap = token_at(&positions, length, at_cap);
        assert_eq!(
            store.validate_committed(&reg.peer_id, &reg.chain_id, at_cap, &t_cap).await.unwrap(),
            ValidateOutcome::Accepted,
        );
    }

    #[tokio::test]
    async fn validate_rejects_past_end() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let (root, _) = fresh_chain([0x12; 32], 4);
        let reg = ChainRegistration {
            peer_id: [0x34; 33],
            chain_id: [0x56; 16],
            root,
            length: 4,
        };
        store.register_committed(reg).await.unwrap();
        assert_eq!(
            store
                .validate_committed(&reg.peer_id, &reg.chain_id, 5, &[0; 32])
                .await
                .unwrap(),
            ValidateOutcome::OutOfRange,
        );
    }

    #[tokio::test]
    async fn persistence_round_trip_across_load() {
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
            store.register_committed(reg).await.unwrap();
            let t1 = token_at(&positions, 16, 1);
            store.validate_committed(&reg.peer_id, &reg.chain_id, 1, &t1).await.unwrap();
        }
        let mut store2 = make_store(tmp.path());
        // After reload, state must remember last_index = 1, so a
        // replay of index 1 still fails.
        let t1 = token_at(&positions, 16, 1);
        assert_eq!(
            store2.validate_committed(&reg.peer_id, &reg.chain_id, 1, &t1).await.unwrap(),
            ValidateOutcome::OutOfRange,
        );
        // And token at index 2 still verifies against the persisted
        // last_value.
        let t2 = token_at(&positions, 16, 2);
        assert_eq!(
            store2.validate_committed(&reg.peer_id, &reg.chain_id, 2, &t2).await.unwrap(),
            ValidateOutcome::Accepted,
        );
    }

    /// S4-01: the off-hot-lock persist is durable BEFORE `commit()`
    /// returns — i.e. once a SEND is treated as accepted, the cursor
    /// advance is on disk and a reload still rejects the replay. This is
    /// the "no lost replay/cursor state across restart" guarantee under
    /// the new two-phase (advance-under-lock, fsync-off-lock) path.
    #[tokio::test]
    async fn s4_01_commit_is_durable_before_returning() {
        let tmp = TempDir::new().unwrap();
        let (root, positions) = fresh_chain([0x3A; 32], 16);
        let reg = ChainRegistration {
            peer_id: [0x4B; 33],
            chain_id: [0x5C; 16],
            root,
            length: 16,
        };
        let mut store = make_store(tmp.path());
        // register returns a Persist; commit it explicitly off-lock.
        let (r_out, r_persist) = store.register(reg).await.unwrap();
        assert_eq!(r_out, RegisterOutcome::Registered);
        r_persist.commit().await.unwrap();

        let t1 = token_at(&positions, 16, 1);
        let (v_out, v_persist) = store
            .validate(&reg.peer_id, &reg.chain_id, 1, &t1)
            .await
            .unwrap();
        assert_eq!(v_out, ValidateOutcome::Accepted);
        // The advance is staged; commit makes it durable.
        v_persist.commit().await.unwrap();

        // A FRESH store loaded from disk right now must already see the
        // advanced cursor (index 1 consumed) — proving the commit wrote
        // through before returning.
        let mut reloaded = make_store(tmp.path());
        assert_eq!(
            reloaded
                .validate_committed(&reg.peer_id, &reg.chain_id, 1, &t1)
                .await
                .unwrap(),
            ValidateOutcome::OutOfRange,
            "the committed cursor advance must be durable across an immediate reload",
        );
    }

    /// S4-01: a rejected validation does NO disk write at all (no
    /// persist amplification on garbage-token spam) — its `Persist`
    /// handle is a no-op and the on-disk file is unchanged.
    #[tokio::test]
    async fn s4_01_rejected_validation_does_not_persist() {
        let tmp = TempDir::new().unwrap();
        let (root, _positions) = fresh_chain([0x6D; 32], 8);
        let reg = ChainRegistration {
            peer_id: [0x7E; 33],
            chain_id: [0x8F; 16],
            root,
            length: 8,
        };
        let mut store = make_store(tmp.path());
        store.register_committed(reg).await.unwrap();
        let path = tmp.path().join(FILE_NAME);
        let before = std::fs::read(&path).unwrap();
        // A bad value is rejected with a NoOp persist handle.
        let (out, persist) = store
            .validate(&reg.peer_id, &reg.chain_id, 1, &[0xFF; 32])
            .await
            .unwrap();
        assert_eq!(out, ValidateOutcome::BadChainValue);
        persist.commit().await.unwrap(); // no-op
        let after = std::fs::read(&path).unwrap();
        assert_eq!(before, after, "a rejected validation must not rewrite the store file");
    }

    /// Audit M1 + M2 negative case: walking the chain all the way to
    /// `length` succeeds for the last token, then any further token
    /// (regardless of value) is rejected as `OutOfRange`. After that,
    /// re-registering with a fresh chain under a NEW `chain_id`
    /// recovers — the sender resumes sending against the new chain
    /// while the exhausted one stays dead in the store.
    #[tokio::test]
    async fn chain_exhaustion_then_recovery_via_new_chain_id() {
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
        assert_eq!(store.register_committed(reg).await.unwrap(), RegisterOutcome::Registered);
        // Walk all `length` tokens — every one must Accept.
        for i in 1..=length {
            let ti = token_at(&positions, length, i);
            assert_eq!(
                store.validate_committed(&reg.peer_id, &reg.chain_id, i, &ti).await.unwrap(),
                ValidateOutcome::Accepted,
                "token at index {i} must accept",
            );
        }
        // One past the end must fail with OutOfRange, even with a
        // structurally valid-shaped token value.
        let bogus = [0u8; 32];
        assert_eq!(
            store
                .validate_committed(&reg.peer_id, &reg.chain_id, length + 1, &bogus)
                .await
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
        assert_eq!(store.register_committed(reg_b).await.unwrap(), RegisterOutcome::Registered);
        let t1_b = token_at(&positions_b, length, 1);
        assert_eq!(
            store
                .validate_committed(&reg_b.peer_id, &reg_b.chain_id, 1, &t1_b)
                .await
                .unwrap(),
            ValidateOutcome::Accepted,
        );
    }

    /// S4-07: an AAD-written store file still loads (the supported
    /// path), but a legacy file written WITHOUT the per-store AAD is now
    /// refused — the unconditional no-AAD decrypt fallback was removed,
    /// so AEAD domain separation holds for the binary's lifetime instead
    /// of being silently downgraded.
    #[tokio::test]
    async fn aad_written_loads_but_no_aad_legacy_file_is_refused() {
        let tmp = TempDir::new().unwrap();
        let (root, positions) = fresh_chain([0x3C; 32], 8);
        let reg = ChainRegistration {
            peer_id: [0x4D; 33],
            chain_id: [0x5E; 16],
            root,
            length: 8,
        };
        // Normal AAD write via register/persist; reloads cleanly.
        {
            let mut store = make_store(tmp.path());
            assert_eq!(store.register_committed(reg).await.unwrap(), RegisterOutcome::Registered);
            let t1 = token_at(&positions, 8, 1);
            store.validate_committed(&reg.peer_id, &reg.chain_id, 1, &t1).await.unwrap();
        }
        let reloaded = make_store(tmp.path()); // must NOT error
        assert_eq!(reloaded.len(), 1);

        // Now forge a legacy no-AAD file at the same path, encrypted
        // with the SAME store key but empty AAD. The old fallback would
        // have happily loaded this; the AAD-only path must reject it.
        let key = encrypted_file::load_or_create_key(
            &tmp.path().join(KEY_FILE_NAME),
            "chain-validator",
        )
        .unwrap();
        let doc = StoreDoc::default();
        let plaintext = serde_json::to_vec(&doc).unwrap();
        let legacy = encrypted_file::encrypt(&key, &plaintext).unwrap(); // empty AAD
        std::fs::write(tmp.path().join(FILE_NAME), legacy).unwrap();
        let err = ChainValidatorStore::load_or_create(
            tmp.path(),
            Duration::from_secs(86_400),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("decrypt"),
            "no-AAD legacy file must be refused, got: {err}",
        );
    }

    /// S4-05: the chain step is the DOMAIN-SEPARATED, versioned
    /// `BLAKE3(CHAIN_STEP_DOMAIN || value)`, NOT a bare `BLAKE3(value)`.
    /// Reproduce the chain root via the public crate API + the exact
    /// domain prefix (so a future swap to a different hash OR a tag
    /// change breaks this loudly rather than silently desynchronising
    /// from the iOS side), and assert the OLD bare-BLAKE3 construction
    /// no longer matches.
    #[test]
    fn chain_step_is_domain_separated_blake3() {
        let seed = [0x42u8; 32];
        // Domain-tagged two-step expansion.
        let step = |v: &[u8; 32]| -> [u8; 32] {
            let mut h = blake3::Hasher::new();
            h.update(CHAIN_STEP_DOMAIN);
            h.update(v);
            *h.finalize().as_bytes()
        };
        let s1 = step(&seed);
        let s2 = step(&s1);
        // fresh_chain(seed, 2) MUST produce the same root as two
        // explicit DOMAIN-TAGGED blake3 applications.
        let (root, _) = fresh_chain(seed, 2);
        assert_eq!(root, s2);
        // And the OLD bare-BLAKE3 construction must NOT match — a chain
        // built with the un-tagged step no longer validates.
        let bare1 = *blake3::hash(&seed).as_bytes();
        let bare2 = *blake3::hash(&bare1).as_bytes();
        assert_ne!(root, bare2, "domain tag must change the chain output");
    }

    /// S4-05 end-to-end: a token whose value was produced with the OLD
    /// bare-`BLAKE3(value)` step does NOT validate against a chain
    /// registered with the new domain-separated root.
    #[tokio::test]
    async fn old_bare_blake3_token_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(tmp.path());
        let seed = [0x7Au8; 32];
        let length = 8u32;
        let (root, _positions) = fresh_chain(seed, length); // domain-separated
        let reg = ChainRegistration {
            peer_id: [0x1F; 33],
            chain_id: [0x2E; 16],
            root,
            length,
        };
        assert_eq!(store.register_committed(reg).await.unwrap(), RegisterOutcome::Registered);

        // Build the index-1 token the OLD way: bare BLAKE3 with no tag.
        // token[1] = position (length - 1) = H_bare^(length-1)(seed).
        let mut bare = seed;
        for _ in 0..(length - 1) {
            bare = *blake3::hash(&bare).as_bytes();
        }
        // The relay walks one domain-separated step from this value and
        // compares to the (domain-separated) root — it will not match.
        assert_eq!(
            store.validate_committed(&reg.peer_id, &reg.chain_id, 1, &bare).await.unwrap(),
            ValidateOutcome::BadChainValue,
            "a token minted with the legacy bare-BLAKE3 step must be rejected",
        );
    }
}
