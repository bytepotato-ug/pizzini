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

pub const CHAIN_ID_LEN: usize = 16;
pub const CHAIN_VALUE_LEN: usize = 32;

/// Hard cap on chain length so a malicious recipient can't register
/// a chain with `length = u32::MAX` and force linear-in-length work
/// on every validation. Chains longer than this are refused at
/// registration. 2^20 (~1 M presentations) is well above any
/// realistic user's lifetime traffic to one peer.
pub const MAX_CHAIN_LENGTH: u32 = 1 << 20;

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
    path: PathBuf,
    key: [u8; encrypted_file::KEY_LEN],
    /// `(peer_id, chain_id) → state`.
    map: HashMap<(Vec<u8>, [u8; CHAIN_ID_LEN]), ChainState>,
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

        let map = match fs::read(&path) {
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

        Ok(ChainValidatorStore { path, key, map })
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
        self.persist()?;
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
        let mut current = *value;
        for _ in 0..delta {
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
        self.persist()?;
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
            self.persist()?;
        }
        Ok(removed)
    }

    fn persist(&self) -> io::Result<()> {
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
        let ciphertext = encrypted_file::encrypt_with_aad(&self.key, &plaintext, AAD)?;
        encrypted_file::write_atomic(&self.path, &ciphertext)
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
}

fn purge_stale(
    doc: StoreDoc,
    max_age: Duration,
) -> HashMap<(Vec<u8>, [u8; CHAIN_ID_LEN]), ChainState> {
    let now = encrypted_file::unix_now();
    let cutoff = now.saturating_sub(max_age.as_secs());
    let mut out: HashMap<(Vec<u8>, [u8; CHAIN_ID_LEN]), ChainState> = HashMap::new();
    for (composite, entry) in doc.entries {
        if entry.last_used_unix <= cutoff {
            continue;
        }
        let Some((peer_hex, chain_hex)) = composite.split_once(':') else {
            continue;
        };
        let Some(peer) = encrypted_file::hex_decode(peer_hex) else {
            continue;
        };
        let Some(chain_id_vec) = encrypted_file::hex_decode(chain_hex) else {
            continue;
        };
        if chain_id_vec.len() != CHAIN_ID_LEN {
            continue;
        }
        let Some(root_vec) = encrypted_file::hex_decode(&entry.root_hex) else {
            continue;
        };
        let Some(last_val_vec) = encrypted_file::hex_decode(&entry.last_value_hex) else {
            continue;
        };
        if root_vec.len() != CHAIN_VALUE_LEN || last_val_vec.len() != CHAIN_VALUE_LEN {
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
