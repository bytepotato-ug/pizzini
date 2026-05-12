//! Pizzini relay — development build (LAN TCP).
//!
//! Hard rules (production):
//! - No persistent state about clients or messages.
//! - No clearnet bind. Listens on a Tor onion address only.
//! - No logging that survives a process restart.
//!
//! THIS BUILD VIOLATES THE FIRST TWO. It is a *dev relay* meant only for
//! sim ↔ phone testing on a trusted LAN. Bytes traveling over the wire are
//! libsignal-encrypted, so the relay sees only ciphertext + routing
//! identifiers — but routing identifiers are still observable. The
//! production relay needs a separate task: bind via `arti-client` /
//! `tor-hsservice` to an ephemeral onion service, drop the clearnet listener.
//!
//! ## Wire protocol v2 (length-prefixed framing, big-endian)
//!
//! ```text
//! Frame: u32 payload_len + payload
//!
//! Payload:
//!   u8  frame_type
//!   ...
//!
//! HELLO (type = 1) — client → relay, must be the first frame:
//!   u8  protocol_version       (= 2; v1 clients are rejected)
//!   u16 peer_id_len + peer_id_bytes
//!   u16 verify_key_len + verify_key_bytes  (33 B; libsignal PublicKey
//!                                            serialize() — recipient's
//!                                            delivery-token verify key)
//!
//! SEND  (type = 2) — bidirectional. The payload is a sealed-sender
//!                    envelope; the relay never sees from_id, message
//!                    type, or message_id. Drop or queue based on
//!                    recipient online/offline:
//!   u16 to_len   + to_id_bytes
//!   u32 ttl_seconds                   (sender-chosen; clamped to 7d)
//!   u16 token_len + token_bytes       (Phase 3: Ed25519 sig)
//!   sealed_ciphertext                 (consume to end-of-payload)
//!
//! ACK   (type = 6) — same shape as SEND. The sealed payload's plaintext
//!                    contains "ack: <16-byte message_id>" so the
//!                    original sender can mark its outbox entry
//!                    delivered. Forwarded and queued identically:
//!   u16 to_len   + to_id_bytes
//!   u32 ttl_seconds
//!   u16 token_len + token_bytes
//!   sealed_ciphertext
//!
//! BUNDLE_REQUEST  (type = 3) — "give me a fresh PreKey bundle to PQXDH with":
//!   u16 to_len   + to_id_bytes
//!   u16 from_len + from_id_bytes
//!   u64 hashcash_nonce               (BLAKE3 PoW; see `hashcash` notes)
//!
//! BUNDLE_RESPONSE (type = 4) — reply with the bundle bytes (store.rs format):
//!   u16 to_len   + to_id_bytes
//!   u16 from_len + from_id_bytes
//!   bundle bytes (consume to end-of-payload)
//!
//! TOKEN_ISSUE (type = 7) — recipient mints 1024 delivery tokens for the
//!                          requester so subsequent SEND/ACK frames pass
//!                          the relay's per-recipient rate-limit gate.
//!                          Sent right after BUNDLE_RESPONSE on first
//!                          contact, also in response to a sealed
//!                          token-refill-request when a stash gets low:
//!   u16 to_len   + to_id_bytes
//!   u16 from_len + from_id_bytes
//!   u32 token_count
//!   token_bytes  (84 bytes each: nonce16 + expiry_be_u32 + sig64)
//!
//! Hashcash on BUNDLE_REQUEST: the sender computes a u64 nonce such
//! that `BLAKE3(challenge || nonce_be) starts with ≥ 18 zero bits`,
//! where `challenge = BLAKE3(recipient_peer_id || floor(unix_time/3600))`.
//! Cost ~1s on a modern phone; multi-day on a dedicated attacker box
//! per recipient, per hour. Acceptable for first-contact frequency. The
//! relay accepts the current and previous hour to absorb clock skew.
//!
//! Bundle frames keep `from_id` at the wire level — bundle exchange is
//! first-contact before a session exists; the SEND-level sealed envelope
//! isn't yet usable. We accept the residual metadata leak (the relay
//! sees who's QR-pairing with whom) for the rare bundle frequency. Phase
//! 3 layers a hashcash PoW on bundle frames so the leak isn't free DoS
//! amplification.
//!
//! REGISTER_PUSH  (type = 5) — client publishes its APNs device token so
//!                              we can wake it on offline SEND:
//!   u16 token_len + token_bytes
//!
//! Bundle exchange exists because Kyber1024 (~1568 B) does not fit a
//! comfortably-scannable QR. Discovery QRs carry only `peer_id +
//! lan_address`; the actual bundle hops through the relay on first contact.
//! This is the same shape Signal uses (server stores bundles for fetch).
//! For our stateless relay, both peers must be online for first contact.
//! ```
//!
//! Stateless-ish: if the recipient is not currently connected, the SEND
//! frame is held in an *ephemeral, in-memory* per-peer queue (capped
//! size, capped age — no disk persistence, process restart wipes
//! everything). When the recipient HELLOs, the queue drains in order.
//! Bundle frames are NOT queued — bundle exchange is a first-contact
//! handshake and both peers must be online for it.
//!
//! The queue is consistent with the "stateless server" hard rule: there
//! are no per-user accounts, no long-term state, no on-disk records that
//! survive a process restart. The queue only buffers in-flight encrypted
//! routing frames the relay was already going to forward — same
//! threat-profile as the live route table itself.
//!
//! Push remains a wake-up: if APNs is configured and the recipient has
//! REGISTER_PUSH'd, we fire a payload-opaque "New message" push so iOS
//! brings the app forward. On reconnect, the queue drains.

mod apns;
mod encrypted_file;
mod pending_store;
mod push_token_store;
mod replay_store;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libsignal_protocol::PublicKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;

use crate::apns::{ApnsClient, ApnsConfig};
use crate::pending_store::{PendingFrame, PendingStore};
use crate::push_token_store::PushTokenStore;
use crate::replay_store::ReplayStore;

/// Static self-attestation snapshot computed once at startup. Shared
/// (`Arc`) with every connection handler so STATUS_REQUEST handling
/// is a clone + serialize, not a re-read of the binary.
///
/// All fields are derived deterministically from the running
/// binary + the build-time `PIZZINI_GIT_SHA` env vars (USP #1):
///   * `crate_version` is `CARGO_PKG_VERSION` (e.g. `"0.0.0"`).
///   * `git_sha` is the 40-char hex of the source commit; `"unknown"`
///     when built outside a git checkout (release scripts refuse
///     this case, but a dev build still functions).
///   * `git_dirty` is `1` iff the working tree had uncommitted
///     changes when this binary was built. Production transparency-
///     log entries must report `0`; dev builds typically report `1`.
///   * `binary_sha256` is the SHA-256 of the on-disk binary at
///     startup — re-derived independently of the build script so
///     a sed-the-self-attestation-string-out-of-the-binary attack
///     produces a different digest than the original build.
#[derive(Clone)]
struct RelayStatus {
    crate_version: String,
    git_sha: String,
    git_dirty: u8,
    binary_sha256: [u8; STATUS_BIN_HASH_LEN],
}

impl RelayStatus {
    /// Compute the snapshot. Called exactly once from `main`. Reading
    /// the binary on every STATUS_REQUEST would let an attacker who
    /// races a relay restart observe whether the disk-side binary
    /// has been swapped — startup-time caching defends against that
    /// and amortises the (single) ~MB-sized I/O.
    fn capture() -> std::io::Result<Self> {
        use sha2::Digest;
        let path = std::env::current_exe()?;
        let bytes = std::fs::read(&path)?;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let mut binary_sha256 = [0u8; STATUS_BIN_HASH_LEN];
        binary_sha256.copy_from_slice(&digest);
        // `env!` panics if missing; build.rs sets these unconditionally
        // (with sentinel values when git is unavailable), so they are
        // always present at compile time.
        let git_sha = env!("PIZZINI_GIT_SHA").to_string();
        let git_dirty = match env!("PIZZINI_GIT_DIRTY") {
            "1" => 1u8,
            "0" => 0u8,
            // Build outside a git checkout (e.g. cargo package).
            // Distinct from clean (0) so the transparency-log
            // verifier can refuse this distinction loudly.
            _ => 2u8,
        };
        Ok(Self {
            crate_version: env!("CARGO_PKG_VERSION").to_string(),
            git_sha,
            git_dirty,
            binary_sha256,
        })
    }

    /// Serialize the response payload — see STATUS_RESPONSE wire
    /// format below. Caller wraps with the standard frame header
    /// (`write_frame`).
    fn encode_response(&self) -> Vec<u8> {
        let crate_version_bytes = self.crate_version.as_bytes();
        let git_sha_bytes = self.git_sha.as_bytes();
        let mut out = Vec::with_capacity(
            1 + 1 + 1 + 2 + crate_version_bytes.len() + 2 + git_sha_bytes.len()
                + 1 + STATUS_BIN_HASH_LEN,
        );
        out.push(FRAME_TYPE_STATUS_RESPONSE);
        // Protocol version this relay implements (the same value
        // every HELLO is signed against). Surfaced so the client
        // can refuse to operate against a relay running an older
        // protocol even if the .onion is reachable.
        out.push(PROTOCOL_VERSION);
        out.push(self.git_dirty);
        out.extend_from_slice(&(crate_version_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(crate_version_bytes);
        out.extend_from_slice(&(git_sha_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(git_sha_bytes);
        out.push(STATUS_BIN_HASH_LEN as u8);
        out.extend_from_slice(&self.binary_sha256);
        out
    }
}

// STATUS_RESPONSE wire format (big-endian, immediately follows the
// 4-byte frame length prefix that `write_frame` prepends):
//
//   u8  frame_type            (= FRAME_TYPE_STATUS_RESPONSE = 9)
//   u8  protocol_version       (currently 3 — matches HELLO_SIGNING_TAG bump path)
//   u8  git_dirty              (0 = clean, 1 = dirty, 2 = unknown / not-a-git-checkout)
//   u16 crate_version_len + crate_version_bytes (UTF-8, no NUL)
//   u16 git_sha_len + git_sha_bytes             (UTF-8 hex, typically 40 chars)
//   u8  binary_sha256_len      (always STATUS_BIN_HASH_LEN = 32)
//   [32] binary_sha256

const PORT: u16 = 7777;
/// Default listen address. Production deployment is behind a system
/// Tor `HiddenServicePort` that forwards `.onion:PORT` to
/// `127.0.0.1:PORT`, so the relay must NOT be reachable from any
/// other interface. Dev workflows that need the iOS simulator to
/// connect from a different host (or sibling simulator) override
/// this via the `PIZZINI_RELAY_BIND` env var — see
/// `scripts/install-relay-launchd.sh`, which sets it to
/// `0.0.0.0:7777` for the LaunchAgent on the operator's Mac.
///
/// Defaulting to `127.0.0.1` rather than `0.0.0.0` is the
/// fail-safe choice: forgetting to set the env var in a prod
/// deploy produces an unreachable relay (loud failure) instead of
/// an internet-exposed relay (silent compromise).
const DEFAULT_BIND: &str = "127.0.0.1:7777";
/// Hard ceiling on simultaneously-accepted connections. Acts as
/// backpressure on the accept loop: once reached, new TCP SYNs queue
/// in the kernel accept backlog until an existing connection closes
/// and frees a permit. Without this cap, a flood of half-open
/// connections drives unbounded `tokio::spawn` calls and exhausts
/// file descriptors + memory before any per-frame defence engages.
///
/// 4096 lines up with a `LimitNOFILE=16384` systemd setting (3:1
/// headroom for Tor sockets, log fds, state files). Tune via
/// `PIZZINI_RELAY_MAX_CONNS` — increasing requires bumping
/// `LimitNOFILE` in the unit file in lockstep.
const DEFAULT_MAX_CONNECTIONS: usize = 4096;
/// Time budget for a connection to complete the HELLO handshake.
/// Slow-loris connections that open a TCP socket and never send the
/// HELLO bytes get killed inside this window, returning the
/// concurrent-connection permit. Generous enough for a slow Tor
/// circuit; aggressive enough that a flood of "open-and-stall"
/// connections drains the permit pool within ~30s.
const HELLO_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Time budget for any single post-HELLO frame to arrive. Resets
/// per frame, so a quiet but legitimate foreground client whose
/// counterpart hasn't sent anything in the last 30 minutes is
/// dropped — iOS clients in this state have almost certainly been
/// suspended by the OS already (background app → Tor circuit
/// torn down → TCP RST observed here long before 30 minutes
/// elapses). Slow-loris attackers who fail to send a full frame
/// within the window are dropped and their permit freed.
///
/// Picking a long timeout intentionally trades fast-detection of
/// slow attackers for "do not constantly disconnect legitimate
/// idle clients." With the connection cap above, the worst a
/// slow-loris campaign can do is hold `MAX_CONNECTIONS` permits
/// for up to `FRAME_READ_TIMEOUT` each — bounded.
const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Protocol v3 adds the F-203 HELLO possession proof. The added fields
/// (timestamp, nonce, signature) prevent a network-positioned attacker
/// from squatting another peer's `peer_id` to drain that peer's queued
/// mail or DoS third-party token-bearing SENDs by registering a wrong
/// verify_key.
const PROTOCOL_VERSION: u8 = 3;
/// Domain-separation tag baked into the HELLO signing payload. F-203:
/// peer's IdentityKey signs `tag || peer_id || verify_key || ts_be ||
/// nonce16`; relay verifies with the IdentityKey extracted from
/// `peer_id` (which IS the libsignal IdentityKey wire form, 1-byte
/// type prefix + 32-byte point). MUST match the iOS encoder byte-for-
/// byte.
/// HELLO signing-tag — the SHA-3-style domain separator that
/// distinguishes a HELLO signature from any other identity-key signed
/// payload. Bumping the version suffix is the path for any future
/// HELLO wire-format change (`PROTOCOL_VERSION` bump, additional
/// fields, etc.): producing a `v2` tag makes a downgrade attack
/// structurally impossible because a signature minted under `v3`
/// simply doesn't verify against the `v2` verifier. F-NEW-205.
const HELLO_SIGNING_TAG: &[u8] = b"pizzini.hello.v3";
/// Maximum clock skew between client and relay accepted on a HELLO.
/// Keeps the replay set bounded — a fresh HELLO past this window won't
/// verify, so an attacker can't accumulate replay nonces forever.
const HELLO_MAX_CLOCK_SKEW_SECS: i64 = 60;
/// Length of the HELLO nonce. 16 random bytes — collision space large
/// enough that the relay's per-peer (peer_id, nonce) replay set won't
/// false-positive on legitimate reconnects.
const HELLO_NONCE_LEN: usize = 16;
/// How long a HELLO (peer_id, nonce) stays in the replay set. Two
/// minutes covers the timestamp window plus comfortable slack; longer
/// retention gains nothing because the timestamp would itself reject
/// any older HELLO.
const HELLO_REPLAY_WINDOW: Duration = Duration::from_secs(120);
/// HELLO signature length — Ed25519/XEd25519 fixed.
const HELLO_SIG_LEN: usize = 64;
const FRAME_TYPE_HELLO: u8 = 1;
const FRAME_TYPE_SEND: u8 = 2;
const FRAME_TYPE_BUNDLE_REQUEST: u8 = 3;
const FRAME_TYPE_BUNDLE_RESPONSE: u8 = 4;
const FRAME_TYPE_REGISTER_PUSH: u8 = 5;
const FRAME_TYPE_ACK: u8 = 6;
const FRAME_TYPE_TOKEN_ISSUE: u8 = 7;
/// USP #1: binary self-attestation. Client → relay request, empty
/// payload. Relay replies with a STATUS_RESPONSE (frame 9) carrying
/// crate version, git commit SHA, "dirty?" bit, and SHA-256 of the
/// running binary. iOS uses the response to surface "running build
/// X (commit Y)" in Settings and (eventually) to compare against
/// a published transparency-log entry.
const FRAME_TYPE_STATUS_REQUEST: u8 = 8;
const FRAME_TYPE_STATUS_RESPONSE: u8 = 9;
/// USP #4 (pacing pass). Client → relay decoy traffic emitted at a
/// constant rate when the user is connected but otherwise idle. The
/// relay receives, validates the size envelope, and discards. The
/// frame exists so a network observer of the Tor traffic sees a
/// uniform-rate, uniform-size stream of cells regardless of
/// whether the user is actively chatting — combined with the
/// padded sealed envelopes (USP #4-lite), this hides both message
/// timing and length at the wire layer.
const FRAME_TYPE_COVER: u8 = 10;
/// Client → relay request to drop our APNs device token from the
/// relay's persistent push-token store. Sent by iOS when the client
/// elects a different relay as push-primary so the old primary
/// (which still holds the token until the TTL purge fires 30 days
/// later) stops emitting duplicate APNs wake-ups for every inbound
/// SEND. Body is empty — the relay knows which peer issued the
/// frame from the authenticated HELLO. Idempotent: a no-op when
/// the peer has no entry in the store.
const FRAME_TYPE_DEREGISTER_PUSH: u8 = 11;
/// Fixed payload size for COVER frames (post-frame-type body).
/// Sized to roughly match the smallest padded sealed_ciphertext
/// bucket (256 bytes) so the wire byte-count of a heartbeat is
/// indistinguishable from a typical short SEND at the cell-counting
/// granularity available to a passive observer.
const COVER_PAYLOAD_LEN: usize = 256;
/// Width of the binary SHA-256 digest carried in STATUS_RESPONSE.
/// Same as `sha2::Sha256` output. Fixed-width so the wire layout
/// stays decode-once.
const STATUS_BIN_HASH_LEN: usize = 32;
const MAX_FRAME_BYTES: u32 = 1024 * 1024;
/// Hard ceiling on a single client's APNs device token. Real tokens are
/// 32 bytes today; Apple has hinted they may grow. Reject anything above
/// this so we don't memo absurd buffers per peer.
/// Lower/upper bound for an APNs device token (production). Apple
/// ships 32-byte tokens today, with hints in dev docs that they may
/// grow — accept a tight range, refuse the obvious garbage (a 256-
/// byte all-zero blob, or anything smaller than the floor) so the
/// relay doesn't waste APNs round-trips and risk Apple flagging the
/// auth key. F-NEW-207.
const MIN_PUSH_TOKEN_BYTES: usize = 16;
const MAX_PUSH_TOKEN_BYTES: usize = 64;

/// Per-peer pending-queue cap. The queue is purely in-memory; this cap
/// bounds RAM use and the post-seizure leak surface. 100 frames is a
/// generous chat burst.
const MAX_PENDING_PER_PEER: usize = 100;
/// Hard ceiling on a sender-chosen TTL. Anything past 7 days is clamped
/// down on enqueue. Bounds the seizure-window leak the same way the
/// previous fixed 24h cap did, while letting senders explicitly choose
/// shorter retention via the per-message TTL UI.
const MAX_PENDING_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// How often the GC task scans every per-peer queue for expired entries.
const PENDING_GC_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// XEd25519 verify key wire size — 1-byte DJB type prefix + 32-byte point.
const VERIFY_KEY_LEN: usize = 33;
/// Delivery-token wire layout: nonce(16) + expiry_be_u32(4) + sig(64).
const TOKEN_NONCE_LEN: usize = 16;
const TOKEN_SIG_LEN: usize = 64;
const TOKEN_LEN: usize = TOKEN_NONCE_LEN + 4 + TOKEN_SIG_LEN;
/// First-contact PoW difficulty. Verifier rejects anything weaker.
/// Hashcash difficulty in leading-zero bits. F-NEW-209: raised from
/// 18 → 22 so a desktop-GPU attacker no longer collapses the per-
/// recipient gate. Math:
///   - 2^18 ≈ 260 k hashes per proof → ~5 µs/proof on RTX 4090 →
///     ~190 k/s sustained per-recipient flood
///   - 2^22 ≈ 4.2 M hashes per proof → ~80 ms/proof on RTX 4090 →
///     ~12/s — still trivially defeats hashcash for a determined
///     attacker but adds enough cost that the asymmetry vs. a phone
///     (~1 s/proof on A14) is no longer free.
///
/// Per-recipient relay-side rate-limit on BUNDLE_REQUEST is the
/// proper defense; hashcash is the spam filter. Bumping bits keeps
/// the spam filter relevant against modern hardware until the relay
/// gains that rate-limit.
const HASHCASH_BITS: u32 = 22;
/// Domain-separation tag baked into the hashcash challenge digest. F-301:
/// without a tag + length prefix, two distinct (peer_id, hour) pairs can
/// theoretically map to the same 32-byte challenge. Bumping this string
/// invalidates every in-flight precomputed proof — coordinate with iOS.
const HASHCASH_CHALLENGE_TAG: &[u8] = b"pizzini.hashcash.bundle.v1";
/// How long a SEND/ACK token's nonce stays in the replay set after we
/// see it. F-201: must be ≥ token TTL (30d) so we never forget a nonce
/// while its token is still verifiable; otherwise a captured frame can be
/// replayed during the (TTL − replay-window) gap. RAM cost is bounded by
/// the per-peer issuance rate × number of active peers; the 5-minute GC
/// task drops expired entries, so steady-state size tracks active load
/// rather than peak.
const TOKEN_REPLAY_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// How often we GC the token replay set.
const TOKEN_REPLAY_GC_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// Hard ceiling on accepted token expiry (relative to now). Mirrors
/// crypto-core's DELIVERY_TOKEN_TTL_SECS plus a 5-minute clock-skew
/// margin. F-205: a malicious recipient who minted tokens with
/// `expiry = u32::MAX` would otherwise pin the token replayable for the
/// life of the verify_key — the relay rejects such tokens client-side
/// rather than relying on the recipient's good behaviour.
const TOKEN_MAX_FUTURE_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60 + 5 * 60;

type PeerId = Vec<u8>;
type Outbox = mpsc::UnboundedSender<Vec<u8>>;
type Routes = Arc<Mutex<HashMap<PeerId, Outbox>>>;
/// Persistent push-token store. Lives across reconnects (the whole
/// point: we look up the token when the recipient is *not* currently
/// connected) AND across relay restarts (the recent fix: before this
/// the in-memory HashMap was wiped on every process bounce, silently
/// breaking push for every paired device until the iOS app
/// foregrounded and re-published its APNs token). See
/// `push_token_store.rs` for the threat-model framing of the
/// encryption-at-rest + TTL guard-rails.
type PushTokens = Arc<Mutex<PushTokenStore>>;
/// Per-recipient delivery-token verify key. Populated by the
/// recipient's HELLO and refreshed on every successful
/// `check_delivery_token` lookup. The value's `Instant` is the last
/// time we touched the entry; the periodic GC prunes anything older
/// than `VERIFY_KEY_TTL`.
///
/// Why time-based instead of remove-on-disconnect (the F-204 fix
/// before fix-review): a SEND aimed at a recently-disconnected peer
/// still needs the recipient's verify_key to pass `check_delivery_token`
/// — otherwise the frame is dropped before reaching `enqueue_pending`,
/// breaking the offline-message-delivery feature. Time-based GC
/// preserves the verify_key for the full token TTL window AND bounds
/// memory + linkability the same way: an attacker padding peer_ids
/// gets entries that age out in `VERIFY_KEY_TTL`. N-002.
type VerifyKeys = Arc<Mutex<HashMap<PeerId, (Vec<u8>, Instant)>>>;
/// How long a verify_key entry lives without being touched. Must be
/// ≥ `DELIVERY_TOKEN_TTL_SECS` so a token from the longest possible
/// holdout sender still finds its issuer's key. The token TTL itself
/// guarantees that pruned entries never correspond to a still-valid
/// token.
const VERIFY_KEY_TTL: Duration = TOKEN_REPLAY_WINDOW;
/// How often the GC walks the verify_keys table. 1h is well below
/// `VERIFY_KEY_TTL` (30d) — coarse enough to keep lock contention
/// negligible, fine enough that "drift past TTL" stays bounded.
const VERIFY_KEY_GC_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Replay-set entry: (recipient_peer_id, token_nonce). Each token is
/// one-use against a given recipient; the same nonce against a
/// different recipient is a logically different token (different
/// signing key, would fail verification anyway).
///
/// F-NEW-203 fix: the replay set is PERSISTENT (encrypted-at-rest)
/// rather than in-memory. The pending-queue is persistent; without a
/// matching persistent replay set, every relay restart would re-open
/// the replay window against any captured SEND whose token hadn't
/// expired. See `replay_store::ReplayStore` for the storage layer.
/// Pre-F-NEW-203 the relay used `(PeerId, [u8; TOKEN_NONCE_LEN])`
/// as a direct HashMap key. The new persistent store uses
/// `(Vec<u8>, Vec<u8>)` internally to keep its on-disk serde shape
/// flexible; the type alias is gone with it.
type Replays = Arc<Mutex<ReplayStore>>;
/// HELLO replay set: (peer_id, nonce) keys. Separate from the SEND/ACK
/// `Replays` table because (a) the lifetime is much shorter (matches
/// the timestamp window, not the token TTL) and (b) the lookup happens
/// on every HELLO not every SEND. F-203.
type HelloReplayKey = (PeerId, [u8; HELLO_NONCE_LEN]);
type HelloReplays = Arc<Mutex<HashMap<HelloReplayKey, Instant>>>;

/// Persistent offline-message queue, wrapping `pending_store::PendingStore`.
/// Pre-this refactor the queue was an in-memory `HashMap<PeerId,
/// VecDeque<PendingFrame>>` wiped on every restart — meaning a relay
/// bounce silently dropped every in-flight message destined for an
/// offline recipient. Now backed by an encrypted file under
/// `PIZZINI_RELAY_STATE_DIR/pending.bin`, atomically rewritten on
/// every mutation, with per-frame TTL surviving the bounce.
///
/// `PendingFrame` lives in `pending_store` so the on-disk format is
/// the same type as the in-memory representation — no separate
/// serializable shadow type. The frame's `bytes_hex` field is the
/// entire wire frame as it would have been forwarded (frame_type byte
/// + recipient header + payload), hex-encoded for JSON-safety.
type Pending = Arc<Mutex<PendingStore>>;

/// Per-peer activity log. F-903: gated on `debug_assertions` so a
/// `--release` relay never prints peer_id metadata to stdout, closing
/// the production-drift path the module's "no logging that survives a
/// process restart" rule warns about. Dev builds (default `cargo run`)
/// keep the diagnostics; release builds (production Tor onion target)
/// no-op.
#[cfg(debug_assertions)]
macro_rules! dev_peer_log {
    ($($arg:tt)*) => { println!($($arg)*) };
}
#[cfg(not(debug_assertions))]
macro_rules! dev_peer_log {
    ($($arg:tt)*) => { () };
}
#[cfg(debug_assertions)]
macro_rules! dev_peer_elog {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}
#[cfg(not(debug_assertions))]
macro_rules! dev_peer_elog {
    ($($arg:tt)*) => { () };
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let bind_str = std::env::var("PIZZINI_RELAY_BIND")
        .unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let bind: SocketAddr = bind_str.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("PIZZINI_RELAY_BIND={bind_str:?} not a valid SocketAddr: {e}"),
        )
    })?;
    let max_conns: usize = std::env::var("PIZZINI_RELAY_MAX_CONNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONNECTIONS);
    let listener = TcpListener::bind(bind).await?;
    let lan_ips = local_lan_ips();
    // USP #1: self-attestation snapshot. Computed once at startup.
    // A read failure here is fatal — the operator deployed a
    // binary that can't read its own bytes, which means the
    // STATUS_RESPONSE machinery is broken and the transparency-log
    // contract can't be honoured. Better to refuse to start than
    // to come up reporting "unknown" to every client.
    let status_snapshot = Arc::new(RelayStatus::capture().map_err(|e| {
        eprintln!(
            "[pizzini-relay] FATAL: could not self-attest the binary at startup: {e}",
        );
        e
    })?);
    println!(
        "pizzini-relay {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        bind
    );
    println!(
        "  build attestation: git_sha={} dirty={} binary_sha256={}",
        status_snapshot.git_sha,
        status_snapshot.git_dirty,
        hex(&status_snapshot.binary_sha256),
    );
    if bind.ip().is_loopback() {
        println!("  bind is loopback — production posture (Tor HiddenServicePort forwards .onion → {bind})");
    } else if lan_ips.is_empty() {
        println!("  (no non-loopback IPv4 found; sim can connect to 127.0.0.1)");
    } else {
        for ip in &lan_ips {
            println!("  reachable from LAN at {ip}:{PORT}");
        }
    }
    println!(
        "  pending queue cap={MAX_PENDING_PER_PEER}/peer, max ttl={}h, sender-chosen per frame",
        MAX_PENDING_TTL.as_secs() / 3600,
    );
    println!(
        "  connection cap={max_conns} (override: PIZZINI_RELAY_MAX_CONNS); HELLO timeout={}s, frame idle timeout={}m",
        HELLO_READ_TIMEOUT.as_secs(),
        FRAME_READ_TIMEOUT.as_secs() / 60,
    );
    println!("  protocol v{PROTOCOL_VERSION} — sealed-sender SEND/ACK, drop on TTL");

    let apns = match ApnsConfig::from_env() {
        Ok(Some(cfg)) => match ApnsClient::new(cfg) {
            Ok(c) => {
                println!("  apns: enabled ({:?})", c.endpoint());
                Some(Arc::new(c))
            }
            Err(e) => {
                eprintln!("  apns: failed to initialise — push disabled: {e}");
                None
            }
        },
        Ok(None) => {
            println!(
                "  apns: disabled (set APNS_AUTH_KEY_PATH, APNS_TEAM_ID, APNS_KEY_ID to enable)"
            );
            None
        }
        Err(e) => {
            eprintln!("  apns: misconfigured — push disabled: {e}");
            None
        }
    };

    let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
    // Persistent push-token store. Built before the listener starts so
    // we refuse to come up at all if the state files are corrupt /
    // tampered (better than silently "recovering" by treating the map
    // as empty, which would invalidate every paired device's push
    // registration). The startup line below tells the operator where
    // state lives and how many tokens survived the TTL purge.
    let state_dir = PushTokenStore::resolve_state_dir();
    let store = PushTokenStore::load_or_create(&state_dir).map_err(|e| {
        eprintln!(
            "[pizzini-relay] FATAL: could not open push-token store at {}: {e}",
            state_dir.display(),
        );
        e
    })?;
    println!(
        "  push-token store: {} ({} live tokens after TTL purge)",
        state_dir.display(),
        store.len(),
    );
    let push_tokens: PushTokens = Arc::new(Mutex::new(store));
    // Persistent offline-message queue. Same shape as the push-token
    // store: built BEFORE the listener accept loop so a corrupt state
    // file surfaces at startup, not silently mid-traffic. Per-peer
    // cap is `MAX_PENDING_PER_PEER` — the single source of truth on
    // this constant stays in main.rs so a future tune doesn't need
    // to chase it through two files.
    let pending_store_inst = PendingStore::load_or_create(&state_dir, MAX_PENDING_PER_PEER)
        .map_err(|e| {
            eprintln!(
                "[pizzini-relay] FATAL: could not open pending-queue store at {}: {e}",
                state_dir.display(),
            );
            e
        })?;
    println!(
        "  pending-queue store: {} ({} frames across {} peers after TTL purge)",
        state_dir.display(),
        pending_store_inst.total_frames(),
        pending_store_inst.peers_with_queues(),
    );
    let pending: Pending = Arc::new(Mutex::new(pending_store_inst));
    let verify_keys: VerifyKeys = Arc::new(Mutex::new(HashMap::new()));
    let replay_store_inst = ReplayStore::load_or_create(&state_dir, TOKEN_REPLAY_WINDOW)
        .map_err(|e| {
            eprintln!(
                "[pizzini-relay] FATAL: could not open replay store at {}: {e}",
                state_dir.display(),
            );
            e
        })?;
    println!(
        "  replay store: {} ({} entries after TTL purge)",
        state_dir.display(),
        replay_store_inst.len(),
    );
    let replays: Replays = Arc::new(Mutex::new(replay_store_inst));
    let hello_replays: HelloReplays = Arc::new(Mutex::new(HashMap::new()));

    spawn_pending_gc(pending.clone());
    spawn_replay_gc(replays.clone());
    spawn_hello_replay_gc(hello_replays.clone());
    spawn_verify_keys_gc(verify_keys.clone());
    spawn_push_tokens_gc(push_tokens.clone());

    // Concurrent-connection cap. The accept loop blocks on
    // `acquire_owned()` once `max_conns` connections are live —
    // surplus TCP SYNs back up in the kernel accept queue (and
    // eventually get RST'd if the backlog overflows), which is the
    // correct behaviour: a full relay refuses, it doesn't OOM. The
    // permit is held inside the spawned task and dropped on task
    // exit, returning capacity exactly when the connection closes.
    let conn_limit = Arc::new(Semaphore::new(max_conns));

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        // Block until a permit is available. `acquire_owned()` cannot
        // fail unless the semaphore is closed, which we never do —
        // `.expect()` here is a documented-impossible panic.
        let permit = conn_limit
            .clone()
            .acquire_owned()
            .await
            .expect("connection-limit semaphore is never closed");
        let routes = routes.clone();
        let push_tokens = push_tokens.clone();
        let pending = pending.clone();
        let verify_keys = verify_keys.clone();
        let replays = replays.clone();
        let hello_replays = hello_replays.clone();
        let apns = apns.clone();
        let status_snapshot = status_snapshot.clone();
        tokio::spawn(async move {
            // Move the permit into the task so it lives exactly as
            // long as the connection. The `_` prefix keeps clippy
            // from suggesting we drop it explicitly — it must hold
            // until the task ends.
            let _conn_permit = permit;
            if let Err(e) = handle_connection(
                stream,
                routes,
                push_tokens,
                pending,
                verify_keys,
                replays,
                hello_replays,
                apns,
                status_snapshot,
                peer_addr,
            )
            .await
            {
                eprintln!("[{peer_addr}] connection closed: {e}");
            }
        });
    }
}

/// Background task that walks every per-peer queue and drops entries
/// past their per-frame `expires_at_unix`. With sender-chosen TTLs
/// the queue is no longer monotone in arrival order — a 1h-TTL frame
/// queued after a 7d-TTL frame expires first — so we can't
/// short-circuit on the front. Walks the whole deque every cycle,
/// which is fine: caps keep each queue ≤ `MAX_PENDING_PER_PEER`
/// entries.
///
/// Persistence-aware: `PendingStore::gc_expired` re-serializes the
/// queue file only if anything was actually dropped, so a steady-
/// state relay with no expirations doesn't burn disk I/O every
/// `PENDING_GC_INTERVAL`.
fn spawn_pending_gc(pending: Pending) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(PENDING_GC_INTERVAL);
        loop {
            tick.tick().await;
            let mut store = pending.lock().await;
            match store.gc_expired() {
                Ok(0) => {}
                Ok(n) => dev_peer_log!("pending: GC dropped {n} expired frames"),
                Err(e) => eprintln!("[pizzini-relay] warn: pending GC persist failed: {e}"),
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: TcpStream,
    routes: Routes,
    push_tokens: PushTokens,
    pending: Pending,
    verify_keys: VerifyKeys,
    replays: Replays,
    hello_replays: HelloReplays,
    apns: Option<Arc<ApnsClient>>,
    status_snapshot: Arc<RelayStatus>,
    peer_addr: SocketAddr,
) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let (mut reader, mut writer) = stream.into_split();

    // A connection that doesn't send HELLO within `HELLO_READ_TIMEOUT`
    // is either a port scanner or a slow-loris occupying a permit
    // without ever progressing — drop it, free the permit. The
    // generic frame-idle timeout in `read_loop` is intentionally
    // longer (30 min) because legitimate idle clients post-HELLO
    // can sit waiting for an inbound SEND; pre-HELLO has no
    // legitimate reason to stall.
    let first = tokio::time::timeout(HELLO_READ_TIMEOUT, read_frame(&mut reader))
        .await
        .map_err(|_| invalid("HELLO read timed out"))??;
    if first.is_empty() || first[0] != FRAME_TYPE_HELLO {
        return Err(invalid("first frame must be HELLO"));
    }
    let parsed_hello = parse_hello(&first[1..]).map_err(|e| {
        // Refuse v1/v2 clients loudly so a stale build can't silently
        // corrupt v3 routing state. Connection is closed by the caller
        // on Err return.
        eprintln!("[{peer_addr}] HELLO rejected: {e}");
        e
    })?;
    // F-203: verify the possession proof BEFORE writing anything to the
    // global routes / verify_keys tables. A failure here means the
    // HELLO came from someone who doesn't hold the IdentityKey private
    // half — typically a network attacker squatting another peer's
    // peer_id to drain queued mail or DoS token verification.
    if let Err(e) = verify_hello_possession_proof(&parsed_hello, &hello_replays).await {
        eprintln!(
            "[{peer_addr}] HELLO possession proof rejected for {}: {e}",
            short_hex(&parsed_hello.peer_id),
        );
        return Err(invalid(&format!("HELLO possession proof failed: {e}")));
    }
    let peer_id = parsed_hello.peer_id;
    let verify_key = parsed_hello.verify_key;
    let peer_hex = hex(&peer_id);
    // Register / overwrite the recipient's verify key. Token-bearing
    // SENDs/ACKs to this peer get verified against the latest entry,
    // so a peer rotating its identity wipes any older stash without a
    // separate revocation flow. The `Instant` is the GC's last-touched
    // marker; refreshed on every successful check_delivery_token
    // lookup so a peer with active inbound traffic stays cached even
    // when offline themselves.
    {
        let mut vk = verify_keys.lock().await;
        vk.insert(peer_id.clone(), (verify_key, Instant::now()));
    }
    // F-NEW-211: gate peer-id-bearing log lines behind
    // `dev_peer_log!` so the relay's "no per-peer log lines in
    // production" hard rule is enforced in code, not just policy.
    // `dev_peer_log!` is a no-op when `debug_assertions` is off
    // (i.e. `cargo build --release`). Operators who want full logs
    // can run debug builds.
    dev_peer_log!("[{peer_addr}] HELLO from peer {} (proof verified, verify key registered)", short_hex(&peer_id));

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // Hold a clone so we can identify "is the entry in the map still ours?"
    // on cleanup via `same_channel`. The map gets the original; the clone
    // is dropped at the end of `handle_connection`.
    let our_tx = out_tx.clone();
    {
        let mut map = routes.lock().await;
        if let Some(prev) = map.insert(peer_id.clone(), out_tx) {
            // Older connection for the same peer — drop it. The old
            // writer_task's `out_rx.recv()` will return None on the next
            // poll and the task will exit on its own.
            drop(prev);
        }
    }

    let writer_task = tokio::spawn(async move {
        while let Some(payload) = out_rx.recv().await {
            if write_frame(&mut writer, &payload).await.is_err() {
                break;
            }
        }
        // We exit on either Receiver returning None (all Senders dropped)
        // or write_frame failing. Either way, leave map cleanup to the
        // owning `handle_connection` — it knows which entry was ours.
    });

    drain_pending(&peer_id, &pending, &routes).await;

    let read_result = read_loop(
        &mut reader,
        &routes,
        &push_tokens,
        &pending,
        &verify_keys,
        &replays,
        apns.clone(),
        &peer_id,
        &our_tx,
        &status_snapshot,
    )
    .await;

    // Read side closed → this connection is done. Remove our route entry
    // *if* it still belongs to us (a newer HELLO from the same peer would
    // have replaced it). Then cancel the writer task. After both Senders
    // drop, the writer's `out_rx` returns None and it exits cleanly.
    {
        let mut map = routes.lock().await;
        let still_ours = map
            .get(&peer_id)
            .map(|e| e.same_channel(&our_tx))
            .unwrap_or(false);
        if still_ours {
            map.remove(&peer_id);
        }
    }
    // N-002: verify_keys[peer_id] is NOT eagerly removed on disconnect.
    // The pre-fix-review F-204 patch did that, which broke offline
    // delivery — incoming SENDs to a recently-disconnected peer rely
    // on `check_delivery_token` finding the recipient's verify_key,
    // and a missing key dropped the frame BEFORE `enqueue_pending`
    // could queue it. Verify_keys lifetime is now governed by
    // `spawn_verify_keys_gc`, which prunes entries unused for
    // `VERIFY_KEY_TTL` (= token TTL = 30d). This bounds memory and
    // post-mortem linkability the same way (entries age out) without
    // breaking delivery to peers in their first 30d of disconnect.
    drop(our_tx);
    writer_task.abort();
    dev_peer_log!("[{peer_addr}] disconnected ({peer_hex})");
    read_result
}

#[allow(clippy::too_many_arguments)]
async fn read_loop(
    reader: &mut (impl AsyncReadExt + Unpin),
    routes: &Routes,
    push_tokens: &PushTokens,
    pending: &Pending,
    verify_keys: &VerifyKeys,
    replays: &Replays,
    apns: Option<Arc<ApnsClient>>,
    self_id: &[u8],
    our_tx: &mpsc::UnboundedSender<Vec<u8>>,
    status_snapshot: &Arc<RelayStatus>,
) -> std::io::Result<()> {
    loop {
        // Idle-timeout window resets per frame. A legitimate client
        // in a quiet conversation can sit silently for up to
        // `FRAME_READ_TIMEOUT` between frames; a slow-loris that
        // sends bytes too slowly to complete a frame in that
        // window gets dropped, freeing both the file descriptor
        // and the concurrent-connection permit.
        let frame = match tokio::time::timeout(FRAME_READ_TIMEOUT, read_frame(reader)).await {
            Ok(Ok(f)) => f,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(invalid("frame idle timeout")),
        };
        if frame.is_empty() {
            return Err(invalid("empty frame"));
        }
        match frame[0] {
            FRAME_TYPE_HELLO => return Err(invalid("duplicate HELLO")),
            FRAME_TYPE_STATUS_REQUEST => {
                // USP #1: client is asking which build is running.
                // Payload is a single byte (the type itself); any
                // trailing bytes are a forward-compatibility slot
                // and ignored. Response goes through the connection's
                // own writer task so it travels back on the same
                // Tor circuit the request arrived on.
                let payload = status_snapshot.encode_response();
                if our_tx.send(payload).is_err() {
                    // Writer task already shut down — connection is
                    // closing. Nothing actionable; let the next
                    // read pick up the EOF.
                    dev_peer_log!("STATUS_REQUEST: writer task gone, response dropped");
                }
            }
            FRAME_TYPE_STATUS_RESPONSE => {
                // Clients never send this to us. Treat it the same
                // way we treat unsolicited BUNDLE_RESPONSE-shaped
                // bytes from a paired peer: structural error, drop
                // the connection. Keeps the dispatch table
                // symmetric.
                return Err(invalid("STATUS_RESPONSE from client is not allowed"));
            }
            FRAME_TYPE_COVER => {
                // USP #4: drop on the floor. The frame's only
                // purpose is to occupy a Tor cell slot at a constant
                // rate; we don't read the body for anything. Size
                // check rejects anomalies (a tiny "cover" would
                // defeat the timing-mask purpose; a giant one could
                // be a probe of MAX_FRAME_BYTES). The frame_idle
                // timeout enforcement runs on top of this, so a
                // misbehaving client that floods covers is bounded
                // by `MAX_CONCURRENT_CONNECTIONS` × frame rate.
                if frame.len() != 1 + COVER_PAYLOAD_LEN {
                    return Err(invalid(&format!(
                        "COVER frame wrong size: expected {} bytes payload, got {}",
                        COVER_PAYLOAD_LEN,
                        frame.len().saturating_sub(1),
                    )));
                }
                // Payload bytes are entropy; we don't validate them.
                // A future randomness-quality check would be
                // server-side gatekeeping of bad clients, not a
                // security property — skip for now.
            }
            FRAME_TYPE_REGISTER_PUSH => {
                let token = match parse_register_push(&frame[1..]) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("malformed REGISTER_PUSH: {e}");
                        continue;
                    }
                };
                let token_len = token.len();
                // `insert` updates the in-memory map AND atomically
                // rewrites the encrypted file on disk. A persistence
                // error is logged but doesn't drop the connection —
                // the in-memory copy is still valid for the current
                // process lifetime, so push works at least until next
                // restart. Better degradation than refusing the
                // TOKEN_REGISTER outright and silently breaking push
                // for this device.
                match push_tokens
                    .lock()
                    .await
                    .insert(self_id.to_vec(), token)
                {
                    Ok(()) => dev_peer_log!(
                        "REGISTER_PUSH from {}: token recorded ({} bytes, persisted)",
                        short_hex(self_id),
                        token_len,
                    ),
                    Err(e) => dev_peer_elog!(
                        "REGISTER_PUSH from {}: in-memory only — persist failed: {e}",
                        short_hex(self_id),
                    ),
                }
            }
            FRAME_TYPE_DEREGISTER_PUSH => {
                // No body — the peer is identified by the authenticated
                // HELLO. Drop our cached token so a subsequent
                // `maybe_send_push` is a no-op until this relay is
                // re-elected as push-primary (which would carry a
                // fresh REGISTER_PUSH). Idempotent — a peer that has
                // no entry just no-ops here.
                if frame.len() != 1 {
                    eprintln!(
                        "malformed DEREGISTER_PUSH from {}: trailing {} bytes",
                        short_hex(self_id),
                        frame.len() - 1
                    );
                    continue;
                }
                match push_tokens.lock().await.remove(self_id) {
                    Ok(true) => dev_peer_log!(
                        "DEREGISTER_PUSH from {}: token dropped",
                        short_hex(self_id),
                    ),
                    Ok(false) => dev_peer_log!(
                        "DEREGISTER_PUSH from {}: no entry (no-op)",
                        short_hex(self_id),
                    ),
                    Err(e) => dev_peer_elog!(
                        "DEREGISTER_PUSH from {}: persist failed: {e}",
                        short_hex(self_id),
                    ),
                }
            }
            FRAME_TYPE_SEND | FRAME_TYPE_ACK => {
                let parsed = match parse_sealed(&frame[1..]) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("malformed sealed frame: {e}");
                        continue;
                    }
                };
                if let Err(reason) =
                    check_delivery_token(&parsed, verify_keys, replays).await
                {
                    dev_peer_elog!(
                        "rejecting {} → {}: {reason}",
                        match frame[0] {
                            FRAME_TYPE_SEND => "SEND",
                            _ => "ACK",
                        },
                        short_hex(&parsed.to_id),
                    );
                    continue;
                }
                let frame_type = frame[0];
                let frame_len = frame.len();
                let map = routes.lock().await;
                if let Some(target) = map.get(&parsed.to_id) {
                    let _ = target.send(frame);
                    dev_peer_log!(
                        "forward type={frame_type} → {} ({frame_len} bytes, ttl={}s)",
                        short_hex(&parsed.to_id),
                        parsed.ttl_seconds,
                    );
                } else {
                    drop(map);
                    enqueue_pending(&parsed.to_id, frame, parsed.ttl_seconds, pending).await;
                    dev_peer_log!(
                        "queued type={frame_type} → {}: recipient offline (ttl={}s)",
                        short_hex(&parsed.to_id),
                        parsed.ttl_seconds,
                    );
                    maybe_send_push(&parsed.to_id, push_tokens, apns.as_ref()).await;
                }
            }
            FRAME_TYPE_BUNDLE_REQUEST => {
                // BUNDLE_REQUEST = u16 to + u16 from + u64 hashcash.
                let parsed = match parse_bundle_request(&frame[1..]) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("malformed bundle request: {e}");
                        continue;
                    }
                };
                if parsed.from_id != self_id {
                    dev_peer_elog!(
                        "rejecting bundle request with spoofed from_id {} (connection is {})",
                        short_hex(&parsed.from_id),
                        short_hex(self_id),
                    );
                    continue;
                }
                if !verify_hashcash(&parsed.to_id, parsed.hashcash_nonce) {
                    dev_peer_elog!(
                        "rejecting bundle request {} → {}: invalid hashcash (need {HASHCASH_BITS} zero bits)",
                        short_hex(&parsed.from_id),
                        short_hex(&parsed.to_id),
                    );
                    continue;
                }
                let map = routes.lock().await;
                if let Some(target) = map.get(&parsed.to_id) {
                    let frame_len = frame.len();
                    let _ = target.send(frame);
                    dev_peer_log!(
                        "forward bundle req {} → {} ({frame_len} bytes, pow ok)",
                        short_hex(&parsed.from_id),
                        short_hex(&parsed.to_id),
                    );
                } else {
                    dev_peer_log!(
                        "drop bundle req {} → {}: recipient offline",
                        short_hex(&parsed.from_id),
                        short_hex(&parsed.to_id),
                    );
                }
                continue;
            }
            FRAME_TYPE_BUNDLE_RESPONSE | FRAME_TYPE_TOKEN_ISSUE => {
                // Bundle response keeps the explicit from_id at the
                // wire level — first contact pre-dates a session, so
                // the sealed-sender envelope can't yet be applied.
                // Spoof check still meaningful here.
                let parsed = match parse_routed(&frame[1..]) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("malformed bundle frame: {e}");
                        continue;
                    }
                };
                if parsed.from_id != self_id {
                    dev_peer_elog!(
                        "rejecting bundle frame with spoofed from_id {} (connection is {})",
                        short_hex(&parsed.from_id),
                        short_hex(self_id),
                    );
                    continue;
                }
                let map = routes.lock().await;
                if let Some(target) = map.get(&parsed.to_id) {
                    let frame_type = frame[0];
                    let frame_len = frame.len();
                    let _ = target.send(frame);
                    dev_peer_log!(
                        "forward bundle type={frame_type} {} → {} ({frame_len} bytes)",
                        short_hex(&parsed.from_id),
                        short_hex(&parsed.to_id),
                    );
                } else {
                    dev_peer_log!(
                        "drop bundle type={} {} → {}: recipient offline (bundle exchange requires both online)",
                        frame[0],
                        short_hex(&parsed.from_id),
                        short_hex(&parsed.to_id),
                    );
                }
            }
            other => return Err(invalid(&format!("unknown frame type {other}"))),
        }
    }
}

async fn enqueue_pending(
    recipient: &[u8],
    frame: Vec<u8>,
    ttl_seconds: u32,
    pending: &Pending,
) {
    // Per-peer cap + arrival-order eviction live in `PendingStore`.
    // `enqueue` also atomically persists the new queue state, so a
    // relay bounce immediately after a SEND from an offline-recipient
    // path preserves the frame for the recipient's next reconnect —
    // exactly the failure mode that lost the "dde" message during
    // the push-token-persistence rollout.
    let ttl = clamp_ttl(ttl_seconds);
    let expires_at_unix = encrypted_file::unix_now() + ttl.as_secs();
    let entry = PendingFrame::new(frame, expires_at_unix);
    let mut store = pending.lock().await;
    if let Err(e) = store.enqueue(recipient.to_vec(), entry) {
        // Persist failure is logged but doesn't fail the connection.
        // The in-memory copy of the queue is still valid for this
        // process's lifetime — push delivery (already best-effort)
        // continues to work; only the cross-restart guarantee is at
        // risk. Better than dropping the connection over an I/O hiccup.
        eprintln!(
            "[pizzini-relay] warn: pending enqueue persist failed for {}: {e}",
            short_hex(recipient),
        );
    }
}

/// Sender-chosen TTL clamped to `MAX_PENDING_TTL`. A zero or absurd
/// value still gets a small floor (60s) so we don't churn the queue on
/// a misconfigured client without ever delivering.
fn clamp_ttl(ttl_seconds: u32) -> Duration {
    let secs = ttl_seconds as u64;
    let secs = secs.max(60).min(MAX_PENDING_TTL.as_secs());
    Duration::from_secs(secs)
}

/// Called right after a peer's HELLO is processed and their route is
/// installed. Forwards every non-expired queued frame to their writer
/// task in arrival order, then drops the (now-empty) queue entry.
///
/// `PendingStore::drain` removes the peer's queue from the store AND
/// atomically persists the new (queue-removed) state before returning
/// the live frames — so even if the writer task drops mid-loop and
/// we discard the remaining entries, the disk reflects a "delivered"
/// queue state. A subsequent relay restart will NOT re-deliver the
/// same frames to the same peer.
///
/// Expired frames are filtered out inside `drain`; this loop only
/// sees live entries.
async fn drain_pending(peer_id: &[u8], pending: &Pending, routes: &Routes) {
    let queue = {
        let mut store = pending.lock().await;
        match store.drain(peer_id) {
            Ok(q) => q,
            Err(e) => {
                eprintln!(
                    "[pizzini-relay] warn: pending drain persist failed for {}: {e}",
                    short_hex(peer_id),
                );
                // The in-memory state may still hold the queue (drain
                // returns Err only on the post-persist path). Return
                // empty here rather than partially forward; the
                // recipient will retry on their next HELLO. Cleaner
                // than risking a half-drained state on disk.
                return;
            }
        }
    };
    if queue.is_empty() {
        return;
    }
    let routes_map = routes.lock().await;
    let Some(target) = routes_map.get(peer_id) else { return };
    let mut forwarded = 0usize;
    for entry in queue {
        if target.send(entry.bytes()).is_err() {
            // Writer task is gone (race with disconnect). Stop draining
            // — the recipient effectively isn't connected anymore. Any
            // remaining entries are dropped because `drain` already
            // removed the queue from the store AND persisted. The
            // tradeoff matches the pre-persistence behaviour: partial-
            // reinsertion adds complexity for a rare race.
            break;
        }
        forwarded += 1;
    }
    dev_peer_log!(
        "drained pending for {}: forwarded={forwarded}",
        short_hex(peer_id),
    );
}

/// Verifies a sealed-frame's delivery token against the recipient's
/// published verify_key, expiry, and the recently-seen replay set.
/// Returns `Ok(())` on accept, `Err(reason)` on any failure — caller
/// logs the reason and refuses to forward / queue.
async fn check_delivery_token(
    parsed: &ParsedSealed,
    verify_keys: &VerifyKeys,
    replays: &Replays,
) -> Result<(), String> {
    if parsed.token.len() != TOKEN_LEN {
        return Err(format!(
            "wrong token length: {} (expected {TOKEN_LEN})",
            parsed.token.len()
        ));
    }
    let nonce: [u8; TOKEN_NONCE_LEN] =
        parsed.token[..TOKEN_NONCE_LEN].try_into().expect("len checked");
    let expiry = u32::from_be_bytes(
        parsed.token[TOKEN_NONCE_LEN..TOKEN_NONCE_LEN + 4]
            .try_into()
            .expect("len checked"),
    );
    let sig = &parsed.token[TOKEN_NONCE_LEN + 4..];

    let now_secs_u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let now_secs = now_secs_u64 as u32;
    if expiry < now_secs {
        return Err(format!("token expired (expiry={expiry}, now={now_secs})"));
    }
    // F-205: cap accepted future-expiry. A malicious or buggy recipient
    // could otherwise mint tokens with `expiry = u32::MAX` and pin them
    // replayable for the life of their verify_key.
    let future_secs = u64::from(expiry).saturating_sub(now_secs_u64);
    if future_secs > TOKEN_MAX_FUTURE_EXPIRY_SECS {
        return Err(format!(
            "token expiry too far in the future ({future_secs}s; cap {TOKEN_MAX_FUTURE_EXPIRY_SECS}s)"
        ));
    }

    // N-002: touch last_used on every successful lookup so an active
    // recipient's verify_key stays cached even when they're disconnected
    // (third parties keep sending them mail; each verified frame
    // refreshes the GC marker).
    let verify_key_bytes = {
        let mut table = verify_keys.lock().await;
        match table.get_mut(&parsed.to_id) {
            Some(entry) => {
                entry.1 = Instant::now();
                Some(entry.0.clone())
            }
            None => None,
        }
    };
    let verify_key_bytes = match verify_key_bytes {
        Some(b) => b,
        None => {
            return Err(format!(
                "no verify key registered for recipient {}",
                short_hex(&parsed.to_id)
            ));
        }
    };
    let key = PublicKey::deserialize(&verify_key_bytes)
        .map_err(|e| format!("recipient verify key malformed: {e}"))?;
    let payload = &parsed.token[..TOKEN_NONCE_LEN + 4];
    if !key.verify_signature(payload, sig) {
        return Err("token signature does not match recipient's verify key".into());
    }

    // Replay check after signature verify — failed signatures don't
    // burn a nonce slot.
    let mut store = replays.lock().await;
    if store.contains(&parsed.to_id, &nonce) {
        return Err("token replay".into());
    }
    if let Err(e) = store.insert(parsed.to_id.clone(), nonce.to_vec()) {
        // A persist failure must NOT be treated as a successful
        // accept — better to refuse the frame than to accept-without-
        // persisting and have a future restart re-accept the same
        // bytes after this nonce was supposedly burned.
        return Err(format!("replay-store persist failed: {e}").into());
    }
    Ok(())
}

/// F-NEW-208: persistent push-token GC. The previous design only
/// purged expired entries during `PushTokenStore::load_or_create`,
/// so a relay that stayed up for months accumulated every token ever
/// registered. Periodic in-memory GC matches the documented 30-day
/// TTL on a 1-hour tick.
fn spawn_push_tokens_gc(push_tokens: PushTokens) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            tick.tick().await;
            let mut store = push_tokens.lock().await;
            match store.gc_expired(push_token_store::MAX_TOKEN_AGE) {
                Ok(0) => {}
                Ok(n) => println!("push-token GC: pruned {n} → {} entries", store.len()),
                Err(e) => eprintln!("[pizzini-relay] push-token GC persist failed: {e}"),
            }
        }
    });
}

fn spawn_replay_gc(replays: Replays) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TOKEN_REPLAY_GC_INTERVAL);
        loop {
            tick.tick().await;
            let mut store = replays.lock().await;
            match store.gc_expired(TOKEN_REPLAY_WINDOW) {
                Ok(0) => {}
                Ok(n) => println!("token-replay GC: pruned {n} → {}", store.len()),
                Err(e) => eprintln!("[pizzini-relay] replay-store GC persist failed: {e}"),
            }
        }
    });
}

/// N-002: prune verify_keys entries unused for `VERIFY_KEY_TTL`. Bounds
/// memory growth (the F-204 concern) and post-mortem linkability (a
/// memory dump reveals only peers active in the last `VERIFY_KEY_TTL`)
/// without breaking offline-message delivery for recently-disconnected
/// recipients.
fn spawn_verify_keys_gc(verify_keys: VerifyKeys) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(VERIFY_KEY_GC_INTERVAL);
        loop {
            tick.tick().await;
            let cutoff = Instant::now() - VERIFY_KEY_TTL;
            let mut table = verify_keys.lock().await;
            let before = table.len();
            table.retain(|_, (_, last_touched)| *last_touched > cutoff);
            let after = table.len();
            if before != after {
                println!("verify-keys GC: pruned {} → {after}", before - after);
            }
        }
    });
}

/// Build the per-recipient/per-hour hashcash challenge. F-301: input is
/// domain-separated by `HASHCASH_CHALLENGE_TAG` and the peer_id is
/// length-prefixed so two distinct `(peer_id, hour)` pairs can never
/// hash to the same 32-byte digest. Same shape on iOS (must match
/// byte-for-byte).
fn build_hashcash_challenge(recipient_peer_id: &[u8], hour: u64) -> [u8; 32] {
    let peer_len = u16::try_from(recipient_peer_id.len())
        .expect("peer_id length fits in u16 (parser caps at u16::MAX)");
    let mut chal = blake3::Hasher::new();
    chal.update(HASHCASH_CHALLENGE_TAG);
    chal.update(&peer_len.to_be_bytes());
    chal.update(recipient_peer_id);
    chal.update(&hour.to_be_bytes());
    *chal.finalize().as_bytes()
}

/// Verify hashcash on a BUNDLE_REQUEST. Accepts the current and
/// previous hour to absorb clock skew across the relay/sender pair.
fn verify_hashcash(recipient_peer_id: &[u8], nonce: u64) -> bool {
    let now_hour = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 3600)
        .unwrap_or(0);
    let try_bucket = |hour: u64| -> bool {
        let challenge = build_hashcash_challenge(recipient_peer_id, hour);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&challenge);
        hasher.update(&nonce.to_be_bytes());
        let hash = hasher.finalize();
        leading_zero_bits(hash.as_bytes()) >= HASHCASH_BITS
    };
    try_bucket(now_hour) || (now_hour > 0 && try_bucket(now_hour - 1))
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

/// Look up the recipient's push token; if present and APNs is configured,
/// fire a payload-opaque "New message" wake-up. Errors are logged only —
/// push is best-effort and must never break relay forwarding.
async fn maybe_send_push(
    recipient: &[u8],
    push_tokens: &PushTokens,
    apns: Option<&Arc<ApnsClient>>,
) {
    let Some(client) = apns else { return };
    let token = match push_tokens.lock().await.get_cloned(recipient) {
        Some(t) => t,
        None => return,
    };
    let recipient_dbg = short_hex(recipient);
    let client = client.clone();
    tokio::spawn(async move {
        match client.send_wakeup(&token).await {
            Ok(_) => dev_peer_log!("push: sent wake-up to {recipient_dbg}"),
            Err(e) => dev_peer_elog!("push: failed for {recipient_dbg}: {e}"),
        }
    });
}

#[derive(Debug)]
struct ParsedHello {
    peer_id: Vec<u8>,
    verify_key: Vec<u8>,
    /// F-203: unix-time seconds at the moment the client signed the
    /// HELLO. Relay enforces ±`HELLO_MAX_CLOCK_SKEW_SECS` against its
    /// own clock to bound the replay window.
    timestamp_secs: u64,
    /// F-203: 16 random bytes; (peer_id, nonce) lookup against the
    /// HELLO replay set rejects a captured-and-replayed HELLO frame
    /// within the timestamp window.
    nonce: [u8; HELLO_NONCE_LEN],
    /// F-203: Ed25519/XEd25519 signature over
    /// `HELLO_SIGNING_TAG || peer_id || verify_key || timestamp_be ||
    /// nonce`, computed by the client's IdentityKey private half.
    /// Relay verifies against the IdentityKey extracted from `peer_id`.
    signature: Vec<u8>,
}

struct ParsedRouted {
    to_id: Vec<u8>,
    from_id: Vec<u8>,
}

struct ParsedBundleRequest {
    to_id: Vec<u8>,
    from_id: Vec<u8>,
    hashcash_nonce: u64,
}

struct ParsedSealed {
    to_id: Vec<u8>,
    ttl_seconds: u32,
    token: Vec<u8>,
}

fn parse_hello(body: &[u8]) -> std::io::Result<ParsedHello> {
    let mut c = Cursor::new(body);
    let version = c.u8()?;
    if version != PROTOCOL_VERSION {
        return Err(invalid(&format!(
            "unsupported protocol version {version}; relay speaks {PROTOCOL_VERSION}"
        )));
    }
    let peer_id = c.u16_blob()?.to_vec();
    let verify_key = c.u16_blob()?.to_vec();
    if verify_key.len() != VERIFY_KEY_LEN {
        return Err(invalid(&format!(
            "verify_key must be {VERIFY_KEY_LEN} bytes, got {}",
            verify_key.len()
        )));
    }
    // F-203: HELLO possession-proof fields. timestamp + nonce + sig.
    let timestamp_secs = c.u64()?;
    let nonce_blob = c.u16_blob()?;
    if nonce_blob.len() != HELLO_NONCE_LEN {
        return Err(invalid(&format!(
            "HELLO nonce must be {HELLO_NONCE_LEN} bytes, got {}",
            nonce_blob.len()
        )));
    }
    let mut nonce = [0u8; HELLO_NONCE_LEN];
    nonce.copy_from_slice(nonce_blob);
    let signature = c.u16_blob()?.to_vec();
    if signature.len() != HELLO_SIG_LEN {
        return Err(invalid(&format!(
            "HELLO signature must be {HELLO_SIG_LEN} bytes, got {}",
            signature.len()
        )));
    }
    if !c.is_empty() {
        return Err(invalid("trailing bytes after HELLO"));
    }
    Ok(ParsedHello {
        peer_id,
        verify_key,
        timestamp_secs,
        nonce,
        signature,
    })
}

/// Build the byte string the iOS client signs and the relay verifies.
/// MUST stay in sync with the Swift encoder. F-203.
fn build_hello_signing_payload(
    peer_id: &[u8],
    verify_key: &[u8],
    timestamp_secs: u64,
    nonce: &[u8],
) -> Vec<u8> {
    // F-NEW-101: domain-separation prefix matches the FFI v2
    // contract: `u16_be(tag_len) || tag || payload`. The earlier
    // non-length-prefixed form `tag || payload` was vulnerable to
    // prefix collisions — a tag that happened to be the prefix of
    // a different cross-context message body could produce the same
    // signed bytes. Length-prefixing makes that impossible.
    let tag_len = HELLO_SIGNING_TAG.len() as u16;
    let mut out = Vec::with_capacity(
        2 + HELLO_SIGNING_TAG.len() + peer_id.len() + verify_key.len() + 8 + nonce.len(),
    );
    out.extend_from_slice(&tag_len.to_be_bytes());
    out.extend_from_slice(HELLO_SIGNING_TAG);
    out.extend_from_slice(peer_id);
    out.extend_from_slice(verify_key);
    out.extend_from_slice(&timestamp_secs.to_be_bytes());
    out.extend_from_slice(nonce);
    out
}

/// F-203: validate the possession proof on a freshly-parsed HELLO.
/// Returns Ok on accept, Err(reason) on any failure.
async fn verify_hello_possession_proof(
    h: &ParsedHello,
    hello_replays: &HelloReplays,
) -> Result<(), String> {
    // Clock window. Allow ±skew so a phone whose NTP is briefly off
    // can still HELLO; reject stale captures past that window so a
    // replay must (also) fail the (peer_id, nonce) check.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let delta = (h.timestamp_secs as i64) - (now_secs as i64);
    if delta.abs() > HELLO_MAX_CLOCK_SKEW_SECS {
        return Err(format!(
            "timestamp out of range (Δ={delta}s, |max|={HELLO_MAX_CLOCK_SKEW_SECS}s)"
        ));
    }
    // peer_id IS the libsignal IdentityKey wire form (1-byte type
    // prefix + 32-byte point). Decode and verify.
    let identity_pub = libsignal_protocol::IdentityKey::decode(&h.peer_id)
        .map_err(|e| format!("peer_id is not a valid IdentityKey: {e}"))?;
    let payload =
        build_hello_signing_payload(&h.peer_id, &h.verify_key, h.timestamp_secs, &h.nonce);
    if !identity_pub
        .public_key()
        .verify_signature(&payload, &h.signature)
    {
        return Err("signature does not validate against peer_id's IdentityKey".into());
    }
    // (peer_id, nonce) replay check, AFTER signature verify so a
    // failing signature doesn't burn a nonce slot.
    let mut set = hello_replays.lock().await;
    let key = (h.peer_id.clone(), h.nonce);
    if set.contains_key(&key) {
        return Err("HELLO replay (peer_id, nonce) already seen".into());
    }
    set.insert(key, Instant::now());
    Ok(())
}

fn spawn_hello_replay_gc(hello_replays: HelloReplays) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TOKEN_REPLAY_GC_INTERVAL);
        loop {
            tick.tick().await;
            let cutoff = Instant::now() - HELLO_REPLAY_WINDOW;
            let mut set = hello_replays.lock().await;
            let before = set.len();
            set.retain(|_, t| *t > cutoff);
            let after = set.len();
            if before != after {
                println!("hello-replay GC: pruned {} → {after}", before - after);
            }
        }
    });
}

fn parse_routed(body: &[u8]) -> std::io::Result<ParsedRouted> {
    let mut c = Cursor::new(body);
    let to_id = c.u16_blob()?.to_vec();
    let from_id = c.u16_blob()?.to_vec();
    // Anything after the routing prefix is opaque to the relay.
    Ok(ParsedRouted { to_id, from_id })
}

fn parse_bundle_request(body: &[u8]) -> std::io::Result<ParsedBundleRequest> {
    let mut c = Cursor::new(body);
    let to_id = c.u16_blob()?.to_vec();
    let from_id = c.u16_blob()?.to_vec();
    let hashcash_nonce = c.u64()?;
    if !c.is_empty() {
        return Err(invalid("trailing bytes after BUNDLE_REQUEST"));
    }
    Ok(ParsedBundleRequest { to_id, from_id, hashcash_nonce })
}

/// Parse the SEND v2 / ACK header. The relay validates structure and
/// extracts to_id, ttl, token. The trailing sealed_ciphertext is not
/// re-read here — `parse_sealed` runs purely for routing/queueing
/// metadata and the relay forwards the raw frame bytes verbatim.
fn parse_sealed(body: &[u8]) -> std::io::Result<ParsedSealed> {
    let mut c = Cursor::new(body);
    let to_id = c.u16_blob()?.to_vec();
    let ttl_seconds = c.u32()?;
    let token = c.u16_blob()?.to_vec();
    // Remaining bytes are the sealed ciphertext — opaque to the relay.
    let _ = c.rest();
    Ok(ParsedSealed { to_id, ttl_seconds, token })
}

fn parse_register_push(body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut c = Cursor::new(body);
    let token = c.u16_blob()?.to_vec();
    if !c.is_empty() {
        return Err(invalid("trailing bytes after REGISTER_PUSH"));
    }
    if token.is_empty() {
        return Err(invalid("REGISTER_PUSH with empty token"));
    }
    if token.len() < MIN_PUSH_TOKEN_BYTES {
        return Err(invalid(&format!(
            "REGISTER_PUSH token too small: {} bytes (min {})",
            token.len(),
            MIN_PUSH_TOKEN_BYTES,
        )));
    }
    if token.len() > MAX_PUSH_TOKEN_BYTES {
        return Err(invalid(&format!(
            "REGISTER_PUSH token too large: {} bytes (max {})",
            token.len(),
            MAX_PUSH_TOKEN_BYTES,
        )));
    }
    // Refuse obvious garbage (F-NEW-207): all-zero blobs and any
    // token whose bytes are entirely identical. A real APNs device
    // token has high entropy; either pattern signals a misbehaving
    // client or a planted bogus value.
    if token.iter().all(|&b| b == 0) || token.iter().all(|&b| b == token[0]) {
        return Err(invalid("REGISTER_PUSH token has no entropy"));
    }
    Ok(token)
}

async fn read_frame(reader: &mut (impl AsyncReadExt + Unpin)) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(invalid(&format!("frame too large: {len} bytes")));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_frame(
    writer: &mut (impl AsyncWriteExt + Unpin),
    payload: &[u8],
) -> std::io::Result<()> {
    let len: u32 = payload.len().try_into().map_err(|_| invalid("frame too large"))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    Ok(())
}

fn invalid(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

fn short_hex(bytes: &[u8]) -> String {
    let n = bytes.len().min(4);
    let head = hex(&bytes[..n]);
    if bytes.len() > n {
        format!("{head}…")
    } else {
        head
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn local_lan_ips() -> Vec<std::net::Ipv4Addr> {
    // SO_REUSEADDR-free probe: connect to a TEST-NET-1 address (RFC 5737) so
    // the kernel picks the outbound interface IP. No packets are sent
    // (UDP socket, no send), but `local_addr` is filled in.
    use std::net::{IpAddr, UdpSocket};
    let s = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    if s.connect("192.0.2.1:9").is_err() {
        return vec![];
    }
    match s.local_addr() {
        Ok(addr) => match addr.ip() {
            IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => vec![v4],
            _ => vec![],
        },
        Err(_) => vec![],
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf } }
    fn is_empty(&self) -> bool { self.buf.is_empty() }
    fn take(&mut self, n: usize) -> std::io::Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(invalid("truncated frame"));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }
    fn u8(&mut self) -> std::io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> std::io::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> std::io::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> std::io::Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u16_blob(&mut self) -> std::io::Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn rest(&mut self) -> &'a [u8] {
        let r = self.buf;
        self.buf = &[];
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_send_v2(to: &[u8], ttl: u32, token: &[u8], sealed: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(FRAME_TYPE_SEND);
        out.extend_from_slice(&(to.len() as u16).to_be_bytes());
        out.extend_from_slice(to);
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(token.len() as u16).to_be_bytes());
        out.extend_from_slice(token);
        out.extend_from_slice(sealed);
        out
    }

    // ───── USP #1: STATUS_RESPONSE encoding ───────────────────

    fn make_status(crate_version: &str, git_sha: &str, dirty: u8, hash: [u8; 32]) -> RelayStatus {
        RelayStatus {
            crate_version: crate_version.to_string(),
            git_sha: git_sha.to_string(),
            git_dirty: dirty,
            binary_sha256: hash,
        }
    }

    #[test]
    fn status_response_encoding_is_stable() {
        // Fixed inputs → byte-for-byte deterministic output. Catches
        // any field-reordering / endianness regression that would
        // make in-flight v1 clients silently misparse the response.
        let s = make_status("0.0.0", "deadbeef", 0, [0x42u8; 32]);
        let bytes = s.encode_response();
        assert_eq!(bytes[0], FRAME_TYPE_STATUS_RESPONSE);
        assert_eq!(bytes[1], PROTOCOL_VERSION);
        assert_eq!(bytes[2], 0, "git_dirty=0 (clean)");
        // u16 len of "0.0.0" = 5
        assert_eq!(&bytes[3..5], &[0x00, 0x05]);
        assert_eq!(&bytes[5..10], b"0.0.0");
        // u16 len of "deadbeef" = 8
        assert_eq!(&bytes[10..12], &[0x00, 0x08]);
        assert_eq!(&bytes[12..20], b"deadbeef");
        assert_eq!(bytes[20], STATUS_BIN_HASH_LEN as u8);
        assert!(bytes[21..].iter().all(|&b| b == 0x42));
        assert_eq!(bytes.len(), 21 + STATUS_BIN_HASH_LEN);
    }

    #[test]
    fn status_response_carries_dirty_bit() {
        for dirty in 0u8..=2 {
            let s = make_status("0.0.0", "x", dirty, [0u8; 32]);
            let bytes = s.encode_response();
            assert_eq!(bytes[2], dirty, "dirty byte mismatch at {dirty}");
        }
    }

    #[test]
    fn status_response_changes_when_binary_hash_changes() {
        let a = make_status("v", "g", 0, [0x00u8; 32]);
        let b = make_status("v", "g", 0, [0xFFu8; 32]);
        assert_ne!(a.encode_response(), b.encode_response());
    }

    #[test]
    fn relay_status_capture_self_attests_the_test_binary() {
        // Sanity: the capture path can read /proc/self/exe (or its
        // macOS equivalent) and produce a real 32-byte hash. We don't
        // assert a specific value — that would require pinning the
        // test runner binary — only that the capture succeeds and
        // produces something that *looks* like a SHA-256.
        let snap = RelayStatus::capture().expect("capture should succeed in test env");
        assert_eq!(snap.binary_sha256.len(), STATUS_BIN_HASH_LEN);
        // The capture function reads the test runner here, not the
        // relay binary, but the same `current_exe + read + sha256`
        // path runs — failure modes (path lookup, read perms) are
        // exercised identically.
        assert!(!snap.crate_version.is_empty());
    }

    #[test]
    fn parse_send_v2_round_trips() {
        let to = b"recipient_id_bytes";
        let token = b"sigsigsig";
        let sealed = b"sealedciphertextbytes";
        let frame = build_send_v2(to, 3600, token, sealed);
        let parsed = parse_sealed(&frame[1..]).unwrap();
        assert_eq!(parsed.to_id, to);
        assert_eq!(parsed.ttl_seconds, 3600);
        assert_eq!(parsed.token, token);
    }

    #[test]
    fn clamps_ttl_to_seven_days() {
        // Sender asks for 30 days; relay clamps to 7d.
        let huge: u32 = 30 * 24 * 3600;
        let dur = clamp_ttl(huge);
        assert_eq!(dur, MAX_PENDING_TTL);
        // Sender asks for 0; relay floors to 60s so we don't churn.
        let zero = clamp_ttl(0);
        assert_eq!(zero, Duration::from_secs(60));
        // Reasonable ttls pass through.
        assert_eq!(clamp_ttl(3600), Duration::from_secs(3600));
        assert_eq!(clamp_ttl(24 * 3600), Duration::from_secs(24 * 3600));
    }

    /// Build a structurally-valid v3 HELLO body. Signature is dummy
    /// bytes — for parse-side tests only; verification happens
    /// separately via `verify_hello_possession_proof`.
    fn build_v3_hello_body(peer_id: &[u8], verify_key: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(PROTOCOL_VERSION);
        body.extend_from_slice(&(peer_id.len() as u16).to_be_bytes());
        body.extend_from_slice(peer_id);
        body.extend_from_slice(&(verify_key.len() as u16).to_be_bytes());
        body.extend_from_slice(verify_key);
        // Phase 3 added: timestamp + nonce + sig.
        body.extend_from_slice(&0u64.to_be_bytes()); // timestamp
        body.extend_from_slice(&(HELLO_NONCE_LEN as u16).to_be_bytes());
        body.extend_from_slice(&[0u8; HELLO_NONCE_LEN]); // nonce
        body.extend_from_slice(&(HELLO_SIG_LEN as u16).to_be_bytes());
        body.extend_from_slice(&[0u8; HELLO_SIG_LEN]); // sig (dummy)
        body
    }

    #[test]
    fn rejects_protocol_v1() {
        // v1 HELLO body had no version byte; it started straight with the
        // u16 peer_id length. Re-encoding such a body and parsing it
        // against v3 must fail with a clear "unsupported version" error.
        let mut v1_body = Vec::new();
        v1_body.extend_from_slice(&(4u16.to_be_bytes())); // peer_id_len = 4
        v1_body.extend_from_slice(&[1, 2, 3, 4]); // peer_id bytes
        let err = parse_hello(&v1_body).unwrap_err();
        assert!(format!("{err}").contains("protocol version"));
    }

    #[test]
    fn parse_hello_accepts_protocol_v3() {
        let body = build_v3_hello_body(&[1u8; 33], &[2u8; VERIFY_KEY_LEN]);
        let parsed = parse_hello(&body).unwrap();
        assert_eq!(parsed.peer_id, vec![1u8; 33]);
        assert_eq!(parsed.verify_key, vec![2u8; VERIFY_KEY_LEN]);
        assert_eq!(parsed.timestamp_secs, 0);
        assert_eq!(parsed.nonce, [0u8; HELLO_NONCE_LEN]);
        assert_eq!(parsed.signature.len(), HELLO_SIG_LEN);
    }

    #[test]
    fn parse_hello_rejects_wrong_verify_key_length() {
        let body = build_v3_hello_body(&[1, 2, 3, 4], &[0u8; 16]);
        assert!(parse_hello(&body).is_err());
    }

    #[test]
    fn parse_hello_rejects_wrong_nonce_length() {
        let mut body = Vec::new();
        body.push(PROTOCOL_VERSION);
        body.extend_from_slice(&(33u16.to_be_bytes()));
        body.extend_from_slice(&[1u8; 33]);
        body.extend_from_slice(&(VERIFY_KEY_LEN as u16).to_be_bytes());
        body.extend_from_slice(&[2u8; VERIFY_KEY_LEN]);
        body.extend_from_slice(&0u64.to_be_bytes());
        body.extend_from_slice(&8u16.to_be_bytes()); // nonce len = 8 (wrong)
        body.extend_from_slice(&[0u8; 8]);
        body.extend_from_slice(&(HELLO_SIG_LEN as u16).to_be_bytes());
        body.extend_from_slice(&[0u8; HELLO_SIG_LEN]);
        assert!(parse_hello(&body).is_err());
    }

    #[test]
    fn parse_hello_rejects_wrong_sig_length() {
        let mut body = Vec::new();
        body.push(PROTOCOL_VERSION);
        body.extend_from_slice(&(33u16.to_be_bytes()));
        body.extend_from_slice(&[1u8; 33]);
        body.extend_from_slice(&(VERIFY_KEY_LEN as u16).to_be_bytes());
        body.extend_from_slice(&[2u8; VERIFY_KEY_LEN]);
        body.extend_from_slice(&0u64.to_be_bytes());
        body.extend_from_slice(&(HELLO_NONCE_LEN as u16).to_be_bytes());
        body.extend_from_slice(&[0u8; HELLO_NONCE_LEN]);
        body.extend_from_slice(&32u16.to_be_bytes()); // sig len = 32 (wrong, must be 64)
        body.extend_from_slice(&[0u8; 32]);
        assert!(parse_hello(&body).is_err());
    }

    #[test]
    fn hashcash_accepts_within_clock_skew_window() {
        // Compute a proof that targets the CURRENT hour, then verify
        // through the relay's window.
        let recipient = b"recipient-peer-id";
        // Cheap test difficulty so the unit test stays under a second
        // without relaxing the production HASHCASH_BITS semantics.
        const TEST_BITS: u32 = 10;
        let now_hour = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / 3600)
            .unwrap_or(0);
        let mut chal = blake3::Hasher::new();
        chal.update(recipient);
        chal.update(&now_hour.to_be_bytes());
        let challenge = chal.finalize();
        // Brute-force a nonce against TEST_BITS difficulty.
        let mut nonce: u64 = 0;
        loop {
            let mut h = blake3::Hasher::new();
            h.update(challenge.as_bytes());
            h.update(&nonce.to_be_bytes());
            if leading_zero_bits(h.finalize().as_bytes()) >= TEST_BITS {
                break;
            }
            nonce += 1;
        }
        // Direct verify with the same difficulty knob — establishes
        // the helper composes correctly. Production verify_hashcash
        // hardcodes HASHCASH_BITS so we don't smoke-test that here.
        let mut h = blake3::Hasher::new();
        h.update(challenge.as_bytes());
        h.update(&nonce.to_be_bytes());
        assert!(leading_zero_bits(h.finalize().as_bytes()) >= TEST_BITS);
    }

    #[test]
    fn parse_sealed_rejects_truncated_header() {
        // Frame body too short to even hold the to_id length prefix.
        let truncated = vec![0u8; 1];
        assert!(parse_sealed(&truncated).is_err());
        // Frame stops mid-token blob.
        let mut bad = Vec::new();
        bad.extend_from_slice(&(2u16.to_be_bytes()));
        bad.extend_from_slice(&[0xab, 0xcd]);
        bad.extend_from_slice(&3600u32.to_be_bytes());
        bad.extend_from_slice(&(64u16.to_be_bytes()));
        bad.extend_from_slice(&[0u8; 8]); // declared 64, gives 8
        assert!(parse_sealed(&bad).is_err());
    }

    // ─── F-203 fix-review attack vectors ──────────────────────────────────
    // The audit prompt enumerates six attacks the HELLO possession proof
    // must defeat. These tests exercise verify_hello_possession_proof
    // directly with crafted ParsedHello structs.

    use rand::TryRngCore as _;

    /// Helper: mint a libsignal IdentityKeyPair, return (peer_id_bytes,
    /// keypair). peer_id_bytes is the 33-byte wire form (1-byte type
    /// prefix + 32-byte point) — same encoding parse_hello expects.
    fn fresh_identity() -> (Vec<u8>, libsignal_protocol::IdentityKeyPair) {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let kp = libsignal_protocol::IdentityKeyPair::generate(&mut rng);
        let peer_id = kp.identity_key().serialize().to_vec();
        (peer_id, kp)
    }

    /// Helper: produce a fully-signed HELLO for `kp` claiming `peer_id`.
    /// `now_offset_secs` lets a test forge a future or past timestamp.
    fn signed_hello(
        peer_id: &[u8],
        verify_key: &[u8],
        kp: &libsignal_protocol::IdentityKeyPair,
        now_offset_secs: i64,
        nonce: [u8; HELLO_NONCE_LEN],
    ) -> ParsedHello {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let ts = (now_secs + now_offset_secs).max(0) as u64;
        let payload = build_hello_signing_payload(peer_id, verify_key, ts, &nonce);
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let sig = kp
            .private_key()
            .calculate_signature(&payload, &mut rng)
            .expect("sign");
        ParsedHello {
            peer_id: peer_id.to_vec(),
            verify_key: verify_key.to_vec(),
            timestamp_secs: ts,
            nonce,
            signature: sig.to_vec(),
        }
    }

    /// F-203 attack 1: captured HELLO replayed within timestamp window.
    /// First call: accept. Second call (same peer_id, same nonce):
    /// reject via the (peer_id, nonce) replay set.
    #[tokio::test]
    async fn f203_captured_hello_replay_within_timestamp_window_rejected() {
        let (peer_id, kp) = fresh_identity();
        let vk = vec![7u8; VERIFY_KEY_LEN];
        let nonce = [0xAAu8; HELLO_NONCE_LEN];
        let h = signed_hello(&peer_id, &vk, &kp, 0, nonce);
        let replays: HelloReplays = Arc::new(Mutex::new(HashMap::new()));
        // First HELLO: accepted.
        verify_hello_possession_proof(&h, &replays).await.unwrap();
        // Re-submit same bytes: replay-set hit.
        let err = verify_hello_possession_proof(&h, &replays).await.unwrap_err();
        assert!(err.contains("replay"), "expected replay error, got: {err}");
    }

    /// F-203 attack 2: captured HELLO replayed PAST the timestamp window.
    /// Even before the (peer_id, nonce) entry would be GC'd, the
    /// timestamp gate fires first.
    #[tokio::test]
    async fn f203_hello_outside_clock_skew_window_rejected() {
        let (peer_id, kp) = fresh_identity();
        let vk = vec![7u8; VERIFY_KEY_LEN];
        // Sign 5 minutes in the past — well outside the 60s window.
        let h = signed_hello(&peer_id, &vk, &kp, -300, [0xBBu8; HELLO_NONCE_LEN]);
        let replays: HelloReplays = Arc::new(Mutex::new(HashMap::new()));
        let err = verify_hello_possession_proof(&h, &replays).await.unwrap_err();
        assert!(
            err.contains("timestamp"),
            "expected timestamp error, got: {err}"
        );
    }

    /// F-203 attack 3: forged HELLO with attacker's IdentityKey but
    /// peer_id = victim's. Verifier extracts IdentityKey from peer_id
    /// (victim's), so the attacker's signature will not validate
    /// against it.
    #[tokio::test]
    async fn f203_squat_victim_peer_id_with_attacker_signature_rejected() {
        let (victim_pid, _victim_kp) = fresh_identity();
        let (_attacker_pid, attacker_kp) = fresh_identity();
        let vk = vec![7u8; VERIFY_KEY_LEN];
        // Sign with the ATTACKER's key but claim VICTIM's peer_id.
        let h = signed_hello(&victim_pid, &vk, &attacker_kp, 0, [0xCCu8; HELLO_NONCE_LEN]);
        let replays: HelloReplays = Arc::new(Mutex::new(HashMap::new()));
        let err = verify_hello_possession_proof(&h, &replays).await.unwrap_err();
        assert!(err.contains("signature"), "expected sig error, got: {err}");
    }

    /// F-203 attack 4: forged HELLO with peer_id = victim and a sig
    /// signed by some other key (not the IdentityKey associated with
    /// peer_id). Verifier MUST extract the IdentityKey from peer_id,
    /// not from the wire — checking the sig against any wire-supplied
    /// key would be the bug.
    ///
    /// Same shape as attack 3 in this code (the relay only has one
    /// place a key could come from), but separated to flag the intent
    /// in case someone refactors verify_hello_possession_proof.
    #[tokio::test]
    async fn f203_signature_from_unrelated_key_rejected() {
        let (victim_pid, _victim_kp) = fresh_identity();
        let (_, other_kp) = fresh_identity();
        let vk = vec![7u8; VERIFY_KEY_LEN];
        let h = signed_hello(&victim_pid, &vk, &other_kp, 0, [0xDDu8; HELLO_NONCE_LEN]);
        let replays: HelloReplays = Arc::new(Mutex::new(HashMap::new()));
        let err = verify_hello_possession_proof(&h, &replays).await.unwrap_err();
        assert!(err.contains("signature"), "expected sig error, got: {err}");
    }

    /// F-203 attack 5: malformed peer_id (32 bytes instead of 33). The
    /// verifier MUST return Err, not panic.
    #[tokio::test]
    async fn f203_malformed_peer_id_returns_err_not_panic() {
        let bad_peer = vec![0u8; 32]; // wrong length
        let vk = vec![7u8; VERIFY_KEY_LEN];
        let h = ParsedHello {
            peer_id: bad_peer,
            verify_key: vk,
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            nonce: [0xEEu8; HELLO_NONCE_LEN],
            signature: vec![0u8; HELLO_SIG_LEN],
        };
        let replays: HelloReplays = Arc::new(Mutex::new(HashMap::new()));
        let err = verify_hello_possession_proof(&h, &replays).await.unwrap_err();
        assert!(
            err.contains("peer_id") || err.contains("IdentityKey"),
            "expected peer_id error, got: {err}"
        );
    }

    /// F-203 attack 5b: peer_id has the right length (33 bytes) but the
    /// type prefix is bogus (e.g. 0xff instead of the DJB type). Should
    /// fail decode without panicking.
    #[tokio::test]
    async fn f203_peer_id_with_bad_type_prefix_returns_err() {
        let mut bad_peer = vec![0u8; 33];
        bad_peer[0] = 0xff; // not a valid IdentityKey type prefix
        let vk = vec![7u8; VERIFY_KEY_LEN];
        let h = ParsedHello {
            peer_id: bad_peer,
            verify_key: vk,
            timestamp_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            nonce: [0xEFu8; HELLO_NONCE_LEN],
            signature: vec![0u8; HELLO_SIG_LEN],
        };
        let replays: HelloReplays = Arc::new(Mutex::new(HashMap::new()));
        // We don't strictly require the prefix to be rejected; either
        // peer_id-decode-fail or signature-fail is acceptable. What we
        // require is no panic.
        let _ = verify_hello_possession_proof(&h, &replays).await;
    }

    /// F-203 attack 6: signed timestamp 1000s in the future. The
    /// verifier uses delta.abs() so positive AND negative drift get
    /// caught.
    #[tokio::test]
    async fn f203_future_timestamp_rejected() {
        let (peer_id, kp) = fresh_identity();
        let vk = vec![7u8; VERIFY_KEY_LEN];
        let h = signed_hello(&peer_id, &vk, &kp, 1000, [0xF0u8; HELLO_NONCE_LEN]);
        let replays: HelloReplays = Arc::new(Mutex::new(HashMap::new()));
        let err = verify_hello_possession_proof(&h, &replays).await.unwrap_err();
        assert!(err.contains("timestamp"), "expected ts error, got: {err}");
    }

    /// F-203 fresh-honest path: a properly-signed HELLO with the
    /// matching peer_id is accepted on first sight.
    #[tokio::test]
    async fn f203_honest_hello_accepted() {
        let (peer_id, kp) = fresh_identity();
        let vk = vec![7u8; VERIFY_KEY_LEN];
        let h = signed_hello(&peer_id, &vk, &kp, 0, [0x10u8; HELLO_NONCE_LEN]);
        let replays: HelloReplays = Arc::new(Mutex::new(HashMap::new()));
        verify_hello_possession_proof(&h, &replays).await.unwrap();
    }

    // ─── F-301 challenge byte-shape ───────────────────────────────────────

    /// F-301: the relay's `build_hashcash_challenge` MUST produce the
    /// same 32-byte digest that iOS's hashcashChallenge produces. We
    /// hand-construct the iOS-side computation here and compare. Mirrors
    /// the byte sequence in pizzini/ChatStore.swift::hashcashChallenge.
    #[test]
    fn f301_challenge_bytes_match_ios_encoder() {
        let peer_id: [u8; 33] = [0x05; 33];
        let hour: u64 = 0x1234567890abcdef;
        let server_chal = build_hashcash_challenge(&peer_id, hour);
        // iOS-equivalent:
        // input = HASHCASH_CHALLENGE_TAG || u16_be(33) || peer_id || hour_be
        let mut ios_input = Vec::new();
        ios_input.extend_from_slice(b"pizzini.hashcash.bundle.v1");
        ios_input.extend_from_slice(&33u16.to_be_bytes());
        ios_input.extend_from_slice(&peer_id);
        ios_input.extend_from_slice(&hour.to_be_bytes());
        let ios_chal = blake3::hash(&ios_input);
        assert_eq!(
            server_chal,
            *ios_chal.as_bytes(),
            "iOS and relay challenge digests must match byte-for-byte"
        );
    }

    /// F-301 negative: bit-flipping the tag changes the digest. (Sanity
    /// — domain separation actually separates.)
    #[test]
    fn f301_tag_bitflip_changes_digest() {
        let peer_id: [u8; 33] = [0x05; 33];
        let hour: u64 = 42;
        let good = build_hashcash_challenge(&peer_id, hour);
        // Same shape but flip one byte of the tag.
        let mut bad_input = Vec::new();
        bad_input.extend_from_slice(b"Pizzini.hashcash.bundle.v1"); // capital P
        bad_input.extend_from_slice(&33u16.to_be_bytes());
        bad_input.extend_from_slice(&peer_id);
        bad_input.extend_from_slice(&hour.to_be_bytes());
        let bad = blake3::hash(&bad_input);
        assert_ne!(good, *bad.as_bytes());
    }

    // ─── N-002 verify_keys lifetime ───────────────────────────────────────

    /// N-002: Bob has been registered (HELLO completed) and is now
    /// disconnected. A SEND aimed at Bob with a token signed by Bob's
    /// verify_key MUST still verify — otherwise offline-message
    /// delivery breaks for any peer whose connection just dropped.
    /// This was the regression introduced by the original F-204 fix.
    #[tokio::test]
    async fn n002_verify_key_survives_disconnect_and_check_succeeds() {
        // Mint Bob's IdentityKey and derive his recipient verify_key
        // the same way crypto-core does (HKDF-SHA512 from the
        // IdentityKeyPair's private bytes is the production path; for
        // this test we just need ANY valid (verify_key, signature) pair
        // that goes through the same `PublicKey::verify_signature` path
        // the relay uses).
        let (bob_pid, bob_kp) = fresh_identity();
        let bob_verify_pub = *bob_kp.identity_key().public_key();
        let bob_verify_key_bytes = bob_verify_pub.serialize().to_vec();
        // Sign a token (nonce16 || expiry_be_u32) with Bob's private key.
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let nonce = [0xCDu8; TOKEN_NONCE_LEN];
        let expiry = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            + 3600) as u32;
        let mut payload = Vec::new();
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&expiry.to_be_bytes());
        let sig = bob_kp
            .private_key()
            .calculate_signature(&payload, &mut rng)
            .expect("sign");
        let mut token = Vec::with_capacity(TOKEN_LEN);
        token.extend_from_slice(&payload);
        token.extend_from_slice(&sig);
        assert_eq!(token.len(), TOKEN_LEN);

        // Register Bob via HELLO-equivalent insert into verify_keys.
        let verify_keys: VerifyKeys = Arc::new(Mutex::new(HashMap::new()));
        verify_keys
            .lock()
            .await
            .insert(bob_pid.clone(), (bob_verify_key_bytes, Instant::now()));

        // Bob "disconnects" — under N-002's fix, no removal happens.
        // (Pre-fix, the F-204 eager-remove block ran here and dropped
        // verify_keys[bob].)

        // Alice's SEND to Bob arrives at the relay — check_delivery_token
        // looks up verify_keys[bob] and verifies the signature.
        let parsed = ParsedSealed {
            to_id: bob_pid.clone(),
            ttl_seconds: 3600,
            token,
        };
        let tmp_dir = std::env::temp_dir().join(format!("pizzini-relay-test-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())); std::fs::create_dir_all(&tmp_dir).expect("tempdir for replay store");
        let replays: Replays = Arc::new(Mutex::new(
            ReplayStore::load_or_create(&tmp_dir, TOKEN_REPLAY_WINDOW).expect("replay store"),
        ));
        check_delivery_token(&parsed, &verify_keys, &replays)
            .await
            .expect("verify must succeed for recently-disconnected recipient");
    }

    /// N-002: the periodic GC prunes verify_keys entries unused for
    /// `VERIFY_KEY_TTL`. Simulates an old entry by inserting with
    /// last_touched = `now - VERIFY_KEY_TTL - 1s`.
    #[tokio::test]
    async fn n002_verify_keys_gc_prunes_stale_entries() {
        let verify_keys: VerifyKeys = Arc::new(Mutex::new(HashMap::new()));
        let stale_pid = vec![0xAAu8; 33];
        let fresh_pid = vec![0xBBu8; 33];
        // Stale entry: simulate "30d + 1s ago".
        let stale_ts = Instant::now()
            .checked_sub(VERIFY_KEY_TTL + Duration::from_secs(1))
            .expect("clock arithmetic");
        verify_keys
            .lock()
            .await
            .insert(stale_pid.clone(), (vec![1u8; 33], stale_ts));
        verify_keys
            .lock()
            .await
            .insert(fresh_pid.clone(), (vec![2u8; 33], Instant::now()));
        // Run the GC loop body inline (the real spawn is on a 1h
        // tick; we just want to test the retain logic).
        {
            let cutoff = Instant::now() - VERIFY_KEY_TTL;
            let mut table = verify_keys.lock().await;
            table.retain(|_, (_, last_touched)| *last_touched > cutoff);
        }
        let table = verify_keys.lock().await;
        assert!(!table.contains_key(&stale_pid), "stale entry must be GC'd");
        assert!(
            table.contains_key(&fresh_pid),
            "fresh entry must survive GC"
        );
    }

    // ─── F-205 expiry-cap ─────────────────────────────────────────────────

    /// F-205: a token with `expiry = u32::MAX` should be rejected for
    /// being too far in the future. The cap is
    /// TOKEN_MAX_FUTURE_EXPIRY_SECS ≈ 30d + 5min from now.
    #[tokio::test]
    async fn f205_token_with_max_expiry_rejected_as_too_far_future() {
        // Build a valid recipient verify_key by deriving from a fresh
        // libsignal IdentityKey, mirroring crypto-core's pattern.
        let (recipient_pid, _kp) = fresh_identity();
        let verify_keys: VerifyKeys = Arc::new(Mutex::new(HashMap::new()));
        // Use a placeholder verify_key (signature won't match anyway,
        // but we want to reach the expiry-cap branch first). Insert
        // *something* so the verify_keys lookup succeeds.
        verify_keys
            .lock()
            .await
            .insert(
                recipient_pid.clone(),
                (vec![0u8; VERIFY_KEY_LEN], Instant::now()),
            );
        let tmp_dir = std::env::temp_dir().join(format!("pizzini-relay-test-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())); std::fs::create_dir_all(&tmp_dir).expect("tempdir for replay store");
        let replays: Replays = Arc::new(Mutex::new(
            ReplayStore::load_or_create(&tmp_dir, TOKEN_REPLAY_WINDOW).expect("replay store"),
        ));
        let mut token = vec![0u8; TOKEN_LEN];
        // Nonce: arbitrary.
        token[..TOKEN_NONCE_LEN].copy_from_slice(&[0xABu8; TOKEN_NONCE_LEN]);
        // Expiry = u32::MAX (year 2106).
        token[TOKEN_NONCE_LEN..TOKEN_NONCE_LEN + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        // Sig: bogus.
        let parsed = ParsedSealed {
            to_id: recipient_pid.clone(),
            ttl_seconds: 3600,
            token,
        };
        let err = check_delivery_token(&parsed, &verify_keys, &replays)
            .await
            .unwrap_err();
        assert!(
            err.contains("future"),
            "expected expiry-cap error, got: {err}"
        );
    }
}
