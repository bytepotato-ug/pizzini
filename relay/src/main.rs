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
//!   u8  protocol_version   (= 2; v1 clients are rejected)
//!   u16 peer_id_len + peer_id_bytes
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
//!
//! BUNDLE_RESPONSE (type = 4) — reply with the bundle bytes (store.rs format):
//!   u16 to_len   + to_id_bytes
//!   u16 from_len + from_id_bytes
//!   bundle bytes (consume to end-of-payload)
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

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::mpsc;

use crate::apns::{ApnsClient, ApnsConfig};

const PORT: u16 = 7777;
const PROTOCOL_VERSION: u8 = 2;
const FRAME_TYPE_HELLO: u8 = 1;
const FRAME_TYPE_SEND: u8 = 2;
const FRAME_TYPE_BUNDLE_REQUEST: u8 = 3;
const FRAME_TYPE_BUNDLE_RESPONSE: u8 = 4;
const FRAME_TYPE_REGISTER_PUSH: u8 = 5;
const FRAME_TYPE_ACK: u8 = 6;
const MAX_FRAME_BYTES: u32 = 1024 * 1024;
/// Hard ceiling on a single client's APNs device token. Real tokens are
/// 32 bytes today; Apple has hinted they may grow. Reject anything above
/// this so we don't memo absurd buffers per peer.
const MAX_PUSH_TOKEN_BYTES: usize = 256;

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

type PeerId = Vec<u8>;
type Outbox = mpsc::UnboundedSender<Vec<u8>>;
type Routes = Arc<Mutex<HashMap<PeerId, Outbox>>>;
/// Lives across reconnects — that's the whole point: we look up the
/// token when the recipient is *not* currently connected.
type PushTokens = Arc<Mutex<HashMap<PeerId, Vec<u8>>>>;

/// One queued routing frame. The body is the entire frame as it would
/// have been forwarded — including the leading frame_type byte and the
/// recipient header — so we can hand it verbatim to the recipient's
/// writer task on reconnect. `expires_at` is sender-chosen TTL clamped
/// to `MAX_PENDING_TTL`; per-frame, not global.
struct PendingFrame {
    bytes: Vec<u8>,
    expires_at: Instant,
}

type Pending = Arc<Mutex<HashMap<PeerId, VecDeque<PendingFrame>>>>;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let bind: SocketAddr = format!("0.0.0.0:{PORT}").parse().expect("static");
    let listener = TcpListener::bind(bind).await?;
    let lan_ips = local_lan_ips();
    println!(
        "pizzini-relay {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        bind
    );
    if lan_ips.is_empty() {
        println!("  (no non-loopback IPv4 found; sim can connect to 127.0.0.1)");
    } else {
        for ip in &lan_ips {
            println!("  reachable from LAN at {ip}:{PORT}");
        }
    }
    println!(
        "  DEV BUILD — clearnet, no auth, ephemeral in-memory queue (cap={MAX_PENDING_PER_PEER}/peer, max ttl={}h, sender-chosen per frame). Tor-only in prod.",
        MAX_PENDING_TTL.as_secs() / 3600,
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
    let push_tokens: PushTokens = Arc::new(Mutex::new(HashMap::new()));
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));

    spawn_pending_gc(pending.clone());

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let routes = routes.clone();
        let push_tokens = push_tokens.clone();
        let pending = pending.clone();
        let apns = apns.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                stream, routes, push_tokens, pending, apns, peer_addr,
            )
            .await
            {
                eprintln!("[{peer_addr}] connection closed: {e}");
            }
        });
    }
}

/// Background task that walks every per-peer queue and drops entries
/// past their per-frame `expires_at`. With sender-chosen TTLs the queue
/// is no longer monotone in arrival order — a 1h-TTL frame queued
/// after a 7d-TTL frame expires first — so we can't short-circuit on
/// the front. Walks the whole deque every cycle, which is fine: caps
/// keep each queue ≤ 100 entries.
fn spawn_pending_gc(pending: Pending) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(PENDING_GC_INTERVAL);
        loop {
            tick.tick().await;
            let now = Instant::now();
            let mut map = pending.lock().await;
            map.retain(|peer_id, queue| {
                let before = queue.len();
                queue.retain(|f| f.expires_at > now);
                if queue.is_empty() {
                    println!(
                        "pending: GC dropped {before} expired entries for {}",
                        short_hex(peer_id)
                    );
                    false
                } else {
                    true
                }
            });
        }
    });
}

async fn handle_connection(
    stream: TcpStream,
    routes: Routes,
    push_tokens: PushTokens,
    pending: Pending,
    apns: Option<Arc<ApnsClient>>,
    peer_addr: SocketAddr,
) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let (mut reader, mut writer) = stream.into_split();

    let first = read_frame(&mut reader).await?;
    if first.is_empty() || first[0] != FRAME_TYPE_HELLO {
        return Err(invalid("first frame must be HELLO"));
    }
    let peer_id = parse_hello(&first[1..]).map_err(|e| {
        // Refuse v1 clients loudly so a stale build can't silently
        // corrupt v2 routing state. Connection is closed by the caller
        // on Err return.
        eprintln!("[{peer_addr}] HELLO rejected: {e}");
        e
    })?;
    let peer_hex = hex(&peer_id);
    println!("[{peer_addr}] HELLO from peer {}", short_hex(&peer_id));

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
        apns.clone(),
        &peer_id,
    )
    .await;

    // Read side closed → this connection is done. Remove our route entry
    // *if* it still belongs to us (a newer HELLO from the same peer would
    // have replaced it). Then cancel the writer task. After both Senders
    // drop, the writer's `out_rx` returns None and it exits cleanly.
    {
        let mut map = routes.lock().await;
        if let Some(existing) = map.get(&peer_id) {
            if existing.same_channel(&our_tx) {
                map.remove(&peer_id);
            }
        }
    }
    drop(our_tx);
    writer_task.abort();
    println!("[{peer_addr}] disconnected ({peer_hex})");
    read_result
}

async fn read_loop(
    reader: &mut (impl AsyncReadExt + Unpin),
    routes: &Routes,
    push_tokens: &PushTokens,
    pending: &Pending,
    apns: Option<Arc<ApnsClient>>,
    self_id: &[u8],
) -> std::io::Result<()> {
    loop {
        let frame = match read_frame(reader).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if frame.is_empty() {
            return Err(invalid("empty frame"));
        }
        match frame[0] {
            FRAME_TYPE_HELLO => return Err(invalid("duplicate HELLO")),
            FRAME_TYPE_REGISTER_PUSH => {
                let token = match parse_register_push(&frame[1..]) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("malformed REGISTER_PUSH: {e}");
                        continue;
                    }
                };
                push_tokens
                    .lock()
                    .await
                    .insert(self_id.to_vec(), token);
                println!(
                    "REGISTER_PUSH from {}: token recorded ({} byte token)",
                    short_hex(self_id),
                    push_tokens
                        .lock()
                        .await
                        .get(self_id)
                        .map(|v| v.len())
                        .unwrap_or(0),
                );
            }
            FRAME_TYPE_SEND | FRAME_TYPE_ACK => {
                let parsed = match parse_sealed(&frame[1..]) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("malformed sealed frame: {e}");
                        continue;
                    }
                };
                let frame_type = frame[0];
                let frame_len = frame.len();
                let map = routes.lock().await;
                if let Some(target) = map.get(&parsed.to_id) {
                    let _ = target.send(frame);
                    println!(
                        "forward type={frame_type} → {} ({frame_len} bytes, ttl={}s, token={}B)",
                        short_hex(&parsed.to_id),
                        parsed.ttl_seconds,
                        parsed.token.len(),
                    );
                } else {
                    drop(map);
                    enqueue_pending(&parsed.to_id, frame, parsed.ttl_seconds, pending).await;
                    println!(
                        "queued type={frame_type} → {}: recipient offline (ttl={}s)",
                        short_hex(&parsed.to_id),
                        parsed.ttl_seconds,
                    );
                    maybe_send_push(&parsed.to_id, push_tokens, apns.as_ref()).await;
                }
            }
            FRAME_TYPE_BUNDLE_REQUEST | FRAME_TYPE_BUNDLE_RESPONSE => {
                // Bundle frames keep the explicit from_id at the wire
                // level — first contact pre-dates a session, so the
                // sealed-sender envelope can't yet be applied. Spoof
                // check still meaningful here.
                let parsed = match parse_routed(&frame[1..]) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("malformed bundle frame: {e}");
                        continue;
                    }
                };
                if parsed.from_id != self_id {
                    eprintln!(
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
                    println!(
                        "forward bundle type={frame_type} {} → {} ({frame_len} bytes)",
                        short_hex(&parsed.from_id),
                        short_hex(&parsed.to_id),
                    );
                } else {
                    println!(
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
    let mut map = pending.lock().await;
    let queue = map.entry(recipient.to_vec()).or_default();
    // Per-peer cap is a DoS safeguard: an attacker spraying SEND at a
    // long-offline peer should not be able to balloon our memory. Drop
    // oldest first; the recipient will at least see the most recent
    // messages on reconnect.
    while queue.len() >= MAX_PENDING_PER_PEER {
        queue.pop_front();
    }
    let ttl = clamp_ttl(ttl_seconds);
    queue.push_back(PendingFrame {
        bytes: frame,
        expires_at: Instant::now() + ttl,
    });
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
async fn drain_pending(peer_id: &[u8], pending: &Pending, routes: &Routes) {
    let queue = {
        let mut map = pending.lock().await;
        map.remove(peer_id)
    };
    let Some(queue) = queue else { return };
    if queue.is_empty() {
        return;
    }
    let now = Instant::now();
    let routes_map = routes.lock().await;
    let Some(target) = routes_map.get(peer_id) else { return };
    let mut forwarded = 0usize;
    let mut expired = 0usize;
    for entry in queue {
        if entry.expires_at <= now {
            expired += 1;
            continue;
        }
        if target.send(entry.bytes).is_err() {
            // Writer task is gone (race with disconnect). Stop draining
            // — the recipient effectively isn't connected anymore. Any
            // remaining entries are dropped because we already removed
            // the queue from `pending`. That's a knowing tradeoff
            // against the alternative of partial reinsertion, which
            // adds complexity for a rare race.
            break;
        }
        forwarded += 1;
    }
    println!(
        "drained pending for {}: forwarded={forwarded} expired={expired}",
        short_hex(peer_id),
    );
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
    let token = match push_tokens.lock().await.get(recipient).cloned() {
        Some(t) => t,
        None => return,
    };
    let recipient_dbg = short_hex(recipient);
    let client = client.clone();
    tokio::spawn(async move {
        match client.send_wakeup(&token).await {
            Ok(_) => println!("push: sent wake-up to {recipient_dbg}"),
            Err(e) => eprintln!("push: failed for {recipient_dbg}: {e}"),
        }
    });
}

struct ParsedRouted {
    to_id: Vec<u8>,
    from_id: Vec<u8>,
}

struct ParsedSealed {
    to_id: Vec<u8>,
    ttl_seconds: u32,
    token: Vec<u8>,
}

fn parse_hello(body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut c = Cursor::new(body);
    let version = c.u8()?;
    if version != PROTOCOL_VERSION {
        return Err(invalid(&format!(
            "unsupported protocol version {version}; relay speaks {PROTOCOL_VERSION}"
        )));
    }
    let id = c.u16_blob()?.to_vec();
    if !c.is_empty() {
        return Err(invalid("trailing bytes after HELLO"));
    }
    Ok(id)
}

fn parse_routed(body: &[u8]) -> std::io::Result<ParsedRouted> {
    let mut c = Cursor::new(body);
    let to_id = c.u16_blob()?.to_vec();
    let from_id = c.u16_blob()?.to_vec();
    // Anything after the routing prefix is opaque to the relay.
    Ok(ParsedRouted { to_id, from_id })
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
    if token.len() > MAX_PUSH_TOKEN_BYTES {
        return Err(invalid(&format!(
            "REGISTER_PUSH token too large: {} bytes",
            token.len()
        )));
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

    #[test]
    fn rejects_protocol_v1() {
        // v1 HELLO body had no version byte; it started straight with the
        // u16 peer_id length. Re-encoding such a body and parsing it
        // against v2 must fail with a clear "unsupported version" error.
        let mut v1_body = Vec::new();
        v1_body.extend_from_slice(&(4u16.to_be_bytes())); // peer_id_len = 4
        v1_body.extend_from_slice(&[1, 2, 3, 4]);          // peer_id bytes
        let err = parse_hello(&v1_body).unwrap_err();
        assert!(format!("{err}").contains("protocol version"));
    }

    #[test]
    fn parse_hello_accepts_protocol_v2() {
        let mut body = Vec::new();
        body.push(PROTOCOL_VERSION);
        body.extend_from_slice(&(33u16.to_be_bytes()));
        body.extend_from_slice(&[0u8; 33]);
        let id = parse_hello(&body).unwrap();
        assert_eq!(id, vec![0u8; 33]);
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
}
