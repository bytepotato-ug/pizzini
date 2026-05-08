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
//! ## Wire protocol (length-prefixed framing, big-endian)
//!
//! ```text
//! Frame: u32 payload_len + payload
//!
//! Payload:
//!   u8  frame_type
//!   ...
//!
//! HELLO (type = 1) — client → relay, must be the first frame:
//!   u16 peer_id_len + peer_id_bytes
//!
//! SEND  (type = 2) — bidirectional. Sender writes; relay forwards verbatim
//!                    if the recipient is online, otherwise drops:
//!   u16 to_len   + to_id_bytes
//!   u16 from_len + from_id_bytes
//!   u8  is_prekey   (0 or 1; surfaces libsignal CiphertextMessageType)
//!   ciphertext bytes (consume to end-of-payload)
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
//! Stateless: if the recipient is not currently connected, the SEND
//! payload is dropped (no queue, no ack, no retry). If the recipient
//! has previously REGISTER_PUSH'd, we additionally fire a payload-opaque
//! "New message" push via APNs as a wake-up. The push carries no peer
//! information — see `apns.rs` for the threat-model rationale.

mod apns;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::mpsc;

use crate::apns::{ApnsClient, ApnsConfig};

const PORT: u16 = 7777;
const FRAME_TYPE_HELLO: u8 = 1;
const FRAME_TYPE_SEND: u8 = 2;
const FRAME_TYPE_BUNDLE_REQUEST: u8 = 3;
const FRAME_TYPE_BUNDLE_RESPONSE: u8 = 4;
const FRAME_TYPE_REGISTER_PUSH: u8 = 5;
const MAX_FRAME_BYTES: u32 = 1024 * 1024;
/// Hard ceiling on a single client's APNs device token. Real tokens are
/// 32 bytes today; Apple has hinted they may grow. Reject anything above
/// this so we don't memo absurd buffers per peer.
const MAX_PUSH_TOKEN_BYTES: usize = 256;

type PeerId = Vec<u8>;
type Outbox = mpsc::UnboundedSender<Vec<u8>>;
type Routes = Arc<Mutex<HashMap<PeerId, Outbox>>>;
/// Lives across reconnects — that's the whole point: we look up the
/// token when the recipient is *not* currently connected.
type PushTokens = Arc<Mutex<HashMap<PeerId, Vec<u8>>>>;

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
    println!("  DEV BUILD — clearnet, no queueing, no auth. Tor-only in prod.");

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

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let routes = routes.clone();
        let push_tokens = push_tokens.clone();
        let apns = apns.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, routes, push_tokens, apns, peer_addr).await
            {
                eprintln!("[{peer_addr}] connection closed: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    routes: Routes,
    push_tokens: PushTokens,
    apns: Option<Arc<ApnsClient>>,
    peer_addr: SocketAddr,
) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let (mut reader, mut writer) = stream.into_split();

    let first = read_frame(&mut reader).await?;
    if first.is_empty() || first[0] != FRAME_TYPE_HELLO {
        return Err(invalid("first frame must be HELLO"));
    }
    let peer_id = parse_hello(&first[1..])?;
    let peer_hex = hex(&peer_id);
    println!("[{peer_addr}] HELLO from peer {}", short_hex(&peer_id));

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    {
        let mut map = routes.lock().await;
        if let Some(prev) = map.insert(peer_id.clone(), out_tx) {
            // Older connection for the same peer — drop it.
            drop(prev);
        }
    }

    let writer_routes = routes.clone();
    let writer_peer = peer_id.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(payload) = out_rx.recv().await {
            if write_frame(&mut writer, &payload).await.is_err() {
                break;
            }
        }
        // Receiver dropped or write failed — clean up our route entry, but
        // only if the entry still belongs to this connection.
        let mut map = writer_routes.lock().await;
        if let Some(existing) = map.get(&writer_peer) {
            if existing.is_closed() {
                map.remove(&writer_peer);
            }
        }
    });

    let read_result =
        read_loop(&mut reader, &routes, &push_tokens, apns.clone(), &peer_id).await;

    {
        let mut map = routes.lock().await;
        if let Some(existing) = map.get(&peer_id) {
            if existing.is_closed() {
                map.remove(&peer_id);
            }
        }
    }
    drop(writer_task);
    println!("[{peer_addr}] disconnected ({peer_hex})");
    read_result
}

async fn read_loop(
    reader: &mut (impl AsyncReadExt + Unpin),
    routes: &Routes,
    push_tokens: &PushTokens,
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
            FRAME_TYPE_SEND
            | FRAME_TYPE_BUNDLE_REQUEST
            | FRAME_TYPE_BUNDLE_RESPONSE => {
                let parsed = match parse_routed(&frame[1..]) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("malformed routed frame: {e}");
                        continue;
                    }
                };
                if parsed.from_id != self_id {
                    eprintln!(
                        "rejecting frame with spoofed from_id {} (connection is {})",
                        short_hex(&parsed.from_id),
                        short_hex(self_id),
                    );
                    continue;
                }
                let map = routes.lock().await;
                if let Some(target) = map.get(&parsed.to_id) {
                    let _ = target.send(frame);
                } else {
                    drop(map);
                    println!(
                        "drop frame {} → {}: recipient offline",
                        short_hex(&parsed.from_id),
                        short_hex(&parsed.to_id),
                    );
                    if frame[0] == FRAME_TYPE_SEND {
                        maybe_send_push(&parsed.to_id, push_tokens, apns.as_ref()).await;
                    }
                }
            }
            other => return Err(invalid(&format!("unknown frame type {other}"))),
        }
    }
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

fn parse_hello(body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut c = Cursor::new(body);
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
    fn u16(&mut self) -> std::io::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u16_blob(&mut self) -> std::io::Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}
