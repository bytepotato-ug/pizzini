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
//!                    (with from_id rewritten to the connection's HELLO id):
//!   u16 to_len   + to_id_bytes
//!   u16 from_len + from_id_bytes
//!   u8  is_prekey   (0 or 1; surfaces libsignal CiphertextMessageType)
//!   ciphertext bytes (consume to end-of-payload)
//! ```
//!
//! Stateless: if the recipient is not currently connected, the SEND is
//! dropped on the floor. There is no queue, no ack, no retry. Senders that
//! care should reattempt at the application layer once the peer reconnects.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::mpsc;

const PORT: u16 = 7777;
const FRAME_TYPE_HELLO: u8 = 1;
const FRAME_TYPE_SEND: u8 = 2;
const MAX_FRAME_BYTES: u32 = 1024 * 1024;

type PeerId = Vec<u8>;
type Outbox = mpsc::UnboundedSender<Vec<u8>>;
type Routes = Arc<Mutex<HashMap<PeerId, Outbox>>>;

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

    let routes: Routes = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let routes = routes.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, routes, peer_addr).await {
                eprintln!("[{peer_addr}] connection closed: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    routes: Routes,
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

    let read_result = read_loop(&mut reader, &routes, &peer_id).await;

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
            FRAME_TYPE_SEND => {
                let parsed = match parse_send(&frame[1..]) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("malformed SEND: {e}");
                        continue;
                    }
                };
                if parsed.from_id != self_id {
                    eprintln!(
                        "rejecting SEND with spoofed from_id {} (connection is {})",
                        short_hex(&parsed.from_id),
                        short_hex(self_id),
                    );
                    continue;
                }
                let map = routes.lock().await;
                let Some(target) = map.get(&parsed.to_id) else {
                    println!(
                        "drop SEND {} → {} ({} B): recipient offline",
                        short_hex(&parsed.from_id),
                        short_hex(&parsed.to_id),
                        parsed.ciphertext.len(),
                    );
                    continue;
                };
                let _ = target.send(frame);
            }
            other => return Err(invalid(&format!("unknown frame type {other}"))),
        }
    }
}

struct ParsedSend {
    to_id: Vec<u8>,
    from_id: Vec<u8>,
    #[allow(dead_code)]
    is_prekey: bool,
    ciphertext: Vec<u8>,
}

fn parse_hello(body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut c = Cursor::new(body);
    let id = c.u16_blob()?.to_vec();
    if !c.is_empty() {
        return Err(invalid("trailing bytes after HELLO"));
    }
    Ok(id)
}

fn parse_send(body: &[u8]) -> std::io::Result<ParsedSend> {
    let mut c = Cursor::new(body);
    let to_id = c.u16_blob()?.to_vec();
    let from_id = c.u16_blob()?.to_vec();
    let is_prekey = c.u8()? != 0;
    let ciphertext = c.rest().to_vec();
    Ok(ParsedSend {
        to_id,
        from_id,
        is_prekey,
        ciphertext,
    })
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
    fn rest(&mut self) -> &'a [u8] {
        let r = self.buf;
        self.buf = &[];
        r
    }
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
    fn u16_blob(&mut self) -> std::io::Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}
