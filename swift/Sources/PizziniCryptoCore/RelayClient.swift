// Swift counterpart to the Rust dev relay (relay/src/main.rs). Speaks the
// same length-prefixed framing: 4-byte BE length + payload.
//
// Frames are dumb byte shuttles. Everything ferried inside is already
// libsignal-encrypted; this layer doesn't touch crypto.
//
// DEV ONLY — sim ↔ phone over LAN. Production transport is Tor.

import Foundation
import Network
import os
import PizziniTor

/// Debug logger for the relay-client transport phases (Tor bootstrap
/// gate → HS-descriptor prime → SOCKS5 handshake → HELLO). Filter
/// for it in Console.app via `subsystem:app.pizzini.relay`. Pairs
/// with `subsystem:app.pizzini.tor` for the full cold-start picture.
private let relayLog = Logger(subsystem: "app.pizzini.relay", category: "connect")

/// USP #1: snapshot of the running relay binary's identity.
/// Returned by `RelayClient.requestStatus()` and delivered to the
/// host via `relayClient(_:didReceiveStatus:)`. The host shows it
/// in Settings and (eventually) compares against an
/// operator-signed transparency-log entry.
public struct RelayStatus: Sendable, Equatable {
    /// Protocol version the relay implements. Must match the
    /// client's `HELLO` signing tag major version — a divergence
    /// means a relay upgrade hasn't shipped to clients yet.
    public let protocolVersion: UInt8
    /// "Was the working tree dirty when this binary was built?"
    /// 0 = clean (reproducible-build eligible), 1 = dirty (dev
    /// build), 2 = unknown (built outside a git checkout).
    public let gitDirty: UInt8
    /// `CARGO_PKG_VERSION` from the build, e.g. `"0.0.0"`.
    public let crateVersion: String
    /// Hex SHA of the source commit. 40 chars in a normal build;
    /// `"unknown"` when the relay was built outside a git checkout.
    public let gitSha: String
    /// SHA-256 of the running binary, computed by the relay at
    /// startup. 32 bytes. Compare against
    /// `sha256sum target/release/pizzini-relay` from
    /// `scripts/build-relay-release.sh`.
    public let binarySha256: Data
}

public protocol RelayClientDelegate: AnyObject, Sendable {
    /// Connection state crossed a meaningful threshold.
    func relayClient(_ client: RelayClient, didChange state: RelayClient.State)
    /// A SEND v2 frame arrived. The payload is the sealed-sender envelope
    /// bytes — feed straight to `Session.decryptSealed`. The host owns
    /// dedup on the unwrapped 16-byte message_id.
    func relayClient(_ client: RelayClient, didReceiveSealedSend sealedCiphertext: Data)
    /// An ACK frame arrived. The payload is itself a sealed-sender
    /// envelope; the inner plaintext begins with `Self.ackMarker` followed
    /// by the 16-byte message_id of the SEND being acked.
    func relayClient(_ client: RelayClient, didReceiveAck sealedCiphertext: Data)
    /// Peer asked us for a fresh PreKey bundle to PQXDH with.
    func relayClient(_ client: RelayClient, didReceiveBundleRequestFrom fromPeer: Data)
    /// Peer answered our earlier `requestBundle` with the bundle bytes.
    func relayClient(
        _ client: RelayClient,
        didReceiveBundleFrom fromPeer: Data,
        bundle: Data
    )
    /// Peer minted delivery tokens for us to use when sending TO them
    /// (Phase 3). Sent right after their BUNDLE_RESPONSE on first
    /// contact and in response to a sealed token-refill-request.
    /// Each token is 84 bytes (nonce + expiry + sig).
    func relayClient(
        _ client: RelayClient,
        didReceiveTokenIssueFrom fromPeer: Data,
        tokens: [Data]
    )
    /// USP #1: relay answered our `requestStatus()` with the
    /// running binary's self-attestation snapshot.
    func relayClient(_ client: RelayClient, didReceiveStatus status: RelayStatus)
}

/// Default no-op so existing delegate implementations don't have
/// to handle the new STATUS callback until they're ready. The
/// host can override to surface the snapshot in Settings.
public extension RelayClientDelegate {
    func relayClient(_ client: RelayClient, didReceiveStatus status: RelayStatus) {}
}

public final class RelayClient: @unchecked Sendable {
    public enum State: Sendable, Equatable {
        case idle
        /// Connecting to a .onion target — Tor bootstrap is in flight.
        /// `progress` is the latest `BOOTSTRAP PROGRESS=N` value the
        /// embedded daemon emitted (0–100). The UI surfaces this as
        /// "Connecting to Tor… N%". Transitions to `.connecting` once
        /// the SOCKS5 handshake begins and to `.connected` once the
        /// relay HELLO completes.
        case connectingToTor(progress: Int)
        case connecting
        case connected
        case failed(String)
    }

    /// On-the-wire protocol version negotiated in HELLO. Bumped from 1
    /// when sealed-sender SEND/ACK landed; v1 relays/clients reject.
    /// Protocol v3 added the F-203 HELLO possession proof — every HELLO
    /// frame now carries `timestamp_be_u64 || u16 nonce_len + nonce16
    /// || u16 sig_len + sig64`, where `sig` is the IdentityKey's Ed25519
    /// signature over `b"pizzini.hello.v3" || peer_id || verify_key ||
    /// timestamp_be || nonce`. Relay verifies against the IdentityKey
    /// extracted from `peer_id`.
    public static let protocolVersion: UInt8 = 3
    /// Domain-separation tag for the HELLO signing payload. MUST match
    /// `HELLO_SIGNING_TAG` in `relay/src/main.rs`.
    /// Domain-separated HELLO signing tag. F-NEW-205: includes the
    /// protocol version so a captured signature can't be reinterpreted
    /// under a different wire version. Must match
    /// `HELLO_SIGNING_TAG` in `relay/src/main.rs`.
    private static let helloSigningTag = Data("pizzini.hello.v3".utf8)
    private static let helloNonceLen = 16

    /// Inner-plaintext type byte. Sealed envelope contents always start
    /// with one of these so the receiver can dispatch without parsing
    /// ambiguous prefixes that could collide with user-typed text.
    public enum InnerEnvelopeKind: UInt8 {
        case chat = 0x01
        case ack = 0x02
        case tokenRefillRequest = 0x03
        case readReceipt = 0x04
        /// Chunked file transfer (Phase 2). Each chunk rides a *separate*
        /// sealed envelope (its own per-chunk replay nonce + delivery
        /// token), but the inner plaintext carries a 16-byte
        /// `attachmentId` shared across the whole file so the receiver
        /// can reassemble. See `FileChunkEnvelope` in the iOS app for
        /// the exact wire layout. Chosen over a relay-layer chunked-
        /// frame type because adding a new outer frame would leak chunk
        /// count + total size to the relay; sealed-sender hides them.
        case fileChunk = 0x05
        /// Group chat (Phase 6). Body: `groupId(16) ‖ SenderKeyMessage`.
        /// Sender encrypts plaintext once via libsignal `group_encrypt`
        /// and broadcasts the resulting ciphertext as N independent
        /// pairwise sealed-sender envelopes, one per group recipient.
        /// The relay sees N independent 1:1 sends with opaque payloads
        /// and learns nothing about group membership.
        case groupChat = 0x06
        /// Group sender-key distribution (Phase 6). Body:
        /// `groupId(16) ‖ SenderKeyDistributionMessage`. Shipped 1:1
        /// from a group member to each recipient when they enrol or
        /// rotate their sender-key chain. Carries the chain key plus
        /// the operator's distribution_id; the recipient feeds it to
        /// `process_sender_key_distribution_message` to install the
        /// chain and later decrypt that operator's `groupChat` output.
        case groupKeyDistribution = 0x07
        /// Signed group operation (Phase 6). Body: the wire bytes of
        /// a `GroupOp` (op-version-1 header + 64-byte XEd25519
        /// signature). Broadcast to every current and incoming group
        /// member so each device's `ChatGroup` can replay the op log
        /// and converge on the same membership / role / chain-id
        /// state. See `GroupOp.swift` for the exact wire format.
        case groupOp = 0x08
        /// Signed group-state bootstrap (Phase 6, slice 4). Body:
        /// `groupId(16) ‖ GroupBootstrap bytes`. Sent by an inviting
        /// admin alongside the `AddMember` op so a newcomer can
        /// reconstruct local `ChatGroup` state (members, current
        /// epoch, last digest, name) without replaying the op chain.
        /// Trust anchor: the receiver verifies (a) the embedded
        /// signature, (b) the immediate sealed-sender is the bootstrap
        /// operator (no forwarding), and (c) the operator is in the
        /// receiver's 1:1 contacts. Without all three, the bootstrap
        /// is dropped — the same trust gate as the Create op.
        case groupBootstrap = 0x09
        /// Group chunked file transfer. Body: `groupId(16) ‖
        /// group_encrypt(FileChunkEnvelope bytes)`. Sender encrypts
        /// each chunk's `FileChunkEnvelope` payload once via libsignal
        /// `group_encrypt` against the local sender-key chain, then
        /// fans out the result as N independent pairwise sealed-sender
        /// envelopes, one per active member. The plaintext envelope
        /// re-uses the 1:1 `FileChunkEnvelope` codec so the
        /// `attachmentId`, total size, chunk index/count, mime, and
        /// filename are still hidden from the relay; what's sealed at
        /// the group layer is the `SenderKeyMessage` carrying the
        /// envelope bytes. Trust gates on receive mirror `groupChat`
        /// (CRITICAL-2): only chunks from active members of the named
        /// group are decrypted; pending-invitation groups advance the
        /// chain but render nothing.
        case groupFileChunk = 0x0A
        /// Delivery-token v2 chain-seed delivery. Body: an 88-byte
        /// `HashChainToken.Chain` binary form (chainID(16) ‖ seed(32)
        /// ‖ root(32) ‖ length(4 BE) ‖ nextIndex(4 BE)) where
        /// `nextIndex == 1`. Sent from the recipient (who minted the
        /// chain and registered the root with the relay) to the
        /// sender (who installs it as the outbound chain for messages
        /// to this peer). Replaces the v1 `TOKEN_ISSUE` 1024-token
        /// fan-out shipped over the unsealed wire frame — chain-seed
        /// delivery rides the Double Ratchet, so the relay never sees
        /// the registration step.
        case chainSeedDelivery = 0x0B
    }
    private static let frameTypeHello: UInt8 = 1
    private static let frameTypeSend: UInt8 = 2
    private static let frameTypeBundleRequest: UInt8 = 3
    private static let frameTypeBundleResponse: UInt8 = 4
    private static let frameTypeRegisterPush: UInt8 = 5
    private static let frameTypeAck: UInt8 = 6
    private static let frameTypeTokenIssue: UInt8 = 7
    /// USP #1: client → relay "what build are you running?". Empty
    /// payload (just the frame type). Match `FRAME_TYPE_STATUS_REQUEST`
    /// in `relay/src/main.rs`.
    private static let frameTypeStatusRequest: UInt8 = 8
    /// Relay → client response carrying crate version, git SHA,
    /// dirty bit, and binary SHA-256. Match
    /// `FRAME_TYPE_STATUS_RESPONSE` in `relay/src/main.rs`.
    private static let frameTypeStatusResponse: UInt8 = 9
    /// Width of the binary SHA-256 the relay reports. Locked at 32
    /// bytes; the relay sends a length byte preceding the digest
    /// so a future hash bump (e.g. SHA-512) lands without
    /// disturbing this client.
    private static let statusBinHashLen: Int = 32
    /// USP #4 (pacing pass): cover-traffic frame. Body is exactly
    /// `coverPayloadLen` random bytes. The relay receives + drops.
    /// Match `FRAME_TYPE_COVER` in `relay/src/main.rs`.
    private static let frameTypeCover: UInt8 = 10
    /// Client → relay request to drop our APNs device token from the
    /// relay's persistent push-token store. Empty body. Sent by the
    /// host when a different relay is elected push-primary so the
    /// previous primary stops emitting duplicate APNs wake-ups.
    /// Match `FRAME_TYPE_DEREGISTER_PUSH` in `relay/src/main.rs`.
    private static let frameTypeDeregisterPush: UInt8 = 11
    /// v2 delivery-token chain registration. Body:
    /// `chain_id(16) ‖ root(32) ‖ length(4 BE)`. The relay binds the
    /// chain to the HELLO-authenticated peer_id of this connection.
    /// Match `FRAME_TYPE_REGISTER_CHAIN` in `relay/src/main.rs`.
    private static let frameTypeRegisterChain: UInt8 = 12
    /// Body length of a COVER frame. Sized to roughly match the
    /// smallest padded sealed_ciphertext bucket so a passive
    /// observer can't trivially distinguish covers from short
    /// real SENDs at the cell-counting granularity.
    private static let coverPayloadLen: Int = 256
    /// Maximum gap between any two outgoing frames on a connected
    /// session before we emit a cover frame to fill the silence.
    /// 30 s balances battery / data overhead (~700 KB / day idle)
    /// against the timing-mask quality — short enough that an
    /// observer can't infer "the user is composing a message"
    /// from a multi-minute lull followed by a burst.
    private static let coverInterval: TimeInterval = 30
    private static let maxFrameBytes: UInt32 = 1024 * 1024
    /// Hard ceiling on the per-message TTL the sender can request; the
    /// relay clamps to this server-side too. 7 days.
    public static let maxTTLSeconds: UInt32 = 7 * 24 * 60 * 60
    /// Wire size of a single delivery token (nonce16 + expiry_be_u32 + sig64).
    public static let deliveryTokenLen: Int = 16 + 4 + 64

    public weak var delegate: RelayClientDelegate?
    /// The onion host this client was last asked to dial. Captured in
    /// `connect(to:port:)` so per-transition diagnostic log lines can
    /// identify which fleet member fired the event without the reader
    /// having to cross-reference timestamps against ChatStore's
    /// "connecting to Relay X" pre-dial line.
    private var lastTargetHost: String = ""
    public private(set) var state: State = .idle {
        didSet {
            guard oldValue != state else { return }
            let snapshot = state
            // Diagnostic — every state transition. Without this, the
            // `.connected → .idle` flap that occasionally hits one
            // member of a multi-relay fleet (`pizziniN…` going dark
            // seconds after the relay-attest line) is invisible:
            // none of the four `.idle`-write sites in this file log
            // anything, so the only signal in the Console.app dump
            // is the perRelayState dict mutating in ChatStore, which
            // is too far downstream to tell us WHICH write fired.
            // %{public}@ formatting because the relay onion is a
            // public address (already on the wire in the SOCKS
            // CONNECT) and the transition itself is the entire
            // diagnostic value.
            let hostPrefix = lastTargetHost.prefix(12)
            relayLog.notice(
                "state: \(hostPrefix, privacy: .public)… \(String(describing: oldValue), privacy: .public) → \(String(describing: snapshot), privacy: .public)"
            )
            let delegate = self.delegate
            let client = self
            queue.async {
                delegate?.relayClient(client, didChange: snapshot)
            }
            // USP #4 (pacing pass): cover-traffic timer follows
            // connection state. Started when we transition into
            // `.connected`, torn down on any other state so the
            // timer can't fire against a dead socket.
            if state == .connected {
                startCoverTimer()
            } else {
                stopCoverTimer()
            }
        }
    }

    /// Closure that signs an arbitrary payload with the local
    /// IdentityKey's private half. F-203: provided at construction time
    /// so RelayClient stays unaware of `Session` internals (cleaner test
    /// substitution + keeps `Sendable` inference simple). In production
    /// it's `{ try? session.identitySign($0) }`.
    public typealias HelloSigner = @Sendable (Data) -> Data?

    private let queue = DispatchQueue(label: "app.pizzini.relay")
    private let myIdentity: Data
    private let myDeliveryTokenVerifyKey: Data
    private let signer: HelloSigner
    private var connection: NWConnection?
    private var readBuffer = Data()
    /// USP #4: wall-clock of the last outgoing frame (real OR
    /// cover). The cover timer skips emission if a real frame
    /// has happened within `coverInterval` — active conversations
    /// produce no overhead.
    private var lastFrameSentAt = Date()
    /// USP #4: repeating timer driving cover emission. Lives on
    /// `queue` so all reads/writes against `lastFrameSentAt` and
    /// the connection happen on the same serial queue.
    private var coverTimer: DispatchSourceTimer?
    /// Latest APNs device token. Cached so we automatically re-register
    /// after a reconnect (the relay's push-token map is in-memory; a
    /// relay restart wipes it).
    private var pushToken: Data?

    /// SOCKS5 retry counter for the .onion path. The first SOCKS5
    /// CONNECT after a fresh install / fresh Tor bootstrap can fail
    /// because tor hasn't fetched the onion's introduction-point
    /// descriptor yet — HSDir lookup + rendezvous setup adds
    /// 10-30 s to the first dial against a new onion, often
    /// longer than the SOCKS reply tor returns when its first
    /// internal attempt times out. Subsequent attempts hit tor's
    /// descriptor cache and succeed in <1 s. Auto-retry up to
    /// `maxSocksRetries` times with `socksRetryDelay` backoff so
    /// the user doesn't see a spurious "Connection refused" on
    /// first launch. Reset to 0 on every new `connect()` call.
    private var socksRetries: Int = 0
    private static let maxSocksRetries: Int = 4
    private static let socksRetryDelay: TimeInterval = 5

    public init(
        myIdentity: Data,
        myDeliveryTokenVerifyKey: Data,
        signer: @escaping HelloSigner
    ) {
        self.myIdentity = myIdentity
        self.myDeliveryTokenVerifyKey = myDeliveryTokenVerifyKey
        self.signer = signer
    }

    public func connect(to host: String, port: UInt16) {
        disconnect()
        lastTargetHost = host
        state = .connecting
        socksRetries = 0
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            state = .failed("invalid port \(port)")
            return
        }
        // **D1 Tor-only enforcement.** The single chokepoint for the
        // production posture: any host that isn't a strictly-validated
        // v3 onion routes through `startTorConnection` below; everything
        // else takes the direct path. A naive `.hasSuffix(".onion")`
        // gate is bypassable (Unicode look-alikes, trailing whitespace,
        // mixed case, `evil.com.onion`), so we use the OnionHost
        // canonicaliser instead. The direct path is gated behind a
        // compile-time `RELAY_ALLOW_DIRECT_TCP` flag so production
        // builds physically cannot reach `startDirectConnection`. Dev
        // builds (Xcode "Debug" config or `swift test`) flip the flag
        // on for the LAN-loopback test harness in
        // `RelayClientLanTests`.
        if let canonical = OnionHost.canonical(host) {
            startTorConnection(host: canonical, port: nwPort)
            return
        }
        #if RELAY_ALLOW_DIRECT_TCP
        startDirectConnection(host: host, port: nwPort)
        #else
        state = .failed("refusing non-onion relay host: \(host)")
        #endif
    }

    private func startDirectConnection(host: String, port: NWEndpoint.Port) {
        let endpoint = NWEndpoint.Host(host)
        let conn = NWConnection(host: endpoint, port: port, using: .tcp)
        self.connection = conn

        conn.stateUpdateHandler = { [weak self] s in
            guard let self else { return }
            switch s {
            case .ready:
                self.sendHello()
                if let token = self.pushToken {
                    self.sendRegisterPush(token: token)
                }
                self.state = .connected
                self.scheduleRead()
            case .waiting:
                // Transient (route flap, brief unreachable). NWConnection
                // will resolve back to `.ready` on its own; until then,
                // bytes won't flow, so don't lie to the UI by leaving
                // state at `.connected`. Surface as `.connecting`, not
                // `.failed` — `.failed` would imply the user should
                // intervene, which is wrong for a recoverable hiccup.
                self.state = .connecting
            case .failed(let err):
                self.state = .failed("\(err)")
            case .cancelled:
                self.state = .idle
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    /// .onion target. Multi-step setup:
    ///   1. Ensure embedded Tor is bootstrapped → get SOCKS port
    ///   2. Prime tor's HS-descriptor cache for `<host>` (see below)
    ///   3. Open NWConnection to 127.0.0.1:<socksPort>
    ///   4. SOCKS5 greeting + CONNECT to <host>:<port>
    ///   5. Drop into the relay HELLO + scheduleRead
    /// Any failure on the way maps to `state = .failed(...)` and the
    /// host's retry timer picks it up on the next tick.
    ///
    /// Step 2 is the difference between a working cold launch and the
    /// historic "first tap to Reconnect" symptom: tor's BOOTSTRAP=100
    /// event only proves the daemon can build *some* circuit, not that
    /// it knows how to reach this particular onion. Without an
    /// HSFETCH, the first SOCKS5 CONNECT is the one that triggers the
    /// HS-descriptor lookup, and tor returns `REP=0x01` or `0x06`
    /// before the lookup completes. See
    /// `TorController.prepareHiddenService(_:)` for the contract.
    private func startTorConnection(host: String, port: NWEndpoint.Port) {
        let target = host
        let targetPort = port.rawValue
        // Hold off on emitting `.connectingToTor(progress: 0)` until
        // we've checked whether Tor is already bootstrapped. The
        // common case after the first launch is "Tor is up", and
        // flashing 0% on every Reconnect tap is misleading. We make
        // the async hop on the Task below — `state` stays as
        // `.connecting` (set in the caller before this function
        // returned) in the meantime.
        Task { [weak self] in
            guard let self else { return }
            let dialStart = Date()
            let hostPrefix = target.prefix(8)
            relayLog.info("dial: start host=\(hostPrefix, privacy: .public)…:\(targetPort)")

            // Already bootstrapped? Skip the Tor UI phase entirely.
            // RelayClient's caller already moved state to .connecting;
            // we leave it there.
            let alreadyReady = await TorController.shared.isReady
            relayLog.debug("dial: TorController.isReady=\(alreadyReady)")
            let socksPort: UInt16
            if !alreadyReady {
                self.queue.async { [weak self] in
                    guard let self else { return }
                    // Seed the UI with the CURRENT bootstrap progress
                    // (which the poll task below will refresh every
                    // 200ms). On a cold launch this is 0; on a warm
                    // restart from cache it's typically already at
                    // 100 by the time we get here.
                    self.state = .connectingToTor(progress: 0)
                }
                // Sibling task: poll TorController.bootstrapProgress
                // and republish via `state`. Cheap (a MainActor hop
                // + int read every 200ms). Cancelled below once
                // bootstrap() returns.
                let progressTask = Task { [weak self] in
                    while !Task.isCancelled {
                        let pct = await TorController.shared.bootstrapProgress
                        self?.queue.async {
                            guard let self else { return }
                            if case .connectingToTor = self.state {
                                self.state = .connectingToTor(progress: pct)
                            }
                        }
                        try? await Task.sleep(nanoseconds: 200_000_000)
                    }
                }

                do {
                    socksPort = try await TorController.shared.bootstrap()
                    relayLog.info("dial: bootstrap done after \(Self.fmtElapsed(from: dialStart)) socksPort=\(socksPort)")
                } catch {
                    progressTask.cancel()
                    relayLog.error("dial: bootstrap threw after \(Self.fmtElapsed(from: dialStart)) — error=\(String(describing: error), privacy: .public)")
                    self.queue.async {
                        self.state = .failed("tor bootstrap failed: \(error)")
                    }
                    return
                }
                progressTask.cancel()
            } else {
                // Tor is already up. `bootstrap()` returns the cached
                // SOCKS port immediately; no progress emission needed.
                do {
                    socksPort = try await TorController.shared.bootstrap()
                    relayLog.debug("dial: bootstrap cached (sub-ms)")
                } catch {
                    relayLog.error("dial: cached-bootstrap unexpectedly threw — \(String(describing: error), privacy: .public)")
                    self.queue.async {
                        self.state = .failed("tor bootstrap failed: \(error)")
                    }
                    return
                }
            }

            // Step 2: warm tor's HS-descriptor cache for this onion
            // BEFORE the SOCKS5 CONNECT goes out. On cold launch
            // this is the load-bearing call — without it, the
            // SOCKS5 CONNECT races tor's directory machinery and
            // loses. On a warm reconnect (descriptor still cached
            // from a previous run) tor returns RECEIVED quickly
            // off its on-disk cache and we add ~1 s of latency to
            // the dial, which is below the user-perceptible
            // threshold. UI state stays at `.connecting` for this
            // phase — surfacing a separate "Fetching service…"
            // bucket is more accurate but noisier than the win is
            // worth.
            self.queue.async {
                self.state = .connecting
            }
            let prepStart = Date()
            do {
                try await TorController.shared.prepareHiddenService(target)
                relayLog.info("dial: prepareHiddenService done after \(Self.fmtElapsed(from: prepStart))")
            } catch {
                relayLog.error("dial: prepareHiddenService failed after \(Self.fmtElapsed(from: prepStart)) — \(String(describing: error), privacy: .public)")
                self.queue.async {
                    self.state = .failed("hs descriptor unavailable: \(error)")
                }
                return
            }

            self.queue.async {
                relayLog.info("dial: opening SOCKS5 connection (total dial elapsed \(Self.fmtElapsed(from: dialStart)))")
                self.openSocksConnection(
                    socksPort: socksPort,
                    targetHost: target,
                    targetPort: targetPort
                )
            }
        }
    }

    /// Same `%.2fs` format as TorController's helper — kept private
    /// to this module so the RelayClient diagnostic lines round-trip
    /// timing data in the same shape `tor.lifecycle` does. Reader
    /// pasting an `app.pizzini.*` filter into Console.app sees one
    /// continuous timeline across the two subsystems.
    private static func fmtElapsed(from start: Date) -> String {
        String(format: "%.2fs", Date().timeIntervalSince(start))
    }

    private func openSocksConnection(
        socksPort: UInt16,
        targetHost: String,
        targetPort: UInt16
    ) {
        guard let nwSocksPort = NWEndpoint.Port(rawValue: socksPort) else {
            state = .failed("invalid SOCKS port \(socksPort)")
            return
        }
        // Loopback IPv4 — tor's SocksPort binds 127.0.0.1 explicitly.
        let conn = NWConnection(
            host: .ipv4(.loopback),
            port: nwSocksPort,
            using: .tcp
        )
        self.connection = conn
        relayLog.debug("socks: TCP open → 127.0.0.1:\(socksPort)")

        conn.stateUpdateHandler = { [weak self] s in
            guard let self else { return }
            switch s {
            case .ready:
                relayLog.debug("socks: TCP ready, starting SOCKS5 handshake")
                self.beginSocksHandshake(on: conn, socksPort: socksPort, targetHost: targetHost, targetPort: targetPort)
            case .waiting(let err):
                relayLog.debug("socks: TCP waiting (\(String(describing: err), privacy: .public))")
                self.state = .connecting
            case .failed(let err):
                relayLog.error("socks: TCP failed — \(String(describing: err), privacy: .public)")
                self.handleSocksFailure(
                    reason: "socks tcp: \(err)",
                    socksPort: socksPort,
                    targetHost: targetHost,
                    targetPort: targetPort
                )
            case .cancelled:
                relayLog.notice("nwconn → .cancelled — setting state=.idle on \(self.lastTargetHost.prefix(12), privacy: .public)…")
                self.state = .idle
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func beginSocksHandshake(
        on conn: NWConnection,
        socksPort: UInt16,
        targetHost: String,
        targetPort: UInt16
    ) {
        // Stage 1: send the NO_AUTH greeting.
        conn.send(content: Socks5.clientGreeting, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if let error {
                self.handleSocksFailure(
                    reason: "socks greeting send: \(error)",
                    socksPort: socksPort,
                    targetHost: targetHost,
                    targetPort: targetPort
                )
                return
            }
            self.readSocksGreetingReply(on: conn, socksPort: socksPort, targetHost: targetHost, targetPort: targetPort)
        })
    }

    private func readSocksGreetingReply(
        on conn: NWConnection,
        socksPort: UInt16,
        targetHost: String,
        targetPort: UInt16
    ) {
        // Greeting reply is exactly 2 bytes. Use minimum=maximum=2 so
        // NWConnection delivers in one chunk.
        conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { [weak self] data, _, _, error in
            guard let self else { return }
            if let error {
                self.handleSocksFailure(
                    reason: "socks greeting reply: \(error)",
                    socksPort: socksPort,
                    targetHost: targetHost,
                    targetPort: targetPort
                )
                return
            }
            guard let data else {
                self.handleSocksFailure(
                    reason: "socks greeting reply: empty",
                    socksPort: socksPort,
                    targetHost: targetHost,
                    targetPort: targetPort
                )
                return
            }
            do {
                _ = try Socks5.parseGreetingReply(data)
            } catch {
                self.handleSocksFailure(
                    reason: "socks greeting reply: \(error)",
                    socksPort: socksPort,
                    targetHost: targetHost,
                    targetPort: targetPort
                )
                return
            }
            self.sendSocksConnect(on: conn, socksPort: socksPort, targetHost: targetHost, targetPort: targetPort)
        }
    }

    private func sendSocksConnect(
        on conn: NWConnection,
        socksPort: UInt16,
        targetHost: String,
        targetPort: UInt16
    ) {
        let req = Socks5.connectRequest(host: targetHost, port: targetPort)
        conn.send(content: req, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if let error {
                self.handleSocksFailure(
                    reason: "socks connect send: \(error)",
                    socksPort: socksPort,
                    targetHost: targetHost,
                    targetPort: targetPort
                )
                return
            }
            self.readSocksConnectReply(on: conn, socksPort: socksPort, targetHost: targetHost, targetPort: targetPort, buffer: Data())
        })
    }

    private func readSocksConnectReply(
        on conn: NWConnection,
        socksPort: UInt16,
        targetHost: String,
        targetPort: UInt16,
        buffer: Data
    ) {
        // CONNECT reply is variable length (10-262 bytes). We can't
        // ask NWConnection for "exactly enough" because we don't know
        // the length until we've parsed past the ATYP byte. Read up to
        // 262 bytes (the absolute maximum) and let the parser tell us
        // when it has a complete frame.
        conn.receive(minimumIncompleteLength: 1, maximumLength: 262) { [weak self] data, _, _, error in
            guard let self else { return }
            if let error {
                self.handleSocksFailure(
                    reason: "socks connect reply: \(error)",
                    socksPort: socksPort,
                    targetHost: targetHost,
                    targetPort: targetPort
                )
                return
            }
            var buf = buffer
            if let data, !data.isEmpty {
                buf.append(data)
            }
            do {
                switch try Socks5.tryParseConnectReply(buf) {
                case .complete(let consumed):
                    // Anything past `consumed` belongs to the relay
                    // stream (the relay's HELLO is client-initiated,
                    // so the proxy shouldn't have any post-reply bytes
                    // yet — but seed the relay buffer defensively).
                    let trailing = buf.dropFirst(consumed)
                    if !trailing.isEmpty {
                        self.readBuffer.append(trailing)
                    }
                    relayLog.info("socks: REP=0x00 success — sending HELLO")
                    self.sendHello()
                    if let token = self.pushToken {
                        self.sendRegisterPush(token: token)
                    }
                    self.state = .connected
                    self.scheduleRead()
                case .incomplete:
                    self.readSocksConnectReply(on: conn, socksPort: socksPort, targetHost: targetHost, targetPort: targetPort, buffer: buf)
                }
            } catch {
                self.handleSocksFailure(
                    reason: "socks connect reply: \(error)",
                    socksPort: socksPort,
                    targetHost: targetHost,
                    targetPort: targetPort
                )
            }
        }
    }

    /// Centralised failure-handling for the .onion SOCKS5 path.
    /// First-time dials against a brand-new onion routinely fail
    /// because tor hasn't yet fetched the hidden-service descriptor
    /// — HSDir lookup + rendezvous setup is 10-30 s on the cold path
    /// while tor's internal timeout for the SOCKS5 request is much
    /// shorter, so tor returns a non-zero REP byte (or the kernel
    /// returns ECONNREFUSED if the SOCKS connection gets torn down)
    /// before the descriptor cache is warm. Auto-retry with a fixed
    /// 5 s back-off up to `maxSocksRetries` times — by then tor has
    /// the descriptor cached and the subsequent SOCKS5 dial
    /// succeeds in well under a second.
    ///
    /// Must run on `queue` (every call-site already does).
    private func handleSocksFailure(
        reason: String,
        socksPort: UInt16,
        targetHost: String,
        targetPort: UInt16
    ) {
        // Cancel the dead SOCKS connection so its stateUpdateHandler
        // doesn't fire `.failed` AGAIN from inside a retry attempt,
        // AND clear the handler first so the in-flight `.cancelled`
        // callback that NWConnection.cancel() will deliver cannot
        // stamp `state = .idle` over the `.connecting` we set below.
        // NWConnection retains the handler closure; nilling it
        // detaches the callback path before we trigger the
        // cancellation that would otherwise enqueue a final
        // `.cancelled` event on `queue`.
        if let conn = connection {
            conn.stateUpdateHandler = nil
            conn.cancel()
        }
        connection = nil

        if socksRetries < Self.maxSocksRetries {
            socksRetries += 1
            // Stay in `.connecting` rather than flapping to `.failed`
            // and back — the UI shouldn't show an error during what
            // is effectively a single ongoing connection attempt.
            state = .connecting
            let attempt = socksRetries
            relayLog.notice("socks: retry \(attempt)/\(Self.maxSocksRetries) in \(Int(Self.socksRetryDelay))s — \(reason, privacy: .public)")
            queue.asyncAfter(deadline: .now() + Self.socksRetryDelay) { [weak self] in
                guard let self else { return }
                self.openSocksConnection(
                    socksPort: socksPort,
                    targetHost: targetHost,
                    targetPort: targetPort
                )
            }
            return
        }
        // Out of retries — surface the last failure to the host so the
        // user-facing retry timer / Reconnect button can pick it up.
        relayLog.error("socks: out of retries — surfacing .failed with reason=\(reason, privacy: .public)")
        state = .failed(reason)
    }

    public func disconnect() {
        // Detach the stateUpdateHandler before cancellation. Without
        // this, NWConnection.cancel() enqueues a `.cancelled` state
        // update on `queue`; that callback would run AFTER a
        // subsequent `connect()` set `state = .connecting`, and the
        // handler's `case .cancelled: state = .idle` line would
        // stamp `.idle` over the freshly-started connection's
        // `.connecting`. Clearing the handler first severs the
        // notification path so we don't mutate stale state.
        if let conn = connection {
            conn.stateUpdateHandler = nil
            conn.cancel()
        }
        connection = nil
        readBuffer.removeAll()
    }

    /// SEND v2 — sealed envelope, sender-chosen TTL (clamped to 7 days
    /// by the relay), optional Phase-3 token. `from_id` no longer rides
    /// at the wire level; it's inside the cert in the sealed envelope.
    public func sendSealed(
        toPeer to: Data,
        sealedCiphertext: Data,
        ttlSeconds: UInt32,
        token: Data = Data()
    ) {
        writeRoutedSealed(
            frameType: Self.frameTypeSend,
            toPeer: to,
            sealedCiphertext: sealedCiphertext,
            ttlSeconds: ttlSeconds,
            token: token,
        )
    }

    /// ACK frame — same shape as SEND v2. The sealed envelope's inner
    /// plaintext should be `RelayClient.ackMarker || message_id`.
    public func sendAck(
        toPeer to: Data,
        sealedCiphertext: Data,
        ttlSeconds: UInt32,
        token: Data = Data()
    ) {
        writeRoutedSealed(
            frameType: Self.frameTypeAck,
            toPeer: to,
            sealedCiphertext: sealedCiphertext,
            ttlSeconds: ttlSeconds,
            token: token,
        )
    }

    private func writeRoutedSealed(
        frameType: UInt8,
        toPeer to: Data,
        sealedCiphertext: Data,
        ttlSeconds: UInt32,
        token: Data,
    ) {
        guard let connection, state == .connected else { return }
        let ttl = min(ttlSeconds, Self.maxTTLSeconds)
        var payload = Data()
        payload.append(frameType)
        appendU16Blob(&payload, to)
        var ttlBE = ttl.bigEndian
        withUnsafeBytes(of: &ttlBE) { payload.append(contentsOf: $0) }
        appendU16Blob(&payload, token)
        payload.append(sealedCiphertext)
        writeFrame(payload, on: connection)
    }

    public func requestBundle(fromPeer to: Data, hashcashNonce: UInt64) {
        guard let connection, state == .connected else { return }
        var payload = Data()
        payload.append(Self.frameTypeBundleRequest)
        appendU16Blob(&payload, to)
        appendU16Blob(&payload, myIdentity)
        var nonceBE = hashcashNonce.bigEndian
        withUnsafeBytes(of: &nonceBE) { payload.append(contentsOf: $0) }
        writeFrame(payload, on: connection)
    }

    public func sendBundle(toPeer to: Data, bundle: Data) {
        guard let connection, state == .connected else { return }
        var payload = Data()
        payload.append(Self.frameTypeBundleResponse)
        appendU16Blob(&payload, to)
        appendU16Blob(&payload, myIdentity)
        payload.append(bundle)
        writeFrame(payload, on: connection)
    }

    /// REGISTER_CHAIN: tell the relay about a hash-chain root we just
    /// minted. The relay binds this chain to our HELLO-authenticated
    /// peer_id, then validates future v2 SENDs to us against the
    /// matching `(chain_id, root)`. Body layout matches the relay's
    /// `parse_register_chain`:
    ///   `chain_id(16) ‖ root(32) ‖ length(4 BE)`.
    /// Frame type 12, paralleling `frameTypeRegisterPush`.
    public func sendRegisterChain(chainID: Data, root: Data, length: UInt32) {
        precondition(chainID.count == 16, "chainID must be 16 bytes")
        precondition(root.count == 32, "root must be 32 bytes")
        guard let connection, state == .connected else { return }
        var payload = Data()
        payload.append(Self.frameTypeRegisterChain)
        payload.append(chainID)
        payload.append(root)
        var lengthBE = length.bigEndian
        withUnsafeBytes(of: &lengthBE) { payload.append(contentsOf: $0) }
        writeFrame(payload, on: connection)
    }

    /// TOKEN_ISSUE: ship 1024 fresh delivery tokens minted for `to` so
    /// they can use them as the rate-limit gate when sending TO us.
    public func sendTokenIssue(toPeer to: Data, tokens: [Data]) {
        guard let connection, state == .connected else { return }
        var payload = Data()
        payload.append(Self.frameTypeTokenIssue)
        appendU16Blob(&payload, to)
        appendU16Blob(&payload, myIdentity)
        var countBE = UInt32(tokens.count).bigEndian
        withUnsafeBytes(of: &countBE) { payload.append(contentsOf: $0) }
        for t in tokens {
            payload.append(t)
        }
        writeFrame(payload, on: connection)
    }

    /// USP #1: ask the relay which build it is running. The relay
    /// replies asynchronously via `didReceiveStatus`. The query is
    /// idempotent — issuing it on every reconnect is the recommended
    /// pattern (the Settings panel reads the latest snapshot).
    public func requestStatus() {
        guard let connection, state == .connected else { return }
        var payload = Data()
        payload.append(Self.frameTypeStatusRequest)
        // Empty body — frame-type byte is the entire payload. The
        // relay tolerates trailing bytes for forward compatibility;
        // we don't send any so an older relay implementation can't
        // be fed a length-prefix that desynchronises its parser.
        writeFrame(payload, on: connection)
    }

    /// Publishes our APNs device token so the relay can wake us when a
    /// SEND lands while we're disconnected. Token is cached and
    /// re-sent automatically after a reconnect.
    public func registerPush(token: Data) {
        pushToken = token
        let st = state
        relayLog.notice("registerPush called on \(self.lastTargetHost.prefix(12), privacy: .public)… (state=\(String(describing: st), privacy: .public), token=\(token.count) bytes)")
        if state == .connected {
            sendRegisterPush(token: token)
        }
    }

    /// Release this relay's claim on our APNs token. Sent by the
    /// host when a different relay is elected push-primary so the
    /// previous primary's persistent push-token store drops the
    /// entry. Without DEREGISTER, after every reshuffle every
    /// historical primary keeps emitting duplicate APNs wake-ups
    /// for every inbound SEND until the relay-side TTL purge
    /// (30 days). Idempotent both client- and server-side; safe
    /// to send even if we never registered. No-op if not connected
    /// — the relay has no record either way once the socket dropped.
    public func deregisterPush() {
        pushToken = nil
        let st = state
        relayLog.notice("deregisterPush called on \(self.lastTargetHost.prefix(12), privacy: .public)… (state=\(String(describing: st), privacy: .public), connection=\(self.connection != nil, privacy: .public))")
        guard state == .connected, let connection else { return }
        var payload = Data()
        payload.append(Self.frameTypeDeregisterPush)
        writeFrame(payload, on: connection)
    }

    private func sendRegisterPush(token: Data) {
        guard let connection else { return }
        var payload = Data()
        payload.append(Self.frameTypeRegisterPush)
        appendU16Blob(&payload, token)
        writeFrame(payload, on: connection)
    }

    private func sendHello() {
        guard let connection else { return }
        // F-203: build the possession-proof payload and sign with the
        // IdentityKey private half before assembling the wire frame.
        let timestampSecs = UInt64(Date().timeIntervalSince1970)
        var nonce = Data(count: Self.helloNonceLen)
        _ = nonce.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, buf.count, buf.baseAddress!)
        }
        // F-NEW-101: the `signer` closure now signs via the domain-
        // separated v2 FFI, which prepends `u16_be(tag_len) || tag`
        // to the payload internally. The relay's verify reconstructs
        // the same bytes via `build_hello_signing_payload`.
        var signingPayload = Data()
        signingPayload.append(myIdentity)
        signingPayload.append(myDeliveryTokenVerifyKey)
        var tsBE = timestampSecs.bigEndian
        withUnsafeBytes(of: &tsBE) { signingPayload.append(contentsOf: $0) }
        signingPayload.append(nonce)
        guard let signature = signer(signingPayload), signature.count == 64 else {
            // Without a valid signature the relay will drop the HELLO,
            // and a half-open TCP connection is worse than a clean
            // failure. Mark .failed so the UI surfaces the error.
            state = .failed("HELLO signing failed (identity key unavailable)")
            return
        }

        var payload = Data()
        payload.append(Self.frameTypeHello)
        payload.append(Self.protocolVersion)
        appendU16Blob(&payload, myIdentity)
        appendU16Blob(&payload, myDeliveryTokenVerifyKey)
        withUnsafeBytes(of: &tsBE) { payload.append(contentsOf: $0) }
        appendU16Blob(&payload, nonce)
        appendU16Blob(&payload, signature)
        writeFrame(payload, on: connection)
    }

    private func writeFrame(_ payload: Data, on connection: NWConnection) {
        var frame = Data(capacity: 4 + payload.count)
        let len = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: len) { frame.append(contentsOf: $0) }
        frame.append(payload)
        // USP #4: every outgoing frame — real or cover — pushes
        // `lastFrameSentAt` forward so the cover timer skips
        // emission for at least `coverInterval` afterwards.
        lastFrameSentAt = Date()
        connection.send(content: frame, completion: .contentProcessed { [weak self] error in
            if let error {
                let host = self?.lastTargetHost.prefix(12) ?? ""
                relayLog.error("writeFrame send error on \(host, privacy: .public)…: \(String(describing: error), privacy: .public)")
                self?.state = .failed("\(error)")
            }
        })
    }

    // ─── USP #4: cover-traffic pacing ─────────────────────────────────

    private func startCoverTimer() {
        // Idempotent re-arm. Reconnect → state cycles through
        // .connecting → .connected; the second entry must not stack
        // a duplicate timer.
        stopCoverTimer()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        // Half-interval cadence so a real send that lands just
        // before the next deadline doesn't push the next cover by
        // an extra full interval. With check-and-skip semantics,
        // this gives an effective worst-case gap of
        // `coverInterval + coverInterval/2` between any two
        // outgoing frames — close enough to "uniform" for the
        // timing-mask purpose.
        let cadence = max(1, Int(Self.coverInterval / 2))
        timer.schedule(
            deadline: .now() + .seconds(cadence),
            repeating: .seconds(cadence),
        )
        timer.setEventHandler { [weak self] in
            self?.maybeSendCover()
        }
        timer.resume()
        coverTimer = timer
    }

    private func stopCoverTimer() {
        coverTimer?.cancel()
        coverTimer = nil
    }

    /// Called on the cover-timer cadence. Emits a COVER frame only
    /// when the channel has been silent for at least
    /// `coverInterval`, so an active conversation produces zero
    /// cover-traffic overhead.
    private func maybeSendCover() {
        guard state == .connected, let connection else { return }
        let elapsed = Date().timeIntervalSince(lastFrameSentAt)
        guard elapsed >= Self.coverInterval else { return }
        var payload = Data(capacity: 1 + Self.coverPayloadLen)
        payload.append(Self.frameTypeCover)
        // Random body. SecRandomCopyBytes returns errSecSuccess on
        // every supported iOS device; a hypothetical failure is
        // benign — we'd just send a zero-filled frame, which the
        // relay accepts (it doesn't validate the body), and the
        // timing-mask property still holds.
        var random = Data(count: Self.coverPayloadLen)
        _ = random.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, buf.count, buf.baseAddress!)
        }
        payload.append(random)
        writeFrame(payload, on: connection)
    }

    private func scheduleRead() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error {
                self.state = .failed("\(error)")
                return
            }
            if let data, !data.isEmpty {
                self.readBuffer.append(data)
                self.drainFrames()
            }
            if isComplete {
                relayLog.notice("receive isComplete=true — peer sent FIN — setting state=.idle on \(self.lastTargetHost.prefix(12), privacy: .public)… (buffer=\(self.readBuffer.count) bytes pending)")
                self.state = .idle
                return
            }
            self.scheduleRead()
        }
    }

    private func drainFrames() {
        while readBuffer.count >= 4 {
            let lenBytes = readBuffer.prefix(4)
            // loadUnaligned: Data slices may not honour 4-byte alignment.
            let len = lenBytes.withUnsafeBytes { ptr -> UInt32 in
                let raw = ptr.loadUnaligned(as: UInt32.self)
                return UInt32(bigEndian: raw)
            }
            if len > Self.maxFrameBytes {
                state = .failed("frame too large: \(len)")
                return
            }
            let total = 4 + Int(len)
            if readBuffer.count < total { return }
            let payload = readBuffer.subdata(in: 4..<total)
            readBuffer.removeSubrange(0..<total)
            handleFrame(payload)
        }
    }

    private func handleFrame(_ payload: Data) {
        guard let type = payload.first else { return }
        var cursor = Cursor(payload.dropFirst())
        let delegate = self.delegate
        let client = self
        switch type {
        case Self.frameTypeSend, Self.frameTypeAck:
            // SEND v2 / ACK: u16 to + u32 ttl + u16 token + sealed.
            // `to` should equal myIdentity (relay routed by it). We
            // re-read but don't validate — a malicious relay forwarding
            // someone else's frame to us still has to clear the
            // sealed-sender contact gate at the next layer.
            guard cursor.u16Blob() != nil else { return }
            guard cursor.skip(4) else { return }     // ttl_seconds
            guard cursor.u16Blob() != nil else { return } // token (Phase 3)
            let sealed = Data(cursor.rest())
            if type == Self.frameTypeSend {
                DispatchQueue.main.async {
                    delegate?.relayClient(client, didReceiveSealedSend: sealed)
                }
            } else {
                DispatchQueue.main.async {
                    delegate?.relayClient(client, didReceiveAck: sealed)
                }
            }
        case Self.frameTypeBundleRequest:
            guard cursor.u16Blob() != nil else { return }
            guard let from = cursor.u16Blob() else { return }
            DispatchQueue.main.async {
                delegate?.relayClient(client, didReceiveBundleRequestFrom: from)
            }
        case Self.frameTypeBundleResponse:
            guard cursor.u16Blob() != nil else { return }
            guard let from = cursor.u16Blob() else { return }
            let bundle = Data(cursor.rest())
            DispatchQueue.main.async {
                delegate?.relayClient(client, didReceiveBundleFrom: from, bundle: bundle)
            }
        case Self.frameTypeStatusResponse:
            // USP #1. Payload after frame-type byte:
            //   u8  protocol_version
            //   u8  git_dirty                  (0 clean / 1 dirty / 2 unknown)
            //   u16 crate_version_len + bytes
            //   u16 git_sha_len + bytes
            //   u8  binary_sha256_len          (always statusBinHashLen)
            //   [N] binary_sha256
            guard let protocolVersion = cursor.u8() else { return }
            guard let gitDirty = cursor.u8() else { return }
            guard let crateBytes = cursor.u16Blob() else { return }
            guard let shaBytes = cursor.u16Blob() else { return }
            guard let hashLen = cursor.u8(), Int(hashLen) == Self.statusBinHashLen else { return }
            guard let binarySha256 = cursor.take(Int(hashLen)) else { return }
            // Parsing is intentionally strict — a truncated /
            // malformed STATUS_RESPONSE is a relay implementation
            // bug, not a value the host should attempt to display.
            let status = RelayStatus(
                protocolVersion: protocolVersion,
                gitDirty: gitDirty,
                crateVersion: String(data: crateBytes, encoding: .utf8) ?? "",
                gitSha: String(data: shaBytes, encoding: .utf8) ?? "",
                binarySha256: binarySha256,
            )
            DispatchQueue.main.async {
                delegate?.relayClient(client, didReceiveStatus: status)
            }
        case Self.frameTypeTokenIssue:
            guard cursor.u16Blob() != nil else { return }
            guard let from = cursor.u16Blob() else { return }
            guard let count = cursor.u32() else { return }
            // **Cap `count` against the actual remaining buffer**
            // before `reserveCapacity` (F-NEW-201). The wire field
            // is a u32; a malicious relay (or paired peer) can ship
            // `count = u32::MAX` in a 79-byte frame and we'd attempt
            // a ~64 GiB allocation, crashing the app via iOS jetsam.
            // Each token is `deliveryTokenLen` bytes, so the maximum
            // valid `count` is bounded by `cursor.buf.count / 84`.
            let maxValidCount = cursor.buf.count / Self.deliveryTokenLen
            guard Int(count) <= maxValidCount else { return }
            var tokens: [Data] = []
            tokens.reserveCapacity(Int(count))
            for _ in 0..<count {
                guard let tok = cursor.take(Self.deliveryTokenLen) else { return }
                tokens.append(tok)
            }
            DispatchQueue.main.async {
                delegate?.relayClient(client, didReceiveTokenIssueFrom: from, tokens: tokens)
            }
        default:
            break
        }
    }

    private func appendU16Blob(_ out: inout Data, _ blob: Data) {
        let len = UInt16(blob.count).bigEndian
        withUnsafeBytes(of: len) { out.append(contentsOf: $0) }
        out.append(blob)
    }
}

private struct Cursor {
    var buf: Data
    init(_ buf: Data) { self.buf = buf }
    mutating func u8() -> UInt8? {
        guard let b = buf.first else { return nil }
        buf = buf.dropFirst()
        return b
    }
    mutating func u16() -> UInt16? {
        guard buf.count >= 2 else { return nil }
        // loadUnaligned: Data slice offsets are arbitrary — `load` would trap.
        let v = buf.prefix(2).withUnsafeBytes { ptr in
            UInt16(bigEndian: ptr.loadUnaligned(as: UInt16.self))
        }
        buf = buf.dropFirst(2)
        return v
    }
    mutating func u16Blob() -> Data? {
        guard let n = u16() else { return nil }
        guard buf.count >= Int(n) else { return nil }
        let blob = buf.prefix(Int(n))
        buf = buf.dropFirst(Int(n))
        return Data(blob)
    }
    mutating func skip(_ n: Int) -> Bool {
        guard buf.count >= n else { return false }
        buf = buf.dropFirst(n)
        return true
    }
    mutating func u32() -> UInt32? {
        guard buf.count >= 4 else { return nil }
        let v = buf.prefix(4).withUnsafeBytes { ptr in
            UInt32(bigEndian: ptr.loadUnaligned(as: UInt32.self))
        }
        buf = buf.dropFirst(4)
        return v
    }
    mutating func take(_ n: Int) -> Data? {
        guard buf.count >= n else { return nil }
        let blob = buf.prefix(n)
        buf = buf.dropFirst(n)
        return Data(blob)
    }
    mutating func rest() -> Data {
        let r = buf
        buf = Data()
        return r
    }
}
