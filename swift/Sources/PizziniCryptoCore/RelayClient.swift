// Swift counterpart to the Rust dev relay (relay/src/main.rs). Speaks the
// same length-prefixed framing: 4-byte BE length + payload.
//
// Frames are dumb byte shuttles. Everything ferried inside is already
// libsignal-encrypted; this layer doesn't touch crypto.
//
// DEV ONLY — sim ↔ phone over LAN. Production transport is Tor.

import Foundation
import Network

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
}

public final class RelayClient: @unchecked Sendable {
    public enum State: Sendable, Equatable {
        case idle
        case connecting
        case connected
        case failed(String)
    }

    /// On-the-wire protocol version negotiated in HELLO. Bumped from 1
    /// when sealed-sender SEND/ACK landed; v1 relays/clients reject.
    public static let protocolVersion: UInt8 = 2
    /// Inner-plaintext content marker for ACK envelopes — matches the
    /// "ack: <16-byte message_id>" convention from Phase 4.
    public static let ackMarker: Data = Data("ack:".utf8)
    private static let frameTypeHello: UInt8 = 1
    private static let frameTypeSend: UInt8 = 2
    private static let frameTypeBundleRequest: UInt8 = 3
    private static let frameTypeBundleResponse: UInt8 = 4
    private static let frameTypeRegisterPush: UInt8 = 5
    private static let frameTypeAck: UInt8 = 6
    private static let maxFrameBytes: UInt32 = 1024 * 1024
    /// Hard ceiling on the per-message TTL the sender can request; the
    /// relay clamps to this server-side too. 7 days.
    public static let maxTTLSeconds: UInt32 = 7 * 24 * 60 * 60

    public weak var delegate: RelayClientDelegate?
    public private(set) var state: State = .idle {
        didSet {
            guard oldValue != state else { return }
            let snapshot = state
            let delegate = self.delegate
            let client = self
            queue.async {
                delegate?.relayClient(client, didChange: snapshot)
            }
        }
    }

    private let queue = DispatchQueue(label: "app.pizzini.relay")
    private let myIdentity: Data
    private var connection: NWConnection?
    private var readBuffer = Data()
    /// Latest APNs device token. Cached so we automatically re-register
    /// after a reconnect (the relay's push-token map is in-memory; a
    /// relay restart wipes it).
    private var pushToken: Data?

    public init(myIdentity: Data) {
        self.myIdentity = myIdentity
    }

    public func connect(to host: String, port: UInt16) {
        disconnect()
        state = .connecting
        let endpoint = NWEndpoint.Host(host)
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            state = .failed("invalid port \(port)")
            return
        }
        let params = NWParameters.tcp
        let conn = NWConnection(host: endpoint, port: nwPort, using: params)
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

    public func disconnect() {
        connection?.cancel()
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

    public func requestBundle(fromPeer to: Data) {
        guard let connection, state == .connected else { return }
        var payload = Data()
        payload.append(Self.frameTypeBundleRequest)
        appendU16Blob(&payload, to)
        appendU16Blob(&payload, myIdentity)
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

    /// Publishes our APNs device token so the relay can wake us when a
    /// SEND lands while we're disconnected. Token is cached and
    /// re-sent automatically after a reconnect.
    public func registerPush(token: Data) {
        pushToken = token
        if state == .connected {
            sendRegisterPush(token: token)
        }
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
        var payload = Data()
        payload.append(Self.frameTypeHello)
        payload.append(Self.protocolVersion)
        appendU16Blob(&payload, myIdentity)
        writeFrame(payload, on: connection)
    }

    private func writeFrame(_ payload: Data, on connection: NWConnection) {
        var frame = Data(capacity: 4 + payload.count)
        let len = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: len) { frame.append(contentsOf: $0) }
        frame.append(payload)
        connection.send(content: frame, completion: .contentProcessed { [weak self] error in
            if let error {
                self?.state = .failed("\(error)")
            }
        })
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
    mutating func rest() -> Data {
        let r = buf
        buf = Data()
        return r
    }
}
