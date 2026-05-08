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
    /// A SEND frame arrived from `fromPeer`. `ciphertext` + `isPreKey` are
    /// what `Session.decrypt` needs.
    func relayClient(
        _ client: RelayClient,
        didReceiveFrom fromPeer: Data,
        ciphertext: Data,
        isPreKey: Bool
    )
}

public final class RelayClient: @unchecked Sendable {
    public enum State: Sendable, Equatable {
        case idle
        case connecting
        case connected
        case failed(String)
    }

    private static let frameTypeHello: UInt8 = 1
    private static let frameTypeSend: UInt8 = 2
    private static let maxFrameBytes: UInt32 = 1024 * 1024

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
                self.state = .connected
                self.scheduleRead()
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

    public func send(toPeer to: Data, ciphertext: Data, isPreKey: Bool) {
        guard let connection, state == .connected else { return }
        var payload = Data()
        payload.append(Self.frameTypeSend)
        appendU16Blob(&payload, to)
        appendU16Blob(&payload, myIdentity)
        payload.append(isPreKey ? 1 : 0)
        payload.append(ciphertext)
        writeFrame(payload, on: connection)
    }

    private func sendHello() {
        guard let connection else { return }
        var payload = Data()
        payload.append(Self.frameTypeHello)
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
            let len = lenBytes.withUnsafeBytes { ptr -> UInt32 in
                let raw = ptr.load(as: UInt32.self)
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
        switch type {
        case Self.frameTypeSend:
            var cursor = Cursor(payload.dropFirst())
            guard
                let to = cursor.u16Blob(),
                let from = cursor.u16Blob(),
                let isPreByte = cursor.u8()
            else { return }
            // We're the recipient — `to` should equal myIdentity, but the
            // relay already routed by it. No need to re-check; caller
            // will surface unexpected senders via libsignal trust failures.
            _ = to
            let ciphertext = Data(cursor.rest())
            let delegate = self.delegate
            let client = self
            DispatchQueue.main.async {
                delegate?.relayClient(
                    client,
                    didReceiveFrom: from,
                    ciphertext: ciphertext,
                    isPreKey: isPreByte != 0
                )
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
        let v = buf.prefix(2).withUnsafeBytes { ptr in
            UInt16(bigEndian: ptr.load(as: UInt16.self))
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
    mutating func rest() -> Data {
        let r = buf
        buf = Data()
        return r
    }
}
