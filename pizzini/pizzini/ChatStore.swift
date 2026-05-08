import Foundation
import PizziniCryptoCore
import SwiftUI

enum ChatBubbleSide: Sendable {
    case me, peer
}

enum ChatMessageKind: Sendable {
    case preKey
    case whisper
    case system
}

struct ChatLogEntry: Identifiable, Sendable {
    let id = UUID()
    let side: ChatBubbleSide
    let text: String
    let kind: ChatMessageKind
    let bytes: Int
    let timestamp = Date()
}

/// One coordinator: owns the libsignal Session, the relay connection, and
/// the per-peer message log. The UI binds to its `@Observable` state.
@MainActor
@Observable
final class ChatStore: NSObject {
    // Persisted (Keychain) — survives launches.
    private static let identityAccount = "long-term-identity"
    private static let relayAccount = "relay-host"
    private static let defaultRelayHost = "127.0.0.1"
    private static let relayPort: UInt16 = 7777

    var relayState: RelayClient.State = .idle
    var relayHost: String = ""
    private(set) var myCard: ContactCard?
    private(set) var peer: Data?
    private(set) var sessionEstablished = false
    private(set) var log: [ChatLogEntry] = []
    private(set) var initError: String?

    private var session: Session?
    private var relay: RelayClient?

    override init() {
        super.init()
        do {
            let session = try resumeOrCreateSession()
            self.session = session
            let id = try session.identityPublic()
            let host = loadRelayHost() ?? Self.defaultRelayHost
            self.relayHost = host
            self.myCard = ContactCard(peerId: id, host: host, port: Self.relayPort)
            connectRelay()
        } catch {
            self.initError = String(describing: error)
        }
    }

    // MARK: - Identity / setup

    private func resumeOrCreateSession() throws -> Session {
        if let seed = Keychain.read(account: Self.identityAccount) {
            return try Session(identitySeed: seed)
        }
        let s = try Session()
        let bytes = try s.identityKeypairBytes()
        _ = Keychain.write(bytes, account: Self.identityAccount)
        return s
    }

    private func loadRelayHost() -> String? {
        guard let data = Keychain.read(account: Self.relayAccount) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func setRelayHost(_ host: String) {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        relayHost = trimmed
        if let bytes = trimmed.data(using: .utf8) {
            _ = Keychain.write(bytes, account: Self.relayAccount)
        }
        if let myId = try? session?.identityPublic() {
            myCard = ContactCard(peerId: myId, host: trimmed, port: Self.relayPort)
        }
        connectRelay()
    }

    func resetIdentity() {
        Keychain.delete(account: Self.identityAccount)
        log.removeAll()
        peer = nil
        sessionEstablished = false
        do {
            session = try resumeOrCreateSession()
            if let id = try session?.identityPublic() {
                myCard = ContactCard(peerId: id, host: relayHost, port: Self.relayPort)
            }
            relay?.disconnect()
            connectRelay()
        } catch {
            initError = String(describing: error)
        }
    }

    // MARK: - Relay

    private func connectRelay() {
        guard let session, let myCard else {
            NSLog("[pizzini] connectRelay: skipped (no session or card)")
            return
        }
        relay?.disconnect()
        let myId: Data
        do { myId = try session.identityPublic() } catch {
            NSLog("[pizzini] connectRelay: identityPublic failed: \(error)")
            return
        }
        let client = RelayClient(myIdentity: myId)
        client.delegate = self
        self.relay = client
        NSLog("[pizzini] connecting to \(myCard.host):\(Self.relayPort)")
        client.connect(to: myCard.host, port: Self.relayPort)
    }

    // MARK: - Contact pairing

    func acceptScannedCard(_ raw: String) {
        guard let card = ContactCard.decode(raw) else {
            appendSystem("Could not decode QR: \(raw)")
            return
        }
        guard let session else { return }
        // Treat the scanned card's host as authoritative — it points at
        // whichever relay the peer is on. For dev, both peers connect to
        // the same Mac, so this should already match relayHost.
        if card.host != relayHost {
            appendSystem("Switching relay to \(card.host) (from peer card)")
            setRelayHost(card.host)
        }
        peer = card.peerId
        sessionEstablished = false
        appendSystem("Scanned peer \(short(card.peerId)). Requesting bundle…")
        guard relayState == .connected else {
            appendSystem("Relay not connected yet. Will retry once HELLO completes.")
            return
        }
        relay?.requestBundle(fromPeer: card.peerId)
        _ = session
    }

    func send(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let session, let peer, let relay else { return }
        guard sessionEstablished else {
            appendSystem("Session not established yet.")
            return
        }
        do {
            let result = try session.encrypt(
                peerIdentity: peer,
                plaintext: Data(trimmed.utf8)
            )
            relay.send(
                toPeer: peer,
                ciphertext: result.ciphertext,
                isPreKey: result.messageType == .preKey
            )
            log.append(
                ChatLogEntry(
                    side: .me,
                    text: trimmed,
                    kind: result.messageType == .preKey ? .preKey : .whisper,
                    bytes: result.ciphertext.count
                )
            )
        } catch {
            appendSystem("Encrypt failed: \(error)")
        }
    }

    // MARK: - Helpers

    private func appendSystem(_ text: String) {
        log.append(ChatLogEntry(side: .me, text: text, kind: .system, bytes: 0))
    }

    private func short(_ data: Data) -> String {
        let head = data.prefix(4).map { String(format: "%02x", $0) }.joined()
        return head + "…"
    }
}

extension ChatStore: RelayClientDelegate {
    nonisolated func relayClient(_ client: RelayClient, didChange state: RelayClient.State) {
        Task { @MainActor in
            self.relayState = state
            if state == .connected, let peer = self.peer, !self.sessionEstablished {
                self.appendSystem("Relay reconnected. Re-requesting bundle.")
                client.requestBundle(fromPeer: peer)
            }
        }
    }

    nonisolated func relayClient(
        _ client: RelayClient,
        didReceiveFrom fromPeer: Data,
        ciphertext: Data,
        isPreKey: Bool
    ) {
        Task { @MainActor in
            guard let session = self.session else { return }
            // First contact via incoming PreKey: the peer initiated, so we
            // adopt them as our peer and store the contact.
            if self.peer == nil {
                self.peer = fromPeer
                self.appendSystem("Incoming PreKey from \(self.short(fromPeer)) — adopting as peer.")
            }
            do {
                let pt = try session.decrypt(
                    peerIdentity: fromPeer,
                    ciphertext: ciphertext,
                    isPreKey: isPreKey
                )
                self.sessionEstablished = true
                let text = String(data: pt, encoding: .utf8) ?? "<\(pt.count) non-utf8 bytes>"
                self.log.append(
                    ChatLogEntry(
                        side: .peer,
                        text: text,
                        kind: isPreKey ? .preKey : .whisper,
                        bytes: ciphertext.count
                    )
                )
            } catch {
                self.appendSystem("Decrypt failed: \(error)")
            }
        }
    }

    nonisolated func relayClient(_ client: RelayClient, didReceiveBundleRequestFrom fromPeer: Data) {
        Task { @MainActor in
            guard let session = self.session else { return }
            do {
                let bundle = try session.publishBundle()
                client.sendBundle(toPeer: fromPeer, bundle: bundle)
                self.appendSystem("Sent bundle to \(self.short(fromPeer)).")
            } catch {
                self.appendSystem("Bundle generation failed: \(error)")
            }
        }
    }

    nonisolated func relayClient(
        _ client: RelayClient,
        didReceiveBundleFrom fromPeer: Data,
        bundle: Data
    ) {
        Task { @MainActor in
            guard let session = self.session else { return }
            do {
                try session.initiateSession(peerIdentity: fromPeer, bundle: bundle)
                if self.peer == nil { self.peer = fromPeer }
                self.sessionEstablished = true
                self.appendSystem("PQXDH complete with \(self.short(fromPeer)). You can chat.")
            } catch {
                self.appendSystem("initiateSession failed: \(error)")
            }
        }
    }
}
