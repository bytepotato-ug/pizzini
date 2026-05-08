import Foundation
import PizziniCryptoCore
import SwiftUI
import UserNotifications

/// Coordinator: owns the libsignal `Session`, the `RelayClient`, the
/// `AppState` (relay host + contacts), and the rules for who's allowed to
/// talk to us.
///
/// Trust model: messages are only accepted from peers whose QR has been
/// scanned (i.e. identity_pub is in `state.contacts`). Inbound frames from
/// unknown identities are dropped before reaching libsignal. The Rust
/// store mirrors the peers list via `registerPeer` / `forgetPeer` so the
/// trusted set survives `serialize`/`init(serialized:)`.
@MainActor
@Observable
final class ChatStore: NSObject {
    /// SwiftUI's `@State private var store = ChatStore()` autoclosure can
    /// fire multiple times before the framework settles which instance to
    /// retain. With a singleton, every fire returns the same coordinator —
    /// `init` runs exactly once, so we open exactly one relay connection.
    static let shared = ChatStore()

    private static let relayPort: UInt16 = 7777

    // Public, observable.
    var relayState: RelayClient.State = .idle
    private(set) var state: AppState
    private(set) var initError: String?
    var myCard: ContactCard? {
        guard let myId = myIdentityPublicCached else { return nil }
        return ContactCard(peerId: myId, host: state.relayHost, port: Self.relayPort)
    }

    // Internal.
    private var session: Session?
    private var relay: RelayClient?
    private var myIdentityPublicCached: Data?

    override init() {
        self.state = Storage.loadAppState()
        super.init()
        do {
            let s = try Storage.loadOrCreateSession()
            self.session = s
            self.myIdentityPublicCached = try s.identityPublic()
            connectRelay()
        } catch {
            self.initError = String(describing: error)
        }
        requestBadgeAuthorization()
        refreshAppBadge()
    }

    /// First-launch ask for the badge bit only. Sound/alert come later
    /// when push notifications land.
    private func requestBadgeAuthorization() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.badge]) { _, _ in }
    }

    // MARK: - Relay

    private func connectRelay() {
        guard let session else { return }
        // Clear the OLD client's delegate before disconnecting — its
        // NWConnection cancellation fires asynchronously, and we don't
        // want its dying `.idle` callback to clobber our relayState
        // after the new client is already connected.
        if let oldRelay = relay {
            oldRelay.delegate = nil
            oldRelay.disconnect()
        }
        guard let myId = myIdentityPublicCached ?? (try? session.identityPublic()) else {
            return
        }
        let client = RelayClient(myIdentity: myId)
        client.delegate = self
        self.relay = client
        NSLog("[pizzini] connecting to \(state.relayHost):\(Self.relayPort)")
        client.connect(to: state.relayHost, port: Self.relayPort)
    }

    func setRelayHost(_ host: String) {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != state.relayHost else { return }
        state.relayHost = trimmed
        Storage.persist(appState: state)
        connectRelay()
    }

    // MARK: - Contacts

    func contact(forIdentity peerId: Data) -> Contact? {
        state.contacts.first { $0.identityPub == peerId }
    }

    private func contactIndex(forIdentity peerId: Data) -> Int? {
        state.contacts.firstIndex { $0.identityPub == peerId }
    }

    /// Commit a freshly-scanned (or pasted) contact. Idempotent on
    /// `card.peerId`: re-adding the same QR is a no-op apart from a bundle
    /// retry. Eagerly requests the peer's bundle if the relay is up.
    ///
    /// `displayName` is what the host (UI) collected from the user at
    /// pairing time. Empty/whitespace falls back to the fingerprint
    /// default so the row is still distinguishable.
    ///
    /// Note: `card.host` is *informational* — it's the address the peer
    /// uses to reach the relay. We never adopt it as our own relay host;
    /// scanning a sim's `127.0.0.1` QR from a real iPhone would otherwise
    /// silently break our connection.
    func addContact(card: ContactCard, displayName: String?) {
        guard let session else { return }
        if state.contacts.contains(where: { $0.identityPub == card.peerId }) {
            relay?.requestBundle(fromPeer: card.peerId)
            return
        }
        let trimmed = (displayName ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let name = trimmed.isEmpty ? Contact.defaultName(for: card.peerId) : trimmed
        let contact = Contact(identityPub: card.peerId, displayName: name)
        state.contacts.append(contact)
        try? session.registerPeer(peerIdentity: card.peerId)
        persistAll()
        if relayState == .connected {
            relay?.requestBundle(fromPeer: card.peerId)
        }
    }

    func send(_ text: String, to contact: Contact) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let session,
              let relay,
              let idx = contactIndex(forIdentity: contact.identityPub)
        else { return }
        guard contact.sessionEstablished else {
            appendSystem("Session not established yet — waiting for the other side to scan you.", to: idx)
            return
        }
        do {
            let result = try session.encrypt(
                peerIdentity: contact.identityPub,
                plaintext: Data(trimmed.utf8)
            )
            relay.send(
                toPeer: contact.identityPub,
                ciphertext: result.ciphertext,
                isPreKey: result.messageType == .preKey
            )
            let entry = PersistedMessage(
                side: .me,
                text: trimmed,
                kind: result.messageType == .preKey ? .preKey : .whisper,
                bytes: result.ciphertext.count
            )
            state.contacts[idx].log.append(entry)
            state.contacts[idx].lastMessageAt = entry.timestamp
            persistAll()
        } catch {
            appendSystem("Encrypt failed: \(error)", to: idx)
        }
    }

    func deleteChat(_ contact: Contact) {
        guard let idx = contactIndex(forIdentity: contact.identityPub) else { return }
        state.contacts[idx].log.removeAll()
        state.contacts[idx].lastMessageAt = nil
        state.contacts[idx].lastSeenAt = Date()
        Storage.persist(appState: state)
        refreshAppBadge()
    }

    func deleteContact(_ contact: Contact) {
        guard let idx = contactIndex(forIdentity: contact.identityPub) else { return }
        state.contacts.remove(at: idx)
        try? session?.forgetPeer(peerIdentity: contact.identityPub)
        persistAll()
    }

    func deleteAllChats() {
        let now = Date()
        for i in state.contacts.indices {
            state.contacts[i].log.removeAll()
            state.contacts[i].lastMessageAt = nil
            state.contacts[i].lastSeenAt = now
        }
        Storage.persist(appState: state)
        refreshAppBadge()
    }

    /// Called when the user enters a chat — clears its unread count.
    func markRead(contactID: UUID) {
        guard let idx = state.contacts.firstIndex(where: { $0.id == contactID }) else { return }
        state.contacts[idx].lastSeenAt = Date()
        Storage.persist(appState: state)
        refreshAppBadge()
    }

    func rename(_ contact: Contact, to newName: String) {
        let trimmed = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let idx = contactIndex(forIdentity: contact.identityPub)
        else { return }
        state.contacts[idx].displayName = trimmed
        Storage.persist(appState: state)
    }

    func resetIdentity() {
        relay?.disconnect()
        Storage.resetEverything()
        state = AppState()
        do {
            let s = try Storage.loadOrCreateSession()
            session = s
            myIdentityPublicCached = try s.identityPublic()
            connectRelay()
            initError = nil
        } catch {
            initError = String(describing: error)
        }
        refreshAppBadge()
    }

    // MARK: - Helpers

    private func persistAll() {
        Storage.persist(appState: state)
        if let session {
            try? Storage.persist(session: session)
        }
        refreshAppBadge()
    }

    /// Total unread → app icon. Uses the modern API (the
    /// `UIApplication.shared.applicationIconBadgeNumber` setter is
    /// deprecated in iOS 17 and we target ≥ 17).
    private func refreshAppBadge() {
        let count = state.totalUnread
        UNUserNotificationCenter.current().setBadgeCount(count) { _ in }
    }

    private func appendSystem(_ text: String, to idx: Int) {
        state.contacts[idx].log.append(
            PersistedMessage(side: .me, text: text, kind: .system, bytes: 0)
        )
        Storage.persist(appState: state)
    }
}

extension ChatStore: RelayClientDelegate {
    nonisolated func relayClient(_ client: RelayClient, didChange state: RelayClient.State) {
        Task { @MainActor in
            self.relayState = state
            if state == .connected {
                // Retry bundle requests for any contact that hasn't yet
                // completed the handshake — the typical reason is "the
                // other side hadn't scanned us when we last asked".
                for c in self.state.contacts where !c.sessionEstablished {
                    client.requestBundle(fromPeer: c.identityPub)
                }
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
            guard let session = self.session,
                  let idx = self.contactIndex(forIdentity: fromPeer)
            else {
                NSLog("[pizzini] dropped SEND from unknown peer \(self.short(fromPeer))")
                return
            }
            do {
                let pt = try session.decrypt(
                    peerIdentity: fromPeer,
                    ciphertext: ciphertext,
                    isPreKey: isPreKey
                )
                let text = String(data: pt, encoding: .utf8) ?? "<\(pt.count) non-utf8 bytes>"
                let entry = PersistedMessage(
                    side: .peer,
                    text: text,
                    kind: isPreKey ? .preKey : .whisper,
                    bytes: ciphertext.count
                )
                self.state.contacts[idx].log.append(entry)
                self.state.contacts[idx].lastMessageAt = entry.timestamp
                self.state.contacts[idx].sessionEstablished = true
                self.persistAll()
            } catch {
                NSLog("[pizzini] decrypt failed for \(self.short(fromPeer)): \(error)")
            }
        }
    }

    nonisolated func relayClient(_ client: RelayClient, didReceiveBundleRequestFrom fromPeer: Data) {
        Task { @MainActor in
            guard let idx = self.contactIndex(forIdentity: fromPeer),
                  let session = self.session
            else {
                NSLog("[pizzini] dropped BUNDLE_REQUEST from unknown peer \(self.short(fromPeer))")
                return
            }
            do {
                let bundle = try session.publishBundle()
                client.sendBundle(toPeer: fromPeer, bundle: bundle)
                self.persistAll()
                // The peer just proved they have us in their contacts (we
                // only get here if our own contact-gate let them through).
                // If we haven't yet got a session ourselves — typical when
                // we were the second of the two to add the other — ask
                // for their bundle now too. Closes the asymmetric pairing.
                if !self.state.contacts[idx].sessionEstablished {
                    client.requestBundle(fromPeer: fromPeer)
                }
            } catch {
                NSLog("[pizzini] publishBundle failed: \(error)")
            }
        }
    }

    nonisolated func relayClient(
        _ client: RelayClient,
        didReceiveBundleFrom fromPeer: Data,
        bundle: Data
    ) {
        Task { @MainActor in
            guard let session = self.session,
                  let idx = self.contactIndex(forIdentity: fromPeer)
            else {
                NSLog("[pizzini] dropped BUNDLE_RESPONSE from unknown peer \(self.short(fromPeer))")
                return
            }
            do {
                try session.initiateSession(peerIdentity: fromPeer, bundle: bundle)
                self.state.contacts[idx].sessionEstablished = true
                self.persistAll()
            } catch {
                NSLog("[pizzini] initiateSession failed: \(error)")
            }
        }
    }

    private func short(_ data: Data) -> String {
        let head = data.prefix(4).map { String(format: "%02x", $0) }.joined()
        return head + "…"
    }
}
