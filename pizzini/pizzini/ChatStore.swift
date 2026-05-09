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
    /// Latest APNs token. Stashed so a relay-host change (which builds
    /// a fresh `RelayClient`) re-publishes the token automatically.
    private var pushTokenCached: Data?

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
        refreshAppBadge()
    }

    /// Forwards the APNs device token to the relay so it can wake us
    /// when a SEND lands while we're disconnected. Called by
    /// `AppDelegate` once iOS has issued a token.
    func publishPushToken(_ token: Data) {
        pushTokenCached = token
        relay?.registerPush(token: token)
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
        guard
            let myId = myIdentityPublicCached ?? (try? session.identityPublic()),
            let verifyKey = try? session.deliveryTokenVerifyKey()
        else {
            return
        }
        let client = RelayClient(myIdentity: myId, myDeliveryTokenVerifyKey: verifyKey)
        client.delegate = self
        if let token = pushTokenCached {
            client.registerPush(token: token)
        }
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

    /// Cleanly tear down the relay socket as the app moves to
    /// background. iOS suspends networking shortly after background;
    /// keeping a half-dead NWConnection across suspension produces
    /// stale `.failed` callbacks that surface only on the *next*
    /// foreground (red → green → red flapping). Closing here avoids
    /// the race entirely.
    func disconnectForBackground() {
        guard let relay else { return }
        NSLog("[pizzini] relay disconnect for background")
        relay.delegate = nil
        relay.disconnect()
        self.relay = nil
        relayState = .idle
    }

    /// Build a fresh relay connection on every foreground entry. We
    /// don't inspect the prior state — see `disconnectForBackground`
    /// for why trusting `relayState` across a suspension cycle is a
    /// bug.
    func reconnectAfterBackground() {
        NSLog("[pizzini] relay reconnect on foreground")
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
            requestBundleWithHashcash(fromPeer: card.peerId)
            return
        }
        let trimmed = (displayName ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let name = trimmed.isEmpty ? Contact.defaultName(for: card.peerId) : trimmed
        let contact = Contact(identityPub: card.peerId, displayName: name)
        state.contacts.append(contact)
        try? session.registerPeer(peerIdentity: card.peerId)
        persistAll()
        if relayState == .connected {
            requestBundleWithHashcash(fromPeer: card.peerId)
        }
    }

    /// Compute the BLAKE3 hashcash on a background queue (~1s on a
    /// modern phone) and ship the BUNDLE_REQUEST. Async — bundle exchange
    /// is rare so the latency is acceptable; the alternative would be a
    /// pre-warmed nonce cache, which would freeze on first launch instead.
    private func requestBundleWithHashcash(fromPeer peer: Data) {
        guard let relay else { return }
        let challenge = Self.hashcashChallenge(for: peer, hour: Self.currentHourBucket())
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let nonce = Hashcash.compute(challenge: challenge)
            DispatchQueue.main.async {
                guard self != nil else { return }
                relay.requestBundle(fromPeer: peer, hashcashNonce: nonce)
            }
        }
    }

    private static func currentHourBucket() -> UInt64 {
        UInt64(Date().timeIntervalSince1970) / 3600
    }

    /// Hashcash challenge layout, mirroring `relay::verify_hashcash`:
    /// `BLAKE3(recipient_peer_id || hour_bucket_be_u64)`. CryptoKit
    /// doesn't expose BLAKE3, so the iOS side reaches into the
    /// `pizzini_blake3_hash` FFI rather than maintaining a parallel
    /// pure-Swift hasher.
    private static func hashcashChallenge(for peer: Data, hour: UInt64) -> Data {
        var input = Data()
        input.append(peer)
        var hourBE = hour.bigEndian
        withUnsafeBytes(of: &hourBE) { input.append(contentsOf: $0) }
        return blake3(input)
    }

    private static func blake3(_ input: Data) -> Data {
        Blake3.hash(input)
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
        guard let token = popDeliveryToken(forContactAt: idx) else {
            appendSystem("Out of delivery tokens — asking your peer for more.", to: idx)
            requestTokenRefill(from: state.contacts[idx], via: relay, session: session)
            return
        }
        do {
            // Phase 2 wire format: sealed envelope on the wire, no
            // from_id / is_prekey at the relay layer. Phase 4 will lift
            // messageId out into a sender-side outbox for retries +
            // delivered (✓✓) tracking; for now generate-and-discard.
            let messageId = Self.makeMessageId()
            var inner = Data([RelayClient.InnerEnvelopeKind.chat.rawValue])
            inner.append(Data(trimmed.utf8))
            let sealed = try session.encryptSealed(
                peer: contact.identityPub,
                messageId: messageId,
                plaintext: inner,
            )
            relay.sendSealed(
                toPeer: contact.identityPub,
                sealedCiphertext: sealed,
                ttlSeconds: Self.defaultTTLSeconds,
                token: token,
            )
            let entry = PersistedMessage(
                side: .me,
                text: trimmed,
                // Bubble metadata stays "PreKey/Whisper" for now —
                // sealed-sender hides that detail at the wire level
                // but the cert-cached SenderCertificate path uses
                // PreKey on the very first send, Whisper after.
                kind: state.contacts[idx].sessionEstablished ? .whisper : .preKey,
                bytes: sealed.count,
            )
            state.contacts[idx].log.append(entry)
            state.contacts[idx].lastMessageAt = entry.timestamp
            persistAll()
            maybeRequestRefill(forContactAt: idx, via: relay, session: session)
        } catch {
            appendSystem("Encrypt failed: \(error)", to: idx)
        }
    }

    /// Pop one token from `contact.deliveryTokensForPeer`. Persists.
    /// Returns nil if the stash is empty — caller must trigger a
    /// refill before retrying.
    private func popDeliveryToken(forContactAt idx: Int) -> Data? {
        guard !state.contacts[idx].deliveryTokensForPeer.isEmpty else { return nil }
        let token = state.contacts[idx].deliveryTokensForPeer.removeFirst()
        Storage.persist(appState: state)
        return token
    }

    /// If the stash dropped below `Contact.refillThreshold` and the
    /// 6h cooldown has elapsed, send a sealed refill-request.
    private func maybeRequestRefill(forContactAt idx: Int, via relay: RelayClient, session: Session) {
        let c = state.contacts[idx]
        guard c.deliveryTokensForPeer.count < Contact.refillThreshold else { return }
        if let last = c.lastRefillRequestSentAt, Date().timeIntervalSince(last) < Contact.refillCooldown {
            return
        }
        requestTokenRefill(from: c, via: relay, session: session)
    }

    private func requestTokenRefill(from contact: Contact, via relay: RelayClient, session: Session) {
        guard let idx = contactIndex(forIdentity: contact.identityPub) else { return }
        // Refill requests bypass the token rate-limit (the relay accepts
        // a SEND with a 0-length token field iff the recipient has not
        // yet registered a verify key for this connection — but in
        // steady state that doesn't apply). The clean answer: spend a
        // token to ask for tokens. If we're at zero, we can't refill —
        // user must re-pair. This is the documented failure mode.
        guard let token = popDeliveryToken(forContactAt: idx) else {
            appendSystem("Token stash exhausted — re-pair this contact.", to: idx)
            return
        }
        do {
            let inner = Data([RelayClient.InnerEnvelopeKind.tokenRefillRequest.rawValue])
            let sealed = try session.encryptSealed(
                peer: contact.identityPub,
                messageId: Self.makeMessageId(),
                plaintext: inner,
            )
            relay.sendSealed(
                toPeer: contact.identityPub,
                sealedCiphertext: sealed,
                ttlSeconds: Self.defaultTTLSeconds,
                token: token,
            )
            state.contacts[idx].lastRefillRequestSentAt = Date()
            Storage.persist(appState: state)
        } catch {
            appendSystem("Refill request failed: \(error)", to: idx)
        }
    }

    /// Mint a fresh batch of tokens for `peer` and ship via TOKEN_ISSUE.
    /// Used both at pair time (right after we send their bundle) and
    /// in response to a refill request. Rate-limited to one issuance
    /// per `Contact.refillCooldown` per peer.
    private func issueTokens(for peer: Data, via relay: RelayClient, session: Session) {
        guard let idx = contactIndex(forIdentity: peer) else { return }
        if let last = state.contacts[idx].lastRefillRequestHandledAt,
           Date().timeIntervalSince(last) < Contact.refillCooldown {
            NSLog("[pizzini] refill rate-limited for \(self.short(peer))")
            return
        }
        var tokens: [Data] = []
        tokens.reserveCapacity(Contact.initialIssuance)
        for _ in 0..<Contact.initialIssuance {
            do {
                tokens.append(try session.mintDeliveryToken())
            } catch {
                NSLog("[pizzini] mintDeliveryToken failed: \(error)")
                return
            }
        }
        relay.sendTokenIssue(toPeer: peer, tokens: tokens)
        state.contacts[idx].lastRefillRequestHandledAt = Date()
        Storage.persist(appState: state)
    }

    /// Default per-message TTL until Phase 4's per-message picker lands.
    /// Matches the brief's "1 day (recommended)" default.
    private static let defaultTTLSeconds: UInt32 = 24 * 60 * 60

    /// 16 random bytes — Phase 4 plumbs this into the outbox so the
    /// sender can match acks against in-flight entries.
    private static func makeMessageId() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        let rc = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(rc == errSecSuccess, "SecRandom must succeed")
        return Data(bytes)
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

    // MARK: - Onboarding + security settings

    func completeOnboarding(enableBiometric: Bool) {
        state.onboardingCompleted = true
        state.biometricLockEnabled = enableBiometric
        Storage.persist(appState: state)
    }

    func setBiometricLockEnabled(_ enabled: Bool) {
        guard state.biometricLockEnabled != enabled else { return }
        state.biometricLockEnabled = enabled
        Storage.persist(appState: state)
        // If the user just disabled the lock, lift any active gate so
        // we don't strand them on an overlay they can no longer dismiss.
        if !enabled {
            LockManager.shared.unlockBecauseDisabled()
        }
    }

    func setAutoLockTimeout(_ value: AutoLockTimeout) {
        guard state.autoLockTimeout != value else { return }
        state.autoLockTimeout = value
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
    ///
    /// Also publishes the count into the shared App Group container so
    /// the Notification Service Extension can pick up an authoritative
    /// baseline whenever a push arrives while the app is dead. The
    /// extension reads, increments, writes back; the main app then
    /// re-syncs from `state.totalUnread` on next launch.
    private func refreshAppBadge() {
        let count = state.totalUnread
        UNUserNotificationCenter.current().setBadgeCount(count) { _ in }
        SharedAppGroup.defaults?.set(count, forKey: SharedAppGroup.unreadCountKey)
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
                    self.requestBundleWithHashcash(fromPeer: c.identityPub)
                }
            }
        }
    }

    nonisolated func relayClient(
        _ client: RelayClient,
        didReceiveSealedSend sealedCiphertext: Data
    ) {
        Task { @MainActor in
            self.handleSealedFrame(sealedCiphertext, isAckFrame: false, via: client)
        }
    }

    nonisolated func relayClient(_ client: RelayClient, didReceiveAck sealedCiphertext: Data) {
        Task { @MainActor in
            self.handleSealedFrame(sealedCiphertext, isAckFrame: true, via: client)
        }
    }

    nonisolated func relayClient(
        _ client: RelayClient,
        didReceiveTokenIssueFrom fromPeer: Data,
        tokens: [Data]
    ) {
        Task { @MainActor in
            guard let idx = self.contactIndex(forIdentity: fromPeer) else {
                NSLog("[pizzini] dropped TOKEN_ISSUE from unknown peer \(self.short(fromPeer))")
                return
            }
            // Append rather than replace — refills layer on top of any
            // unspent tokens. Cap stash size so a malicious peer can't
            // balloon Keychain by spamming refills.
            let cap = 2 * Contact.initialIssuance
            var stash = self.state.contacts[idx].deliveryTokensForPeer
            stash.append(contentsOf: tokens)
            if stash.count > cap {
                stash.removeFirst(stash.count - cap)
            }
            self.state.contacts[idx].deliveryTokensForPeer = stash
            self.persistAll()
            NSLog(
                "[pizzini] received \(tokens.count) tokens from \(self.short(fromPeer)); stash now \(stash.count)"
            )
        }
    }

    @MainActor
    private func handleSealedFrame(_ sealedCiphertext: Data, isAckFrame: Bool, via client: RelayClient) {
        guard let session = self.session else { return }
        let received: Session.SealedReceived
        do {
            received = try session.decryptSealed(sealedCiphertext)
        } catch {
            NSLog("[pizzini] sealed decrypt failed: \(error)")
            return
        }
        guard let idx = self.contactIndex(forIdentity: received.peer) else {
            NSLog("[pizzini] dropped sealed frame from unknown peer \(self.short(received.peer))")
            return
        }
        guard let kindByte = received.plaintext.first,
              let kind = RelayClient.InnerEnvelopeKind(rawValue: kindByte) else {
            NSLog("[pizzini] dropped sealed frame: unknown inner-envelope kind")
            return
        }
        let payload = received.plaintext.dropFirst()
        switch kind {
        case .chat:
            self.handleChatPayload(payload, sealedSize: sealedCiphertext.count, contactIdx: idx, ackId: received.messageId, via: client)
        case .ack:
            self.handleAckPayload(payload, contactIdx: idx)
        case .tokenRefillRequest:
            guard let session = self.session else { return }
            self.issueTokens(for: received.peer, via: client, session: session)
        case .readReceipt:
            // Phase 4 hooks read-receipt UI here.
            NSLog("[pizzini] read-receipt from \(self.short(received.peer)) (Phase 4)")
        }
        // Defensive: an ACK arriving on the SEND channel would have
        // landed in the chat path above unless its inner-kind byte is
        // 0x02. The wire-frame `isAckFrame` distinguishes the relay's
        // routing decision but the inner kind is authoritative.
        let _ = isAckFrame
    }

    @MainActor
    private func handleChatPayload(_ payload: Data, sealedSize: Int, contactIdx idx: Int, ackId: Data, via client: RelayClient) {
        let text = String(data: payload, encoding: .utf8) ?? "<\(payload.count) non-utf8 bytes>"
        let entry = PersistedMessage(
            side: .peer,
            text: text,
            kind: .whisper,
            bytes: sealedSize,
        )
        self.state.contacts[idx].log.append(entry)
        self.state.contacts[idx].lastMessageAt = entry.timestamp
        self.state.contacts[idx].sessionEstablished = true
        self.persistAll()
        // Emit an ACK so the sender's outbox (Phase 4) can flip ✓→✓✓.
        self.emitAck(for: ackId, toPeer: state.contacts[idx].identityPub, via: client)
    }

    @MainActor
    private func handleAckPayload(_ payload: Data, contactIdx idx: Int) {
        guard payload.count == 16 else {
            NSLog("[pizzini] malformed ACK from \(self.short(state.contacts[idx].identityPub))")
            return
        }
        // Phase 4 hooks the per-message-id outbox here.
        let messageId = payload.map { String(format: "%02x", $0) }.joined()
        NSLog("[pizzini] ACK for message \(messageId) from \(self.short(state.contacts[idx].identityPub))")
    }

    @MainActor
    private func emitAck(for messageId: Data, toPeer: Data, via client: RelayClient) {
        guard let session = self.session,
              let idx = contactIndex(forIdentity: toPeer)
        else { return }
        guard let token = popDeliveryToken(forContactAt: idx) else {
            NSLog("[pizzini] cannot emit ACK to \(self.short(toPeer)): out of tokens")
            return
        }
        var inner = Data([RelayClient.InnerEnvelopeKind.ack.rawValue])
        inner.append(messageId)
        do {
            let sealed = try session.encryptSealed(
                peer: toPeer,
                messageId: Self.makeMessageId(),
                plaintext: inner,
            )
            client.sendAck(
                toPeer: toPeer,
                sealedCiphertext: sealed,
                ttlSeconds: Self.defaultTTLSeconds,
                token: token,
            )
        } catch {
            NSLog("[pizzini] failed to emit ACK to \(self.short(toPeer)): \(error)")
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
                // Right after the bundle, mint and ship a fresh stash
                // of delivery tokens for the requester. They'll need
                // these for every subsequent SEND/ACK to clear our
                // relay-side rate-limit gate.
                self.issueTokens(for: fromPeer, via: client, session: session)
                self.persistAll()
                // The peer just proved they have us in their contacts (we
                // only get here if our own contact-gate let them through).
                // If we haven't yet got a session ourselves — typical when
                // we were the second of the two to add the other — ask
                // for their bundle now too. Closes the asymmetric pairing.
                if !self.state.contacts[idx].sessionEstablished {
                    self.requestBundleWithHashcash(fromPeer: fromPeer)
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
