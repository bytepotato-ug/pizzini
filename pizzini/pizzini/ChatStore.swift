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
    private(set) var outbox: OutboxStore
    private(set) var initError: String?
    /// True iff the most recent attempt to persist the libsignal session
    /// blob to Keychain failed. F-602 fix-review: the audit's deeper
    /// recommendation was to "block further encrypts behind a 'Keychain
    /// unavailable; tap to retry' UI guard rather than letting in-memory
    /// drift further". A flag drives a banner in ContentView that warns
    /// the user — chronic write failure means a force-quit will roll
    /// the on-disk session back to the last successful persist, and the
    /// next outbound encrypt will reuse a counter the peer has already
    /// consumed. Cleared the next time persistSession succeeds.
    private(set) var keychainWriteFailing: Bool = false
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
    /// Periodic retry/TTL-expiry walk. Re-armed in `connectRelay` so
    /// each fresh socket gets one timer; cancelled on disconnect.
    private var retryTimer: Timer?

    override init() {
        self.state = Storage.loadAppState()
        self.outbox = Storage.loadOutbox()
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

    /// Outbox entry for `messageId`, if any. Used by the chat row to
    /// pick its status icon.
    func outboxEntry(forMessageId id: Data) -> OutboxEntry? {
        outbox.entries[id]
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
        // F-203: capture the session for HELLO signing. Using a strong
        // capture here is fine because RelayClient lifetime is bounded
        // by ChatStore (we own it as `self.relay`). If the user resets
        // identity, `teardownRelay` nils self.relay, and the closure's
        // captured session is harmless.
        let signingSession = session
        let client = RelayClient(
            myIdentity: myId,
            myDeliveryTokenVerifyKey: verifyKey,
            signer: { payload in
                try? signingSession.identitySign(payload)
            },
        )
        client.delegate = self
        if let token = pushTokenCached {
            client.registerPush(token: token)
        }
        self.relay = client
        NSLog("[pizzini] connecting to \(state.relayHost):\(Self.relayPort)")
        client.connect(to: state.relayHost, port: Self.relayPort)
        scheduleRetryTimer()
    }

    private func scheduleRetryTimer() {
        retryTimer?.invalidate()
        // 30s matches the OutboxEntry.shouldRetry minimum baseline so
        // every wake-up is actionable on at least the freshest entry.
        let timer = Timer(timeInterval: 30, repeats: true) { [weak self] _ in
            guard let self else { return }
            DispatchQueue.main.async {
                self.runRetryWalk()
            }
        }
        timer.tolerance = 5
        RunLoop.main.add(timer, forMode: .common)
        retryTimer = timer
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
        guard relay != nil else { return }
        NSLog("[pizzini] relay disconnect for background")
        teardownRelay()
    }

    /// F-704: shared disconnect path used by `disconnectForBackground`
    /// AND `resetIdentity`. The earlier asymmetry — where `resetIdentity`
    /// only called `relay?.disconnect()` and relied on the next
    /// `connectRelay()` to clear delegate / timer / `self.relay` — was
    /// not exploitable but was a refactor trip-wire: any future `await`
    /// inserted between disconnect and reconnect could let a queued
    /// retry tick fire on the OLD client with the new outbox state. Make
    /// the cleanup symmetric and explicit.
    private func teardownRelay() {
        if let relay {
            relay.delegate = nil
            relay.disconnect()
        }
        self.relay = nil
        relayState = .idle
        retryTimer?.invalidate()
        retryTimer = nil
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
    ///
    /// F-303 fix: re-derive the hour bucket INSIDE the dispatch closure
    /// right before computing the proof, in case iOS suspended the queue
    /// (e.g. user backgrounded the app mid-PoW) and the originally
    /// captured hour is stale by the time we resume. Capture `relay`
    /// weakly via `self.relay` so an instance swap (relay-host change /
    /// reconnect) doesn't ship the proof to a torn-down client.
    private func requestBundleWithHashcash(fromPeer peer: Data) {
        guard relay != nil else { return }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            // Re-derive hour bucket here. If suspended for ≥1h between
            // request scheduling and PoW completion, the bucket would
            // otherwise be stale and the relay would reject.
            let challenge = Self.hashcashChallenge(
                for: peer,
                hour: Self.currentHourBucket(),
            )
            let nonce = Hashcash.compute(challenge: challenge)
            DispatchQueue.main.async {
                // Look up the CURRENT relay instance via self — capturing
                // the local `relay` strongly would target the pre-swap
                // client. Drop on the floor if the chat-store or relay
                // are gone (e.g. identity reset mid-PoW).
                guard let liveRelay = self?.relay else { return }
                liveRelay.requestBundle(fromPeer: peer, hashcashNonce: nonce)
            }
        }
    }

    /// Pure deterministic helper — `nonisolated` so the F-303 dispatch
    /// closure (which runs on `DispatchQueue.global`) can call it
    /// without a MainActor hop. Strict concurrency would otherwise
    /// reject the call site.
    nonisolated private static func currentHourBucket() -> UInt64 {
        UInt64(Date().timeIntervalSince1970) / 3600
    }

    /// Domain-separation tag baked into the hashcash challenge digest.
    /// MUST match `HASHCASH_CHALLENGE_TAG` in `relay/src/main.rs` byte
    /// for byte. F-301. `nonisolated` so the F-303 background dispatch
    /// can read it without a MainActor hop — it's an immutable Sendable
    /// constant.
    nonisolated private static let hashcashChallengeTag = Data("pizzini.hashcash.bundle.v1".utf8)

    /// F-402: BUNDLE_RESPONSE wire size for the decoy path. A real
    /// Pizzini bundle is 1858 bytes (kyber1024 PK 1568 + 4× signatures
    /// 64 each + 4× public keys 33 each + headers/IDs); we round up to
    /// 1860 to absorb future tweaks below detection. Token batch size
    /// is `Contact.initialIssuance × 84` = 86016 bytes.
    private static let decoyBundleSize = 1860
    /// Pacing budget for the real BUNDLE_RESPONSE + TOKEN_ISSUE path on
    /// a modern phone — kyber1024 keygen + 1024 XEd25519 signatures
    /// runs ~1s. Decoy waits within this window before emitting so the
    /// relay can't time-distinguish "Y is in Alice's contacts" from
    /// "Y is not". 50ms jitter prevents a learned-fixed-1s signature.
    private static let decoyEmitDelay: ClosedRange<Duration> = .milliseconds(900) ... .milliseconds(1100)

    @MainActor
    private func emitBundleResponseDecoy(toFakePeer fromPeer: Data, via client: RelayClient) {
        // Capture the client and target before we go async — the iOS
        // app may reset identity / swap the relay before our delay
        // fires; if so, drop silently rather than ship to a stale
        // client.
        let target = fromPeer
        Task { @MainActor [weak self, weak client] in
            // Random sleep within the budget so the decoy doesn't have
            // a fixed-latency fingerprint. Even if iOS suspends mid-
            // sleep, we still want to ship on resume to keep the
            // wire-shape consistent — the leak is the asymmetry, not
            // the precise timing.
            let nanos = UInt64.random(in: 900_000_000 ... 1_100_000_000)
            try? await Task.sleep(nanoseconds: nanos)
            guard let self else { return }
            guard let client else { return }
            // After the await we may also have lost the connection or
            // had identity reset. emitDecoyOnSocket guards on those.
            self.emitDecoyOnSocket(toPeer: target, via: client)
            _ = ChatStore.decoyEmitDelay  // silence unused range
        }
    }

    @MainActor
    private func emitDecoyOnSocket(toPeer: Data, via client: RelayClient) {
        // Random bytes shaped to match a real BUNDLE_RESPONSE payload.
        // The recipient (the malicious relay or its colluding client)
        // can't decrypt — bundle decoder rejects on the version byte
        // mismatch — but the relay's outbound observation is identical
        // to the real-contact path.
        var decoyBundle = Data(count: ChatStore.decoyBundleSize)
        _ = decoyBundle.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, buf.count, buf.baseAddress!)
        }
        client.sendBundle(toPeer: toPeer, bundle: decoyBundle)

        // Same-shape decoy TOKEN_ISSUE: 1024 random 84-byte "tokens".
        var decoyTokens: [Data] = []
        decoyTokens.reserveCapacity(Contact.initialIssuance)
        for _ in 0 ..< Contact.initialIssuance {
            var tok = Data(count: 84)
            _ = tok.withUnsafeMutableBytes { buf in
                SecRandomCopyBytes(kSecRandomDefault, buf.count, buf.baseAddress!)
            }
            decoyTokens.append(tok)
        }
        client.sendTokenIssue(toPeer: toPeer, tokens: decoyTokens)
    }

    /// Hashcash challenge layout, mirroring `relay::build_hashcash_challenge`:
    /// `BLAKE3(tag || u16_be(peer_id_len) || peer_id || hour_bucket_be_u64)`.
    /// F-301: domain-separated and length-prefixed. CryptoKit doesn't
    /// expose BLAKE3, so the iOS side reaches into the
    /// `pizzini_blake3_hash` FFI rather than maintaining a parallel
    /// pure-Swift hasher.
    ///
    /// `nonisolated` so the F-303 dispatch closure (background queue,
    /// not MainActor) can call it directly — pure function of its
    /// arguments, no MainActor state touched.
    nonisolated private static func hashcashChallenge(for peer: Data, hour: UInt64) -> Data {
        var input = Data()
        input.append(hashcashChallengeTag)
        var peerLenBE = UInt16(peer.count).bigEndian
        withUnsafeBytes(of: &peerLenBE) { input.append(contentsOf: $0) }
        input.append(peer)
        var hourBE = hour.bigEndian
        withUnsafeBytes(of: &hourBE) { input.append(contentsOf: $0) }
        return blake3(input)
    }

    /// Pure FFI wrapper — `nonisolated` for the same reason as
    /// `hashcashChallenge`: called from `hashcashChallenge` which is
    /// itself reachable from the F-303 background dispatch closure.
    nonisolated private static func blake3(_ input: Data) -> Data {
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
            // from_id / is_prekey at the relay layer. Phase 4 records
            // an OutboxEntry per send so retries + delivered (✓✓)
            // tracking work even across relay restarts.
            let messageId = Self.makeMessageId()
            var inner = Data([RelayClient.InnerEnvelopeKind.chat.rawValue])
            inner.append(Data(trimmed.utf8))
            let sealed = try session.encryptSealed(
                peer: contact.identityPub,
                messageId: messageId,
                plaintext: inner,
            )
            let ttl = state.contacts[idx].ttlSeconds
            let now = Date()
            // Insert into outbox BEFORE handing off to the relay so a
            // crash mid-send still leaves a retryable record on disk.
            var entry = OutboxEntry(
                messageId: messageId,
                recipientPeerId: contact.identityPub,
                sealedCiphertext: sealed,
                token: token,
                ttl: TimeInterval(ttl),
                sentAt: now,
                retries: 0,
                deliveredAt: nil,
                failedAt: nil,
                relayedAt: nil,
            )
            outbox.entries[messageId] = entry
            Storage.persist(outbox: outbox)
            // CRITICAL: encryptSealed advanced the ratchet; flush that
            // state to Keychain BEFORE the socket write. The
            // outbox-then-session-then-send order means a force-quit
            // mid-send leaves the outbox knowing we tried (so the
            // retry walk picks it up after restart) AND the libsignal
            // session pinned at the post-encrypt counter (so the retry
            // doesn't reuse a chain key the peer has already consumed).
            persistSession()
            // Send. NWConnection completion fires async; we treat a
            // synchronous return + state==.connected as the "✓ relayed"
            // tier — see `markRelayed` for the explicit completion
            // hook in the new RelayClient.send completion.
            relay.sendSealed(
                toPeer: contact.identityPub,
                sealedCiphertext: sealed,
                ttlSeconds: ttl,
                token: token,
            )
            entry.relayedAt = now
            // F-505: scrub the token field once the relay accepts the
            // bytes. The signed token is no longer needed (further
            // retries on a relayed entry are capped by F-501 and
            // wouldn't burn a token even if they fired). Keeping it on
            // disk widens the post-Keychain-extraction replay surface
            // for the token's 30-day TTL.
            entry.token = Data()
            outbox.entries[messageId] = entry
            Storage.persist(outbox: outbox)

            let logEntry = PersistedMessage(
                side: .me,
                text: trimmed,
                // Bubble metadata stays "PreKey/Whisper" for now —
                // sealed-sender hides that detail at the wire level
                // but the cert-cached SenderCertificate path uses
                // PreKey on the very first send, Whisper after.
                kind: state.contacts[idx].sessionEstablished ? .whisper : .preKey,
                bytes: sealed.count,
                messageId: messageId,
            )
            state.contacts[idx].log.append(logEntry)
            state.contacts[idx].lastMessageAt = logEntry.timestamp
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
            // F-601: persist the advanced ratchet state BEFORE handing
            // off to the relay. A force-quit between encryptSealed and
            // persistAll otherwise rolls the on-disk session back one
            // step and the next outbound encrypt reuses an already-
            // consumed counter; the peer rejects with DuplicatedMessage
            // and the user sees ✓✓ on a message that never arrived.
            // Mirrors the invariant the other encrypt sites uphold (see
            // emitAck and emitReadReceiptIfEnabled).
            state.contacts[idx].lastRefillRequestSentAt = Date()
            persistAll()
            relay.sendSealed(
                toPeer: contact.identityPub,
                sealedCiphertext: sealed,
                ttlSeconds: Self.defaultTTLSeconds,
                token: token,
            )
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

    /// Called when the user enters a chat — clears its unread count
    /// and, if read receipts are enabled for this contact, emits a
    /// single sealed `read` envelope covering the highest message_id
    /// seen so the peer can show "Read" in their UI.
    func markRead(contactID: UUID) {
        guard let idx = state.contacts.firstIndex(where: { $0.id == contactID }) else { return }
        state.contacts[idx].lastSeenAt = Date()
        Storage.persist(appState: state)
        refreshAppBadge()
        emitReadReceiptIfEnabled(forContactAt: idx)
    }

    func setContactTTL(_ contact: Contact, seconds: UInt32) {
        guard let idx = contactIndex(forIdentity: contact.identityPub) else { return }
        state.contacts[idx].ttlSeconds = seconds
        Storage.persist(appState: state)
    }

    func setReadReceipts(_ contact: Contact, enabled: Bool) {
        guard let idx = contactIndex(forIdentity: contact.identityPub) else { return }
        state.contacts[idx].readReceiptsEnabled = enabled
        Storage.persist(appState: state)
    }

    @MainActor
    private func emitReadReceiptIfEnabled(forContactAt idx: Int) {
        let contact = state.contacts[idx]
        guard contact.readReceiptsEnabled,
              let session, let relay,
              let last = contact.log.last(where: { $0.side == .peer && $0.messageId != nil }),
              let highest = last.messageId
        else { return }
        guard let token = popDeliveryToken(forContactAt: idx) else {
            NSLog("[pizzini] cannot emit read receipt: out of tokens")
            return
        }
        var inner = Data([RelayClient.InnerEnvelopeKind.readReceipt.rawValue])
        inner.append(highest)
        do {
            let sealed = try session.encryptSealed(
                peer: contact.identityPub,
                messageId: Self.makeMessageId(),
                plaintext: inner,
            )
            // Same root-cause guard as `emitAck`: persist before the
            // socket write so a force-quit between encrypt and the
            // next chat send can't roll the ratchet back.
            persistSession()
            relay.sendSealed(
                toPeer: contact.identityPub,
                sealedCiphertext: sealed,
                ttlSeconds: contact.ttlSeconds,
                token: token,
            )
        } catch {
            NSLog("[pizzini] read-receipt encrypt failed: \(error)")
        }
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
        // F-704: full teardown — null self.relay, invalidate retry
        // timer, clear delegate. Mirrors disconnectForBackground so
        // any queued retry tick that fires before connectRelay runs
        // again can't observe a half-reset state.
        teardownRelay()
        // Preserve non-identity configuration across the wipe. The relay
        // host is a network endpoint (typically a LAN IP for a physical
        // iPhone, loopback for the sim); resetting it to the
        // 127.0.0.1 default would leave a real device unable to find
        // the relay until the user re-edited it. Same reasoning for
        // the UX prefs (auto-lock, biometric, onboarding-seen):
        // they're not identity-derived.
        let preservedHost = state.relayHost
        let preservedAutoLock = state.autoLockTimeout
        let preservedBiometric = state.biometricLockEnabled
        let preservedOnboarding = state.onboardingCompleted
        let resetState = AppState(
            relayHost: preservedHost,
            onboardingCompleted: preservedOnboarding,
            biometricLockEnabled: preservedBiometric,
            autoLockTimeout: preservedAutoLock,
        )
        // F-703: write the post-reset AppState to Keychain BEFORE wiping
        // the device-store / outbox / legacy slots. The previous order
        // (wipe, then re-create-and-persist) had a process-kill window
        // between the two where on next launch `loadAppState()` returned
        // `AppState()` defaults — silently dropping the user's biometric
        // lock posture among the preserved fields. Now the new value is
        // durable across the wipe call's sequence of Keychain ops.
        Storage.persist(appState: resetState)
        Storage.resetEverything(preserveAppState: true)
        state = resetState
        outbox = .empty
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
        persistSession()
        refreshAppBadge()
    }

    /// Persist *only* the libsignal session blob — used after every
    /// `Session.encryptSealed` / `decryptSealed` whose call-site doesn't
    /// already trigger a `persistAll()` for unrelated reasons. The
    /// libsignal ratchet advances on every encrypt and on every decrypt;
    /// dropping that state on the floor (e.g. after `emitAck` followed
    /// by a force-quit) rolls the on-disk session back, so the NEXT
    /// outbound message reuses an already-consumed counter and the peer
    /// rejects with `DuplicatedMessage`. Cheap to call — the blob is
    /// kilobytes and Keychain writes are async.
    private func persistSession() {
        guard let session else { return }
        do {
            try Storage.persist(session: session)
            // Clear the warning the moment a write succeeds. Chronic
            // failure stays surfaced; transient hiccups self-resolve
            // on the next persistSession call.
            if keychainWriteFailing {
                keychainWriteFailing = false
            }
        } catch {
            // F-602: surface to UI via the published flag. Storage layer
            // already NSLog'd the underlying errSec status — the banner
            // tells the user to investigate before they trust further
            // ✓✓ indicators (which would otherwise be lying about
            // delivery in the worst case).
            keychainWriteFailing = true
        }
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
                //
                // Also re-request for paired contacts whose `peerVerifyKey`
                // is nil. This catches the F-202 upgrade-path strand: a
                // user upgrading from pre-Phase-3 has every Contact row
                // with `peerVerifyKey == nil` (the field didn't exist on
                // disk). Without this, every TOKEN_ISSUE batch from those
                // peers gets dropped at didReceiveTokenIssueFrom and the
                // user silently drains their stash. The next BUNDLE_RESPONSE
                // re-populates the key via Session.extractBundleVerifyKey.
                // F-404's lastBundleServedAt cooldown (peer-side) keeps
                // this from amplifying into a flood.
                for c in self.state.contacts
                    where !c.sessionEstablished || c.peerVerifyKey == nil
                {
                    self.requestBundleWithHashcash(fromPeer: c.identityPub)
                }
                // F-502: also kick the outbox retry walk immediately on
                // reconnect rather than waiting up to 30s for the next
                // timer tick. `runRetryWalk` is idempotent — if no
                // entries are due, it's a no-op.
                self.runRetryWalk()
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
            // F-202/F-401: authenticate the batch end-to-end against the
            // peer's bundle-published verify_key before any token enters
            // the stash. A malicious relay could otherwise swap legitimate
            // tokens for relay-forged ones and wedge our send path.
            guard let verifyKey = self.state.contacts[idx].peerVerifyKey else {
                NSLog(
                    "[pizzini] dropped TOKEN_ISSUE from \(self.short(fromPeer)): no peerVerifyKey on contact (re-pair to refresh)"
                )
                return
            }
            var verified: [Data] = []
            verified.reserveCapacity(tokens.count)
            for token in tokens {
                do {
                    if try Session.verifyDeliveryToken(verifyKey: verifyKey, token: token) {
                        verified.append(token)
                    } else {
                        NSLog(
                            "[pizzini] dropping batch from \(self.short(fromPeer)): token signature did not verify against bundle-published verify_key"
                        )
                        return
                    }
                } catch {
                    NSLog(
                        "[pizzini] dropping batch from \(self.short(fromPeer)): verify error \(error)"
                    )
                    return
                }
            }
            // F-206: cap stash size, but trim from the BACK (newest first)
            // rather than the front. Combined with verify above this is
            // belt-and-suspenders — fabricated tokens never enter — but a
            // peer that legitimately issues lots of refills shouldn't be
            // able to push older trusted tokens off the queue either.
            let cap = 2 * Contact.initialIssuance
            var stash = self.state.contacts[idx].deliveryTokensForPeer
            stash.append(contentsOf: verified)
            if stash.count > cap {
                stash.removeLast(stash.count - cap)
            }
            self.state.contacts[idx].deliveryTokensForPeer = stash
            self.persistAll()
            NSLog(
                "[pizzini] received \(verified.count) verified tokens from \(self.short(fromPeer)); stash now \(stash.count)"
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
            NSLog("[pizzini] sealed decrypt failed: \(error) (sealed=\(sealedCiphertext.count) bytes, isAckFrame=\(isAckFrame))")
            return
        }
        // Persist BEFORE dispatching to per-kind handlers. The libsignal
        // ratchet has already advanced (decrypt is destructive); if we
        // crash mid-handler the on-disk session must reflect that step
        // or the peer's NEXT inbound to us reuses a chain key we've
        // already consumed and the whole conversation desyncs.
        persistSession()
        guard let idx = self.contactIndex(forIdentity: received.peer) else {
            NSLog("[pizzini] dropped sealed frame from unknown peer \(self.short(received.peer))")
            return
        }
        if received.isDuplicate {
            // Sender retried a SEND we already processed (their first
            // ACK from us probably got lost). Re-emit a fresh ACK
            // pointing at the same message_id so their outbox can flip
            // ✓→✓✓; do NOT re-append to the chat log or advance any
            // app-level state. The ratchet already returned us to
            // a quiescent state in this case (libsignal's
            // DuplicatedMessage path doesn't mutate the session).
            NSLog(
                "[pizzini] duplicate sealed frame from \(self.short(received.peer)) — re-emitting ACK"
            )
            self.emitAck(for: received.messageId, toPeer: received.peer, via: client)
            return
        }
        guard let kindByte = received.plaintext.first,
              let kind = RelayClient.InnerEnvelopeKind(rawValue: kindByte) else {
            // F-403: surface as a visible system row so a malicious paired
            // peer can't silently advance our chain key (the ratchet step
            // already happened above; we keep the persisted advance) — the
            // user sees something arrived from this contact and can act
            // (e.g. re-pair) even though we couldn't decode the envelope.
            let kindHex = received.plaintext.first.map { String(format: "0x%02x", $0) } ?? "(empty)"
            self.appendSystem(
                "Received an unknown envelope (\(kindHex)) — possible client mismatch.",
                to: idx,
            )
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
            self.handleReadReceiptPayload(payload, contactIdx: idx)
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
    private func handleReadReceiptPayload(_ payload: Data, contactIdx idx: Int) {
        guard payload.count == 16 else { return }
        // F-405: honour `readReceiptsEnabled` symmetrically. If the user
        // disabled emission of their own read receipts to this contact,
        // also drop incoming claims that we read — otherwise a paired
        // peer could spoof "Read" stamps onto our own messages
        // unilaterally regardless of our setting.
        guard state.contacts[idx].readReceiptsEnabled else {
            return
        }
        let highest = Data(payload)
        let now = Date()
        // Locate the cutoff timestamp for the message_id the peer claims
        // to have read up to. Prefer the outbox entry's `sentAt`; fall
        // back to the chat log's own `timestamp` if the outbox entry has
        // already been GC'd (terminal entries are dropped 24h after
        // delivery, so reads more than a day late would otherwise be
        // silently dropped — F-503).
        let cutoff: Date
        if let highestEntry = outbox.entries[highest] {
            cutoff = highestEntry.sentAt
        } else if let logEntry = state.contacts[idx]
            .log
            .last(where: { $0.side == .me && $0.messageId == highest })
        {
            cutoff = logEntry.timestamp
        } else {
            return
        }
        var changed = false
        for i in state.contacts[idx].log.indices {
            let m = state.contacts[idx].log[i]
            guard m.side == .me, m.timestamp <= cutoff else { continue }
            if state.contacts[idx].log[i].readAt == nil {
                state.contacts[idx].log[i].readAt = now
                changed = true
            }
        }
        if changed { Storage.persist(appState: state) }
    }

    @MainActor
    private func handleAckPayload(_ payload: Data, contactIdx idx: Int) {
        guard payload.count == 16 else {
            NSLog("[pizzini] malformed ACK from \(self.short(state.contacts[idx].identityPub))")
            return
        }
        let messageId = Data(payload)
        guard var entry = outbox.entries[messageId] else {
            NSLog("[pizzini] ACK for unknown messageId \(messageId.map { String(format: "%02x", $0) }.joined())")
            return
        }
        entry.deliveredAt = Date()
        outbox.entries[messageId] = entry
        Storage.persist(outbox: outbox)
    }

    /// Periodic walk: re-send unacked entries that satisfy
    /// `OutboxEntry.shouldRetry`, mark expired entries failed, drop
    /// terminal entries older than 24h to keep the JSON blob bounded.
    @MainActor
    private func runRetryWalk() {
        guard let session, let relay else { return }
        let now = Date()
        var changed = false

        // 1. TTL expiry → mark failed.
        for (id, entry) in outbox.entries where entry.hasExpired(now: now) {
            var e = entry
            e.failedAt = now
            outbox.entries[id] = e
            changed = true
        }

        // 2. Retry walk — only if connected. NWConnection.send while
        // disconnected silently drops; we'd burn tokens.
        if relayState == .connected {
            for entry in outbox.retryableEntries(now: now) {
                guard let idx = contactIndex(forIdentity: entry.recipientPeerId) else {
                    continue
                }
                guard let token = popDeliveryToken(forContactAt: idx) else {
                    NSLog("[pizzini] cannot retry \(short(entry.recipientPeerId)): out of tokens")
                    continue
                }
                relay.sendSealed(
                    toPeer: entry.recipientPeerId,
                    sealedCiphertext: entry.sealedCiphertext,
                    ttlSeconds: UInt32(entry.ttl),
                    token: token,
                )
                var e = entry
                e.retries += 1
                // `relayedAt` records the FIRST time bytes left our
                // socket — bumping it on retry would lie to the UI
                // about how long this message has been waiting. The
                // status icon reads from `relayedAt`/`deliveredAt`/
                // `failedAt`; only the new retry count is interesting.
                outbox.entries[entry.messageId] = e
                changed = true
                _ = session  // silence unused-let in current scope
            }
        }

        // 3. Garbage-collect terminal entries past their post-mortem
        // window. 24h after delivered or failed is plenty for the UI
        // to read; the user can still see the message in the chat
        // log, just without a status icon.
        let postMortem: TimeInterval = 24 * 60 * 60
        for (id, entry) in outbox.entries {
            if let t = entry.deliveredAt ?? entry.failedAt,
               now.timeIntervalSince(t) > postMortem {
                outbox.entries.removeValue(forKey: id)
                changed = true
            }
        }

        if changed { Storage.persist(outbox: outbox) }
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
            // CRITICAL: persist immediately. encryptSealed advanced the
            // ratchet; if the app is killed before the next persistAll,
            // the on-disk session rolls back one step and our NEXT
            // outbound encrypt reuses an already-consumed counter that
            // the peer will reject as DuplicatedMessage.
            persistSession()
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
                // F-402: a malicious relay can fabricate BUNDLE_REQUEST
                // frames with arbitrary `from_id` to probe our contact
                // set — silence-vs-(BUNDLE_RESPONSE+TOKEN_ISSUE) on the
                // wire is the oracle. Mask by emitting a same-shape,
                // same-timing decoy when the requester isn't in our
                // contacts, so the relay sees identical outbound
                // bandwidth + latency for known-vs-unknown.
                NSLog("[pizzini] BUNDLE_REQUEST from unknown peer \(self.short(fromPeer)) — emitting decoy")
                self.emitBundleResponseDecoy(toFakePeer: fromPeer, via: client)
                return
            }
            // F-404: cooldown publishBundle the same way we cooldown
            // issueTokens. A paired peer can otherwise loop BUNDLE_REQUEST
            // (the per-recipient hashcash bound is per-hour and they have
            // our peer_id, so they can grind one proof per hour) and
            // burn one one-time prekey + one kyber1024 keygen per
            // request — a CPU/battery DoS amplified by the existing
            // F-402 ability for a malicious relay to inject requests.
            if let last = self.state.contacts[idx].lastBundleServedAt,
               Date().timeIntervalSince(last) < Contact.refillCooldown
            {
                NSLog(
                    "[pizzini] BUNDLE_REQUEST from \(self.short(fromPeer)) rate-limited; last served \(last)"
                )
                return
            }
            do {
                let bundle = try session.publishBundle()
                client.sendBundle(toPeer: fromPeer, bundle: bundle)
                self.state.contacts[idx].lastBundleServedAt = Date()
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
                // F-202/F-401: stash the peer's delivery-token verify key
                // BEFORE consuming the bundle in initiateSession. Used to
                // authenticate every later TOKEN_ISSUE batch from this
                // peer end-to-end. Failing to extract is fatal for the
                // bundle exchange — better to refuse the pair than accept
                // a malformed bundle whose token batches we can't verify.
                let verifyKey = try Session.extractBundleVerifyKey(bundle)
                try session.initiateSession(peerIdentity: fromPeer, bundle: bundle)
                self.state.contacts[idx].peerVerifyKey = verifyKey
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
