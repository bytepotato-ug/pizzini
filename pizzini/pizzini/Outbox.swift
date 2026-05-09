import Foundation

/// Sender-side outbox: every sealed SEND lands here at submit time so we
/// can retry on relay reconnect, surface ⏳ / ✓ / ✓✓ / ✗ in the UI, and
/// give up cleanly when the per-message TTL elapses without an ACK.
///
/// Persisted as JSON in a Keychain slot (`outbox`). Outbox state survives
/// crash / kill / reboot; not duress (clears with `Storage.resetEverything`).
/// SQLCipher migration is the obvious follow-up — outbox JSON in Keychain
/// hits the slot's size ceiling around the low thousands of unacked
/// entries, which is fine for a journalist's day but not multi-week
/// offline.
struct OutboxEntry: Codable, Sendable {
    let messageId: Data         // 16 bytes
    let recipientPeerId: Data
    let sealedCiphertext: Data
    /// The XEd25519-signed delivery token attached to the original SEND.
    /// **F-505**: scrubbed to empty once `relayedAt != nil` — the relay
    /// has accepted the bytes; storing the signed token onward only
    /// widens the post-extraction replay surface (a Keychain-extracted
    /// blob within the token's 30-day TTL would otherwise let an
    /// attacker re-inject the SEND, force the recipient onto the
    /// duplicate-ACK path, and burn a recipient token per replay).
    /// Retries that fire BEFORE `relayedAt` is set still need this
    /// token; retries AFTER are blocked by F-501's relayedAt-aware cap.
    var token: Data
    let ttl: TimeInterval
    let sentAt: Date
    var retries: Int
    var deliveredAt: Date?      // set when ACK received → flips ✓ to ✓✓
    var failedAt: Date?         // set when TTL expires without ACK → ✗
    /// Set when the underlying NWConnection.send completion fires
    /// without error — this is the "delivered to relay" tier (✓).
    /// `deliveredAt == nil && relayedAt != nil` is the visible
    /// "single tick" state.
    var relayedAt: Date?

    // MARK: - Phase 2 chunked-attachment grouping
    /// 16-byte attachment id when this entry is a single chunk of a
    /// chunked attachment send. Nil for plain chat / ack / token-refill
    /// / read-receipt entries. Multiple OutboxEntries share the same
    /// `attachmentId`; the UI rolls up per-attachment status across
    /// chunks via `OutboxStore.attachmentStatus(forId:)`.
    var attachmentId: Data?
    /// 0-based chunk index in the attachment. Nil when `attachmentId`
    /// is nil. Encoded with `encodeIfPresent` so non-attachment entries
    /// don't grow the JSON.
    var chunkIndex: UInt32?
    /// Total chunk count for this attachment. Nil when attachmentId is
    /// nil. Captured per-entry rather than referenced from a single
    /// shared record so a future SQLCipher migration can drop the
    /// JSON-blob OutboxStore without losing the grouping math.
    var chunkCount: UInt32?

    private enum CodingKeys: String, CodingKey {
        case messageId, recipientPeerId, sealedCiphertext, token, ttl, sentAt
        case retries, deliveredAt, failedAt, relayedAt
        case attachmentId, chunkIndex, chunkCount
    }

    init(
        messageId: Data,
        recipientPeerId: Data,
        sealedCiphertext: Data,
        token: Data,
        ttl: TimeInterval,
        sentAt: Date,
        retries: Int,
        deliveredAt: Date?,
        failedAt: Date?,
        relayedAt: Date?,
        attachmentId: Data? = nil,
        chunkIndex: UInt32? = nil,
        chunkCount: UInt32? = nil
    ) {
        self.messageId = messageId
        self.recipientPeerId = recipientPeerId
        self.sealedCiphertext = sealedCiphertext
        self.token = token
        self.ttl = ttl
        self.sentAt = sentAt
        self.retries = retries
        self.deliveredAt = deliveredAt
        self.failedAt = failedAt
        self.relayedAt = relayedAt
        self.attachmentId = attachmentId
        self.chunkIndex = chunkIndex
        self.chunkCount = chunkCount
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.messageId = try c.decode(Data.self, forKey: .messageId)
        self.recipientPeerId = try c.decode(Data.self, forKey: .recipientPeerId)
        self.sealedCiphertext = try c.decode(Data.self, forKey: .sealedCiphertext)
        self.token = try c.decode(Data.self, forKey: .token)
        self.ttl = try c.decode(TimeInterval.self, forKey: .ttl)
        self.sentAt = try c.decode(Date.self, forKey: .sentAt)
        self.retries = try c.decode(Int.self, forKey: .retries)
        self.deliveredAt = try c.decodeIfPresent(Date.self, forKey: .deliveredAt)
        self.failedAt = try c.decodeIfPresent(Date.self, forKey: .failedAt)
        self.relayedAt = try c.decodeIfPresent(Date.self, forKey: .relayedAt)
        self.attachmentId = try c.decodeIfPresent(Data.self, forKey: .attachmentId)
        self.chunkIndex = try c.decodeIfPresent(UInt32.self, forKey: .chunkIndex)
        self.chunkCount = try c.decodeIfPresent(UInt32.self, forKey: .chunkCount)
    }
}

extension OutboxEntry {
    enum Status: Sendable, Equatable {
        case pending     // ⏳ — in retry queue, not yet through NWConnection
        case relayed     // ✓  — relay accepted the bytes
        case delivered   // ✓✓ — peer ACKed
        case failed      // ✗  — TTL expired without ACK
    }

    var status: Status {
        if deliveredAt != nil { return .delivered }
        if failedAt != nil { return .failed }
        if relayedAt != nil { return .relayed }
        return .pending
    }

    /// True iff the retry timer should attempt to re-send this entry.
    /// F-501 schedule:
    /// - Terminal states (`deliveredAt`/`failedAt`) → no retry.
    /// - `relayedAt != nil` (relay accepted bytes; only the peer's ACK
    ///   is missing): cap at `maxRetriesAfterRelayed = 3` and use
    ///   exponential backoff `60 * 2^retries` capped at 1h. Relay
    ///   acceptance means further retries unlikely to help — the bytes
    ///   either reached the peer (and the ACK is in flight / lost) or
    ///   the peer is offline; either way exponential backoff is the
    ///   right shape, and capping at 3 turns the F-501 "11-token-burn-
    ///   per-message" attack into "4-token-burn-per-message".
    /// - `relayedAt == nil` (transient relay outage / disconnect):
    ///   keep the historic `min(60 + retries*60)` baseline up to
    ///   `maxRetries = 10` since the original send hasn't even
    ///   reached the relay; tokens were already popped, so retrying
    ///   doesn't burn extra stash on the sender side.
    func shouldRetry(now: Date) -> Bool {
        guard deliveredAt == nil, failedAt == nil else { return false }
        let elapsed = now.timeIntervalSince(sentAt)
        if relayedAt != nil {
            guard retries < OutboxEntry.maxRetriesAfterRelayed else { return false }
            // Exponential: 60s, 120s, 240s after the original send.
            let backoff = min(60.0 * pow(2.0, Double(retries)), 3600.0)
            return elapsed > backoff
        } else {
            guard retries < OutboxEntry.maxRetries else { return false }
            let baseline = max(30.0, TimeInterval(retries) * 60.0)
            return elapsed > baseline
        }
    }

    /// True iff `now` is past `sentAt + ttl` and we still have no ACK.
    /// Caller stamps `failedAt` when this fires so the UI flips to ✗.
    func hasExpired(now: Date) -> Bool {
        guard deliveredAt == nil, failedAt == nil else { return false }
        return now.timeIntervalSince(sentAt) > ttl
    }

    /// Cap on retries while the relay has not yet acknowledged the
    /// original send (transient relay disconnect / queueing). Retains
    /// the historic max so we don't regress this path.
    static let maxRetries: Int = 10
    /// Cap on retries AFTER the relay has acked the original send
    /// (`relayedAt != nil`). F-501: turns a malicious-paired-peer
    /// "drop every ACK" attack into a 4-token burn instead of 11.
    static let maxRetriesAfterRelayed: Int = 3
}

/// Codable container so we can persist the whole outbox in one
/// Keychain blob. Keyed on messageId for O(1) ACK lookups.
struct OutboxStore: Codable, Sendable {
    var entries: [Data: OutboxEntry] = [:]

    static let empty = OutboxStore()

    /// Sorted-newest-first list. Used for retry walks (oldest first
    /// would risk burning tokens on stale entries when the relay just
    /// came back, which is the opposite of what the user wants).
    var byNewest: [OutboxEntry] {
        entries.values.sorted { $0.sentAt > $1.sentAt }
    }

    /// All currently-retryable entries, oldest first so the retry path
    /// processes them in submission order.
    func retryableEntries(now: Date) -> [OutboxEntry] {
        entries.values
            .filter { $0.shouldRetry(now: now) }
            .sorted { $0.sentAt < $1.sentAt }
    }

    /// Roll up status across every chunk that belongs to a chunked
    /// attachment. Used by the chat row to drive ⏳/✓/✓✓/✗ for the
    /// attachment as a whole rather than its individual chunks (the
    /// user just sees "the photo"; the chunk count is plumbing).
    /// Status precedence (worst-wins):
    ///   `failed` > `pending` > `relayed` > `delivered`
    /// — that matches how the user reads the row: any failure ✗ wins,
    /// otherwise the slowest tier across chunks. An attachment with
    /// no entries (already GC'd post-delivery) returns nil; the row
    /// falls back to "no status" which is fine post-completion.
    func attachmentStatus(forId attachmentId: Data) -> OutboxEntry.Status? {
        let chunks = entries.values.filter { $0.attachmentId == attachmentId }
        guard !chunks.isEmpty else { return nil }
        if chunks.contains(where: { $0.status == .failed }) { return .failed }
        if chunks.contains(where: { $0.status == .pending }) { return .pending }
        if chunks.contains(where: { $0.status == .relayed }) { return .relayed }
        return .delivered
    }
}
