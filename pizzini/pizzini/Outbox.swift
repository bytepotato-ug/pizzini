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
    let token: Data
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
    /// `deliveredAt`/`failedAt` are terminal states; `retries` caps the
    /// total attempts at 10 to avoid burning the token stash on a peer
    /// who's gone for good before TTL expiry catches it.
    func shouldRetry(now: Date) -> Bool {
        guard deliveredAt == nil, failedAt == nil else { return false }
        guard retries < OutboxEntry.maxRetries else { return false }
        let baseline = max(30.0, TimeInterval(retries) * 60.0)
        return now.timeIntervalSince(sentAt) > baseline
    }

    /// True iff `now` is past `sentAt + ttl` and we still have no ACK.
    /// Caller stamps `failedAt` when this fires so the UI flips to ✗.
    func hasExpired(now: Date) -> Bool {
        guard deliveredAt == nil, failedAt == nil else { return false }
        return now.timeIntervalSince(sentAt) > ttl
    }

    static let maxRetries: Int = 10
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
}
