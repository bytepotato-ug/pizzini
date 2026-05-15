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
    /// The 52-byte v2 hash-chain delivery token attached to the
    /// original SEND. **F-505**: scrubbed to empty once
    /// `relayedAt != nil` — the relay has accepted the bytes, and
    /// storing the token onward only widens the post-extraction
    /// replay surface against the per-(recipient, chain_id) state.
    /// Retries that fire BEFORE `relayedAt` is set re-derive a fresh
    /// token from the chain at retry time; retries AFTER are blocked
    /// by F-501's relayedAt-aware cap.
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

    // MARK: - Phase 7 group fan-out grouping
    /// 16-byte stable id of the LOGICAL group message this pairwise
    /// send is one leg of. A group send to N members produces N
    /// OutboxEntries (one per recipient) sharing the same
    /// `groupMessageId`; a group attachment send produces N × chunkCount
    /// entries sharing the same `groupMessageId` AND `attachmentId`.
    /// The chat-row indicator rolls up via
    /// `OutboxStore.groupMessageStatus(forId:)`. Nil for 1:1 entries
    /// and for non-chat housekeeping entries.
    var groupMessageId: Data?
    /// `Date` the recipient emitted a 0x04 readReceipt covering this
    /// pairwise send. The aggregate "group message read by all" eye-
    /// glyph fires when every entry under the same `groupMessageId`
    /// has `readAt != nil`. F-405 read-receipts-symmetry rule from 1:1
    /// applies — we only honour an incoming readReceipt if the local
    /// user's `readReceiptsEnabled` toggle is ON for that contact.
    var readAt: Date?

    private enum CodingKeys: String, CodingKey {
        case messageId, recipientPeerId, sealedCiphertext, token, ttl, sentAt
        case retries, deliveredAt, failedAt, relayedAt
        case attachmentId, chunkIndex, chunkCount
        case groupMessageId, readAt
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
        chunkCount: UInt32? = nil,
        groupMessageId: Data? = nil,
        readAt: Date? = nil
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
        self.groupMessageId = groupMessageId
        self.readAt = readAt
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
        self.groupMessageId = try c.decodeIfPresent(Data.self, forKey: .groupMessageId)
        self.readAt = try c.decodeIfPresent(Date.self, forKey: .readAt)
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
    /// - Terminal states (`deliveredAt`/`failedAt`) → no retry.
    /// - `relayedAt != nil` (a relay has accepted the bytes) → no
    ///   retry, ever. The message is in that relay's offline queue
    ///   under its own TTL and WILL reach the recipient on their next
    ///   connect; re-sending cannot make an offline recipient online.
    ///   A retry would only mint fresh single-use delivery tokens
    ///   (chain drain), queue duplicate frames, and fire duplicate
    ///   "New message" pushes at the recipient. The entry resolves to
    ///   ✓✓ on the peer ACK or ✗ at `ttl`. This also fully closes
    ///   F-501's "drop every ACK to burn the sender's tokens" attack:
    ///   zero post-relay token burn.
    /// - `relayedAt == nil` (the send never reached a relay —
    ///   transient outage / disconnect): retry up to `maxRetries` on
    ///   the `max(30, retries*60)` baseline. Each retry re-derives a
    ///   fresh token; this is the only path that legitimately
    ///   re-sends.
    func shouldRetry(now: Date) -> Bool {
        guard deliveredAt == nil, failedAt == nil else { return false }
        // A relayed entry is never retried — see the doc comment.
        guard relayedAt == nil else { return false }
        guard retries < OutboxEntry.maxRetries else { return false }
        let elapsed = now.timeIntervalSince(sentAt)
        let baseline = max(30.0, TimeInterval(retries) * 60.0)
        return elapsed > baseline
    }

    /// True iff `now` is past `sentAt + ttl` and we still have no ACK.
    /// Caller stamps `failedAt` when this fires so the UI flips to ✗.
    func hasExpired(now: Date) -> Bool {
        guard deliveredAt == nil, failedAt == nil else { return false }
        return now.timeIntervalSince(sentAt) > ttl
    }

    /// Cap on retries while the relay has not yet accepted the
    /// original send (transient relay disconnect / queueing). Once a
    /// relay HAS accepted the bytes `shouldRetry` stops outright, so
    /// there is no separate post-relay cap — there are no post-relay
    /// retries.
    static let maxRetries: Int = 10

    /// How long a `pending` outbox entry sits without bytes leaving
    /// the socket before the UI marks it user-retryable. Below this
    /// the spinner is enough signal; above it the user has been
    /// staring at an hourglass long enough to suspect we're stuck,
    /// and a tappable "Retry" affordance starts being more help than
    /// noise. Matches the 60s baseline the auto-retry walker uses
    /// for its first re-broadcast attempt.
    static let userRetryThreshold: TimeInterval = 60
}

/// UI-facing rollup of every condition that drives the chat-row
/// status glyph and any inline affordance (a Retry button on a
/// stuck row, a Try Again button on an expired row, a progress
/// bar on an in-flight attachment). The six cases below are the
/// *complete* set of states any outbound row can be in — if you
/// find yourself wanting a 7th, audit whether one of these
/// already covers it before adding.
///
/// Pinned in `ChatRowStatusTests` against the canonical
/// transition table.
enum ChatRowStatus: Equatable, Sendable {
    /// Submitted to the outbox but bytes have NOT yet left the
    /// socket. `retryable == true` once the entry has been sitting
    /// past `OutboxEntry.userRetryThreshold` so the row can show
    /// a tappable "Retry" affordance rather than an indefinite
    /// hourglass.
    case pending(retryable: Bool)
    /// Bytes left the socket (relay accepted the SEND) but no
    /// peer ACK has arrived. The first observable "we are doing
    /// something" state after pending.
    case sending
    /// Peer returned at least one ACK covering this messageId.
    /// `✓` glyph.
    case delivered
    /// Peer returned a read receipt covering this messageId AND
    /// the local user honours receipts for this contact (so the
    /// eye glyph is permitted to render). `✓✓` / eye glyph.
    case read
    /// `sentAt + ttl` elapsed without a peer ACK. Terminal until
    /// the user taps "Try Again" — which re-queues the message
    /// under the current TTL clock.
    case expired
    /// Retries exhausted with no relay ever accepting the bytes
    /// (network/encrypt/persist failures). Terminal — no Try
    /// Again path because no relay was ever reached.
    case failed
}

/// Inputs to `rowStatus` — three orthogonal slices of the outbox
/// row's state, deliberately split so the pure function has no
/// hidden Date / I/O dependency.
struct ChatRowStatusInputs: Equatable, Sendable {
    /// Coarse outbox tier — derived from `OutboxEntry.status` or
    /// from the chunked-attachment rollup.
    enum Outbox: Equatable, Sendable {
        /// No bytes on the wire yet, `pendingFor` is the elapsed
        /// time since the entry was submitted to the outbox.
        case pending(pendingFor: TimeInterval, retriesExhausted: Bool)
        /// Bytes left the socket; relay accepted the SEND. No
        /// peer ACK yet.
        case relayed
        /// Peer ACK received covering this messageId.
        case delivered
        /// Underlying `OutboxEntry.failedAt` is set — encrypt or
        /// session-persist failed before the bytes could be
        /// safely broadcast.
        case failed
    }
    enum Ack: Equatable, Sendable {
        case unread
        case read
    }
    enum Ttl: Equatable, Sendable {
        case active
        case expired
    }

    var outbox: Outbox
    var ack: Ack
    var ttl: Ttl
}

/// Pure mapping from `(outboxState, ackState, ttlState)` to the
/// glyph + affordance the chat row should render. Lives next to
/// `OutboxEntry` rather than in `ChatView` so unit tests can pin
/// the table without bringing SwiftUI in.
///
/// Precedence (top wins on every conflict):
///   1. `outbox == .delivered` AND `ack == .read` → `.read`
///   2. `outbox == .delivered`                    → `.delivered`
///   3. `outbox == .failed`                       → `.failed`
///   4. `ttl == .expired`                         → `.expired`
///   5. `outbox == .relayed`                      → `.sending`
///   6. `outbox == .pending`                      → `.pending(retryable: …)`
///
/// Notes on the ordering:
///   - Delivered/read wins over expired: if the peer already
///     ACKed and we later notice the TTL passed, the message
///     LANDED. The row stays at ✓/eye, never flips to ✗.
///   - Failed wins over expired: a hard encrypt/persist failure
///     is more actionable to the user than the TTL clock running
///     out behind it.
///   - Expired wins over pending/sending: once the TTL is past,
///     the message will not be accepted by the recipient even if
///     a late ACK arrives. Surface "Try Again" rather than a
///     hopeful spinner.
func rowStatus(inputs: ChatRowStatusInputs) -> ChatRowStatus {
    if inputs.outbox == .delivered {
        return inputs.ack == .read ? .read : .delivered
    }
    if inputs.outbox == .failed {
        return .failed
    }
    if inputs.ttl == .expired {
        return .expired
    }
    if inputs.outbox == .relayed {
        return .sending
    }
    if case .pending(let pendingFor, let retriesExhausted) = inputs.outbox {
        if retriesExhausted {
            return .failed
        }
        let retryable = pendingFor >= OutboxEntry.userRetryThreshold
        return .pending(retryable: retryable)
    }
    // Unreachable — the enum is exhausted above; the explicit
    // return keeps the compiler happy without adding a default
    // branch that would swallow a future enum addition silently.
    return .pending(retryable: false)
}

extension ChatRowStatusInputs {
    /// Build the inputs row from a concrete `OutboxEntry` + the
    /// current wall clock + an optional peer-read flag.
    static func from(
        entry: OutboxEntry,
        now: Date,
        peerHasRead: Bool,
    ) -> ChatRowStatusInputs {
        let outbox: Outbox
        if entry.deliveredAt != nil {
            outbox = .delivered
        } else if entry.failedAt != nil {
            outbox = .failed
        } else if entry.relayedAt != nil {
            outbox = .relayed
        } else {
            outbox = .pending(
                pendingFor: now.timeIntervalSince(entry.sentAt),
                retriesExhausted: entry.retries >= OutboxEntry.maxRetries,
            )
        }
        let ack: Ack = peerHasRead ? .read : .unread
        let ttl: Ttl = entry.hasExpired(now: now) ? .expired : .active
        return ChatRowStatusInputs(outbox: outbox, ack: ack, ttl: ttl)
    }
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

    /// Roll up status across every pairwise leg of a group fan-out.
    /// A group message to N members produces N entries (text) or
    /// N × chunkCount entries (attachment); the chat row needs ONE
    /// indicator. Same worst-wins precedence as
    /// `attachmentStatus(forId:)`: any failure ✗ wins, otherwise the
    /// slowest tier across the legs. A group message with no entries
    /// (post-GC) returns nil; the row falls back to "no status".
    func groupMessageStatus(forId groupMessageId: Data) -> OutboxEntry.Status? {
        let legs = entries.values.filter { $0.groupMessageId == groupMessageId }
        guard !legs.isEmpty else { return nil }
        if legs.contains(where: { $0.status == .failed }) { return .failed }
        if legs.contains(where: { $0.status == .pending }) { return .pending }
        if legs.contains(where: { $0.status == .relayed }) { return .relayed }
        return .delivered
    }

    /// True iff every pairwise leg of the named group message has
    /// `readAt != nil`. The eye glyph in `GroupChatBubble` lights when
    /// status == .delivered AND this returns true. Returns false (NOT
    /// nil) when no entries exist — post-GC, we don't surface a stale
    /// "all read" claim from a row whose backing receipts have aged
    /// out. F-405-style honesty: only assert "read by everyone" when
    /// we have explicit per-recipient confirmation in hand.
    func groupMessageReadByAll(forId groupMessageId: Data) -> Bool {
        let legs = entries.values.filter { $0.groupMessageId == groupMessageId }
        guard !legs.isEmpty else { return false }
        return legs.allSatisfy { $0.readAt != nil }
    }

    /// Cutoff date for a read receipt covering up to `highest`
    /// messageId. PREFERS the `.me` log row's `timestamp` over the
    /// outbox entry's `sentAt` — the log timestamp is created
    /// strictly after the outbox `sentAt` (sentAt is captured before
    /// `encryptSealed`; the log row is built post-relay-handoff), so
    /// using `sentAt` as the cutoff would silently skip the row the
    /// receipt explicitly cites (regression that showed as "eye
    /// only lights on the previous message when a new one is sent").
    /// Falls back to the outbox entry's `sentAt` only when the log
    /// row has already been GC'd. Returns `nil` when neither source
    /// has the messageId — the receipt is too late.
    static func readReceiptCutoff(
        highest: Data,
        log: [PersistedMessage],
        outbox: OutboxStore,
    ) -> Date? {
        if let row = log.last(where: { $0.side == .me && $0.messageId == highest }) {
            return row.timestamp
        }
        if let entry = outbox.entries[highest] {
            return entry.sentAt
        }
        return nil
    }
}
