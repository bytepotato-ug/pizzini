import Foundation
import Testing
@testable import pizzini

/// `DuplicateAckSuppressor` is the defence against the chain-token
/// runaway documented in QA-debug capture 2026-05-13 (22,088
/// duplicate-frame events, 5,704 chain-exhaustion lines, single
/// peer, single foreground/background cycle). Every behaviour the
/// host relies on is pinned by an assertion below; if any of these
/// regress, the runaway can recur silently.
@Suite("DuplicateAckSuppressor — per-(peer, messageId) sliding window")
struct DuplicateAckSuppressorTests {

    /// 32-byte synthetic peer identity_pub. Matches production
    /// width so the internal `peer ‖ messageId` key has the same
    /// shape it does in the live app.
    private static func peer(_ tag: UInt8) -> Data {
        Data(repeating: tag, count: 32)
    }

    /// 16-byte synthetic messageId. Matches the production
    /// `makeMessageId()` width (UUID bytes).
    private static func msgId(_ tag: UInt8) -> Data {
        Data(repeating: tag, count: 16)
    }

    /// A fresh suppressor sees no prior emission, so the first ACK
    /// for a (peer, messageId) pair must NOT be suppressed.
    @Test("fresh entry is never suppressed")
    func freshEntryNotSuppressed() {
        let s = DuplicateAckSuppressor()
        #expect(!s.shouldSuppress(peer: Self.peer(1), messageId: Self.msgId(1)))
    }

    /// After recording an emission, the SAME (peer, messageId) must
    /// be suppressed on the next check — this is the whole point of
    /// the type: prevent re-emission for already-acked messageIds.
    @Test("recorded entry is suppressed within TTL")
    func recordedEntrySuppressed() {
        var s = DuplicateAckSuppressor()
        let p = Self.peer(1)
        let m = Self.msgId(1)
        s.record(peer: p, messageId: m)
        #expect(s.shouldSuppress(peer: p, messageId: m))
    }

    /// Different messageIds for the same peer must NOT collide.
    /// The key composition (`peer ‖ messageId`) makes this
    /// trivially correct, but pinning it prevents a future "let's
    /// just use peer for the key" simplification from silently
    /// breaking the per-message semantics.
    @Test("different messageId for same peer is independent")
    func differentMessageIdIsIndependent() {
        var s = DuplicateAckSuppressor()
        let p = Self.peer(1)
        s.record(peer: p, messageId: Self.msgId(1))
        #expect(!s.shouldSuppress(peer: p, messageId: Self.msgId(2)))
    }

    /// Different peers for the same messageId must NOT collide.
    /// Same reasoning as above on the peer axis — messageIds are
    /// only unique within a (peer, peer) conversation, so two
    /// different peers could in principle pick the same one.
    @Test("same messageId from different peer is independent")
    func differentPeerIsIndependent() {
        var s = DuplicateAckSuppressor()
        let m = Self.msgId(1)
        s.record(peer: Self.peer(1), messageId: m)
        #expect(!s.shouldSuppress(peer: Self.peer(2), messageId: m))
    }

    /// Once a record's timestamp falls outside the TTL window, it
    /// must NOT suppress anymore. This is the relief valve that
    /// lets a genuinely-lost ACK get a fresh emission attempt
    /// after enough time has passed.
    @Test("entry past TTL is not suppressed")
    func entryPastTTLIsNotSuppressed() {
        var s = DuplicateAckSuppressor(ttl: 60)
        let p = Self.peer(1)
        let m = Self.msgId(1)
        let t0 = Date()
        s.record(peer: p, messageId: m, now: t0)
        let later = t0.addingTimeInterval(61)
        #expect(!s.shouldSuppress(peer: p, messageId: m, now: later))
    }

    /// Re-record before the TTL elapses bumps the timestamp; the
    /// effective expiry slides forward. A duplicate flood that
    /// keeps re-recording (which production code does NOT do —
    /// the host only records on a real emit) would extend the
    /// window indefinitely. We don't rely on this behaviour in
    /// production but pin it so the contract is unambiguous.
    @Test("re-record refreshes timestamp")
    func reRecordRefreshesTimestamp() {
        var s = DuplicateAckSuppressor(ttl: 60)
        let p = Self.peer(1)
        let m = Self.msgId(1)
        let t0 = Date()
        s.record(peer: p, messageId: m, now: t0)
        let t1 = t0.addingTimeInterval(30)
        s.record(peer: p, messageId: m, now: t1)
        // Still inside the window from t1; t1+45 is still within ttl.
        let t2 = t1.addingTimeInterval(45)
        #expect(s.shouldSuppress(peer: p, messageId: m, now: t2))
        // Past t1+ttl, expired.
        let t3 = t1.addingTimeInterval(61)
        #expect(!s.shouldSuppress(peer: p, messageId: m, now: t3))
    }

    /// FIFO eviction: once the capacity is exceeded, the OLDEST
    /// (first-inserted) entry is dropped. We can't observe the
    /// drop directly but we can drive the suppressor over capacity
    /// and assert that the count never exceeds the cap.
    @Test("capacity bounds the entry count")
    func capacityBoundsEntries() {
        var s = DuplicateAckSuppressor(capacity: 4)
        for i: UInt8 in 1...10 {
            s.record(peer: Self.peer(1), messageId: Self.msgId(i))
        }
        #expect(s.count == 4, "exactly capacity entries retained, got \(s.count)")
    }

    /// FIFO direction: when capacity is exceeded, the oldest
    /// `record`-ed entry becomes the first to drop. After
    /// inserting messages 1..5 with capacity 4, message 1 should
    /// be gone (and therefore no longer suppressed) while 5 should
    /// be retained.
    @Test("FIFO drops oldest first")
    func fifoDropsOldest() {
        var s = DuplicateAckSuppressor(capacity: 4)
        let p = Self.peer(1)
        for i: UInt8 in 1...5 {
            s.record(peer: p, messageId: Self.msgId(i))
        }
        #expect(!s.shouldSuppress(peer: p, messageId: Self.msgId(1)),
                "oldest (1) evicted")
        #expect(s.shouldSuppress(peer: p, messageId: Self.msgId(5)),
                "newest (5) retained")
    }

    /// Storm regression: simulate the exact pattern observed in
    /// the QA-debug capture — one peer, many distinct messageIds,
    /// each replayed thousands of times via the relay's at-least-
    /// once redelivery. The first emission for each messageId
    /// goes through; every subsequent duplicate for the SAME
    /// messageId is suppressed. Without this contract, the chain
    /// burns one token per duplicate.
    @Test("storm of duplicates for same messageId is suppressed after first")
    func stormOfDuplicatesSuppressed() {
        var s = DuplicateAckSuppressor()
        let p = Self.peer(1)
        let m = Self.msgId(1)
        // First emit: not suppressed; host calls emitAck + record.
        #expect(!s.shouldSuppress(peer: p, messageId: m))
        s.record(peer: p, messageId: m)
        // Every subsequent duplicate within the TTL is suppressed.
        for _ in 0..<10_000 {
            #expect(s.shouldSuppress(peer: p, messageId: m))
        }
    }

    /// `purgeExpired` drops stale entries and leaves fresh ones
    /// alone. Test hook only — production doesn't call it, but
    /// having the predicate well-defined and tested gives us a
    /// place to wire periodic cleanup if memory bounding ever
    /// becomes interesting beyond the FIFO cap.
    @Test("purgeExpired drops stale, keeps fresh")
    func purgeExpiredDropsStale() {
        var s = DuplicateAckSuppressor(ttl: 60)
        let p = Self.peer(1)
        let t0 = Date()
        s.record(peer: p, messageId: Self.msgId(1), now: t0)
        s.record(peer: p, messageId: Self.msgId(2), now: t0.addingTimeInterval(50))
        let now = t0.addingTimeInterval(70)
        // msgId(1) is 70s old, > ttl=60 → drop.
        // msgId(2) is 20s old → keep.
        s.purgeExpired(now: now)
        #expect(s.count == 1)
        #expect(!s.shouldSuppress(peer: p, messageId: Self.msgId(1), now: now))
        #expect(s.shouldSuppress(peer: p, messageId: Self.msgId(2), now: now))
    }
}
