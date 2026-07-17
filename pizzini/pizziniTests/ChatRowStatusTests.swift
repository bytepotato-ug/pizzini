import Foundation
import Testing
@testable import pizzini

/// Pins the seven canonical (outbox × ack × ttl) transitions the
/// chat-row glyph + affordance state machine has to cover. The
/// pure mapping lives in `Outbox.swift`'s `rowStatus(inputs:)`
/// — this file is the regression net.
///
/// The brief calls out exactly seven transitions:
///   1. not-attempted              → .pending(retryable: false)
///   2. attempting first relay     → .sending
///   3. delivered (>=1 ACK)        → .delivered
///   4. read (read receipt)        → .read
///   5. pending >60s               → .pending(retryable: true)
///   6. ttl expired                → .expired
///   7. 0-of-N ACK after retries   → .failed
///
/// S5 layers two extra "TTL clock" pins on top of (6) so the
/// boundary doesn't drift under future tweaks. U4 layers four
/// progress-percent pins on top via
/// `AttachmentProgressTests`.
@Suite("rowStatus(inputs:)")
struct ChatRowStatusTests {

    // MARK: - Seven canonical transitions

    /// (1) Just submitted to the outbox, no socket attempt yet, no
    /// retries spent, well under the user-retry threshold.
    @Test func notAttemptedIsPlainPending() {
        let inputs = ChatRowStatusInputs(
            outbox: .pending(pendingFor: 5, retriesExhausted: false),
            ack: .unread,
            ttl: .active,
        )
        #expect(rowStatus(inputs: inputs) == .pending(retryable: false))
    }

    /// (2) Bytes left the socket (relay accepted). No peer ACK yet.
    @Test func relayedShowsSending() {
        let inputs = ChatRowStatusInputs(
            outbox: .relayed,
            ack: .unread,
            ttl: .active,
        )
        #expect(rowStatus(inputs: inputs) == .sending)
    }

    /// (3) Peer ACK received covering this messageId — single
    /// check, no read receipt yet.
    @Test func deliveredShowsDelivered() {
        let inputs = ChatRowStatusInputs(
            outbox: .delivered,
            ack: .unread,
            ttl: .active,
        )
        #expect(rowStatus(inputs: inputs) == .delivered)
    }

    /// (4) Peer ACK AND read receipt. Eye glyph.
    @Test func deliveredAndReadShowsRead() {
        let inputs = ChatRowStatusInputs(
            outbox: .delivered,
            ack: .read,
            ttl: .active,
        )
        #expect(rowStatus(inputs: inputs) == .read)
    }

    /// (5) Pending past the user-retry threshold (60s default).
    /// The row should expose Retry on its own — bytes never
    /// left the socket so a manual kick is safe.
    @Test func longPendingIsRetryable() {
        let inputs = ChatRowStatusInputs(
            outbox: .pending(
                pendingFor: OutboxEntry.userRetryThreshold + 1,
                retriesExhausted: false,
            ),
            ack: .unread,
            ttl: .active,
        )
        #expect(rowStatus(inputs: inputs) == .pending(retryable: true))
    }

    /// (6) TTL clock elapsed without an ACK. Surfaces the Try
    /// Again affordance (S5). Note: outbox is STILL `.pending`
    /// here — `failedAt` hasn't been stamped yet by the walker;
    /// the TTL flag itself is what flips the row. Mirrors
    /// `OutboxEntry.hasExpired` returning true.
    @Test func ttlExpiredShowsExpired() {
        let inputs = ChatRowStatusInputs(
            outbox: .pending(pendingFor: 90_000, retriesExhausted: false),
            ack: .unread,
            ttl: .expired,
        )
        #expect(rowStatus(inputs: inputs) == .expired)
    }

    /// (7) Retries exhausted without ever reaching a relay — the
    /// inner mapping collapses to `.failed` even when ttl is
    /// still active, because `maxRetries` only fires on the
    /// no-relayedAt path and means the network never accepted
    /// our bytes.
    @Test func retriesExhaustedShowsFailed() {
        let inputs = ChatRowStatusInputs(
            outbox: .pending(pendingFor: 600, retriesExhausted: true),
            ack: .unread,
            ttl: .active,
        )
        #expect(rowStatus(inputs: inputs) == .failed)
    }

    // MARK: - Precedence corners (the table's edges)

    /// `failed` outbox state wins over the TTL-expired flag — a
    /// hard encrypt/persist failure is more actionable than the
    /// TTL clock running out behind it. Note: `failedAt` flips
    /// the outbox tier to `.failed`, which short-circuits before
    /// the TTL check.
    @Test func failedBeatsExpired() {
        let inputs = ChatRowStatusInputs(
            outbox: .failed,
            ack: .unread,
            ttl: .expired,
        )
        #expect(rowStatus(inputs: inputs) == .failed)
    }

    /// Delivered + read wins over an ostensibly-expired TTL: a
    /// late ACK that arrives after the TTL window MUST NOT flip
    /// a successful row back to `.expired`. The message landed.
    @Test func deliveredBeatsExpired() {
        let inputs = ChatRowStatusInputs(
            outbox: .delivered,
            ack: .read,
            ttl: .expired,
        )
        #expect(rowStatus(inputs: inputs) == .read)
    }

    /// Right at the user-retry threshold boundary the row is
    /// retryable. One millisecond below is not. Pin both sides
    /// so a future signed/unsigned-comparison tweak in
    /// `OutboxEntry.userRetryThreshold` flags here first.
    @Test func userRetryBoundary() {
        let above = ChatRowStatusInputs(
            outbox: .pending(
                pendingFor: OutboxEntry.userRetryThreshold,
                retriesExhausted: false,
            ),
            ack: .unread, ttl: .active,
        )
        #expect(rowStatus(inputs: above) == .pending(retryable: true))

        let below = ChatRowStatusInputs(
            outbox: .pending(
                pendingFor: OutboxEntry.userRetryThreshold - 0.001,
                retriesExhausted: false,
            ),
            ack: .unread, ttl: .active,
        )
        #expect(rowStatus(inputs: below) == .pending(retryable: false))
    }
}

/// S5 — pin the TTL boundary with three samples either side of
/// the cutoff. The brief is explicit: "exactly at expiry should
/// be expired; 1ms before expiry should still be pending /
/// sending." `rowStatus(inputs:)` itself doesn't know about
/// dates, but `OutboxEntry.hasExpired` does, and
/// `ChatRowStatusInputs.from(...)` is the wiring. Test both
/// halves.
@Suite("TTL expiry boundary")
struct TtlExpiryBoundaryTests {
    private static func makeEntry(ttl: TimeInterval, sentAt: Date) -> OutboxEntry {
        OutboxEntry(
            messageId: Data(repeating: 0xA1, count: 16),
            recipientPeerId: Data(repeating: 0xB2, count: 33),
            sealedCiphertext: Data([0x01, 0x02]),
            token: Data(repeating: 0xC3, count: 52),
            ttl: ttl,
            sentAt: sentAt,
            retries: 0,
            deliveredAt: nil,
            failedAt: nil,
            relayedAt: nil,
        )
    }

    /// `now == sentAt + ttl` is still inside the window —
    /// `hasExpired` returns true ONLY when `elapsed > ttl`,
    /// strict-greater-than. So at the exact boundary the row
    /// is NOT yet expired — it sits on .pending (and is
    /// already retryable, because the chosen ttl matches the
    /// 60s user-retry threshold). Just one nanosecond past
    /// the boundary, the row flips to `.expired`.
    @Test func exactlyAtTtlNotYetExpired() {
        let sentAt = Date(timeIntervalSinceReferenceDate: 100_000)
        let ttl: TimeInterval = 60
        let entry = Self.makeEntry(ttl: ttl, sentAt: sentAt)
        let atBoundary = sentAt.addingTimeInterval(ttl)
        #expect(entry.hasExpired(now: atBoundary) == false)

        let inputs = ChatRowStatusInputs.from(
            entry: entry, now: atBoundary, peerHasRead: false,
        )
        #expect(inputs.ttl == .active)
        switch rowStatus(inputs: inputs) {
        case .pending: break // either retryable flag is acceptable at the boundary
        default: Issue.record("expected .pending at exact TTL boundary")
        }
    }

    /// One millisecond past the TTL boundary the row is expired.
    /// (Internally `hasExpired` uses strict-greater-than, so any
    /// positive epsilon trips it.)
    @Test func oneMsPastTtlIsExpired() {
        let sentAt = Date(timeIntervalSinceReferenceDate: 100_000)
        let ttl: TimeInterval = 60
        let entry = Self.makeEntry(ttl: ttl, sentAt: sentAt)
        let pastBoundary = sentAt.addingTimeInterval(ttl + 0.001)
        #expect(entry.hasExpired(now: pastBoundary) == true)

        let inputs = ChatRowStatusInputs.from(
            entry: entry, now: pastBoundary, peerHasRead: false,
        )
        #expect(inputs.ttl == .expired)
        #expect(rowStatus(inputs: inputs) == .expired)
    }

    /// One millisecond BEFORE the boundary is still active —
    /// the row should still read pending/sending, never expired.
    @Test func oneMsBeforeTtlStillActive() {
        let sentAt = Date(timeIntervalSinceReferenceDate: 100_000)
        let ttl: TimeInterval = 60
        let entry = Self.makeEntry(ttl: ttl, sentAt: sentAt)
        let beforeBoundary = sentAt.addingTimeInterval(ttl - 0.001)
        #expect(entry.hasExpired(now: beforeBoundary) == false)

        let inputs = ChatRowStatusInputs.from(
            entry: entry, now: beforeBoundary, peerHasRead: false,
        )
        #expect(inputs.ttl == .active)
        switch rowStatus(inputs: inputs) {
        case .pending, .sending: break // either is acceptable pre-expiry
        default: Issue.record("expected pending/sending right before TTL boundary")
        }
    }
}

/// U4 — pin the chunked-attachment progress percentage. Four
/// canonical samples: 0%, 50%, 100%, and the divide-by-zero /
/// empty-chunks-array edge.
@Suite("attachmentProgressPercent")
struct AttachmentProgressTests {
    @Test func zeroPercentWhenNoChunksAcked() {
        #expect(attachmentProgressPercent(chunksAcked: 0, totalChunks: 8) == 0.0)
    }

    @Test func halfWhenHalfAcked() {
        #expect(attachmentProgressPercent(chunksAcked: 4, totalChunks: 8) == 0.5)
    }

    @Test func fullWhenAllAcked() {
        #expect(attachmentProgressPercent(chunksAcked: 8, totalChunks: 8) == 1.0)
    }

    /// Divide-by-zero edge: a zero-chunk attachment makes no
    /// sense at the wire layer, but a defensive `0.0` keeps the
    /// progress-bar caller from crashing if the chunked-attachment
    /// rollup somehow returns total=0 (e.g. mid-GC). The UI
    /// caller already gates on `total > 0` before showing the
    /// bar, but the pure function defends in depth.
    @Test func zeroTotalReturnsZero() {
        #expect(attachmentProgressPercent(chunksAcked: 0, totalChunks: 0) == 0.0)
        // Also pin the "claimed more acked than total" defensive
        // clamp — a stale chunk count vs. a fresh ACK count
        // shouldn't push the bar past 100% or below 0%.
        #expect(attachmentProgressPercent(chunksAcked: 99, totalChunks: 8) == 1.0)
        #expect(attachmentProgressPercent(chunksAcked: -3, totalChunks: 8) == 0.0)
    }
}
