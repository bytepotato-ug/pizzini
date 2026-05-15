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

