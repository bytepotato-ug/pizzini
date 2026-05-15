// RelayFanoutVerdictTests
//
// Pins the per-relay fanout aggregator (D3, app-side fanout across
// three independent onions). The contract: one ACK out of N is
// sufficient for `.delivered` — sibling relays' refusals do NOT
// downgrade the verdict, because libsignal's receive-side dedupe
// drops the redundant copies. Only when zero relays ACK AND no
// retryable outcome is left should the verdict be `.failed`.
//
// If any future refactor collapses the aggregator back to "all must
// ACK" or "first ACK wins, the rest cancel," the user-visible
// effect is silent message loss on a multi-relay fleet with a
// flaky member — exactly the failure mode multi-relay was built to
// neutralise.

import Foundation
import PizziniCryptoCore
import Testing

@Suite("Per-relay fanout verdict (D3)")
struct RelayFanoutVerdictTests {

    // MARK: - Truth-table rows from the brief

    @Test func threeOfThreeAckIsDelivered() {
        let v = relayFanoutVerdict([.ack, .ack, .ack])
        #expect(v == .delivered)
    }

    @Test func twoOfThreeAckIsDelivered() {
        let v = relayFanoutVerdict([
            .ack,
            .ack,
            .nack(reason: "token replay"),
        ])
        #expect(v == .delivered)
    }

    @Test func oneOfThreeAckIsDelivered() {
        let v = relayFanoutVerdict([
            .nack(reason: "token replay"),
            .ack,
            .timeout,
        ])
        #expect(v == .delivered)
    }

    /// 0 of 3 ACK after every outcome is a hard refusal (`.nack`) →
    /// `.failed`. No retryable outcome left to wait on.
    @Test func zeroOfThreeAllNackIsFailed() {
        let v = relayFanoutVerdict([
            .nack(reason: "token replay"),
            .nack(reason: "malformed sealed frame"),
            .nack(reason: "unknown chain"),
        ])
        if case let .failed(reason) = v {
            #expect(reason.contains("token replay"))
            #expect(reason.contains("malformed sealed frame"))
            #expect(reason.contains("unknown chain"))
        } else {
            Issue.record("expected .failed; got \(v)")
        }
    }

    // MARK: - Pending vs failed

    /// 0 of 3 ACK but at least one outcome is potentially-transient
    /// (`.timeout` / `.networkError` / `.notAttempted`) → `.pending`.
    /// The host's retry timer picks it up.
    @Test func mixedNackAndTimeoutIsPending() {
        let v = relayFanoutVerdict([
            .nack(reason: "token replay"),
            .timeout,
            .nack(reason: "unknown chain"),
        ])
        if case let .pending(after) = v {
            #expect(after > 0)
        } else {
            Issue.record("expected .pending; got \(v)")
        }
    }

    @Test func allNetworkErrorsIsPending() {
        let v = relayFanoutVerdict([
            .networkError("socks tcp: timed out"),
            .networkError("hs descriptor unavailable"),
            .networkError("connection refused"),
        ])
        if case .pending = v { return }
        Issue.record("expected .pending; got \(v)")
    }

    @Test func allNotAttemptedIsPending() {
        // Every relay was `.failed` / `.idle` at submission time; the
        // SEND never reached any wire. Retry-meaningful — surface as
        // pending so the next outbox tick picks it up once any relay
        // recovers.
        let v = relayFanoutVerdict([
            .notAttempted,
            .notAttempted,
            .notAttempted,
        ])
        if case .pending = v { return }
        Issue.record("expected .pending; got \(v)")
    }

    // MARK: - Edge cases

    @Test func emptyFanoutIsFailed() {
        let v = relayFanoutVerdict([])
        if case let .failed(reason) = v {
            #expect(reason.contains("empty"))
        } else {
            Issue.record("expected .failed; got \(v)")
        }
    }

    /// Single-relay BYO custom-relay case: one `.ack` is still
    /// `.delivered`. The aggregator must not assume N≥2.
    @Test func singleRelayAckIsDelivered() {
        #expect(relayFanoutVerdict([.ack]) == .delivered)
    }

    @Test func singleRelayNackIsFailed() {
        let v = relayFanoutVerdict([.nack(reason: "token replay")])
        if case .failed = v { return }
        Issue.record("expected .failed; got \(v)")
    }

    @Test func singleRelayTimeoutIsPending() {
        let v = relayFanoutVerdict([.timeout])
        if case .pending = v { return }
        Issue.record("expected .pending; got \(v)")
    }
}
