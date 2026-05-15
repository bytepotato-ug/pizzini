import Foundation
import PizziniCryptoCore
import Testing
@testable import pizzini

/// Tests for the multi-relay (D3) fanout failover contract.
///
/// The invariant: while at least one relay in the bundled fleet is
/// `.connected`, the aggregate user-facing state is `.connected` —
/// NOT `.failed` and NOT a degraded "N of M" string. The fanout is
/// the whole point of the fleet; the user has working send/receive
/// as long as one route is up. The dead routes are retried silently
/// by `scheduleSilentPerRelayRetry` so the fleet self-heals without
/// banner blips.
///
/// Also pins the per-relay backoff math (`computePerRelayRetryDecision`)
/// so a future tweak can't silently widen the silent-retry cadence
/// past the documented ceiling.
@Suite("Multi-relay failover invariants")
struct PerRelayFailoverTests {

    // MARK: aggregateRelayState

    /// 1 of 1 connected → aggregate `.connected`. Base case.
    @Test func singleRelayConnectedIsConnected() {
        let agg = ChatStore.aggregateRelayState(states: [.connected])
        #expect(agg == .connected)
    }

    /// 1 of 1 failed → aggregate `.failed`. Base case.
    @Test func singleRelayFailedIsFailed() {
        let agg = ChatStore.aggregateRelayState(states: [.failed("bootstrap failed")])
        if case .failed = agg { return }
        Issue.record("expected .failed; got \(agg)")
    }

    /// **The load-bearing test for T1.** With the default 3-relay
    /// fleet (DE / NO / US), if two are healthy and one is dead, the
    /// user must NOT see a `.failed` aggregate — the fanout still
    /// has two working paths, and surfacing failure would be a lie
    /// that drives the user to manually reconnect over a working
    /// fleet. The dead route is retried silently in the background;
    /// the aggregate stays `.connected` throughout.
    @Test func twoOfThreeConnectedStaysConnected() {
        let agg = ChatStore.aggregateRelayState(states: [
            .connected,
            .connected,
            .failed("hs descriptor unavailable: timed out"),
        ])
        #expect(agg == .connected)
    }

    /// Symmetric case: only one of three healthy is still enough to
    /// keep the aggregate `.connected`. The user's send/receive path
    /// is intact; the two dead routes retry silently.
    @Test func oneOfThreeConnectedStaysConnected() {
        let agg = ChatStore.aggregateRelayState(states: [
            .failed("tor bootstrap failed"),
            .connected,
            .failed("hs descriptor unavailable"),
        ])
        #expect(agg == .connected)
    }

    /// All N relays failed → aggregate `.failed`. This is the only
    /// case that should surface the loud reconnect-or-tap banner —
    /// every route is down and the fanout has nothing left to fan
    /// out to.
    @Test func allThreeFailedIsFailed() {
        let agg = ChatStore.aggregateRelayState(states: [
            .failed("a"),
            .failed("b"),
            .failed("c"),
        ])
        if case .failed = agg { return }
        Issue.record("expected .failed when every relay is failed; got \(agg)")
    }

    /// Empty fleet → `.idle`. Defensive — `connectRelay` always
    /// stands up at least one client, but a brief
    /// `teardownRelay → connectRelay` window has zero clients and
    /// the aggregator must not crash or claim `.failed`.
    @Test func emptyFleetIsIdle() {
        let agg = ChatStore.aggregateRelayState(states: [])
        #expect(agg == .idle)
    }

    /// While at least one relay is still bootstrapping Tor and none
    /// has reached `.connected`, the aggregate surfaces the highest
    /// progress integer so the user sees "Connecting Tor 87%"
    /// rather than "Connecting" with no number.
    @Test func bootstrappingProgressTakesMax() {
        let agg = ChatStore.aggregateRelayState(states: [
            .connectingToTor(progress: 20),
            .connectingToTor(progress: 87),
            .connectingToTor(progress: 45),
        ])
        if case let .connectingToTor(progress) = agg {
            #expect(progress == 87)
        } else {
            Issue.record("expected .connectingToTor; got \(agg)")
        }
    }

    /// A mid-flight bootstrap mixed with a `.failed` peer still
    /// surfaces the progress — the user is mid-handshake, not
    /// blocked. The failed peer will retry silently once at least
    /// one connects.
    @Test func bootstrappingWithFailedSiblingShowsProgress() {
        let agg = ChatStore.aggregateRelayState(states: [
            .connectingToTor(progress: 50),
            .failed("not ready"),
        ])
        if case let .connectingToTor(progress) = agg {
            #expect(progress == 50)
        } else {
            Issue.record("expected .connectingToTor; got \(agg)")
        }
    }

    // MARK: computePerRelayRetryDecision

    /// Floor-clamped: a freshly failed relay starts at the
    /// `perRelayBackoffFloor` (2 s) — tight enough that a single
    /// transient circuit fail recovers within a couple of seconds.
    @Test func perRelayRetryStartsAtFloor() {
        let d = ChatStore.computePerRelayRetryDecision(
            currentBackoff: ChatStore.perRelayBackoffFloor,
        )
        #expect(d.delaySeconds == ChatStore.perRelayBackoffFloor)
        #expect(d.nextBackoff == ChatStore.perRelayBackoffFloor * 2)
    }

    /// Exponential walk: 2 → 4 → 8 → 16 → 32 → 60-cap. Pins the
    /// cadence so a future tweak can't silently widen or shrink it.
    @Test func perRelayBackoffDoublesUntilCeiling() {
        var backoff: TimeInterval = ChatStore.perRelayBackoffFloor
        var observed: [TimeInterval] = []
        for _ in 0..<6 {
            let d = ChatStore.computePerRelayRetryDecision(currentBackoff: backoff)
            observed.append(d.delaySeconds)
            backoff = d.nextBackoff
        }
        #expect(observed == [2, 4, 8, 16, 32, 60])
    }

    /// Ceiling is sticky: once at 60 s, further failures stay there
    /// — the silent retry does not amplify into a multi-minute
    /// no-show on a permanently-dead relay.
    @Test func perRelayBackoffCeilingIsSticky() {
        let d = ChatStore.computePerRelayRetryDecision(
            currentBackoff: ChatStore.perRelayBackoffCeiling,
        )
        #expect(d.delaySeconds == ChatStore.perRelayBackoffCeiling)
        #expect(d.nextBackoff == ChatStore.perRelayBackoffCeiling)
    }

    /// Below-floor input (defensive: nothing should pass this, but
    /// a future caller might) clamps up to the floor rather than
    /// firing an instant retry that would just hammer the network.
    @Test func belowFloorInputClampsToFloor() {
        let d = ChatStore.computePerRelayRetryDecision(currentBackoff: 0)
        #expect(d.delaySeconds == ChatStore.perRelayBackoffFloor)
    }
}
