import Foundation
import Testing
@testable import pizzini

/// Tests for `ChatStore.computeAutoReconnectDecision(previousStreak:currentBackoff:)`.
///
/// The decision is the pure-data half of the auto-reconnect state
/// machine: given the pre-failure streak and current backoff, return
/// either "schedule another retry with this delay and this next-
/// backoff" or "stop retrying, the user has to tap Reconnect".
/// All the side effects (Task.sleep, connectRelay) live in the
/// caller; the math lives here so we can pin it without spinning
/// up a ChatStore.
@Suite("ChatStore.computeAutoReconnectDecision")
struct AutoReconnectDecisionTests {

    @Test func firstFailureSchedulesAtFloor() {
        let d = ChatStore.computeAutoReconnectDecision(
            previousStreak: 0,
            currentBackoff: ChatStore.autoReconnectBackoffFloor,
        )
        #expect(d.newStreak == 1)
        if case let .scheduleRetry(delay, next) = d.action {
            #expect(delay == ChatStore.autoReconnectBackoffFloor)
            #expect(next == ChatStore.autoReconnectBackoffFloor * 2)
        } else {
            Issue.record("expected scheduleRetry; got \(d.action)")
        }
    }

    @Test func backoffDoublesEachFailure() {
        var streak = 0
        var backoff: TimeInterval = ChatStore.autoReconnectBackoffFloor
        let observed: [TimeInterval] = (0..<3).map { _ in
            let d = ChatStore.computeAutoReconnectDecision(
                previousStreak: streak,
                currentBackoff: backoff,
            )
            streak = d.newStreak
            if case let .scheduleRetry(delay, next) = d.action {
                backoff = next
                return delay
            }
            return -1
        }
        // 3 attempts at 5 → 10 → 20 s (next would be 40, then 60-cap,
        // then requireManual on the 5th).
        #expect(observed == [5, 10, 20])
    }

    @Test func backoffClampedAtCeiling() {
        let d = ChatStore.computeAutoReconnectDecision(
            previousStreak: 1,
            currentBackoff: ChatStore.autoReconnectBackoffCeiling,
        )
        if case let .scheduleRetry(_, next) = d.action {
            #expect(next == ChatStore.autoReconnectBackoffCeiling)
        } else {
            Issue.record("expected scheduleRetry; got \(d.action)")
        }
    }

    /// On the FIFTH consecutive failure (streak crosses the cap of 5),
    /// we stop auto-retrying and require the user to tap Reconnect.
    @Test func fifthFailureRequiresManual() {
        let d = ChatStore.computeAutoReconnectDecision(
            previousStreak: 4,
            currentBackoff: 60,
        )
        #expect(d.newStreak == 5)
        #expect(d.action == .requireManual)
    }

    /// And the SIXTH failure (shouldn't normally happen since we cancel
    /// the auto-task at the cap, but the decision function should still
    /// be defensive about it) also returns requireManual.
    @Test func furtherFailuresAlsoRequireManual() {
        let d = ChatStore.computeAutoReconnectDecision(
            previousStreak: 5,
            currentBackoff: 60,
        )
        #expect(d.newStreak == 6)
        #expect(d.action == .requireManual)
    }

    /// The full 5-failure walk: starting from a fresh streak of 0, we
    /// schedule four retries then require manual on the fifth.
    @Test func fullFiveFailureWalk() {
        var streak = 0
        var backoff: TimeInterval = ChatStore.autoReconnectBackoffFloor
        var actions: [ChatStore.AutoReconnectAction] = []
        for _ in 0..<5 {
            let d = ChatStore.computeAutoReconnectDecision(
                previousStreak: streak,
                currentBackoff: backoff,
            )
            streak = d.newStreak
            if case let .scheduleRetry(_, next) = d.action {
                backoff = next
            }
            actions.append(d.action)
        }
        #expect(actions.count == 5)
        #expect(actions[0] == .scheduleRetry(delaySeconds: 5, nextBackoff: 10))
        #expect(actions[1] == .scheduleRetry(delaySeconds: 10, nextBackoff: 20))
        #expect(actions[2] == .scheduleRetry(delaySeconds: 20, nextBackoff: 40))
        #expect(actions[3] == .scheduleRetry(delaySeconds: 40, nextBackoff: 60))
        #expect(actions[4] == .requireManual)
    }
}
