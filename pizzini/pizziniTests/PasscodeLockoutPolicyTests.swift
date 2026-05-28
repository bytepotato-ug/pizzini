import Foundation
import Testing
@testable import pizzini

/// PZ-C7: pure-predicate tests for the passcode-lockout state machine.
/// These exercise `PasscodeLockoutPolicy.decision` + `.nextState` in
/// isolation — no Keychain, no clock, no LockManager — so the lockout
/// invariants can be verified on the simulator without entitlements.
@Suite("Passcode lockout policy (PZ-C7)")
struct PasscodeLockoutPolicyTests {

    // A deterministic policy with small numbers so the tests stay
    // readable. Production values are larger but the shape is the same.
    private static let testPolicy = PasscodeLockoutPolicy(
        graceAttempts: 3,
        backoffBaseSeconds: 1,
        backoffCapSeconds: 8,
        hardCeiling: 10
    )

    private static let t0 = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - decision()

    @Test
    func graceAttemptsAreAllowed() {
        for n in 0...3 {
            let d = Self.testPolicy.decision(attempts: n, lastFailedAt: nil, now: Self.t0)
            #expect(d == .allow, "attempts=\(n) within grace must be allowed")
        }
    }

    @Test
    func firstAttemptPastGraceBlocksUntilBaseDelay() {
        // attempts=4 (one over grace) should require 1s wait from lastFailedAt.
        let last = Self.t0
        // Mid-window: still blocked.
        let mid = Self.t0.addingTimeInterval(0.5)
        let d = Self.testPolicy.decision(attempts: 4, lastFailedAt: last, now: mid)
        if case .blocked(let retryAt) = d {
            #expect(retryAt == last.addingTimeInterval(1.0))
        } else {
            Issue.record("expected .blocked, got \(d)")
        }
        // Exactly at retryAt: allowed (>= boundary).
        let atRetry = Self.t0.addingTimeInterval(1.0)
        #expect(Self.testPolicy.decision(attempts: 4, lastFailedAt: last, now: atRetry) == .allow)
    }

    @Test
    func backoffDoublesAndIsCapped() {
        // attempts=5 → 2s, attempts=6 → 4s, attempts=7 → 8s, attempts=8 → 8s (cap).
        let last = Self.t0
        let expectedDelays: [(Int, TimeInterval)] = [
            (5, 2), (6, 4), (7, 8), (8, 8), (9, 8), (10, 8),
        ]
        for (attempts, delay) in expectedDelays {
            let mid = last.addingTimeInterval(delay - 0.5)
            let d = Self.testPolicy.decision(attempts: attempts, lastFailedAt: last, now: mid)
            if case .blocked(let retryAt) = d {
                #expect(
                    retryAt == last.addingTimeInterval(delay),
                    "attempts=\(attempts) expected retryAt=last+\(delay)s"
                )
            } else {
                Issue.record("attempts=\(attempts) expected .blocked, got \(d)")
            }
        }
    }

    @Test
    func hardCeilingIsPermanent() {
        // strictly above hardCeiling → permanent. Recovery is reinstall.
        let d = Self.testPolicy.decision(
            attempts: Self.testPolicy.hardCeiling + 1,
            lastFailedAt: Self.t0,
            now: Self.t0.addingTimeInterval(86_400 * 365)
        )
        #expect(d == .permanentlyLocked, "above ceiling must stay permanent forever")
    }

    @Test
    func missingLastFailedAtAllows() {
        // Belt-and-braces: if attempts somehow exceed grace but no
        // timestamp is recorded (corrupt blob, manual edit), fail OPEN
        // (allow), don't permanently brick the user.
        let d = Self.testPolicy.decision(attempts: 7, lastFailedAt: nil, now: Self.t0)
        #expect(d == .allow)
    }

    // MARK: - nextState() — the constant-time-write contract

    @Test
    func realResetsTheCounter() {
        let prior = LockoutState(attempts: 7, lastFailedAt: Self.t0)
        let next = PasscodeLockoutPolicy.nextState(after: .real, prior: prior, now: Self.t0)
        #expect(next == .empty)
    }

    /// The load-bearing duress invariant: a duress unlock must produce
    /// the SAME persisted state as a real unlock. Otherwise an attacker
    /// who sees the post-attempt lockout state could tell whether the
    /// duress PIN was the one that matched.
    @Test
    func duressProducesIdenticalStateToReal() {
        let prior = LockoutState(attempts: 9, lastFailedAt: Self.t0)
        let afterReal = PasscodeLockoutPolicy.nextState(after: .real, prior: prior, now: Self.t0)
        let afterDuress = PasscodeLockoutPolicy.nextState(after: .duress, prior: prior, now: Self.t0)
        #expect(afterReal == afterDuress,
                "real and duress MUST persist identical state — this is the anti-leak invariant")
        #expect(afterReal == .empty)
    }

    @Test
    func neitherIncrementsAndStampsTime() {
        let prior = LockoutState(attempts: 4, lastFailedAt: Self.t0)
        let later = Self.t0.addingTimeInterval(10)
        let next = PasscodeLockoutPolicy.nextState(after: .neither, prior: prior, now: later)
        #expect(next.attempts == 5)
        #expect(next.lastFailedAt == later)
    }

    /// `nextState` is total over the three Match cases — every branch
    /// returns a value (no `fatalError`, no nil) — so the LockManager's
    /// post-verify write is guaranteed to execute the same call exactly
    /// once regardless of which match was hit.
    @Test
    func nextStateCoversEveryMatchBranch() {
        let prior = LockoutState(attempts: 1, lastFailedAt: Self.t0)
        let matches: [AppPasscode.Match] = [.real, .duress, .neither]
        for m in matches {
            let next = PasscodeLockoutPolicy.nextState(after: m, prior: prior, now: Self.t0)
            // Just exercising every branch — the per-match value
            // assertions live above.
            _ = next
        }
    }

    // MARK: - LockoutState codable round-trip (the Keychain blob format)

    @Test
    func lockoutStateRoundTripsViaJSON() {
        let original = LockoutState(attempts: 12, lastFailedAt: Self.t0)
        let data = try? JSONEncoder().encode(original)
        #expect(data != nil)
        let decoded = try? JSONDecoder().decode(LockoutState.self, from: data!)
        #expect(decoded == original)
    }

    @Test
    func emptyLockoutStateRoundTrips() {
        let data = try? JSONEncoder().encode(LockoutState.empty)
        #expect(data != nil)
        let decoded = try? JSONDecoder().decode(LockoutState.self, from: data!)
        #expect(decoded == .empty)
    }
}
