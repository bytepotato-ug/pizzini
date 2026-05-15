//  DialBudgetTests.swift
//  pizziniTests
//
//  Regression pin for F-tor-01: the .onion dial path enforces a
//  single end-to-end wall-clock budget that spans bootstrap +
//  HSFETCH + SOCKS retries, sized as a strict BACKSTOP above the
//  additive sum of the per-phase deadlines.
//
//  If anyone reduces `RelayClient.dialBudget` below the per-phase
//  sum, the budget stops being a backstop and starts cutting honest
//  cold-start dials short — defeating the audit fix. If anyone bumps
//  it above the user-patience ceiling, the budget stops surfacing an
//  actionable `.failed` and the audit's bound is gone too.

import Foundation
import PizziniCryptoCore
import PizziniTor
import Testing

@Suite("RelayClient dial-budget invariants (F-tor-01)")
struct DialBudgetTests {

    /// The dial budget must strictly exceed the additive sum of
    /// every per-phase deadline below it — bootstrap hard cap,
    /// first-HSFETCH cap, and the worst-case SOCKS retry budget.
    /// This is what makes the watchdog a backstop rather than the
    /// primary mechanism: an honest-but-slow dial that drives each
    /// per-phase deadline to its ceiling still completes inside the
    /// budget, and only a genuinely stuck dial (network slow-drip,
    /// stalled bootstrap) ever trips it.
    @Test func budgetIsStrictBackstopAboveAdditiveSum() {
        let additive =
            TorController.bootstrapHardDeadline
            + TorController.hsFetchDeadline
            + Double(RelayClient.maxSocksRetries) * RelayClient.socksRetryDelay
        #expect(RelayClient.dialBudget > additive,
                "dialBudget (\(RelayClient.dialBudget)s) must exceed the additive per-phase sum (\(additive)s) so the watchdog only trips on a stuck dial, never on an honest-but-slow one")
    }

    /// The dial budget must stay inside what a high-threat user
    /// will tolerate before a `.failed` becomes more useful than a
    /// "Connecting…" pill. 10 minutes is the documented ceiling —
    /// any longer and a hostile network has won the availability
    /// fight regardless of what the watchdog says afterwards.
    @Test func budgetStaysInsideUserPatienceCeiling() {
        #expect(RelayClient.dialBudget <= 10 * 60,
                "dialBudget (\(RelayClient.dialBudget)s) exceeded the 10-minute user-patience ceiling — the audit's bound on time-to-actionable-failure is gone")
    }

    /// Per-phase deadlines must each stay positive. A zero or
    /// negative deadline would compose into nonsense additive math
    /// and silently let the dial budget drift below intent.
    @Test func perPhaseDeadlinesArePositive() {
        #expect(TorController.bootstrapHardDeadline > 0)
        #expect(TorController.hsFetchDeadline > 0)
        #expect(RelayClient.socksRetryDelay > 0)
        #expect(RelayClient.maxSocksRetries > 0)
    }
}
