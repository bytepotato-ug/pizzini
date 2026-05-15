import Foundation
import PizziniCryptoCore
import Testing
@testable import pizzini

/// Tests for `ChatStore.connectionPillLabel(for:connectedRelays:totalRelays:)`.
///
/// The pill is the user's continuous signal of whether Pizzini can
/// send and receive. The label-from-state mapping is the only
/// stylable string visible during the load-bearing 7-minute worst-
/// case cold-cellular bootstrap; a copy regression here turns the
/// bootstrap into an opaque spinner the user has no way to read.
///
/// Pinning every branch in CI is a hedge against the
/// `version = "0.0.0"`-style miss (a copy bug the unit tests
/// didn't catch, only `RELEASE-CHECKLIST.md` did, after months in
/// the field). The pill copy is small enough that the test cost is
/// negligible and the regression cost is real.
@Suite("ChatStore.connectionPillLabel")
struct ConnectionPillLabelTests {

    @Test func bootstrappingTorAtZeroShowsPlainLabel() {
        let label = ChatStore.connectionPillLabel(
            for: .connectingToTor(progress: 0),
            connectedRelays: 0,
            totalRelays: 3,
        )
        #expect(label == "Connecting Tor…")
    }

    /// Mid-bootstrap percent is surfaced verbatim. The mission was
    /// specifically: a stuck cold start used to show "Connecting…"
    /// for up to 7 minutes with no signal that progress was being
    /// made; now the user sees the percent climb so they can tell
    /// "slow" from "stuck".
    @Test func bootstrappingTorMidwayShowsPercent() {
        let label = ChatStore.connectionPillLabel(
            for: .connectingToTor(progress: 45),
            connectedRelays: 0,
            totalRelays: 3,
        )
        #expect(label == "Connecting Tor… 45%")
    }

    /// Edge case: progress=100 still shows the bootstrap label —
    /// the state machine flips to `.connecting` only after the
    /// RelayClient sees TorController.isReady, so there's a brief
    /// window where the pct hits 100 but state is still
    /// `.connectingToTor`. Showing "100%" reads correctly.
    @Test func bootstrappingTorAtHundredShowsPercent() {
        let label = ChatStore.connectionPillLabel(
            for: .connectingToTor(progress: 100),
            connectedRelays: 0,
            totalRelays: 3,
        )
        #expect(label == "Connecting Tor… 100%")
    }

    /// Tor is up, SOCKS dials are in flight. With 0 of 3 relays
    /// connected so far, the pill counts up to "Connecting 0 of 3"
    /// so the user can tell relay-dial latency from a stuck-tor.
    @Test func connectingZeroOfThree() {
        let label = ChatStore.connectionPillLabel(
            for: .connecting,
            connectedRelays: 0,
            totalRelays: 3,
        )
        #expect(label == "Connecting 0 of 3")
    }

    /// With 1 of 3 already connected, the aggregate state would
    /// usually be `.connected` (any-ready-wins), but the pill
    /// label function should still produce a sensible string if
    /// the caller does pass `.connecting` with a non-zero count —
    /// defensive, and pins the format for U1's partial-state pill.
    @Test func connectingOneOfThree() {
        let label = ChatStore.connectionPillLabel(
            for: .connecting,
            connectedRelays: 1,
            totalRelays: 3,
        )
        #expect(label == "Connecting 1 of 3")
    }

    /// Single-relay (BYO override) fleet: "Connecting 0 of 1"
    /// reads weirdly but the math is correct, and BYO mode is
    /// a dev/test path that real users don't hit. Pin the format
    /// so a future "hide the count when total == 1" tweak is an
    /// intentional opt-in, not a silent regression.
    @Test func connectingSingleRelay() {
        let label = ChatStore.connectionPillLabel(
            for: .connecting,
            connectedRelays: 0,
            totalRelays: 1,
        )
        #expect(label == "Connecting 0 of 1")
    }

    /// Defensive: a `.connecting` aggregate with no relays yet
    /// built (the brief teardown→connectRelay window) falls back
    /// to a bare "Connecting" so the pill never reads "Connecting
    /// 0 of 0" — which would be both misleading and a regression
    /// trigger in the screenshot QA checklist.
    @Test func connectingWithEmptyFleet() {
        let label = ChatStore.connectionPillLabel(
            for: .connecting,
            connectedRelays: 0,
            totalRelays: 0,
        )
        #expect(label == "Connecting")
    }

    /// Pre-connection `.idle` (relays array built, none dialed
    /// yet) shows "Starting" — a one-word "I see your tap, I am
    /// working on it" affordance.
    @Test func idleShowsStarting() {
        let label = ChatStore.connectionPillLabel(
            for: .idle,
            connectedRelays: 0,
            totalRelays: 3,
        )
        #expect(label == "Starting")
    }

    /// `.connected` hides the pill (nil label). The pill is a
    /// transient-state affordance; healthy steady state should
    /// not waste toolbar real estate.
    @Test func connectedHidesPill() {
        let label = ChatStore.connectionPillLabel(
            for: .connected,
            connectedRelays: 3,
            totalRelays: 3,
        )
        #expect(label == nil)
    }

    /// `.failed` hides the pill too — the caller renders a red
    /// "tap to reconnect" badge instead (different shape, different
    /// tap action), so the label function returning nil for both
    /// `.connected` and `.failed` reflects "this is not a spinner
    /// state".
    @Test func failedHidesPill() {
        let label = ChatStore.connectionPillLabel(
            for: .failed("tor bootstrap failed"),
            connectedRelays: 0,
            totalRelays: 3,
        )
        #expect(label == nil)
    }
}
