import Foundation
import PizziniCryptoCore
import Testing
@testable import pizzini

/// Tests for `ChatStore.pillState(bootstrap:relays:)` and the
/// per-state `label` / `tint` projections.
///
/// The pill is the user's only continuous signal of whether
/// Pizzini can send and receive. The derivation function is the
/// load-bearing surface: a regression where the bootstrap branch
/// stops firing leaves users staring at a "Connecting" pill for
/// minutes, and a regression in the `.partial` branch hides
/// fleet degradation behind a `.connected` label. Every branch
/// is pinned here so a future tweak has to update the test in
/// the same commit.
@Suite("ChatStore.pillState")
struct PillStateTests {

    // MARK: bootstrap branch

    /// Bootstrap < 100 with no relays connected → bootstrap state.
    @Test func bootstrapMidwayShowsBootstrap() {
        let s = ChatStore.pillState(
            bootstrap: 45,
            relays: [.bootstrapping(progress: 45), .bootstrapping(progress: 45), .bootstrapping(progress: 45)],
        )
        #expect(s == .bootstrappingTor(progress: 45))
        #expect(s.label == "Connecting to Tor 45%")
        #expect(s.tint == .grey)
        #expect(s.isTappable == false)
    }

    /// Bootstrap = 0 — pre-progress state, just after the bootstrap
    /// started. The label drops the percent so we don't read
    /// "Connecting to Tor 0%" (technically truthful but unhelpfully
    /// alarming).
    @Test func bootstrapZeroShowsPlainLabel() {
        let s = ChatStore.pillState(
            bootstrap: 0,
            relays: [.idle],
        )
        #expect(s == .bootstrappingTor(progress: 0))
        #expect(s.label == "Connecting to Tor")
    }

    /// Bootstrap reached 100 even though the relay-dial hasn't
    /// started → fall through to `.connectingRelays`. There's a
    /// brief window post-bootstrap where every relay is still
    /// in `.connecting` and the pill needs to flip away from the
    /// bootstrap label.
    @Test func bootstrapAtHundredFallsThroughToConnecting() {
        let s = ChatStore.pillState(
            bootstrap: 100,
            relays: [.connecting, .connecting, .connecting],
        )
        #expect(s == .connectingRelays(connected: 0, total: 3))
        #expect(s.label == "Connecting to relays (0/3)")
        #expect(s.tint == .amber)
    }

    // MARK: connectingRelays branch

    @Test func connectingZeroOfThree() {
        let s = ChatStore.pillState(
            bootstrap: 100,
            relays: [.connecting, .connecting, .connecting],
        )
        #expect(s.label == "Connecting to relays (0/3)")
    }

    /// A single connected relay should NOT show
    /// "Connecting to relays (1/3)" — it should show the partial state
    /// (which says "1/3 relays online", a different message) since the
    /// user has working send/receive even with one route up.
    @Test func oneConnectedTwoConnectingShowsPartial() {
        let s = ChatStore.pillState(
            bootstrap: 100,
            relays: [.connected, .connecting, .connecting],
        )
        #expect(s == .partial(connected: 1, total: 3))
        #expect(s.label == "1/3 relays online")
        #expect(s.tint == .amber)
    }

    // MARK: connected branch

    @Test func allConnectedShowsConnected() {
        let s = ChatStore.pillState(
            bootstrap: 100,
            relays: [.connected, .connected, .connected],
        )
        #expect(s == .connected)
        #expect(s.label == "Connected")
        #expect(s.tint == .green)
        #expect(s.isTappable == false)
    }

    // MARK: partial branch

    /// Two of three connected, one failed — degraded redundancy
    /// but the user has working send/receive. The pill stays
    /// up so the user knows retries are happening; the silent
    /// per-relay retry flips back to `.connected` on recovery.
    @Test func partialTwoOfThree() {
        let s = ChatStore.pillState(
            bootstrap: 100,
            relays: [.connected, .connected, .failed],
        )
        #expect(s == .partial(connected: 2, total: 3))
        #expect(s.label == "2/3 relays online")
        #expect(s.tint == .amber)
        #expect(s.isTappable == false)
    }

    /// One of three connected, two failed — still partial (not
    /// failed) because one route is serving traffic.
    @Test func partialOneOfThree() {
        let s = ChatStore.pillState(
            bootstrap: 100,
            relays: [.failed, .connected, .failed],
        )
        #expect(s == .partial(connected: 1, total: 3))
        #expect(s.label == "1/3 relays online")
    }

    // MARK: failed branch

    /// Every relay failed → failed state. Tappable; tap kicks a
    /// manual reconnect.
    @Test func allFailedShowsFailed() {
        let s = ChatStore.pillState(
            bootstrap: 100,
            relays: [.failed, .failed, .failed],
        )
        #expect(s == .failed)
        #expect(s.label == "Couldn't connect — tap to retry")
        #expect(s.tint == .red)
        #expect(s.isTappable == true)
    }

    /// All relays failed BEFORE bootstrap completes — still failed,
    /// not bootstrap. A user staring at `.bootstrappingTor` while
    /// every relay has already given up would be misled.
    @Test func allFailedDuringBootstrapStillShowsFailed() {
        let s = ChatStore.pillState(
            bootstrap: 75,
            relays: [.failed, .failed, .failed],
        )
        #expect(s == .failed)
    }

    // MARK: idle branch

    /// Empty fleet — brief teardown→connectRelay window. Shows the
    /// "Starting" label rather than collapsing to no chrome at all.
    @Test func emptyFleetShowsIdle() {
        let s = ChatStore.pillState(bootstrap: 0, relays: [])
        // Empty + bootstrap=0 hits the bootstrap branch (bootstrap < 100
        // and no relay is connected). Label reads "Connecting to Tor"
        // rather than "Starting" — the user sees the same chrome they
        // see during the actual bootstrap that follows in the next
        // frame, no flicker.
        #expect(s == .bootstrappingTor(progress: 0))
    }

    /// Empty fleet after bootstrap is done — fall through to idle.
    @Test func emptyFleetPostBootstrapIsIdle() {
        let s = ChatStore.pillState(bootstrap: 100, relays: [])
        #expect(s == .idle)
        #expect(s.label == "Starting")
    }

    // MARK: RelayHealth projection

    /// `RelayHealth.init(_:)` drops the failure-message detail but
    /// preserves the cardinal state — the pill counts states, not
    /// reasons.
    @Test func relayHealthProjectionDropsFailureMessage() {
        let h1 = ChatStore.RelayHealth(.failed("tor bootstrap failed: deadline"))
        let h2 = ChatStore.RelayHealth(.failed("hs descriptor unavailable"))
        #expect(h1 == .failed)
        #expect(h2 == .failed)
        #expect(h1 == h2)
    }

    @Test func relayHealthProjectionMapsAllCases() {
        #expect(ChatStore.RelayHealth(.idle) == .idle)
        #expect(ChatStore.RelayHealth(.connecting) == .connecting)
        #expect(ChatStore.RelayHealth(.connected) == .connected)
        #expect(ChatStore.RelayHealth(.connectingToTor(progress: 45)) == .bootstrapping(progress: 45))
    }
}
