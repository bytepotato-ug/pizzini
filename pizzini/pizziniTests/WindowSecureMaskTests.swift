import Testing
@testable import pizzini

/// PZ-M10 — the screenshot mask reparents the window layer one runloop
/// turn after scene activation, leaving a gap where the live, unmasked
/// window could be captured. The fix raises a synchronous opaque cover
/// across that gap. `shouldRaiseBridgingCover` is the pure gate that
/// decides when the cover is warranted; these pin its truth table so a
/// future refactor can't silently (a) stop covering a real reparent
/// — re-opening the race — or (b) start flashing a black cover on a
/// no-op re-activation / when masking is disabled.
@Suite("WindowSecureMask — PZ-M10 bridging-cover gate")
struct WindowSecureMaskTests {
    @Test("a fresh reparent with masking enabled raises the cover")
    func freshReparentCovers() {
        #expect(WindowSecureMask.shouldRaiseBridgingCover(
            maskingEnabled: true, alreadyMaskedAndIntact: false) == true)
    }

    @Test("a no-op re-activation (already masked + intact) does NOT flash a cover")
    func noOpReactivationNoCover() {
        #expect(WindowSecureMask.shouldRaiseBridgingCover(
            maskingEnabled: true, alreadyMaskedAndIntact: true) == false)
    }

    @Test("masking disabled never raises a cover (no mask to bridge to)")
    func maskingDisabledNoCover() {
        #expect(WindowSecureMask.shouldRaiseBridgingCover(
            maskingEnabled: false, alreadyMaskedAndIntact: false) == false)
        #expect(WindowSecureMask.shouldRaiseBridgingCover(
            maskingEnabled: false, alreadyMaskedAndIntact: true) == false)
    }
}
