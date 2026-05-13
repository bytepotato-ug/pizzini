import Foundation
import PizziniTor
import Testing

/// Tests for `TorController.shouldRotateCircuits(previous:current:)`.
///
/// The function is the gate between the raw NWPathMonitor pathfingerprint
/// stream and the "rotate circuits" side effect (SIGNAL NEWNYM +
/// relay redial). Three contract bits matter:
///   1. First sample is a no-op — there's no prior state to invalidate.
///   2. Same fingerprint twice in a row is a no-op — the path observer
///      can fire spuriously on app foreground.
///   3. Any other transition fires.
@Suite("TorController.shouldRotateCircuits")
struct NetworkPathRotationTests {

    @Test func firstSampleDoesNotRotate() {
        let result = TorController.shouldRotateCircuits(
            previous: nil,
            current: "satisfied:false:wifi",
        )
        #expect(!result)
    }

    @Test func identicalFingerprintDoesNotRotate() {
        let result = TorController.shouldRotateCircuits(
            previous: "satisfied:false:wifi",
            current: "satisfied:false:wifi",
        )
        #expect(!result)
    }

    @Test func wifiToCellularRotates() {
        let result = TorController.shouldRotateCircuits(
            previous: "satisfied:false:wifi",
            current: "satisfied:false:cellular",
        )
        #expect(result)
    }

    @Test func statusFlipRotates() {
        let result = TorController.shouldRotateCircuits(
            previous: "satisfied:false:wifi",
            current: "unsatisfied:false:",
        )
        #expect(result)
    }

    @Test func constrainedFlipRotates() {
        let result = TorController.shouldRotateCircuits(
            previous: "satisfied:false:cellular",
            current: "satisfied:true:cellular",
        )
        #expect(result)
    }

    /// Captive-portal-style transition: same interface set, but the
    /// path went unsatisfied (joining a network) and came back.
    /// Even though the final fingerprint may LOOK identical to the
    /// pre-portal state on some networks, the intermediate
    /// `unsatisfied` sample arrives first and is the rotation
    /// trigger. This test pins that two consecutive different
    /// samples both fire, even if a third sample matches the first.
    @Test func portalCycleFiresOnEntryAndExit() {
        let entry = TorController.shouldRotateCircuits(
            previous: "satisfied:false:wifi",
            current: "unsatisfied:false:",
        )
        let exit = TorController.shouldRotateCircuits(
            previous: "unsatisfied:false:",
            current: "satisfied:false:wifi",
        )
        #expect(entry)
        #expect(exit)
    }
}
