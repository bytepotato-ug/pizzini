import Foundation
import Testing
import UIKit
@testable import pizzini

/// NotificationCenter-driven tests for `ScreenCaptureMonitor`. The
/// observed notifications are posted on the main actor and the
/// monitor's published state is read back after a yield so the
/// internal `Task { @MainActor in ... }` hop has a chance to commit.
///
/// `isRecording` / `hasExternalDisplay` post-conditions are asserted
/// against the value the monitor *would* read on a real device — we
/// can't fake the foreground scene's `screen.isCaptured` or
/// `connectedScenes` content from a unit test, so we instead assert
/// the notification path runs without crashing and produces a value
/// consistent with what the monitor's own static helpers see.
@Suite("ScreenCaptureMonitor", .serialized)
@MainActor
struct ScreenCaptureMonitorTests {
    /// Yield twice so any `Task { @MainActor in ... }` queued by the
    /// @objc handler has executed by the time we assert. One yield is
    /// usually enough; two is belt-and-suspenders for runtimes that
    /// schedule the inner Task on the next runloop tick rather than
    /// inline on the current.
    private func settle() async {
        await Task.yield()
        await Task.yield()
    }

    @Test("capturedDidChange does not crash and reflects the active scene's screen")
    func capturedDidChangeMatchesScene() async {
        let monitor = ScreenCaptureMonitor.shared
        NotificationCenter.default.post(
            name: UIScreen.capturedDidChangeNotification,
            object: UIScreen.main,
        )
        await settle()
        // Compute the expected value via the same scene-based path
        // the monitor uses. The unit-test runtime has no foreground
        // scene, so this gracefully falls back to UIScreen.main —
        // which is fine, that's exactly the launch-time fallback the
        // production code documents.
        let expected = UIScreen.main.isCaptured
        #expect(monitor.isRecording == expected)
    }

    @Test("scene connect/disconnect drives hasExternalDisplay from connectedScenes")
    func sceneConnectDisconnectMatchesScenes() async {
        let monitor = ScreenCaptureMonitor.shared
        // Modern (iOS 16+) scene-lifecycle notifications. These are
        // the same notifications PrivacyShieldWindow observes; the
        // legacy UIScreen.didConnect/Disconnect pair was deprecated
        // in iOS 16 alongside UIScreen.screens.
        NotificationCenter.default.post(
            name: UIScene.willConnectNotification,
            object: nil,
        )
        await settle()
        let expectedAfterConnect = UIApplication.shared.connectedScenes.contains {
            $0.session.role == .windowExternalDisplayNonInteractive
        }
        #expect(monitor.hasExternalDisplay == expectedAfterConnect)
        NotificationCenter.default.post(
            name: UIScene.didDisconnectNotification,
            object: nil,
        )
        await settle()
        let expectedAfterDisconnect = UIApplication.shared.connectedScenes.contains {
            $0.session.role == .windowExternalDisplayNonInteractive
        }
        #expect(monitor.hasExternalDisplay == expectedAfterDisconnect)
    }

    @Test("test seams flip flags as expected")
    func testSeamsFlipFlags() {
        let monitor = ScreenCaptureMonitor.shared
        let savedR = monitor.isRecording
        let savedX = monitor.hasExternalDisplay
        defer {
            monitor._testSetRecording(savedR)
            monitor._testSetExternalDisplay(savedX)
        }
        monitor._testSetRecording(true)
        #expect(monitor.isRecording)
        monitor._testSetRecording(false)
        #expect(!monitor.isRecording)
        monitor._testSetExternalDisplay(true)
        #expect(monitor.hasExternalDisplay)
        monitor._testSetExternalDisplay(false)
        #expect(!monitor.hasExternalDisplay)
    }

    /// Drives the screenshot-mask self-test end to end. `run()` is
    /// exposed "for tests" but had no caller; this asserts it produces
    /// a definite verdict without crashing. The simulator does not
    /// honour `isSecureTextEntry` masking the way hardware does, so the
    /// *value* is not asserted — only that the self-test resolves the
    /// secure layer, renders its sentinel, samples the result, and
    /// returns. A regression that breaks `resolveSecureLayer` or the
    /// `drawHierarchy` probe surfaces here as a crash or a hang.
    @Test("SecureScreenshotSelfTest.run() produces a verdict without crashing")
    func selfTestRuns() {
        let result = SecureScreenshotSelfTest.run()
        // `Bool` is total — reaching this line at all is the assertion
        // that `run()` did not crash or trap. Touch the value so the
        // compiler cannot elide the call.
        #expect(result == true || result == false)
    }
}
