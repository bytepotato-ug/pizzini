import Foundation
import Testing
import UIKit
@testable import pizzini

/// NotificationCenter-driven tests for `ScreenCaptureMonitor`. The four
/// observed notifications are posted on the main actor and the
/// monitor's published state is read back after a yield so the
/// internal `Task { @MainActor in ... }` hop has a chance to commit.
///
/// `isRecording` / `hasExternalDisplay` post-conditions are asserted
/// against the value the monitor *would* read on a real device — we
/// can't fake `UIScreen.main.isCaptured` or `UIScreen.screens.count`
/// from a unit test, so we instead assert the notification path runs
/// without crashing and produces a value consistent with the screen.
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

    @Test("screenshot notification updates lastScreenshotAt + counter")
    func screenshotNotificationUpdatesState() async {
        let monitor = ScreenCaptureMonitor.shared
        let before = monitor.screenshotCount
        let beforeAt = monitor.lastScreenshotAt
        NotificationCenter.default.post(
            name: UIApplication.userDidTakeScreenshotNotification,
            object: nil,
        )
        await settle()
        #expect(monitor.screenshotCount == before &+ 1)
        // lastScreenshotAt must have been refreshed to a strictly later
        // wall-clock than its prior value (or be non-nil if it was nil).
        if let beforeAt {
            #expect(monitor.lastScreenshotAt != nil)
            if let now = monitor.lastScreenshotAt {
                #expect(now >= beforeAt)
            }
        } else {
            #expect(monitor.lastScreenshotAt != nil)
        }
    }

    @Test("onScreenshot closure fires on screenshot")
    func onScreenshotClosureFires() async {
        let monitor = ScreenCaptureMonitor.shared
        let priorClosure = monitor.onScreenshot
        var fired = false
        monitor.onScreenshot = { @MainActor in fired = true }
        defer { monitor.onScreenshot = priorClosure }
        NotificationCenter.default.post(
            name: UIApplication.userDidTakeScreenshotNotification,
            object: nil,
        )
        await settle()
        #expect(fired)
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
}
