import Foundation
import SwiftUI
import UIKit

/// Coordinator for screen-capture observability — peer to `LockManager`.
///
/// What iOS lets us see, ordered by what an attacker would do:
///
/// 1. **Screenshot** (`UIApplication.userDidTakeScreenshotNotification`) —
///    fires *after* the system has captured the framebuffer. iOS
///    deliberately exposes no API to *prevent* a screenshot from any
///    app — the policy is Apple's, not ours. Reactive only.
/// 2. **Screen recording / mirroring** (`UIScreen.main.isCaptured` +
///    `UIScreen.capturedDidChangeNotification`) — fires while a capture
///    pipeline is active. Includes Control-Centre Record, AirPlay
///    mirroring, QuickTime over USB, and external-display mirroring.
///    We can read this every frame and swap content for a shield.
/// 3. **External display connected** (`UIScreen.didConnectNotification`,
///    `UIScreen.didDisconnectNotification`) — also fires for AirPlay
///    mirroring (iOS reports the AirPlay receiver as a `UIScreen`).
///    Doubles as a refusal hook: when an extra screen is attached we
///    decline to render sensitive content at all.
///
/// What we DO NOT promise: there's no "prevent screenshot" API. The QR
/// sheet has a separate `isSecureTextEntry` workaround, gated by a
/// runtime self-test, and even there the user-facing copy is "best
/// effort, may break in future iOS releases."
///
/// Why a singleton: same shape as `LockManager.shared` — `@State`
/// initialisers can fire more than once before SwiftUI commits to one
/// instance, and we want exactly one notification observer per
/// notification, not one per re-render.
@MainActor
@Observable
final class ScreenCaptureMonitor {
    static let shared = ScreenCaptureMonitor()

    /// True while iOS reports the framebuffer is being captured —
    /// screen-recording, AirPlay mirror, USB mirror, or any third
    /// `UIScreen` mirroring our window. Mirrors `UIScreen.main.isCaptured`
    /// and is updated on every `UIScreen.capturedDidChangeNotification`.
    private(set) var isRecording: Bool

    /// True while there is more than one connected `UIScreen`, i.e. an
    /// external display is attached — TV via Lightning/USB-C, AirPlay
    /// mirror target, or the iPad Stage Manager external display. We
    /// refuse to render sensitive content in this state because the
    /// extra `UIScreen` will mirror the keyWindow by default unless the
    /// app explicitly opts into a separate scene, which we don't.
    private(set) var hasExternalDisplay: Bool

    /// Wall-clock the most recent `userDidTakeScreenshotNotification`
    /// arrived. ChatStore reads this transiently so the chat layer can
    /// append a "Screenshot taken" system row at the moment it happens;
    /// the value otherwise lingers for the lifetime of the process.
    private(set) var lastScreenshotAt: Date?

    /// Bumped every time a screenshot notification arrives. Exists so
    /// SwiftUI re-renders even when two screenshots land in the same
    /// wall-clock second (Date equality at second precision would
    /// otherwise fail to fire `@Observable`'s change tracking).
    private(set) var screenshotCount: Int = 0

    /// Closure invoked on every screenshot, on the main actor. ChatStore
    /// registers itself here at init so the system-row append happens
    /// without a circular import — the monitor compiles in tests with
    /// no ChatStore visible.
    var onScreenshot: (@MainActor () -> Void)?

    private init() {
        // Initial snapshot — covers the case where a recording was
        // already underway when the app launched (e.g. user started a
        // recording, then opened Pizzini).
        self.isRecording = UIScreen.main.isCaptured
        self.hasExternalDisplay = UIScreen.screens.count > 1
        let nc = NotificationCenter.default
        nc.addObserver(
            self,
            selector: #selector(handleScreenshot(_:)),
            name: UIApplication.userDidTakeScreenshotNotification,
            object: nil,
        )
        nc.addObserver(
            self,
            selector: #selector(handleCapturedChanged(_:)),
            name: UIScreen.capturedDidChangeNotification,
            object: nil,
        )
        nc.addObserver(
            self,
            selector: #selector(handleScreenConnected(_:)),
            name: UIScreen.didConnectNotification,
            object: nil,
        )
        nc.addObserver(
            self,
            selector: #selector(handleScreenDisconnected(_:)),
            name: UIScreen.didDisconnectNotification,
            object: nil,
        )
    }

    // The four @objc handlers are `nonisolated` so NotificationCenter
    // can call them from whatever thread Apple posts on (documented as
    // main for the screenshot notification, but the others are not
    // contractually pinned). They bounce immediately onto the main
    // actor before touching observable state. Tests post the same
    // notifications and assert state via an `await` on MainActor.

    @objc nonisolated private func handleScreenshot(_ note: Notification) {
        Task { @MainActor in
            self.lastScreenshotAt = Date()
            self.screenshotCount &+= 1
            self.onScreenshot?()
        }
    }

    @objc nonisolated private func handleCapturedChanged(_ note: Notification) {
        // `UIScreen.main.isCaptured` is the authoritative read. We do
        // NOT trust the notification's userInfo — Apple has historically
        // shipped this notification with no userInfo on some iOS
        // versions, so we always re-poll.
        Task { @MainActor in
            self.isRecording = UIScreen.main.isCaptured
        }
    }

    @objc nonisolated private func handleScreenConnected(_ note: Notification) {
        Task { @MainActor in
            self.hasExternalDisplay = UIScreen.screens.count > 1
        }
    }

    @objc nonisolated private func handleScreenDisconnected(_ note: Notification) {
        Task { @MainActor in
            self.hasExternalDisplay = UIScreen.screens.count > 1
        }
    }

    /// Test seam — the unit-test target drives the recording / external-
    /// display flags directly because `UIScreen.main.isCaptured` and
    /// `UIScreen.screens.count` cannot be faked from a unit test. The
    /// notification-driven path itself is exercised separately.
    #if DEBUG
    func _testSetRecording(_ value: Bool) { self.isRecording = value }
    func _testSetExternalDisplay(_ value: Bool) { self.hasExternalDisplay = value }
    #endif
}
