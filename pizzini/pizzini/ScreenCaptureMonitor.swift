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
/// 2. **Screen recording / mirroring** (`UIScreen.capturedDidChangeNotification`
///    + the foreground scene's `windowScene.screen.isCaptured`) —
///    fires while a capture pipeline is active. Includes Control-
///    Centre Record, AirPlay mirroring, QuickTime over USB, and
///    external-display mirroring on single-window apps.
/// 3. **External display connected** (`UIScene.willConnectNotification`,
///    `UIScene.didDisconnectNotification`, filtered by
///    `UISceneSession.role == .windowExternalDisplayNonInteractive`).
///    Doubles as a refusal hook for multi-window-capable builds; for
///    single-window apps like ours, the mirroring case lights up
///    `isCaptured` and (2) catches it instead.
///
/// **API choice — why scene-based, not screen-based.** Apple
/// deprecated `UIScreen.screens`, `UIScreen.didConnectNotification`
/// and `UIScreen.didDisconnectNotification` in iOS 16, replacing them
/// with the scene-graph equivalents above. `UIScreen.isCaptured` and
/// `UIScreen.capturedDidChangeNotification` are NOT deprecated — only
/// the multi-display enumeration path was. We read capture state via
/// the foreground scene's `screen.isCaptured` (the path Apple
/// recommends for multi-scene apps) with a single `UIScreen.main`
/// fallback for the launch-time window before any scene is
/// foreground-active.
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
        self.isRecording = Self.computeIsRecording()
        self.hasExternalDisplay = Self.computeHasExternalDisplay()
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
        // Modern (iOS 16+) scene-lifecycle notifications. The legacy
        // `UIScreen.didConnect/DisconnectNotification` were deprecated
        // alongside `UIScreen.screens`; multi-scene apps can have
        // external-display scenes that don't map 1:1 to physical
        // UIScreens. PrivacyShieldWindow already uses the same pair
        // for its scene tracking.
        nc.addObserver(
            self,
            selector: #selector(handleSceneConnected(_:)),
            name: UIScene.willConnectNotification,
            object: nil,
        )
        nc.addObserver(
            self,
            selector: #selector(handleSceneDisconnected(_:)),
            name: UIScene.didDisconnectNotification,
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
        // We do NOT trust the notification's userInfo — Apple has
        // historically shipped this notification with no userInfo on
        // some iOS versions, so we always re-poll via the modern
        // scene-based path.
        Task { @MainActor in
            self.isRecording = Self.computeIsRecording()
        }
    }

    @objc nonisolated private func handleSceneConnected(_ note: Notification) {
        Task { @MainActor in
            self.hasExternalDisplay = Self.computeHasExternalDisplay()
            // A scene attaching to an external display also typically
            // flips capture on the foreground scene's screen (the OS
            // mirrors content to the new display on single-window
            // apps). Re-poll to keep the two flags consistent.
            self.isRecording = Self.computeIsRecording()
        }
    }

    @objc nonisolated private func handleSceneDisconnected(_ note: Notification) {
        Task { @MainActor in
            self.hasExternalDisplay = Self.computeHasExternalDisplay()
            self.isRecording = Self.computeIsRecording()
        }
    }

    /// Reads the capture state of the foreground-active window scene's
    /// screen — Apple's recommended scene-based replacement for
    /// `UIScreen.main.isCaptured`. Falls back to `UIScreen.main` only
    /// during the launch window before any scene reaches
    /// `.foregroundActive`. `UIScreen.main` itself is not deprecated
    /// in iOS 26; only `UIScreen.screens` and the
    /// `didConnect/DisconnectNotification` pair were.
    @MainActor
    private static func computeIsRecording() -> Bool {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        // Prefer a foreground-active scene; degrade through
        // foreground-inactive then any window scene. Whatever the user
        // is looking at right now is what matters for "is this view
        // being captured."
        let preferred = scenes.first(where: { $0.activationState == .foregroundActive })
            ?? scenes.first(where: { $0.activationState == .foregroundInactive })
            ?? scenes.first
        if let s = preferred {
            return s.screen.isCaptured
        }
        // Launch-time fallback. Once any scene attaches we'll re-poll.
        return UIScreen.main.isCaptured
    }

    /// True iff any connected scene targets a non-primary display —
    /// AirPlay receiver, Lightning/USB-C-attached monitor, iPad Stage
    /// Manager external display. Modern (iOS 16+) replacement for
    /// `UIScreen.screens.count > 1`.
    ///
    /// Note for single-window apps (us): iOS doesn't typically create
    /// a `.windowExternalDisplayNonInteractive` scene unless the app
    /// declares multi-scene support, so this flag may stay false even
    /// when the iPhone is mirrored to AirPlay. The mirroring case
    /// still lights up `isCaptured` on the foreground scene's screen,
    /// so `isRecording` catches it; the two flags drive the same
    /// shield path. Keeping `hasExternalDisplay` separately surfaced
    /// gives a future multi-scene build a more semantic refusal hook.
    @MainActor
    private static func computeHasExternalDisplay() -> Bool {
        UIApplication.shared.connectedScenes.contains { scene in
            scene.session.role == .windowExternalDisplayNonInteractive
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
