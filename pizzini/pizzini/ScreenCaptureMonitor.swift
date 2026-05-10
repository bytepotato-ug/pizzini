import Foundation
import SwiftUI
import UIKit

/// Coordinator for screen-capture observability — peer to `LockManager`.
///
/// What iOS lets us see, ordered by what an attacker would do:
///
/// 1. **Screen recording / mirroring** (`UIScreen.capturedDidChangeNotification`
///    + the foreground scene's `windowScene.screen.isCaptured`) —
///    fires while a capture pipeline is active. Includes Control-
///    Centre Record, AirPlay mirroring, QuickTime over USB, and
///    external-display mirroring on single-window apps.
/// 2. **External display connected** (`UIScene.willConnectNotification`,
///    `UIScene.didDisconnectNotification`, filtered by
///    `UISceneSession.role == .windowExternalDisplayNonInteractive`).
///    Doubles as a refusal hook for multi-window-capable builds; for
///    single-window apps like ours, the mirroring case lights up
///    `isCaptured` and (1) catches it instead.
///
/// **What we do NOT observe.** `UIApplication.userDidTakeScreenshotNotification`
/// is unused — Pizzini's screenshot defence is the unconditional
/// `SecureScreenshotShield` wrap (see `.maskAppContents()`). When the
/// wrap works, screenshots capture a black frame and there's no
/// after-the-fact reaction worth taking; when it doesn't (Apple has
/// closed the gap on this iOS), reacting to the notification doesn't
/// rebuild the protection. The wrap is the answer; this monitor only
/// watches the live-recording surface that needs an extra in-body
/// shield overlay.
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
    /// `UIScreen` mirroring our window. Read from the foreground
    /// scene's `windowScene.screen.isCaptured` and re-polled on
    /// every `UIScreen.capturedDidChangeNotification`.
    private(set) var isRecording: Bool

    /// True while there is more than one connected `UIScreen`, i.e. an
    /// external display is attached — TV via Lightning/USB-C, AirPlay
    /// mirror target, or the iPad Stage Manager external display. We
    /// refuse to render sensitive content in this state because the
    /// extra `UIScreen` will mirror the keyWindow by default unless the
    /// app explicitly opts into a separate scene, which we don't.
    private(set) var hasExternalDisplay: Bool

    private init() {
        // Initial snapshot — covers the case where a recording was
        // already underway when the app launched (e.g. user started a
        // recording, then opened Pizzini).
        self.isRecording = Self.computeIsRecording()
        self.hasExternalDisplay = Self.computeHasExternalDisplay()
        let nc = NotificationCenter.default
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

    // The three @objc handlers are `nonisolated` so NotificationCenter
    // can call them from whatever thread Apple posts on. They bounce
    // immediately onto the main actor before touching observable state.

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
