import SwiftUI
import UIKit

/// Window-level privacy shield. Hosts `PrivacyShieldView` in a separate
/// `UIWindow` at `.alert + 1` so it sits above every in-app surface
/// EXCEPT the iOS keyboard — see F-801 caveat below.
///
/// Why a separate window and not just an overlay in `ContentView`'s
/// `body`: SwiftUI sheets are presented in the *same* window as the
/// root view but at a higher z-position, so a ZStack overlay only
/// covers the underlying content. Sheets remain visible in the
/// snapshot. A second `UIWindow` at a higher level genuinely covers
/// content beneath the keyboard.
///
/// Lifecycle: per-scene window dictionary (F-803 fix — was a single
/// `UIWindow?` previously, which silently lost coverage for the second
/// scene the moment iPad multi-window was enabled). One window per
/// scene, created on connect, torn down on disconnect.
///
/// Touch behaviour: deliberately **does not** call
/// `makeKeyAndVisible`. Setting `isHidden = false` makes the window
/// visible without making it the key window, so the main app window
/// keeps its first-responder state and touches don't get re-routed.
/// (When the user re-foregrounds, the shield hides; the keyboard's
/// pre-deactivation responder is still the active one.)
///
/// **F-801 — Keyboard caveat**: iOS 11+ places the system keyboard in a
/// `UIRemoteKeyboardWindow` whose level was elevated above `.alert`.
/// Bumping our shield to `.alert + 1` does NOT cover the keyboard. The
/// multitasking snapshot would otherwise show QuickType predictions of
/// in-flight composer text. We resign first responder on
/// `willDeactivate` BEFORE iOS captures the snapshot, which dismisses
/// the keyboard window entirely and is the path Apple sanctions for
/// this exact scenario.
@MainActor
final class PrivacyShieldWindow: NSObject {
    static let shared = PrivacyShieldWindow()

    /// One shield window per `UIWindowScene`. F-803.
    private var windows: [ObjectIdentifier: UIWindow] = [:]

    private override init() {}

    /// Wire up scene-lifecycle observers. Idempotent — call from
    /// `application(_:didFinishLaunchingWithOptions:)`. If any scenes
    /// are already connected (SwiftUI bootstrapped before us), we
    /// attach to each immediately rather than waiting for willConnect.
    func install() {
        let nc = NotificationCenter.default
        nc.addObserver(
            self,
            selector: #selector(sceneWillConnect(_:)),
            name: UIScene.willConnectNotification,
            object: nil
        )
        nc.addObserver(
            self,
            selector: #selector(sceneDidDisconnect(_:)),
            name: UIScene.didDisconnectNotification,
            object: nil
        )
        nc.addObserver(
            self,
            selector: #selector(sceneWillDeactivate(_:)),
            name: UIScene.willDeactivateNotification,
            object: nil
        )
        nc.addObserver(
            self,
            selector: #selector(sceneDidActivate(_:)),
            name: UIScene.didActivateNotification,
            object: nil
        )
        for scene in UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
        {
            createShieldWindow(in: scene)
        }
    }

    @objc private func sceneWillConnect(_ note: Notification) {
        guard let scene = note.object as? UIWindowScene else { return }
        createShieldWindow(in: scene)
    }

    @objc private func sceneDidDisconnect(_ note: Notification) {
        guard let scene = note.object as? UIScene else { return }
        windows.removeValue(forKey: ObjectIdentifier(scene))
    }

    @objc private func sceneWillDeactivate(_ note: Notification) {
        // F-801: dismiss the keyboard BEFORE iOS captures the
        // multitasking snapshot. Resigning first responder takes the
        // remote keyboard window with it, eliminating the QuickType
        // leak. Apple-sanctioned approach for hiding sensitive
        // composer state from snapshots; what Signal/WhatsApp do.
        //
        // **Scope the resign to this scene's app windows**, not the
        // global responder chain. A global resign would dismiss the
        // first responder inside an in-flight system overlay (the
        // photo picker's search field, the document picker's name
        // field) — the user comes back to find their picker reset.
        // Calling `endEditing(true)` on each app-owned UIWindow in
        // the scene walks only OUR responder chain; system-presented
        // remote view controllers live in another process and are
        // unaffected.
        if let scene = note.object as? UIWindowScene {
            for w in scene.windows where w.windowLevel == .normal {
                w.endEditing(true)
            }
            windows[ObjectIdentifier(scene)]?.isHidden = false
        } else if let scene = note.object as? UIScene {
            windows[ObjectIdentifier(scene)]?.isHidden = false
        } else {
            // Fallback for older notifications without a scene object —
            // raise every shield (cheap, < 5 windows in practice).
            for w in windows.values { w.isHidden = false }
        }
    }

    @objc private func sceneDidActivate(_ note: Notification) {
        if let scene = note.object as? UIScene {
            windows[ObjectIdentifier(scene)]?.isHidden = true
        } else {
            for w in windows.values { w.isHidden = true }
        }
    }

    private func createShieldWindow(in scene: UIWindowScene) {
        let key = ObjectIdentifier(scene)
        guard windows[key] == nil else { return }
        let host = UIHostingController(rootView: PrivacyShieldView())
        // The hosting view paints its own background; clearing here
        // avoids the system-grey flash before the SwiftUI view's first
        // layout pass.
        host.view.backgroundColor = .clear
        let w = UIWindow(windowScene: scene)
        w.windowLevel = UIWindow.Level.alert + 1
        w.rootViewController = host
        w.isHidden = true
        // Crucially NOT makeKeyAndVisible — see class doc.
        windows[key] = w
    }
}
