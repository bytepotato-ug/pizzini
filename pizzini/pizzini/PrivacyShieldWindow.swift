import SwiftUI
import UIKit

/// Window-level privacy shield. Hosts `PrivacyShieldView` in a separate
/// `UIWindow` at `.alert + 1` so it sits above every in-app surface —
/// including SwiftUI sheets, `Menu` popovers, alerts, action sheets,
/// and the keyboard — when the scene goes inactive. Without this, the
/// iOS multitasking snapshot would happily capture whatever sheet
/// happens to be open (notably the QR sheet and the ⋯ menu).
///
/// Why a separate window and not just an overlay in `ContentView`'s
/// `body`: SwiftUI sheets are presented in the *same* window as the
/// root view but at a higher z-position, so a ZStack overlay only
/// covers the underlying content. Sheets remain visible in the
/// snapshot. A second `UIWindow` at a higher level genuinely covers
/// everything.
///
/// Lifecycle: created on first scene connection, kept alive forever,
/// toggled via `isHidden`. `UIScene.willDeactivateNotification` fires
/// *before* iOS captures the multitasking snapshot, so a single
/// synchronous `isHidden = false` in that handler is enough — no
/// pre-render warm-up or animation needed.
///
/// Touch behaviour: deliberately **does not** call
/// `makeKeyAndVisible`. Setting `isHidden = false` makes the window
/// visible without making it the key window, so the main app window
/// keeps its first-responder state and touches don't get re-routed.
/// (When the user re-foregrounds, the shield hides; the keyboard's
/// pre-deactivation responder is still the active one.)
@MainActor
final class PrivacyShieldWindow: NSObject {
    static let shared = PrivacyShieldWindow()

    private var window: UIWindow?

    private override init() {}

    /// Wire up scene-lifecycle observers. Idempotent — call from
    /// `application(_:didFinishLaunchingWithOptions:)`. If a scene is
    /// already connected (SwiftUI bootstrapped before us), we attach
    /// to it immediately rather than waiting for the next willConnect.
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
        if let scene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .first
        {
            createShieldWindow(in: scene)
        }
    }

    @objc private func sceneWillConnect(_ note: Notification) {
        guard let scene = note.object as? UIWindowScene else { return }
        createShieldWindow(in: scene)
    }

    @objc private func sceneWillDeactivate(_ note: Notification) {
        // Synchronous so the snapshot iOS is about to take sees the
        // shield, not the sheet behind it.
        window?.isHidden = false
    }

    @objc private func sceneDidActivate(_ note: Notification) {
        window?.isHidden = true
    }

    private func createShieldWindow(in scene: UIWindowScene) {
        guard window == nil else { return }
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
        window = w
    }
}
