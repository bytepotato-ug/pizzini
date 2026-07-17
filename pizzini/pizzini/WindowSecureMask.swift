import UIKit

/// Window-level screenshot / screen-recording / mirroring mask.
///
/// For each `UIWindowScene` the app brings up, this manager reparents
/// the scene's main `UIWindow.layer` under a hidden secure
/// `UITextField`'s layer chain. The OS capture pipeline treats the
/// resulting layer subtree as a password field and renders it as a
/// black frame in screenshots, AirPlay, screen recording, and most
/// remote-screen-sharing tooling that uses the public capture path.
///
/// **Why window-level rather than view-level wrapping**: the earlier
/// `SecureScreenshotShield` wrapped the entire SwiftUI hierarchy in a
/// `UITextField` subview. UITextField's internal text-canvas subview
/// doesn't reliably size itself to the field's full bounds — particularly
/// on the status-bar / home-indicator rows on iOS 26 — which left white
/// safe-area strips on every grouped-background screen (Settings, FAQ).
/// Reparenting at the window's CALayer leaves the view hierarchy
/// untouched: SwiftUI sees the normal window frame and safe-area insets,
/// so `Form` and `.insetGrouped` `List` backgrounds extend through the
/// status-bar and home-indicator regions exactly as in an unprotected
/// app, while the screenshot pipeline still sees a secure subtree.
///
/// **Pattern source**: production banking and authenticator apps.
/// Documented at length in the iOS-screenshot-protection write-ups
/// referenced in the FAQ. Reimplemented in-tree to keep this
/// security-critical path off any third-party SDK, per the README's
/// "no third-party SDKs" hard rule.
///
/// **Simulator caveat**: iOS Simulator does not honour `isSecureTextEntry`
/// masking in the same way as a real device. The runtime self-test
/// (`SecureScreenshotSelfTest`) uses `drawHierarchy(in:afterScreenUpdates:)`,
/// the documented snapshot path that shares masking with the screenshot
/// service, so it returns a meaningful answer on simulator and device.
/// The actual screenshot service in the simulator is not protected,
/// however — verify on hardware before shipping.
///
/// **Lifecycle**: per-scene. One reparent per scene's main window,
/// applied on first activation, idempotent on subsequent activations.
/// Mirrors `PrivacyShieldWindow`'s scene-keyed dictionary so iPad
/// multi-window doesn't silently drop coverage on the second scene.
///
/// **Honesty about what this is** (developer comments — NEVER user
/// copy): this relies on undocumented Core Animation behaviour. Apple
/// has been narrowing the secure-text-entry capture skip across
/// releases. The runtime self-test is the safety net: if the skip
/// stops working we mark `qrBlockEffective = false` and bail out of
/// the reparent so we don't falsely advertise protection.
@MainActor
final class WindowSecureMask: NSObject {
    static let shared = WindowSecureMask()

    /// Windows whose layer has been reparented under a secure field.
    /// Identified by `ObjectIdentifier(window)` so re-activations are
    /// no-ops.
    private var masked: Set<ObjectIdentifier> = []

    /// Strong reference to each masking text field, one per masked
    /// window. The reparented `CALayer` chain only weakly retains
    /// `field.layer` via the superlayer pointer; if the field deallocs
    /// the secure subtree collapses and screenshot capture leaks.
    private var fields: [ObjectIdentifier: UITextField] = [:]

    override private init() {}

    /// Wire up scene-lifecycle observers. Idempotent — safe to call
    /// from `application(_:didFinishLaunchingWithOptions:)` alongside
    /// `PrivacyShieldWindow.shared.install()`.
    func install() {
        let nc = NotificationCenter.default
        nc.addObserver(
            self,
            selector: #selector(sceneDidActivate(_:)),
            name: UIScene.didActivateNotification,
            object: nil,
        )
        // Stage Manager off-stage transitions disconnect scenes; on
        // reconnect iOS may hand back a new UIWindow instance with a
        // different ObjectIdentifier. Without cleanup, the `masked`
        // and `fields` dictionaries leak old keys + retain old
        // text-field instances forever. Observe disconnect and clean
        // up so re-application on the new window starts from a clean
        // bookkeeping state.
        nc.addObserver(
            self,
            selector: #selector(sceneDidDisconnect(_:)),
            name: UIScene.didDisconnectNotification,
            object: nil,
        )
        // If scenes are already connected (SwiftUI typically bootstraps
        // its first scene before AppDelegate finishes), apply to each
        // immediately rather than waiting for the next activation tick.
        for scene in UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
        {
            applyToScene(scene)
        }
    }

    @objc private func sceneDidActivate(_ note: Notification) {
        guard let scene = note.object as? UIWindowScene else { return }
        applyToScene(scene)
    }

    @objc private func sceneDidDisconnect(_ note: Notification) {
        guard let scene = note.object as? UIWindowScene else { return }
        // Drop entries for any window owned by this scene. We don't
        // hold a back-pointer from key → window, so we walk the
        // scene's known windows and remove their identifiers.
        for window in scene.windows {
            let key = ObjectIdentifier(window)
            masked.remove(key)
            fields.removeValue(forKey: key)
        }
    }

    private func applyToScene(_ scene: UIWindowScene) {
        // Honour the runtime self-test result. When the secure-text-
        // entry trick is known broken on this iOS, applying it would
        // be theatre — return without touching the layer hierarchy.
        guard ChatStore.shared.shouldMaskAppContents else { return }
        // Find the SwiftUI app's main window — the one with a root VC
        // set by `WindowGroup`. `PrivacyShieldWindow`'s overlay window
        // has no `rootViewController` until activated and is at
        // `.alert + 1`, so we filter to the scene's standard-level
        // window.
        guard let window = scene.windows.first(where: { window in
            window.rootViewController != nil && window.windowLevel == .normal
        }) else { return }
        applyToWindow(window)
    }

    /// PZ-M10 — should a synchronous bridging cover be raised before
    /// we schedule the deferred reparent? Yes exactly when masking is
    /// enabled AND this activation will actually do a fresh reparent.
    ///
    /// • masking disabled (self-test says the secure-text trick is
    ///   broken on this OS) → no cover; a black flash would be pure
    ///   theatre with no mask to bridge to.
    /// • already masked-and-intact (a no-op re-activation) → no cover;
    ///   flashing one would be a visible glitch with nothing to hide.
    ///
    /// When it returns true the contract is: an opaque cover is on
    /// screen for every frame between now and the reparent commit, so
    /// the OS capture pipeline never sees an unmasked live frame during
    /// the one-runloop deferral.
    nonisolated static func shouldRaiseBridgingCover(
        maskingEnabled: Bool,
        alreadyMaskedAndIntact: Bool,
    ) -> Bool {
        maskingEnabled && !alreadyMaskedAndIntact
    }

    /// Build the opaque cover that bridges the activate→reparent gap.
    /// Black, full-window, follows resize, non-interactive. It is added
    /// as a window subview so it sits inside `window.layer`'s subtree
    /// and therefore rides along when the window layer is reparented
    /// under the secure mask — there is never a frame where the cover
    /// is gone but the mask is not yet installed.
    private func makeBridgingCover(for window: UIWindow) -> UIView {
        let cover = UIView(frame: window.bounds)
        cover.backgroundColor = .black
        cover.isOpaque = true
        cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        cover.isUserInteractionEnabled = false
        cover.accessibilityElementsHidden = true
        return cover
    }

    private func applyToWindow(_ window: UIWindow) {
        let key = ObjectIdentifier(window)
        // If we already applied to this window AND the layer chain is
        // still intact, no-op. iOS Stage Manager bring-back of the
        // same UIWindow can leave our reparented field intact OR
        // discard it depending on the transition; re-validate the
        // parentage so we re-wire if needed rather than trusting the
        // bookkeeping.
        let alreadyIntact: Bool = masked.contains(key)
            && (fields[key].flatMap {
                resolveSecureLayer(in: $0)?.sublayers?.contains(window.layer)
            } ?? false)
        guard Self.shouldRaiseBridgingCover(
            maskingEnabled: ChatStore.shared.shouldMaskAppContents,
            alreadyMaskedAndIntact: alreadyIntact,
        ) else {
            // Either masking is disabled, or the window is already
            // masked-and-intact — nothing to do, no cover to flash.
            return
        }
        // Stale bookkeeping (masked but layer chain broken) — clear it
        // and fall through to re-apply.
        if masked.contains(key) {
            masked.remove(key)
            fields.removeValue(forKey: key)
        }

        // PZ-M10: close the cold-launch / Stage-Manager-bring-back race.
        // `applyToWindow` runs synchronously on the main thread during
        // scene activation, but the reparent below is deferred one
        // runloop turn (it needs `window.layer.superlayer` + the initial
        // layout pass). Between activation and that turn, the live,
        // UNMASKED window would render to the screenshot / recording /
        // mirroring pipeline. Raise an opaque cover NOW — in the same
        // synchronous turn that lays out the first content frame, so the
        // first composited frame is already black — and tear it down only
        // after the reparent has landed (or failed). The multitasking
        // snapshot is covered separately by `PrivacyShieldWindow`; this
        // closes the live-foreground-capture gap that shield does not.
        let cover = makeBridgingCover(for: window)
        window.addSubview(cover)

        // Two preconditions for the reparent to land:
        //   1. window.layer.superlayer must already exist — that's the
        //      slot we hand the secure field's layer into.
        //   2. The window must have completed its initial layout pass.
        // Deferring one runloop turn satisfies both on iOS 17/18/26.
        DispatchQueue.main.async { [weak self, weak window, weak cover] in
            // Remove the bridging cover on EVERY exit path. On success
            // the window layer is already under the secure mask by the
            // time this runs, so lifting the cover reveals masked
            // content with no gap. On failure we revert to the
            // pre-M10 behaviour (unmasked but usable) rather than
            // leaving the UI stuck behind a black cover.
            defer { cover?.removeFromSuperview() }
            guard let self, let window else { return }
            guard let parent = window.layer.superlayer else { return }

            let field = NonInteractiveSecureTextField()
            field.isSecureTextEntry = true
            field.isUserInteractionEnabled = false
            // DO NOT set `field.alpha = 0` here. UIView.alpha sets
            // layer.opacity, which propagates to every sublayer — and
            // immediately below we make `window.layer` a sublayer of
            // `field.layer`'s secure container. An alpha of zero on
            // the field would render the entire app window invisible
            // (black screen on launch). The field is naturally invisible
            // anyway: default frame is (0, 0, 0, 0), no border, no
            // text, no background.
            field.backgroundColor = .clear
            window.addSubview(field)
            // Force the field's layout pass so its secure canvas
            // subview/sublayer exists before `resolveSecureLayer`
            // walks for it.
            field.layoutIfNeeded()

            // The reparent. Step-by-step:
            //   - parent.addSublayer(field.layer) puts the secure
            //     field's layer beside the window in the screen's
            //     render tree.
            //   - `resolveSecureLayer` returns the secure container
            //     layer that iOS marks as "skip in screenshots" — the
            //     SAME layer `SecureScreenshotSelfTest` validates.
            //     Adding window.layer as its sublayer moves the entire
            //     app window underneath the secure mark.
            // Visually unchanged because the window's frame and
            // CATransform are untouched; only its layer position in
            // the render tree moved.
            guard let secureLayer = resolveSecureLayer(in: field) else { return }
            parent.addSublayer(field.layer)
            secureLayer.addSublayer(window.layer)

            self.masked.insert(key)
            self.fields[key] = field
        }
    }
}
