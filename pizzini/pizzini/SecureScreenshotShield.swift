import os
import SwiftUI
import UIKit

/// Screenshot-mask self-test log channel. Console.app filter:
/// `subsystem:app.pizzini category:screencap`. A failed self-test
/// is `.fault` so it surfaces in unified logging even on release
/// (an attacker-extractable sysdiagnose seeing "self-test FAILED"
/// is fine — it tells them nothing useful about the user's data,
/// only that this device's UIKit revision broke our mask). The
/// OS version string is `.private` out of caution.
private let screenCapLog = Logger(subsystem: "app.pizzini", category: "screencap")

/// Subclassed secure `UITextField` used by `WindowSecureMask` (in
/// production) and by `SecureScreenshotSelfTest` (at launch) to host
/// the secure-text-entry mask. Disables every interactive path the
/// field would otherwise wire up — first-responder, caret, selection
/// rects, edit menu — because we never want it to actually receive
/// input. The subclass MUST be `final` and `@objc` so the Objective-C
/// runtime metadata that `resolveSecureLayer` uses (class-name
/// reflection) surfaces consistently across iOS versions.
///
/// **Honesty about what this is** (developer comments — NEVER user
/// copy): `isSecureTextEntry` is not a documented screenshot-masking
/// API. Banking apps and password managers have used the side effect
/// for years (it is also why iOS Keychain password autofill produces
/// a blank cell in screenshots), but Apple has been narrowing the
/// behaviour across releases. The runtime self-test below is the
/// safety net: if the trick stops working we bail out of the
/// `WindowSecureMask` reparent and the call sites fall back to the
/// conventional shield rather than continue to falsely advertise the
/// protection.
///
/// Prior art consulted (one-shot read; no code copied verbatim):
/// - freeRASP-iOS (Talsec, MIT)
/// - ScreenShield by Diego Rico (MIT)
/// - The Moin iOS app's internal handoff (the source of the
///   non-interactive secure-field subclass pattern below).
@objc(PizziniNonInteractiveSecureTextField)
final class NonInteractiveSecureTextField: UITextField {
    override var canBecomeFirstResponder: Bool { false }
    override func caretRect(for position: UITextPosition) -> CGRect { .zero }
    override func selectionRects(for range: UITextRange) -> [UITextSelectionRect] { [] }
    override func canPerformAction(_ action: Selector, withSender _: Any?) -> Bool { false }
}

/// Resolves the single `CALayer` that iOS marks as "skip in screen
/// captures" inside a secure `UITextField` — the one and only layer
/// both the production `WindowSecureMask` reparent AND the
/// `SecureScreenshotSelfTest` must target. Routing both code paths
/// through this function guarantees the self-test validates exactly
/// the layer production reparents under; there is no second path that
/// can pick a different one.
///
/// Strategy:
/// 1. Prefer the layer of a subview whose class name matches Apple's
///    known pattern (`_UITextLayoutCanvasView`, `UITextLayoutCanvasView`,
///    or any `*Canvas*` class) — robust to subview/sublayer-order
///    shuffles, which Apple has done across iOS major releases.
/// 2. Fall back to `layer.sublayers.last` (correct on iOS 16-26) and
///    then `.first` (correct on older code paths some references still
///    document) so we degrade gracefully if the class names change.
@MainActor
func resolveSecureLayer(in textField: UITextField) -> CALayer? {
    for sv in textField.subviews {
        let name = String(describing: type(of: sv))
        // Common class names across iOS versions:
        //   _UITextLayoutCanvasView (iOS 16+)
        //   UITextLayoutCanvasView (iOS 14-15-ish)
        //   _UITextFieldCanvasView (older)
        // Substring "Canvas" is the stable signal across all three.
        // A subview's layer is itself a sublayer of `textField.layer`,
        // so returning it keeps us in the same layer tree the fallback
        // walks.
        if name.contains("Canvas") {
            return sv.layer
        }
    }
    return textField.layer.sublayers?.last ?? textField.layer.sublayers?.first
}

/// Runtime self-test for the `isSecureTextEntry` screenshot-mask side
/// effect. Renders a sentinel red square inside a
/// `NonInteractiveSecureTextField`'s secure canvas and asks
/// `UIView.drawHierarchy(in:afterScreenUpdates:)` — the documented
/// snapshot path that secure-text-entry containers honour the same
/// way they honour the actual screenshot pipeline — to capture the
/// result. If the captured pixels at the sentinel's centre are red,
/// the trick is broken on this iOS version and we must fall back.
///
/// Why `drawHierarchy` and not the actual screenshot service: there
/// is no in-process API to programmatically invoke iOS's screenshot
/// service. `drawHierarchy(in:afterScreenUpdates:)` is the closest
/// documented approximation — Apple uses the same masking path for
/// snapshots, mirroring, and screenshots. If `drawHierarchy` shows
/// our sentinel, the screenshot service definitely will too. If it
/// shows blank, the screenshot service almost certainly will as well,
/// but Apple's documentation does not contractually guarantee
/// identity — so we surface the user-facing copy as "best effort,
/// may break in future iOS releases" even when the self-test passes.
@MainActor
enum SecureScreenshotSelfTest {
    /// Runs the self-test if it has not already run on this iOS
    /// major version. Persists the result via
    /// `ChatStore.setQRBlockEffective`.
    static func runIfNeeded(store: ChatStore) {
        let currentOS = UIDevice.current.systemVersion
        let currentMajor = majorVersion(of: currentOS)
        let priorMajor = store.state.qrBlockTestedOSVersion.map(majorVersion(of:))
        if store.state.qrBlockEffective != nil, priorMajor == currentMajor {
            return
        }
        let effective = run()
        store.setQRBlockEffective(effective, osVersion: currentOS)
        if !effective {
            screenCapLog.fault(
                "SecureScreenshotSelfTest FAILED on iOS \(currentOS, privacy: .private) — isSecureTextEntry no longer masks captured frames. WindowSecureMask is now a no-op; investigate."
            )
        } else {
            screenCapLog.notice(
                "SecureScreenshotSelfTest passed on iOS \(currentOS, privacy: .private). WindowSecureMask is active."
            )
        }
    }

    /// Standalone runner — no persistence, returns the result. Exposed
    /// for tests.
    static func run() -> Bool {
        let sentinelColor = UIColor.red
        let probeSize: CGFloat = 64

        let secureField = NonInteractiveSecureTextField()
        secureField.isSecureTextEntry = true
        secureField.frame = CGRect(x: 0, y: 0, width: probeSize, height: probeSize)
        secureField.layoutIfNeeded()

        // Structural check first — if we cannot find the secure layer
        // at all, the trick is unreachable on this OS. Resolves the
        // SAME layer `WindowSecureMask` reparents under, so a class-
        // name / sublayer-order shuffle catches both code paths.
        guard let secureLayer = resolveSecureLayer(in: secureField) else { return false }

        // The 64×64 probe proves the trick works *somewhere*, but
        // `WindowSecureMask` hosts the production mask on a
        // DEFAULT-frame (0×0) field. Independently confirm the secure
        // layer also resolves in that exact configuration — without
        // this, a future iOS that only instantiates the secure canvas
        // for a sized field would let the self-test pass while
        // production silently fails to mask. Fail closed.
        let productionShapeField = NonInteractiveSecureTextField()
        productionShapeField.isSecureTextEntry = true
        productionShapeField.layoutIfNeeded()
        guard resolveSecureLayer(in: productionShapeField) != nil else { return false }

        // Mirror `WindowSecureMask`: add the sentinel as a sublayer of
        // the secure layer, exactly as production parents `window.layer`
        // under it. Validating a layer the production path does not use
        // is precisely the bug this test guards against.
        let sentinel = CALayer()
        sentinel.frame = CGRect(x: 0, y: 0, width: probeSize, height: probeSize)
        sentinel.backgroundColor = sentinelColor.cgColor
        secureLayer.sublayers?.forEach { $0.removeFromSuperlayer() }
        secureLayer.addSublayer(sentinel)
        secureField.layoutIfNeeded()

        let renderer = UIGraphicsImageRenderer(size: secureField.bounds.size)
        let image = renderer.image { _ in
            // afterScreenUpdates: true forces a fresh layout pass
            // before capture, which is what iOS's actual screenshot
            // service does. afterScreenUpdates: false caches a stale
            // render and would mask the test.
            secureField.drawHierarchy(in: secureField.bounds, afterScreenUpdates: true)
        }
        return !sampleIsRed(image: image, threshold: 0.10)
    }

    /// Samples a 4×4 grid in the centre 50% of the image. Returns true
    /// iff the fraction of "red" pixels exceeds `threshold`. Used by
    /// `run()` — if too much red leaked through the secure container,
    /// the trick has stopped working.
    private static func sampleIsRed(image: UIImage, threshold: Double) -> Bool {
        guard let cg = image.cgImage else { return false }
        let w = cg.width
        let h = cg.height
        guard w > 0, h > 0 else { return false }
        guard let data = cg.dataProvider?.data,
              let bytes = CFDataGetBytePtr(data)
        else { return false }
        let bpr = cg.bytesPerRow
        let bpp = cg.bitsPerPixel / 8
        let alphaInfo = cg.alphaInfo

        var redHits = 0
        var samples = 0
        let gridN = 4
        for gy in 1...gridN {
            for gx in 1...gridN {
                let x = (w * gx) / (gridN + 1)
                let y = (h * gy) / (gridN + 1)
                let offset = y * bpr + x * bpp
                guard offset + 3 < bpr * h else { continue }
                let b0 = bytes[offset]
                let b1 = bytes[offset + 1]
                let b2 = bytes[offset + 2]
                let red: UInt8
                let green: UInt8
                let blue: UInt8
                if alphaInfo == .premultipliedFirst || alphaInfo == .first {
                    red = max(b0, b1, b2)
                    green = min(b0, b1, b2)
                    blue = (UInt8(b0) &+ UInt8(b1) &+ UInt8(b2)) &- red &- green
                } else {
                    red = b0
                    green = b1
                    blue = b2
                }
                if red > 200, green < 80, blue < 80 {
                    redHits += 1
                }
                samples += 1
            }
        }
        guard samples > 0 else { return false }
        return Double(redHits) / Double(samples) > threshold
    }

    /// Extract the major-version component as an integer-valued
    /// string. "26.0" → "26", "17.5" → "17". We only re-test across
    /// major boundaries because Apple has only ever changed
    /// secure-text-entry behaviour in major releases.
    private static func majorVersion(of os: String) -> String {
        os.split(separator: ".").first.map(String.init) ?? os
    }
}
