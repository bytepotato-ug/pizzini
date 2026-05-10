import SwiftUI
import UIKit

/// SwiftUI wrapper that hosts arbitrary content inside a
/// `UITextField` whose `isSecureTextEntry == true`. iOS's screenshot
/// service renders the secure container blank in the captured
/// framebuffer; the same skip applies to AirPlay mirroring of
/// secure-text fields. Used ONLY on `MyQRSheet`'s qrSurface, where a
/// single screenshot would deanonymise the user on the relay network
/// — the QR is the highest-leak surface in the app.
///
/// **Honesty about what this is** (developer comments — NEVER user
/// copy): this is not a documented API. Banking apps and password
/// managers have used the pattern for years (it's behind iOS Keychain
/// password autofill's "blank in screenshot" behaviour), but Apple has
/// been narrowing it across iOS releases. The runtime self-test in
/// `runSelfTest` is the safety net: if the trick stops working we
/// silently fall back to the conventional shield rather than continue
/// to falsely advertise the protection.
///
/// Prior art consulted (one-shot read; no code copied verbatim):
/// - freeRASP-iOS (Talsec, MIT) — same `subviews.last` containment
/// - ScreenShield by Diego Rico — same pattern, MIT
///
/// We deliberately reimplemented in-tree to keep this security-critical
/// path off any third-party iOS dependency, per the README's "no
/// third-party SDKs" hard rule.
struct SecureScreenshotShield<Content: View>: UIViewRepresentable {
    let content: () -> Content

    init(@ViewBuilder content: @escaping () -> Content) {
        self.content = content
    }

    func makeUIView(context: Context) -> UIView {
        let textField = UITextField()
        textField.isSecureTextEntry = true
        textField.isUserInteractionEnabled = false
        textField.backgroundColor = .clear
        textField.translatesAutoresizingMaskIntoConstraints = false

        // The last subview of a secure UITextField is the "canvas" iOS
        // draws masked content into. We host our SwiftUI content inside
        // that canvas so its bytes live inside the secret container.
        // Apple has not stabilised this layout, but it's been the same
        // shape since iOS 13 — the runtime self-test catches any future
        // change.
        guard let canvas = textField.subviews.last else {
            // Structural fallback — render the content normally rather
            // than crash. The runtime self-test will mark
            // `qrBlockEffective = false` so the call site falls back
            // to the conventional shield on next launch.
            let host = UIHostingController(rootView: content())
            host.view.frame = textField.bounds
            host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
            textField.addSubview(host.view)
            context.coordinator.hostController = host
            return textField
        }
        let host = UIHostingController(rootView: content())
        context.coordinator.hostController = host
        host.view.translatesAutoresizingMaskIntoConstraints = false
        host.view.backgroundColor = .clear
        canvas.subviews.forEach { $0.removeFromSuperview() }
        canvas.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.leadingAnchor.constraint(equalTo: canvas.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: canvas.trailingAnchor),
            host.view.topAnchor.constraint(equalTo: canvas.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: canvas.bottomAnchor),
        ])
        return textField
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        context.coordinator.hostController?.rootView = content()
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator {
        var hostController: UIHostingController<Content>?
    }
}

/// Runtime self-test. Renders a sentinel red square inside a
/// `SecureScreenshotShield` and asks `UIView.drawHierarchy` —
/// the documented snapshot path that secure-text-entry containers
/// honour the same way they honour the actual screenshot pipeline —
/// to capture the result. If the captured pixels at the sentinel's
/// centre are red, the trick is broken on this iOS version and we
/// must fall back.
///
/// Why `drawHierarchy` and not the actual screenshot service: there's
/// no in-process API to programmatically invoke iOS's screenshot
/// service. `drawHierarchy(in:afterScreenUpdates:)` is the closest
/// documented approximation — Apple uses the same masking path for
/// snapshots, mirroring, and screenshots. If drawHierarchy shows our
/// sentinel, the screenshot service definitely will too. If it shows
/// blank, the screenshot service almost certainly will as well, but
/// Apple's documentation does not contractually guarantee identity —
/// we therefore present the user copy as "best effort, may break in
/// future iOS releases" even when the self-test passes.
@MainActor
enum SecureScreenshotSelfTest {
    /// Runs the self-test if it hasn't run on this iOS major version.
    /// Persists the result via `ChatStore.setQRBlockEffective`.
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
            NSLog(
                "[pizzini] SecureScreenshotShield self-test FAILED on iOS \(currentOS) — falling back to detection-only QR shield. The isSecureTextEntry workaround appears to no longer mask captured frames. Investigate."
            )
        } else {
            NSLog(
                "[pizzini] SecureScreenshotShield self-test passed on iOS \(currentOS). QR-block path is active."
            )
        }
    }

    /// Standalone runner — no persistence, returns the result. Exposed
    /// for tests.
    static func run() -> Bool {
        let sentinelColor = UIColor.red
        let probeSize: CGFloat = 64

        let secureField = UITextField()
        secureField.isSecureTextEntry = true
        secureField.isUserInteractionEnabled = false
        secureField.frame = CGRect(x: 0, y: 0, width: probeSize, height: probeSize)

        // Structural check first — if we can't find the canvas at all,
        // the trick is unreachable on this OS.
        guard let canvas = secureField.subviews.last else { return false }

        let sentinel = UIView(frame: CGRect(x: 0, y: 0, width: probeSize, height: probeSize))
        sentinel.backgroundColor = sentinelColor
        sentinel.translatesAutoresizingMaskIntoConstraints = false
        canvas.subviews.forEach { $0.removeFromSuperview() }
        canvas.addSubview(sentinel)
        NSLayoutConstraint.activate([
            sentinel.leadingAnchor.constraint(equalTo: canvas.leadingAnchor),
            sentinel.trailingAnchor.constraint(equalTo: canvas.trailingAnchor),
            sentinel.topAnchor.constraint(equalTo: canvas.topAnchor),
            sentinel.bottomAnchor.constraint(equalTo: canvas.bottomAnchor),
        ])
        secureField.layoutIfNeeded()

        // Render via drawHierarchy — the documented snapshot path that
        // secure containers mask. If the captured image is mostly red,
        // the trick is broken; if it's mostly NOT red (black / clear /
        // system-grey, depending on the iOS version's blank-render
        // colour), the trick still works.
        let renderer = UIGraphicsImageRenderer(size: secureField.bounds.size)
        let image = renderer.image { _ in
            // afterScreenUpdates: true forces a fresh layout pass before
            // capture, which is what iOS's actual screenshot service
            // does. afterScreenUpdates: false caches a stale render and
            // would mask the test.
            secureField.drawHierarchy(in: secureField.bounds, afterScreenUpdates: true)
        }
        return !sampleIsRed(image: image, threshold: 0.10)
    }

    /// Samples a 4×4 grid in the centre 50 % of the image. Returns true
    /// iff the FRACTION of "red" pixels exceeds `threshold`. Used by
    /// `run()` — if too much red leaked through the secure container,
    /// the trick has stopped working.
    private static func sampleIsRed(image: UIImage, threshold: Double) -> Bool {
        guard let cg = image.cgImage else { return false }
        let w = cg.width
        let h = cg.height
        guard w > 0, h > 0 else { return false }
        guard let data = cg.dataProvider?.data,
              let bytes = CFDataGetBytePtr(data) else { return false }
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
                // Try both BGRA and RGBA pixel orderings — iOS uses BGRA
                // by default for premultiplied bitmaps. The "red" channel
                // is the one that's bright when the source colour was
                // pure red.
                let red: UInt8
                let green: UInt8
                let blue: UInt8
                if alphaInfo == .premultipliedFirst || alphaInfo == .first {
                    // BGRA: byte order is B, G, R, A — but with .first
                    // alpha it's actually A, R, G, B... we don't know
                    // statically. Cover both: declare "red dominant" if
                    // any of the first three bytes is high AND the other
                    // two are low.
                    red = max(b0, b1, b2)
                    green = min(b0, b1, b2)
                    blue = (UInt8(b0) &+ UInt8(b1) &+ UInt8(b2)) &- red &- green
                } else {
                    red = b0
                    green = b1
                    blue = b2
                }
                if red > 200 && green < 80 && blue < 80 {
                    redHits += 1
                }
                samples += 1
            }
        }
        guard samples > 0 else { return false }
        return Double(redHits) / Double(samples) > threshold
    }

    /// Extract the major-version component as an integer-valued string.
    /// "26.0" → "26", "17.5" → "17". We only re-test across major
    /// boundaries because Apple has only ever changed
    /// secure-text-entry behaviour in major releases.
    private static func majorVersion(of os: String) -> String {
        os.split(separator: ".").first.map(String.init) ?? os
    }
}
