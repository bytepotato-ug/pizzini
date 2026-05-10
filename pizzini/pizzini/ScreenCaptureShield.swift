import SwiftUI
import UIKit

/// Opaque overlay shown above chat / contacts / settings whenever
/// `ScreenCaptureMonitor.isRecording` or `.hasExternalDisplay` is true.
/// Re-uses `PrivacyShieldView`'s visual language (lock-shield icon on
/// the system background) so users learn one shape: "this view is
/// covered for a privacy reason."
///
/// We deliberately keep the surrounding navigation bar visible. A user
/// who triggered the shield by accidentally enabling Control Centre's
/// Record button must still be able to navigate out, and "Pizzini just
/// became unresponsive" is a worse failure mode than "Pizzini briefly
/// hides content while you're recording."
///
/// Why this is a separate file from `PrivacyShieldView`: the
/// app-switcher snapshot shield is plain — there is no useful copy to
/// show because the user isn't reading at that moment. The capture
/// shield IS in front of the user, so it carries copy that names the
/// reason. Keeping both in one type with a `mode` enum invites future
/// drift; two small views is cleaner.
struct ScreenCaptureShield: View {
    enum Reason {
        case recording
        case externalDisplay

        var iconName: String {
            switch self {
            case .recording: return "record.circle"
            case .externalDisplay: return "tv"
            }
        }

        var headline: String {
            switch self {
            case .recording: return "Recording detected"
            case .externalDisplay: return "External display detected"
            }
        }

        var detail: String {
            switch self {
            case .recording:
                return "Your chats are hidden while screen recording or screen mirroring is active."
            case .externalDisplay:
                return "Your chats are hidden while another display is connected. AirPlay mirroring counts."
            }
        }
    }

    let reason: Reason

    var body: some View {
        ZStack {
            Color(.systemBackground)
                .ignoresSafeArea()
            VStack(spacing: 14) {
                Image(systemName: reason.iconName)
                    .font(.system(size: 56))
                    .foregroundStyle(.tint)
                Text(reason.headline)
                    .font(.title3.weight(.semibold))
                Text(reason.detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 36)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(reason.headline). \(reason.detail)")
    }
}

/// SwiftUI modifier that overlays `ScreenCaptureShield` above any view
/// containing chat / contact / QR data when capture is active. External
/// display takes precedence over recording (the message names a
/// stronger constraint, and an external-display attach often *also*
/// flips `isCaptured` so we'd otherwise flicker between the two
/// reasons).
struct ScreenCaptureShieldModifier: ViewModifier {
    @Bindable var monitor: ScreenCaptureMonitor

    func body(content: Content) -> some View {
        ZStack {
            content
            if monitor.hasExternalDisplay {
                ScreenCaptureShield(reason: .externalDisplay)
                    .transition(.opacity)
            } else if monitor.isRecording {
                ScreenCaptureShield(reason: .recording)
                    .transition(.opacity)
            }
        }
    }
}

extension View {
    /// Wraps the view in a `ScreenCaptureShield` overlay that activates
    /// while iOS reports a screen recording or an external display.
    /// Apply to any surface that contains chat / contact / QR data.
    ///
    /// Reads `ScreenCaptureMonitor.shared` directly inside a
    /// `@MainActor` body rather than via a default arg — Swift 6
    /// rejects a main-actor-isolated default expression on a
    /// nonisolated callsite, and SwiftUI body callsites are
    /// nonisolated. Tests / previews that need to inject a custom
    /// monitor can construct `ScreenCaptureShieldModifier` directly.
    func screenCaptureShielded() -> some View {
        modifier(SharedScreenCaptureShieldModifier())
    }
}

/// Thin wrapper that resolves `ScreenCaptureMonitor.shared` lazily on
/// the main actor (where SwiftUI's body runs). Splitting this out keeps
/// `ScreenCaptureShieldModifier` test-friendly: tests can inject a
/// custom monitor; callers in production code never have to think
/// about the actor isolation.
private struct SharedScreenCaptureShieldModifier: ViewModifier {
    func body(content: Content) -> some View {
        // SwiftUI body runs on the main actor, so it's safe to touch
        // the main-actor-isolated `.shared` here.
        let monitor = ScreenCaptureMonitor.shared
        return ZStack {
            content
            if monitor.hasExternalDisplay {
                ScreenCaptureShield(reason: .externalDisplay)
                    .transition(.opacity)
            } else if monitor.isRecording {
                ScreenCaptureShield(reason: .recording)
                    .transition(.opacity)
            }
        }
    }
}
