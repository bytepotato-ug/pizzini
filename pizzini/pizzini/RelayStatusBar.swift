import PizziniCryptoCore
import SwiftUI

/// Always-visible relay connection indicator. Lives in the
/// `.safeAreaInset(.top)` slot above every tab's navigation bar so
/// the user has one canonical place to glance at, regardless of
/// whether they're in the Chats list, inside a 1:1 / group chat,
/// on the Profile tab, or anywhere in Settings.
///
/// Visibility contract:
///   • `.connected`              → strip is **hidden** entirely. Steady
///                                 state has zero chrome.
///   • `.connecting`, `.idle`    → blue strip, "Connecting…" + spinner.
///   • `.connectingToTor(p)`     → blue strip, "Connecting to Tor… N%"
///                                 + spinner.
///   • `.failed(reason)`         → red strip, "No connection" + a
///                                 "Reconnect" action button. Tapping
///                                 invokes the same `forceReconnectRelays`
///                                 path the old in-list pill used to.
///
/// Animation: slide-from-top + fade on appear/disappear so connection
/// hiccups read as a soft drop-in rather than a layout jump that pushes
/// chat content. The `animation(_:value:)` keys on the case-discriminant
/// string so progress-tick updates within `.connectingToTor` don't
/// re-fire the slide animation, just the text.
///
/// Color rationale:
///   • Blue (`Color.composerAccent`, `#005bfd`) for in-progress states
///     reuses the brand accent already standardised in MessageComposer.
///   • Red (system) for `.failed` is the universal "this needs your
///     attention" signal.
struct RelayStatusBar: View {
    let state: RelayClient.State
    let onReconnect: () -> Void

    var body: some View {
        Group {
            if let kind = kind {
                strip(for: kind)
                    .transition(.move(edge: .top).combined(with: .opacity))
            }
        }
        .animation(.easeInOut(duration: 0.25), value: stateID)
    }

    /// Stable identifier for the current state that ignores
    /// progress-tick churn. `.connectingToTor(25)` and
    /// `.connectingToTor(75)` map to the same id, so the SwiftUI
    /// animation only fires on a real category change (e.g.
    /// connecting → failed), not on every BOOTSTRAP=N% update.
    private var stateID: String {
        switch state {
        case .idle: "idle"
        case .connecting: "connecting"
        case .connectingToTor: "tor"
        case .connected: "connected"
        case .failed: "failed"
        }
    }

    /// What flavour of strip to show. Returns `nil` for `.connected`
    /// (no strip), letting the surrounding `Group` collapse to empty
    /// and the `.safeAreaInset` shrink to zero height.
    private enum Kind {
        case connecting(text: String)
        case failed
    }
    private var kind: Kind? {
        switch state {
        case .connected:
            return nil
        case .idle, .connecting:
            return .connecting(text: "Connecting…")
        case .connectingToTor(let p):
            return .connecting(text: "Connecting to Tor… \(p)%")
        case .failed:
            return .failed
        }
    }

    @ViewBuilder
    private func strip(for kind: Kind) -> some View {
        switch kind {
        case .connecting(let text):
            HStack(spacing: 10) {
                ProgressView()
                    .controlSize(.mini)
                    .tint(.white)
                Text(text)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.composerAccent)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Pizzini is \(text.lowercased())")
        case .failed:
            HStack(spacing: 10) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .imageScale(.small)
                    .foregroundStyle(.white)
                Text("No connection")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.white)
                Spacer(minLength: 8)
                Button(action: onReconnect) {
                    Text("Reconnect")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(
                            Capsule()
                                .fill(Color.white.opacity(0.18))
                        )
                }
                .buttonStyle(.plain)
                .accessibilityHint("Retries the relay connection.")
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.red)
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Pizzini is not connected. Tap Reconnect to retry.")
        }
    }
}
