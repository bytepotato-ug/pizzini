import SwiftUI

/// First-launch flow. Two steps: welcome screen (threat-model TL;DR),
/// then a Face ID opt-in. The opt-in does a real authentication
/// round-trip *before* flipping `biometricLockEnabled` on, so we
/// don't end up with a setting enabled when biometrics are
/// unavailable / unenrolled / dismissed.
///
/// `onComplete` is called with the chosen biometric setting; the host
/// then writes it to AppState and dismisses the cover.
struct OnboardingView: View {
    let onComplete: (_ enableBiometric: Bool) -> Void

    @State private var step: Step = .welcome
    @State private var authError: String?
    @State private var authInFlight = false

    private enum Step { case welcome, icons, biometric }

    var body: some View {
        NavigationStack {
            VStack {
                switch step {
                case .welcome:    welcomeStep
                case .icons:      iconsStep
                case .biometric:  biometricStep
                }
            }
            .padding(.horizontal, 24)
        }
        .interactiveDismissDisabled(true)
    }

    private var iconsStep: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 72))
                .foregroundStyle(.tint)
            Text("What the ticks mean")
                .font(.title.bold())
                .multilineTextAlignment(.center)
            VStack(alignment: .leading, spacing: 14) {
                iconRow("⏳", color: .secondary, label: "Waiting — your phone or the relay was offline.")
                iconRow("✓", color: .secondary, label: "Sent to the relay.")
                iconRow("✓✓", color: .blue, label: "Your contact's phone got it.")
                eyeRow(label: "They read it. (Only shows when your contact has read receipts on for you.)")
                iconRow("✗", color: .red, label: "Expired before reaching them. Try again.")
            }
            .font(.body)
            .padding(.top, 8)
            Spacer()
            Button {
                step = .biometric
            } label: {
                Text("Continue")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding()
            }
            .buttonStyle(.borderedProminent)
            .padding(.bottom, 24)
        }
    }

    private func iconRow(_ glyph: String, color: Color, label: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(glyph)
                .font(.title2.monospaced())
                .foregroundStyle(color)
                .frame(minWidth: 36, alignment: .leading)
            Text(label)
        }
    }

    /// SF-Symbol variant for the eye glyph. Kept separate from
    /// `iconRow` because the unicode-Text path doesn't render an SF
    /// Symbol cleanly at the same size; using `Image(systemName:)`
    /// matches the live chat-row glyph in `ChatView.statusIcon`.
    private func eyeRow(label: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: "eye.fill")
                .font(.title2)
                .foregroundStyle(.blue)
                .frame(minWidth: 36, alignment: .leading)
            Text(label)
        }
    }

    private var welcomeStep: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "lock.fill")
                .font(.system(size: 72))
                .foregroundStyle(.tint)
            Text("Welcome to Pizzini")
                .font(.largeTitle.bold())
                .multilineTextAlignment(.center)
            VStack(alignment: .leading, spacing: 12) {
                bullet("End-to-end encrypted by libsignal — same protocol Signal uses, with the same post-quantum upgrades.")
                bullet("No phone numbers. Pair with QR codes in person.")
                bullet("No telemetry, no analytics, no third-party SDKs.")
                bullet("Designed for journalists and activists. Lockdown Mode-friendly.")
            }
            .font(.body)
            .padding(.top, 8)
            Spacer()
            Button {
                step = .icons
            } label: {
                Text("Continue")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding()
            }
            .buttonStyle(.borderedProminent)
            .padding(.bottom, 24)
        }
    }

    private var biometricStep: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "faceid")
                .font(.system(size: 72))
                .foregroundStyle(.tint)
            Text("Protect Pizzini with Face ID")
                .font(.title.bold())
                .multilineTextAlignment(.center)
            Text("Anyone with your unlocked phone can read every message in Pizzini unless you add a second lock. Strongly recommended — Face ID (or Touch ID, or your device passcode) will be required to open the app.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if let authError {
                Text(authError)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }
            Spacer()
            VStack(spacing: 12) {
                Button {
                    enableBiometric()
                } label: {
                    Label("Enable Face ID", systemImage: "faceid")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                }
                .buttonStyle(.borderedProminent)
                .disabled(authInFlight)
                Button {
                    onComplete(false)
                } label: {
                    Text("Skip — I'll add it later")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                }
                .buttonStyle(.bordered)
                .disabled(authInFlight)
            }
            .padding(.bottom, 24)
        }
    }

    private func enableBiometric() {
        authError = nil
        authInFlight = true
        Task { @MainActor in
            defer { authInFlight = false }
            // Use the same LockManager auth path so we exercise the exact
            // code that will run in production. If the round-trip succeeds,
            // we know the user can actually unlock the app — no risk of
            // shipping them out of onboarding into a locked-out state.
            do {
                try await LockManager.shared.authenticate(reason: "Confirm Face ID for Pizzini")
                onComplete(true)
            } catch LockManager.AuthError.cancelled {
                // User dismissed the system prompt — stay on this step
                // so they can re-tap "Enable Face ID" or "Skip".
            } catch LockManager.AuthError.unavailable(let msg) {
                authError = msg
            } catch LockManager.AuthError.failed(let msg) {
                authError = msg
            } catch {
                authError = String(describing: error)
            }
        }
    }

    private func bullet(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.body)
            Text(text)
        }
    }
}
