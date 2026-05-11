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
    @State private var notificationsInFlight = false

    private enum Step { case welcome, icons, notifications, biometric }

    var body: some View {
        NavigationStack {
            VStack {
                switch step {
                case .welcome:        welcomeStep
                case .icons:          iconsStep
                case .notifications:  notificationsStep
                case .biometric:      biometricStep
                }
            }
            .padding(.horizontal, 24)
        }
        .interactiveDismissDisabled(true)
    }

    private var iconsStep: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
            Text("What the ticks mean")
                .font(.title.bold())
                .multilineTextAlignment(.center)
            VStack(alignment: .leading, spacing: 18) {
                legendRow(.pending,   "Waiting — your phone or the relay was offline.")
                legendRow(.sent,      "Sent to the relay.")
                legendRow(.delivered, "Your contact's phone got it.")
                legendRow(.read,      "They read it. Only shows when your contact has read receipts on for you.")
                legendRow(.failed,    "Expired before reaching them. Try again.")
            }
            .padding(.top, 8)
            Spacer()
            Button {
                step = .notifications
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

    /// Permission step #1 of 2 — notifications. Shown after the icons
    /// legend so the user understands what's being unlocked before
    /// the iOS prompt fires. Two buttons (Enable / Skip) so the
    /// system alert only appears in response to a deliberate tap;
    /// the old design fired the alert automatically at first launch.
    private var notificationsStep: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "bell.badge.fill")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
            Text("Get notified of new messages")
                .font(.title.bold())
                .multilineTextAlignment(.center)
            Text("When a contact messages you while Pizzini is closed, your phone wakes you up. The notification doesn't leak any content — it only says \"New message\". Names, previews, and the message itself stay sealed until you open Pizzini.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            VStack(spacing: 12) {
                Button {
                    enableNotifications()
                } label: {
                    Label("Enable notifications", systemImage: "bell.fill")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                }
                .buttonStyle(.borderedProminent)
                .disabled(notificationsInFlight)
                Button {
                    step = .biometric
                } label: {
                    Text("Skip — I'll enable in Settings later")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                }
                .buttonStyle(.bordered)
                .disabled(notificationsInFlight)
            }
            .padding(.bottom, 24)
        }
    }

    private func enableNotifications() {
        notificationsInFlight = true
        Task { @MainActor in
            defer { notificationsInFlight = false }
            // The result (granted or denied) doesn't change the
            // onboarding flow — we always advance after the user
            // has answered the iOS prompt. If they deny, the rest
            // of the app works fine; they just won't get push
            // wake-ups until they enable it in iOS Settings.
            _ = await AppDelegate.shared?.requestAuthorizationAndRegister()
            step = .biometric
        }
    }

    /// One row in the legend. Icon rendered via the shared
    /// `ChatStatusGlyph` view so what the user learns here matches
    /// pixel-for-pixel what they'll see in the chat row later.
    /// 36 × 24 frame so every icon column lines up regardless of
    /// glyph width.
    private func legendRow(_ kind: ChatStatusGlyph.Kind, _ label: String) -> some View {
        HStack(alignment: .center, spacing: 16) {
            ChatStatusGlyph(kind: kind)
                .font(.title3)
                .frame(width: 36, height: 24, alignment: .center)
            Text(label)
                .font(.subheadline)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
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
