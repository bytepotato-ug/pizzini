import SwiftUI
import PizziniCryptoCore
import PizziniTor

/// First-launch flow. The user steps through: welcome → network
/// bootstrap → icon legend → notifications opt-in → **mandatory
/// lock-posture step**.
///
/// The network step is what U2 added: tor bootstrap runs concurrently
/// with the rest of onboarding (kicked off when `ChatStore.shared`
/// initialises in ContentView), and this dedicated screen explains
/// what the user is waiting for. The "Get started" button only enables
/// once `TorController.bootstrapProgress` hits 100. Before that, the
/// user reads the explainer instead of staring at a generic
/// "Connecting…" pill.
///
/// The lock-posture step is the security gate that defends against
/// "user installs Pizzini, pairs with contacts, never sets a lock,
/// loses unlocked phone." `onComplete` is only reachable after Face
/// ID has been enabled OR an app passcode has been set — there is no
/// "skip" path. The user can still disable both later in Settings,
/// but the first-launch flow forces a deliberate decision.
///
/// `onComplete` is called with the chosen biometric setting; the host
/// then writes it to AppState and dismisses the cover.
struct OnboardingView: View {
    let onComplete: (_ enableBiometric: Bool) -> Void

    @State private var step: Step = .welcome
    @State private var authError: String?
    @State private var authInFlight = false
    @State private var notificationsInFlight = false
    @State private var passcodeSheetPresented = false
    /// Live mirror of `TorController.bootstrapProgress`. Initialised
    /// to 0 and seeded via the `.onReceive($bootstrapProgress)` hop
    /// below — Combine delivers the current value on subscription, so
    /// the bar shows the real progress on the very first render. We
    /// don't read `TorController.shared.bootstrapProgress` directly at
    /// init time because the controller is `@MainActor`-isolated and
    /// `@State` defaults aren't.
    @State private var torProgress: Int = 0

    private enum Step { case welcome, network, icons, notifications, biometric }

    var body: some View {
        NavigationStack {
            VStack {
                switch step {
                case .welcome:        welcomeStep
                case .network:        networkStep
                case .icons:          iconsStep
                case .notifications:  notificationsStep
                case .biometric:      biometricStep
                }
            }
            .padding(.horizontal, 24)
        }
        .interactiveDismissDisabled(true)
        // Subscribe to the controller's `@Published` projected
        // publisher so the network step animates with bootstrap
        // progress live, and the "Get started" gate flips the moment
        // tor reports 100. SwiftUI cancels the subscription when this
        // view disappears (the cover dismiss path).
        .onReceive(TorController.shared.$bootstrapProgress) { progress in
            torProgress = progress
        }
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
                    .prominentLabelText()
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
                        .prominentLabelText()
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
            // Real app logo. Beats an SF Symbol lock here — the
            // welcome screen is the user's first paint of the
            // brand, and recognising the icon they just tapped on
            // the home screen reduces "did I open the right app?"
            // friction.
            Image("AppLogo")
                .resizable()
                .interpolation(.high)
                .aspectRatio(contentMode: .fit)
                .frame(width: 128, height: 128)
                .clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
                .shadow(color: .black.opacity(0.15), radius: 8, x: 0, y: 4)
                .accessibilityLabel("Pizzini logo")
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
                step = .network
            } label: {
                Text("Continue")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .prominentLabelText()
            }
            .buttonStyle(.borderedProminent)
            .padding(.bottom, 24)
        }
    }

    /// U2 step. Tor bootstrap runs concurrently with the rest of
    /// onboarding (it kicks off the moment `ChatStore.shared`
    /// initialises in `ContentView` — well before this step
    /// renders), so by the time the user arrives here, progress is
    /// usually already in flight or done. The bar mirrors
    /// `TorController.bootstrapProgress` (0–100) and the
    /// "Get started" button only becomes tappable once it reaches
    /// 100; otherwise the user is reading the explainer instead of
    /// staring at a blank "Connecting…" pill.
    ///
    /// The jurisdiction list in the explainer is generated from the
    /// bundled `RelayRegistry.trusted` — never hard-coded — so adding
    /// or removing a relay updates onboarding copy in the same
    /// release. See `onboardingExplainerText(jurisdictions:)`.
    private var networkStep: some View {
        let isReady = torProgress >= 100
        return VStack(spacing: 18) {
            Spacer()
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
            Text("Setting up the network")
                .font(.title.bold())
                .multilineTextAlignment(.center)
            Text(onboardingExplainerText(jurisdictions: currentTrustedJurisdictions()))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            // Progress bar wired to TorController. The numeric percent
            // is shown below the bar so a stalled bootstrap is visible
            // (the bar alone is easy to dismiss as a UI animation).
            VStack(spacing: 8) {
                ProgressView(value: Double(torProgress), total: 100)
                    .progressViewStyle(.linear)
                    .tint(.green)
                Text(isReady ? "Ready." : "Connecting. \(torProgress)%")
                    .font(.footnote.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .padding(.top, 8)
            Spacer()
            Button {
                step = .icons
            } label: {
                Text("Get started")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .prominentLabelText()
            }
            .buttonStyle(.borderedProminent)
            .disabled(!isReady)
            .padding(.bottom, 24)
        }
    }

    private var biometricStep: some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "faceid")
                .font(.system(size: 72))
                .foregroundStyle(.tint)
            Text("Lock Pizzini")
                .font(.title.bold())
                .multilineTextAlignment(.center)
            Text("Anyone with your unlocked phone can read every message in Pizzini unless you add a second lock. Choose Face ID (recommended — fast, biometric-gated) or set an app passcode you'll type to unlock.")
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
                        .prominentLabelText()
                }
                .buttonStyle(.borderedProminent)
                .disabled(authInFlight)
                Button {
                    passcodeSheetPresented = true
                } label: {
                    Label("Use app passcode instead", systemImage: "lock.fill")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                }
                .buttonStyle(.bordered)
                .disabled(authInFlight)
            }
            .padding(.bottom, 24)
        }
        .sheet(isPresented: $passcodeSheetPresented) {
            PasscodeSetupView(
                mode: .real,
                onSaved: {
                    passcodeSheetPresented = false
                    // Passcode is set; biometric stays OFF (the user
                    // explicitly chose passcode-only). LockManager's
                    // `isLockGateActive` now returns true via the
                    // `isPasscodeSet` path so the user is gated on
                    // every cold launch.
                    onComplete(false)
                },
                onCancel: {
                    passcodeSheetPresented = false
                },
            )
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

/// Returns the jurisdictions for the production relays bundled in
/// `RelayRegistry.trusted`, in the order they appear in the registry.
///
/// Labels in the registry are shaped as `"Relay <country>"` (e.g.
/// `"Relay Germany"`); this helper strips the `"Relay "` prefix so
/// onboarding copy reads as a country list rather than a list of
/// relay-product names. If a future label drops the prefix the full
/// label is used unchanged, so the function is forgiving — but the
/// expected shape is documented in `RelayRegistry.swift`.
func currentTrustedJurisdictions() -> [String] {
    RelayRegistry.trusted.map { descriptor in
        let prefix = "Relay "
        if descriptor.label.hasPrefix(prefix) {
            return String(descriptor.label.dropFirst(prefix.count))
        }
        return descriptor.label
    }
}

/// Generate the onboarding explainer copy from the live list of
/// jurisdictions. Pure function (no globals, no side-effects) so it
/// can be unit-tested in isolation — `OnboardingExplainerTests` pins
/// the contract.
///
/// Shape per arity:
///   - 0 jurisdictions: a degenerate fallback that omits the country
///     list. Pizzini's fleet always ships with ≥1, so this path is
///     defence against a future refactor accidentally returning an
///     empty list — not a real user-visible state.
///   - 1: `"Setting up a private network connection through Germany. About 30 seconds."`
///   - 2: `"Setting up a private network connection through Germany and Norway. About 30 seconds."`
///   - 3+: Oxford-comma list `"Germany, Norway, and USA"`. The
///     formatter handles the comma + "and" placement so additional
///     jurisdictions slot in without a copy edit.
///
/// "About 30 seconds" is intentionally hedged — bootstrap on a warm
/// cache lands in <5 s, a cold cellular start can take 60 s. 30 is a
/// useful order-of-magnitude anchor that won't make the average user
/// feel betrayed in either direction.
func onboardingExplainerText(jurisdictions: [String]) -> String {
    if jurisdictions.isEmpty {
        return "Setting up a private network connection. About 30 seconds."
    }
    let formatter = ListFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    let list = formatter.string(from: jurisdictions) ?? jurisdictions.joined(separator: ", ")
    return "Setting up a private network connection through \(list). About 30 seconds."
}
