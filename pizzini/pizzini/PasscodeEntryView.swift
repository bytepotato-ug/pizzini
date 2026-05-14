import SwiftUI

/// Passcode entry surface used from two places:
///
/// 1. `LockOverlayView` — pulled up via the long-press-anywhere
///    gesture when Face ID is enabled, or shown directly on cold
///    launch when Face ID is disabled but a passcode is set.
/// 2. `SecuritySettingsView` — confirms the user knows the current
///    passcode before allowing them to change it or set a duress
///    passcode.
///
/// The entry path runs Argon2id against both stored hashes (real +
/// duress) on every submit via `LockManager.submitPasscode`. On a
/// duress match the caller is responsible for invoking the wipe
/// BEFORE dropping the lock — see the docs on
/// `LockManager.PasscodeOutcome`.
struct PasscodeEntryView: View {
    @Bindable var lockManager: LockManager
    /// Caller-supplied callback fired exactly once per successful
    /// submission. `.unlocked` / `.duress` should dismiss the sheet;
    /// `.wrong` keeps it open with the error visible.
    let onOutcome: (LockManager.PasscodeOutcome) -> Void
    /// Called when the user taps Cancel. The sheet host should
    /// dismiss without changing lock state.
    var onCancel: () -> Void

    @State private var entry: String = ""
    @State private var inFlight: Bool = false
    @State private var errorMessage: String?
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Image(systemName: "key.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(.tint)
                    .padding(.top, 32)
                Text("Enter passcode")
                    .font(.title2.bold())
                Text("Pizzini will check your passcode and unlock if it matches.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)

                SecureField("Passcode", text: $entry)
                    // No `.textContentType(.password)` here, deliberately.
                    // That hint integrates the field with iCloud Keychain
                    // AutoFill — *exactly* what we don't want for the
                    // app's local lock passcode: the whole point is that
                    // this string never leaves the device. Bonus: drops
                    // the per-keystroke "variant selector cell index
                    // number could not be found" UIKit chatter on iOS 26
                    // that the password-AutoFill machinery triggers.
                    .keyboardType(.asciiCapable)
                    .hardenedTextInput()
                    .padding(.horizontal, 16)
                    .frame(height: 44)
                    .background(Color(.secondarySystemBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .padding(.horizontal, 32)
                    .focused($focused)
                    .submitLabel(.go)
                    .onSubmit(submit)

                if let errorMessage {
                    Text(errorMessage)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }

                Button(action: submit) {
                    if inFlight {
                        ProgressView()
                    } else {
                        Text("Unlock")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .prominentLabelText()
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(inFlight || entry.isEmpty)
                .padding(.horizontal, 32)

                Spacer()
            }
            .navigationTitle("Passcode")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { onCancel() }
                        .disabled(inFlight)
                }
            }
            .onAppear { focused = true }
        }
        // Interactive dismissal disabled — entering a passcode is a
        // deliberate action, and a half-typed entry shouldn't get
        // accidentally dismissed by a downward drag (especially
        // important during a coercion scenario where the user is
        // already under pressure).
        .interactiveDismissDisabled()
    }

    private func submit() {
        // Synchronously gate against re-entry BEFORE the Task spawn:
        // setting `inFlight` inside the Task left a window where a
        // rapid double-tap enqueued two main-actor tasks before the
        // first set the flag. The second tap could then submit a
        // panicked-second-try passcode against a Keychain state that
        // the first task had already wiped (duress path), exposing
        // the fresh-install gate-less UI.
        guard !entry.isEmpty, !inFlight else { return }
        inFlight = true
        errorMessage = nil
        // Argon2id verification is ~250 ms on a recent device. Bounce
        // off the main actor so the spinner can render while it runs.
        // The verify is MainActor-isolated in `LockManager.submitPasscode`,
        // so we Task back to the main actor to do the work — the brief
        // suspension lets SwiftUI paint the spinner first.
        let toCheck = entry
        Task { @MainActor in
            await Task.yield()
            let outcome = lockManager.submitPasscode(toCheck)
            inFlight = false
            entry = ""
            switch outcome {
            case .unlocked, .duress:
                onOutcome(outcome)
            case .wrong:
                errorMessage = "Incorrect passcode."
                onOutcome(outcome)
            }
        }
    }
}
