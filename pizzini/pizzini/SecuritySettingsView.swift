import SwiftUI

/// User-facing controls for the biometric lock, the app passcode,
/// and the duress passcode. Pushed via NavigationLink from the
/// parent `SettingsView`, so it owns its Form rows but NOT the
/// NavigationStack or the trailing "Done" button — the parent
/// settings screen handles dismissal.
///
/// Lock rules:
///   - Face ID toggle: on/off, unchanged from the pre-duress design.
///   - App passcode: optional when Face ID is on (fallback / duress
///     entry point), MANDATORY when Face ID is off (otherwise the
///     duress check has nothing to compare against).
///   - Duress passcode: always optional; requires an app passcode to
///     be set first (the duress check runs alongside the real
///     check, so without a real passcode the only way to trigger
///     duress would be to set EVERY entry as the duress one — bad
///     UX).
struct SecuritySettingsView: View {
    @Bindable var store: ChatStore

    @State private var error: String?
    @State private var inFlight = false

    // Passcode sheet presentation state.
    @State private var settingPasscode = false
    @State private var settingDuressPasscode = false
    @State private var passcodeChangeAuthShown = false
    @State private var duressAuthShown = false
    /// True when the user is in the "change passcode" flow and the
    /// PasscodeEntryView is verifying the current passcode before we
    /// allow them to set a new one. Distinguishes "tap Change → enter
    /// current → enter new" from "tap Set → enter new" (no current).
    @State private var verifyingCurrentForChange = false

    /// `@State` shadows for the AppPasscode helpers so the view re-
    /// renders when the user adds/removes a passcode without us
    /// having to chase the underlying Keychain.
    @State private var hasPasscode: Bool = AppPasscode.isPasscodeSet
    @State private var hasDuressPasscode: Bool = AppPasscode.isDuressPasscodeSet

    var body: some View {
        Form {
            faceIDSection
            if store.state.biometricLockEnabled {
                autoLockSection
            }
            passcodeSection
            duressPasscodeSection

            if let error {
                Section {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("App lock")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $settingPasscode) {
            PasscodeSetupView(
                mode: .real,
                onSaved: {
                    settingPasscode = false
                    hasPasscode = AppPasscode.isPasscodeSet
                    error = nil
                },
                onCancel: { settingPasscode = false },
            )
        }
        .sheet(isPresented: $settingDuressPasscode) {
            PasscodeSetupView(
                mode: .duress,
                onSaved: {
                    settingDuressPasscode = false
                    hasDuressPasscode = AppPasscode.isDuressPasscodeSet
                    error = nil
                },
                onCancel: { settingDuressPasscode = false },
            )
        }
    }

    // MARK: - Sections

    private var faceIDSection: some View {
        Section {
            Toggle(isOn: Binding(
                get: { store.state.biometricLockEnabled },
                set: { handleFaceIDToggle(target: $0) }
            )) {
                Label("Require Face ID", systemImage: "faceid")
            }
            .disabled(inFlight)
        } header: {
            Text("App lock")
        } footer: {
            if !store.state.biometricLockEnabled && !hasPasscode {
                Text("Pizzini will open without authentication. Set Face ID or a passcode to require unlock.")
            } else {
                Text("Pizzini will require Face ID (or your device passcode) to open the app and to read messages.")
            }
        }
    }

    private var autoLockSection: some View {
        Section {
            Picker(
                "Lock when backgrounded",
                selection: Binding(
                    get: { store.state.autoLockTimeout },
                    set: { store.setAutoLockTimeout($0) }
                )
            ) {
                ForEach(AutoLockTimeout.allCases, id: \.self) { option in
                    Text(option.label).tag(option)
                }
            }
            .pickerStyle(.inline)
            .labelsHidden()
        } header: {
            Text("Auto-lock")
        } footer: {
            Text("How long Pizzini stays unlocked after you switch away from it.")
        }
    }

    private var passcodeSection: some View {
        Section {
            if hasPasscode {
                Button("Change passcode") {
                    settingPasscode = true
                }
                Button("Remove passcode", role: .destructive) {
                    handleRemovePasscode()
                }
                .disabled(removePasscodeBlocked)
            } else {
                Button("Set passcode") {
                    settingPasscode = true
                }
            }
        } header: {
            Text("App passcode")
        } footer: {
            Text(passcodeFooter)
        }
    }

    private var duressPasscodeSection: some View {
        Section {
            if hasDuressPasscode {
                Button("Change duress passcode") {
                    settingDuressPasscode = true
                }
                Button("Remove duress passcode", role: .destructive) {
                    AppPasscode.clearDuressPasscode()
                    hasDuressPasscode = AppPasscode.isDuressPasscodeSet
                }
            } else {
                Button("Set duress passcode") {
                    settingDuressPasscode = true
                }
                .disabled(!hasPasscode)
            }
        } header: {
            Text("Duress passcode")
        } footer: {
            Text(duressFooter)
        }
    }

    // MARK: - Footers

    private var passcodeFooter: String {
        if hasPasscode {
            return "Required to unlock Pizzini when Face ID is unavailable. "
                + "Long-press anywhere on the lock screen to enter it."
        }
        if store.state.biometricLockEnabled {
            return "Optional. When set, you can long-press anywhere on the lock screen to enter your passcode "
                + "instead of using Face ID."
        }
        return "Required if Face ID is off. Without one, Pizzini opens without authentication."
    }

    private var duressFooter: String {
        if !hasPasscode {
            return "Set an app passcode first. The duress passcode is checked alongside it — without a real "
                + "passcode there's no path to enter either one."
        }
        if hasDuressPasscode {
            return "Entering this passcode at the lock screen wipes every message, contact, and key, and "
                + "re-opens Pizzini to an empty state. The wipe is silent — there's no warning prompt."
        }
        return "Optional. If you ever enter this passcode at the lock screen, Pizzini wipes every message, "
            + "contact, and key, and re-opens to an empty state. Use it if you're ever forced to unlock the "
            + "app against your will."
    }

    private var removePasscodeBlocked: Bool {
        // If Face ID is off, the user can't have NO unlock path —
        // removing the passcode in that state would leave the app
        // gateless. Block it. They can either enable Face ID first
        // or live with the passcode.
        !store.state.biometricLockEnabled
    }

    // MARK: - Actions

    private func handleFaceIDToggle(target enable: Bool) {
        error = nil
        inFlight = true
        Task { @MainActor in
            defer { inFlight = false }
            do {
                let reason = enable
                    ? "Confirm Face ID for Pizzini"
                    : "Disable Pizzini's app lock"
                try await LockManager.shared.authenticate(reason: reason)
                if !enable && !hasPasscode {
                    // Disabling Face ID without a passcode set means
                    // the lock gate would be lifted entirely. We
                    // allow the toggle but flag the consequence in
                    // the footer copy; the user can still set a
                    // passcode in the row below.
                }
                store.setBiometricLockEnabled(enable)
            } catch LockManager.AuthError.cancelled {
                // Leave the toggle as-is.
            } catch LockManager.AuthError.unavailable(let msg) {
                error = msg
            } catch LockManager.AuthError.failed(let msg) {
                error = msg
            } catch {
                self.error = String(describing: error)
            }
        }
    }

    private func handleRemovePasscode() {
        AppPasscode.clearPasscode()
        AppPasscode.clearDuressPasscode()  // duress is meaningless without real
        hasPasscode = AppPasscode.isPasscodeSet
        hasDuressPasscode = AppPasscode.isDuressPasscodeSet
        if !store.state.biometricLockEnabled {
            LockManager.shared.unlockBecauseDisabled()
        }
    }
}
