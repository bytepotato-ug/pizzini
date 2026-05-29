import SwiftUI

/// Setup / change surface for the real or duress passcode. Two
/// entry fields (passcode + confirm), both `SecureField`, with a
/// minimum-length and a "matches" gate before the Save button
/// enables. The actual Argon2id derivation runs in
/// `AppPasscode.setPasscode` / `setDuressPasscode` after Save.
///
/// Distinct from `PasscodeEntryView` so this view never tries to
/// _validate_ — it only writes. Validation of an old passcode (for
/// the "change passcode" path) is done by mounting
/// `PasscodeEntryView` first, then transitioning to this view on
/// successful unlock.
struct PasscodeSetupView: View {
    enum Mode: Sendable, Equatable {
        case real
        case duress
    }

    let mode: Mode
    let onSaved: () -> Void
    var onCancel: () -> Void

    @State private var entry: String = ""
    @State private var confirm: String = ""
    /// PZ-M11: the user's current real passcode, re-entered when setting
    /// a duress passcode. Required so setup can reject a duress value
    /// within a fat-finger typo of the real one — the real passcode is
    /// stored only as a hash, so the plaintext must be supplied here.
    /// Unused (and not shown) in `.real` mode.
    @State private var currentReal: String = ""
    @State private var errorMessage: String?
    @State private var inFlight: Bool = false
    @FocusState private var focusedField: Field?

    private enum Field: Hashable { case currentReal, entry, confirm }

    var body: some View {
        NavigationStack {
            Form {
                if mode == .duress {
                    // PZ-M11: re-authenticate with the current real
                    // passcode so setup can compare the two by edit
                    // distance and reject a typo-confusable duress value.
                    Section {
                        SecureField("Current passcode", text: $currentReal)
                            .keyboardType(.asciiCapable)
                            .hardenedTextInput()
                            .focused($focusedField, equals: .currentReal)
                            .submitLabel(.next)
                            .onSubmit { focusedField = .entry }
                    } footer: {
                        Text("Confirm your real passcode to set the duress passcode.")
                    }
                }
                Section {
                    // No `.textContentType(.newPassword)` on either field
                    // — that hint asks iOS to offer "Save to iCloud
                    // Keychain" + "Suggest strong password" overlays,
                    // which for a local lock-screen passcode is wrong on
                    // every axis: we don't want it iCloud-synced (defeats
                    // the device-pin contract), the Argon2id derivation
                    // is ours and a Keychain entry can't replay it, and
                    // the AutoFill overlay machinery triggers the
                    // per-keystroke "variant selector cell index number
                    // could not be found" UIKit chatter on iOS 26.
                    SecureField(
                        mode == .real ? "New passcode" : "New duress passcode",
                        text: $entry,
                    )
                    .keyboardType(.asciiCapable)
                    .hardenedTextInput()
                    .focused($focusedField, equals: .entry)
                    .submitLabel(.next)
                    .onSubmit { focusedField = .confirm }

                    SecureField("Confirm", text: $confirm)
                        .keyboardType(.asciiCapable)
                        .hardenedTextInput()
                        .focused($focusedField, equals: .confirm)
                        .submitLabel(.done)
                        .onSubmit(save)
                } footer: {
                    Text(footerText)
                }

                if let errorMessage {
                    Section {
                        Text(errorMessage)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { onCancel() }
                        .disabled(inFlight)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: save)
                        .disabled(!canSave || inFlight)
                }
            }
            .onAppear { focusedField = mode == .duress ? .currentReal : .entry }
        }
        .interactiveDismissDisabled()
    }

    private var title: String {
        mode == .real ? "Set app passcode" : "Set duress passcode"
    }

    private var footerText: String {
        switch mode {
        case .real:
            return "At least \(AppPasscode.minLength) characters. "
                + "You'll be asked for this passcode whenever Face ID isn't used to unlock Pizzini."
        case .duress:
            return "At least \(AppPasscode.minLength) characters. "
                + "If you ever enter this passcode at the lock screen, Pizzini wipes every "
                + "message, contact, and key, and re-opens to an empty state. "
                + "Choose something memorable but distinct from your real passcode."
        }
    }

    private var canSave: Bool {
        let base = !entry.isEmpty
            && entry.count >= AppPasscode.minLength
            && entry == confirm
        // PZ-M11: duress setup also needs the current real passcode.
        return mode == .duress ? base && !currentReal.isEmpty : base
    }

    private func save() {
        guard canSave, !inFlight else { return }
        inFlight = true
        errorMessage = nil
        let toSet = entry
        let realEntered = currentReal
        Task { @MainActor in
            await Task.yield()
            defer { inFlight = false }
            do {
                switch mode {
                case .real:
                    try AppPasscode.setPasscode(toSet)
                case .duress:
                    try AppPasscode.setDuressPasscode(toSet, currentRealPasscode: realEntered)
                }
                entry = ""
                confirm = ""
                currentReal = ""
                onSaved()
            } catch AppPasscode.PasscodeError.tooShort(let min) {
                errorMessage = "Passcode must be at least \(min) characters."
            } catch AppPasscode.PasscodeError.realPasscodeIncorrect {
                errorMessage = "That isn't your current passcode."
            } catch AppPasscode.PasscodeError.tooSimilarToReal {
                errorMessage = "Too close to your real passcode — a single typo could wipe by accident. "
                    + "Choose something more clearly different."
            } catch AppPasscode.PasscodeError.sameAsExisting {
                errorMessage = "Duress passcode can't match your real passcode."
            } catch AppPasscode.PasscodeError.keychainWriteFailed {
                errorMessage = "Couldn't save to Keychain — try again."
            } catch {
                errorMessage = "Couldn't save the passcode. Try again."
            }
        }
    }
}
