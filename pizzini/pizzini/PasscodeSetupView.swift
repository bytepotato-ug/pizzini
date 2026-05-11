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
    @State private var errorMessage: String?
    @State private var inFlight: Bool = false
    @FocusState private var focusedField: Field?

    private enum Field: Hashable { case entry, confirm }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField(
                        mode == .real ? "New passcode" : "New duress passcode",
                        text: $entry,
                    )
                    .textContentType(.newPassword)
                    .keyboardType(.asciiCapable)
                    .hardenedTextInput()
                    .focused($focusedField, equals: .entry)
                    .submitLabel(.next)
                    .onSubmit { focusedField = .confirm }

                    SecureField("Confirm", text: $confirm)
                        .textContentType(.newPassword)
                        .keyboardType(.asciiCapable)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
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
            .onAppear { focusedField = .entry }
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
        !entry.isEmpty
            && entry.count >= AppPasscode.minLength
            && entry == confirm
    }

    private func save() {
        guard canSave, !inFlight else { return }
        inFlight = true
        errorMessage = nil
        let toSet = entry
        Task { @MainActor in
            await Task.yield()
            defer { inFlight = false }
            do {
                switch mode {
                case .real:
                    try AppPasscode.setPasscode(toSet)
                case .duress:
                    try AppPasscode.setDuressPasscode(toSet)
                }
                entry = ""
                confirm = ""
                onSaved()
            } catch AppPasscode.PasscodeError.tooShort(let min) {
                errorMessage = "Passcode must be at least \(min) characters."
            } catch AppPasscode.PasscodeError.sameAsExisting {
                errorMessage = "Duress passcode can't match your real passcode."
            } catch AppPasscode.PasscodeError.keychainWriteFailed {
                errorMessage = "Couldn't save to Keychain — try again."
            } catch {
                errorMessage = "Setup failed: \(error)"
            }
        }
    }
}
