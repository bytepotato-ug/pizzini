import SwiftUI

/// User-facing controls for the biometric lock. Reached from the
/// contacts-list ⋯ menu. Toggling biometric lock OFF requires a
/// successful auth — defends against "I have your unlocked phone for
/// 10 seconds, let me kill the lock so I can read everything later".
/// Toggling ON also requires auth so we never persist `enabled = true`
/// without first confirming the user can actually pass the prompt.
struct SecuritySettingsView: View {
    @Bindable var store: ChatStore
    let onClose: () -> Void

    @State private var error: String?
    @State private var inFlight = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle(isOn: Binding(
                        get: { store.state.biometricLockEnabled },
                        set: { newValue in handleToggle(target: newValue) }
                    )) {
                        Label("Require Face ID", systemImage: "faceid")
                    }
                    .disabled(inFlight)
                } header: {
                    Text("App lock")
                } footer: {
                    Text("Pizzini will require Face ID (or your device passcode) to open the app and to read messages.")
                }

                if store.state.biometricLockEnabled {
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

                if let error {
                    Section {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Security")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done", action: onClose)
                }
            }
        }
    }

    private func handleToggle(target enable: Bool) {
        error = nil
        inFlight = true
        Task { @MainActor in
            defer { inFlight = false }
            do {
                let reason = enable
                    ? "Confirm Face ID for Pizzini"
                    : "Disable Pizzini's app lock"
                try await LockManager.shared.authenticate(reason: reason)
                store.setBiometricLockEnabled(enable)
            } catch LockManager.AuthError.cancelled {
                // No-op: leave the toggle as-is.
            } catch LockManager.AuthError.unavailable(let msg) {
                error = msg
            } catch LockManager.AuthError.failed(let msg) {
                error = msg
            } catch {
                self.error = String(describing: error)
            }
        }
    }
}
