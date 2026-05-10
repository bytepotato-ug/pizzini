import SwiftUI

/// User-facing controls for the biometric lock. Pushed via NavigationLink
/// from the parent `SettingsView`, so it owns its Form rows but NOT
/// the NavigationStack or the trailing "Done" button — the parent
/// settings screen handles dismissal. Toggling biometric lock OFF
/// requires a successful auth — defends against "I have your unlocked
/// phone for 10 seconds, let me kill the lock so I can read everything
/// later". Toggling ON also requires auth so we never persist
/// `enabled = true` without first confirming the user can pass the
/// prompt.
struct SecuritySettingsView: View {
    @Bindable var store: ChatStore

    @State private var error: String?
    @State private var inFlight = false

    var body: some View {
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

            screenCaptureSection

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
    }

    /// Phase 6: user-facing controls for the screen-capture protection
    /// stack. Sits under "App lock" rather than as its own screen
    /// because the threats are adjacent (an attacker with brief
    /// physical access can either kill the lock or screenshot a chat;
    /// keep the controls together).
    @ViewBuilder
    private var screenCaptureSection: some View {
        Section {
            Toggle(isOn: Binding(
                get: { store.state.notifyPeerOnScreenshot },
                set: { store.setNotifyPeerOnScreenshot($0) }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Label("Tell my contact when I screenshot", systemImage: "bell.badge")
                    Text("Off by default. Sends a sealed marker to your contact when you screenshot one of their chats; they see 'You took a screenshot.' as a system row.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Toggle(isOn: Binding(
                get: { store.state.blockQRScreenshots },
                set: { store.setBlockQRScreenshots($0) }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Label("Block screenshots of my QR", systemImage: "qrcode")
                    Text("Best effort. iOS doesn't let any app fully prevent screenshots, but the QR sheet uses a known technique that masks the code in the captured image. Turn off if you use VoiceOver — the technique breaks selection and screen-reader semantics.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Toggle(isOn: Binding(
                get: { store.state.blockChatScreenshots },
                set: { store.setBlockChatScreenshots($0) }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Label("Block screenshots of chats", systemImage: "bubble.left.and.bubble.right")
                    Text("Same technique as the QR block, applied to chat bubbles. Tradeoff is bigger here: long-press → Copy on a message stops working, and VoiceOver inside the chat is degraded. Off by default; turn on only if you accept the accessibility cost.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .disabled(store.state.qrBlockEffective == false)
            if store.state.qrBlockEffective == false {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("On this iOS version, the QR-block technique didn't pass our runtime self-test. The QR sheet falls back to the same shield used during screen recording — your QR is still hidden by default and re-hides whenever the app deactivates.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Screen capture")
        } footer: {
            Text("Pizzini detects screenshots and screen recording. While recording is active, your chats are blurred. iOS does not let any app fully prevent screenshots — we will tell you in the chat when one is taken.")
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
