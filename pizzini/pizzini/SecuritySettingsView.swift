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
                get: { store.state.blockAppScreenshots },
                set: { store.setBlockAppScreenshots($0) }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Label("Block screenshots of Pizzini", systemImage: "eye.slash")
                    Text("On by default. Wraps every screen — chats, QR, settings, all of it — in a secure container so screenshots, screen recording, AirPlay mirroring, and remote-screen-sharing tools see a black frame. iOS doesn't expose an official API for this; the technique is best-effort and tested at every iOS update. Costs: long-press → Copy on a chat bubble stops working, VoiceOver is degraded inside the wrapped views, and dictation may not work on the message composer.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .disabled(store.state.qrBlockEffective == false)
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
            if store.state.qrBlockEffective == false {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("On this iOS version, the screenshot-block technique didn't pass our runtime self-test. The screen-recording shield still works (chat content is hidden whenever iOS reports a recording or external display), but a still screenshot will capture what's on screen. We re-test on every iOS update.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Screen capture")
        } footer: {
            Text("Pizzini also detects screenshots and screen recording: a system row appears in the chat when you screenshot, and chats are hidden during screen recording or AirPlay. iOS does not let any app fully prevent screenshots — system-rendered alerts (camera permission, etc.) cannot be masked.")
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
