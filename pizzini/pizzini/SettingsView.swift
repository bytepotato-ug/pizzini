import SwiftUI

/// Unified settings entry point. Reached as a NavigationLink push from
/// the contacts toolbar (gear icon). Lives inside the parent
/// `NavigationStack`, so the back button is automatic and there is no
/// modal feel — Apple's own Settings, WhatsApp, Signal, and Telegram
/// all use push for primary navigation.
///
/// Each toggle row is intentionally bare: just `Label` + the
/// SwiftUI-rendered switch. The 1-line section footer carries the
/// rationale; anyone wanting more taps Help → FAQ. This is the
/// Apple-Settings pattern, and it scales — verbose inline text under
/// every row makes the surface feel cluttered.
///
/// Layout:
/// - Connection: NavigationLink to RelayHostScreen
/// - Security: NavigationLink to SecuritySettingsView
/// - Panic mode: inline Toggle + 1-line footer
/// - Attachments: inline Toggle + 1-line footer
/// - (conditional) Screenshot protection — degraded notice
/// - Help: NavigationLink to FAQ
/// - Advanced: NavigationLink to AdvancedScreen (delete-all-chats /
///   reset-identity)
struct SettingsView: View {
    @Bindable var store: ChatStore

    var body: some View {
        Form {
            Section {
                NavigationLink {
                    RelayHostScreen(store: store)
                } label: {
                    SettingsRow(
                        icon: "antenna.radiowaves.left.and.right",
                        title: "Relay host",
                        value: store.state.relayHost,
                    )
                }
            } header: {
                Text("Connection")
            } footer: {
                Text("Both peers must use the same relay.")
            }

            Section("Security") {
                NavigationLink {
                    SecuritySettingsView(store: store)
                } label: {
                    SettingsRow(
                        icon: "faceid",
                        title: "App lock",
                        value: store.state.biometricLockEnabled ? "Face ID" : "Off",
                    )
                }
            }

            Section {
                Toggle(isOn: Binding(
                    get: { store.state.panicModeEnabled },
                    set: { store.setPanicModeEnabled($0) }
                )) {
                    Label("Panic mode", systemImage: "exclamationmark.octagon")
                }
            } header: {
                Text("Panic mode")
            } footer: {
                Text("Three fast taps in a chat instantly delete it. No undo.")
            }

            Section {
                Toggle(isOn: Binding(
                    get: { store.state.contactsBeforeGroups },
                    set: { store.setContactsBeforeGroups($0) }
                )) {
                    Label("Contacts before groups", systemImage: "list.bullet.indent")
                }
            } header: {
                Text("Chat list")
            } footer: {
                Text("On: 1:1 chats appear above groups. Off: groups appear above 1:1 chats. Pending invitations always pin to the top.")
            }

            Section {
                Toggle(isOn: Binding(
                    get: { store.state.quickLookPreviewEnabled },
                    set: { store.setQuickLookPreviewEnabled($0) }
                )) {
                    Label("In-app preview", systemImage: "eye")
                }
            } header: {
                Text("Attachments")
            } footer: {
                Text("Off keeps received files out of Pizzini until you tap Save to Files.")
            }

            Section {
                Toggle(isOn: Binding(
                    get: { store.state.inAppHapticsEnabled },
                    set: { store.setInAppHapticsEnabled($0) }
                )) {
                    Label("Haptic on new messages", systemImage: "iphone.radiowaves.left.and.right")
                }
            } header: {
                Text("Notifications")
            } footer: {
                Text("On: a soft haptic fires when a new message lands in a chat other than the one you're in. No banner, no sound, no preview — same posture as Signal / WhatsApp / Threema. The badge and chat list always update either way.")
            }

            if store.state.qrBlockEffective == false {
                Section {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                        Text("This iOS version blocks the screenshot mask. Screenshots will capture content. We'll ship a fix.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("Screenshot protection — degraded")
                }
            }

            Section("Help") {
                NavigationLink {
                    FAQContent(initialSection: nil)
                        .navigationTitle("FAQ")
                        .navigationBarTitleDisplayMode(.inline)
                } label: {
                    SettingsRow(icon: "questionmark.circle", title: "FAQ")
                }
                NavigationLink {
                    DiagnosticsView(store: store)
                } label: {
                    SettingsRow(icon: "stethoscope", title: "Diagnostics")
                }
                NavigationLink {
                    RelayAttestationView(store: store)
                } label: {
                    SettingsRow(icon: "checkmark.seal", title: "Relay attestation")
                }
            }

            Section {
                NavigationLink {
                    AdvancedScreen(store: store)
                } label: {
                    SettingsRow(icon: "exclamationmark.triangle", title: "Advanced")
                }
            } footer: {
                Text("Delete all chats, reset your identity.")
            }
        }
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// Standard iOS settings row: SF symbol on the left, title, optional
/// trailing value text, automatic chevron via the parent
/// NavigationLink. Spaces and truncates the value so a long relay
/// IP doesn't push the chevron off-screen.
private struct SettingsRow: View {
    let icon: String
    let title: String
    var value: String? = nil

    var body: some View {
        HStack(spacing: 0) {
            Label(title, systemImage: icon)
            if let value {
                Spacer(minLength: 8)
                Text(value)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
    }
}

/// Form-only relay-host editor pushed via NavigationLink onto the
/// parent NavigationStack.
private struct RelayHostScreen: View {
    @Bindable var store: ChatStore
    @Environment(\.dismiss) private var dismiss
    @State private var draft: String

    init(store: ChatStore) {
        self.store = store
        self._draft = State(initialValue: store.state.relayHost)
    }

    var body: some View {
        Form {
            Section {
                TextField("host (e.g. 192.168.x.x)", text: $draft)
                    .hardenedTextInput()
                    .keyboardType(.URL)
            } header: {
                Text("Host")
            } footer: {
                Text("Sim → 127.0.0.1; physical phone → the Mac's LAN IP. Port is fixed at 7777.")
            }
        }
        .navigationTitle("Relay host")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") {
                    store.setRelayHost(draft)
                    dismiss()
                }
                .disabled(draft == store.state.relayHost || draft.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }
}

/// Destructive actions live here, one navigation level below the
/// settings root, with explicit confirmation dialogs. Two intents
/// (navigate here + tap destructive + confirm) before anything
/// dangerous happens.
private struct AdvancedScreen: View {
    @Bindable var store: ChatStore
    @Environment(\.dismiss) private var dismiss

    @State private var confirmDeleteAllChats = false
    @State private var confirmReset = false

    var body: some View {
        Form {
            Section {
                Button(role: .destructive) {
                    confirmDeleteAllChats = true
                } label: {
                    Label("Delete all chats", systemImage: "trash")
                }
            } footer: {
                Text("Wipes every chat log. Contacts and sessions stay.")
            }

            Section {
                Button(role: .destructive) {
                    confirmReset = true
                } label: {
                    Label("Reset identity", systemImage: "arrow.counterclockwise")
                }
            } footer: {
                Text("Generates a fresh keypair and wipes contacts and chats. Every contact must scan you again.")
            }
        }
        .navigationTitle("Advanced")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog(
            "Delete every chat log?",
            isPresented: $confirmDeleteAllChats,
            titleVisibility: .visible,
        ) {
            Button("Delete all chats", role: .destructive) {
                store.deleteAllChats()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Contacts stay paired. Only the message history is wiped.")
        }
        .confirmationDialog(
            "Reset your identity?",
            isPresented: $confirmReset,
            titleVisibility: .visible,
        ) {
            Button("Reset identity", role: .destructive) {
                store.resetIdentity()
                // Pop AdvancedScreen back to Settings. The user can
                // tap back once more to see the now-empty contacts
                // list. We deliberately don't pop all the way to root
                // because that would require threading a NavigationPath
                // closure through three layers — for an action the
                // user has already double-confirmed (tap → dialog →
                // confirm), the extra back-tap is fine.
                dismiss()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("All contacts, sessions, and chats will be erased. Peers will need to scan you again.")
        }
    }
}
