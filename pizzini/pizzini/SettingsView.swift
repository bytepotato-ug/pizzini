import SwiftUI

/// Unified settings entry point. Reached from the gear icon on the
/// contacts list. Replaces the old "stack everything in the ⋯ Menu"
/// approach where adding a contact, changing relay host, toggling
/// Face ID, and resetting identity all sat one tap apart.
///
/// Layout follows iOS settings conventions:
/// - Connection / Security as named sections with NavigationLink rows
///   and the current value on the trailing edge.
/// - Destructive actions (Delete all chats, Reset identity) live one
///   navigation level deeper under "Advanced", behind explicit
///   confirmation dialogs. Mis-tapping "Reset identity" while looking
///   for a relay-host edit is no longer possible.
struct SettingsView: View {
    @Bindable var store: ChatStore
    let onClose: () -> Void

    var body: some View {
        NavigationStack {
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
                    Text("Both peers must use the same relay. The relay sees only ciphertext and routing identifiers.")
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
                    NavigationLink {
                        AdvancedScreen(store: store, onResetClose: onClose)
                    } label: {
                        SettingsRow(icon: "exclamationmark.triangle", title: "Advanced")
                    }
                } footer: {
                    Text("Delete all chats, reset your identity. Hidden behind an extra tap so you don't trip on them.")
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done", action: onClose)
                }
            }
        }
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

/// Form-only relay-host editor pushed via NavigationLink. Replaces
/// the old modal RelaySettingsSheet — settings flow now stays in one
/// navigation stack instead of stacking sheets-on-sheets.
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
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
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
/// settings root, with explicit explanation footers. Each action
/// goes through a confirmationDialog before executing — two intents
/// (navigate here + tap destructive + confirm) before anything
/// dangerous happens.
private struct AdvancedScreen: View {
    @Bindable var store: ChatStore
    /// `resetIdentity` on the store eventually rebuilds the relay
    /// connection; we close the parent settings sheet so the user
    /// lands back on a freshly-initialized contacts list.
    let onResetClose: () -> Void

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
                Text("Wipes every contact's message log. Contacts and sessions stay; you can keep chatting with them. The wiped messages cannot be recovered.")
            }

            Section {
                Button(role: .destructive) {
                    confirmReset = true
                } label: {
                    Label("Reset identity", systemImage: "arrow.counterclockwise")
                }
            } footer: {
                Text("Generates a fresh keypair and wipes contacts, sessions, and message logs. Every contact will need to scan you again to chat. There is no recovery.")
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
                onResetClose()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("All contacts, sessions, and chats will be erased. Peers will need to scan you again.")
        }
    }
}
