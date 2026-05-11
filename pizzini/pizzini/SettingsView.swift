import PizziniCryptoCore
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
                        title: "Relays",
                        value: relaySummary(),
                    )
                }
            } header: {
                Text("Connection")
            } footer: {
                Text(RelayRegistry.trusted.count > 1
                     ? "Messages fan out across every trusted relay in parallel — peers stay reachable as long as at least one route survives."
                     : "Messages route through the trusted relay. Once additional jurisdictions come online, the app will dial them all in parallel automatically.")
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

    /// Render the Settings root row's trailing value text. Three
    /// cases:
    ///   - BYO override set → "Custom: <host>".
    ///   - Bundled fleet with exactly one entry → show the relay's
    ///     label (e.g. "Relay Germany") so the user immediately sees
    ///     which jurisdiction they're on without tapping in.
    ///   - Bundled fleet with multiple entries → "N relays" so the
    ///     value scales without overflowing the row.
    private func relaySummary() -> String {
        if !store.state.relayHost.isEmpty {
            return "Custom: \(store.state.relayHost)"
        }
        let trusted = RelayRegistry.trusted
        switch trusted.count {
        case 0:  return "No relays configured"
        case 1:  return trusted[0].label
        default: return "\(trusted.count) relays"
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

/// Relay screen — surfaces the bundled trusted fleet (read-only) plus
/// an optional BYO host override per `docs/relay-architecture.md` D5.
///
/// The trusted-fleet section is the default routing target: messages
/// fan out across every alive onion (D3). The BYO field is for
/// dev/community deployments — a non-empty value collapses the fleet
/// down to a single client dialling that host instead.
private struct RelayHostScreen: View {
    @Bindable var store: ChatStore
    @Environment(\.dismiss) private var dismiss
    @State private var draft: String
    /// Which descriptor is currently expanded (showing full onion +
    /// failure detail). `nil` means all rows collapsed. Tap-toggle.
    @State private var expanded: String? = nil

    init(store: ChatStore) {
        self.store = store
        self._draft = State(initialValue: store.state.relayHost)
    }

    var body: some View {
        Form {
            Section {
                ForEach(RelayRegistry.trusted, id: \.host) { descriptor in
                    relayRow(descriptor)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            withAnimation(.snappy) {
                                expanded = (expanded == descriptor.host) ? nil : descriptor.host
                            }
                        }
                }
            } header: {
                Text("Trusted relays")
            } footer: {
                Text("Bundled with this app build and signed under its code-signature. We dial all of them in parallel; the first one that reaches your contact delivers, the others drop the duplicate. Tap a row for the full onion address and any error detail.")
            }

            Section {
                Button {
                    store.forceReconnectRelays()
                } label: {
                    Label("Reconnect now", systemImage: "arrow.clockwise")
                }
            } footer: {
                Text("Closes every relay socket and dials again. Tor stays up if it was already bootstrapped — the second connect cycle is sub-5 seconds.")
            }

            Section {
                TextField("custom host (leave empty for trusted)", text: $draft)
                    .hardenedTextInput()
                    .keyboardType(.URL)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            } header: {
                Text("Custom relay (advanced)")
            } footer: {
                Text("Empty = use the trusted fleet above. Non-empty = collapse to this single host (a community onion, etc.). Port stays 7777.")
            }
        }
        .navigationTitle("Relays")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") {
                    store.setRelayHost(draft)
                    dismiss()
                }
                .disabled(draft == store.state.relayHost)
            }
        }
    }

    @ViewBuilder
    private func relayRow(_ descriptor: RelayDescriptor) -> some View {
        let state = clientState(for: descriptor)
        let isExpanded = (expanded == descriptor.host)
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .foregroundStyle(.secondary)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 2) {
                    Text(descriptor.label)
                    Text(shortOnion(descriptor.host))
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                statusBadge(state)
                Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            if isExpanded {
                VStack(alignment: .leading, spacing: 4) {
                    Text(descriptor.host)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    // `Text("Port \(port)")` would let SwiftUI apply
                    // locale-specific grouping to the integer (e.g.
                    // de_DE renders 7777 as "7.777"). `verbatim`
                    // forces literal string interpolation, no
                    // localization.
                    Text(verbatim: "Port \(descriptor.port)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Text(stateDetail(state))
                        .font(.caption)
                        .foregroundStyle(stateDetailColor(state))
                }
                .padding(.leading, 34)
                .padding(.top, 2)
            }
        }
    }

    /// Display only the first 12 chars of the onion's vanity prefix +
    /// `…onion` — the full 56-char base32 string is read-only metadata,
    /// not actionable for the user. Tapping the row in a future
    /// iteration could expand to the full address for QR sharing.
    private func shortOnion(_ host: String) -> String {
        let h = host
        if h.count <= 18 { return h }
        return String(h.prefix(12)) + "…" + (h.hasSuffix(".onion") ? "onion" : "")
    }

    /// Map a per-relay `RelayClient.State` to a small dot + label.
    @ViewBuilder
    private func statusBadge(_ state: RelayClient.State?) -> some View {
        let (color, label): (Color, String) = {
            switch state {
            case .connected:                  return (.green, "connected")
            case .connecting:                 return (.orange, "connecting…")
            case let .connectingToTor(p):     return (.orange, "Tor \(p)%")
            case .idle:                       return (.gray, "idle")
            case .failed:                     return (.red, "failed")
            case .none:                       return (.gray, "offline")
            }
        }()
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    /// Expanded-row detail text for a given `RelayClient.State`.
    /// Surfaces failure reasons so the user can act (retry, switch
    /// network, file an issue) instead of just seeing "offline".
    private func stateDetail(_ state: RelayClient.State?) -> String {
        switch state {
        case .connected:
            return "Connected. Outbound messages are being broadcast through this relay."
        case .connecting:
            return "TCP / SOCKS5 handshake to the onion is in progress."
        case let .connectingToTor(p):
            return "Bootstrapping Tor — \(p)%. First-launch can take 5-30 seconds on a healthy network."
        case .idle:
            return "Not connected yet. The fleet starts dialling on app launch; pull-to-refresh below or use \"Reconnect now\" to retry."
        case let .failed(msg):
            return "Failed: \(msg)"
        case .none:
            return store.state.relayHost.isEmpty
                ? "This relay isn't being dialled. (Internal state mismatch — try Reconnect now.)"
                : "Bundled fleet disabled: a Custom relay is set below. Clear it to re-enable the fleet."
        }
    }

    private func stateDetailColor(_ state: RelayClient.State?) -> Color {
        if case .failed = state { return .red }
        if case .none = state { return .orange }
        return .secondary
    }

    /// Look up the per-client state for this descriptor. Reads the
    /// observable `ChatStore.perRelayState` dict so SwiftUI redraws
    /// the row badge live as the client crosses through
    /// `.connectingToTor → .connecting → .connected`. Returns `nil`
    /// when the user is in BYO mode (the bundled fleet isn't being
    /// dialled at all) or the descriptor isn't mounted yet.
    private func clientState(for descriptor: RelayDescriptor) -> RelayClient.State? {
        let isFleetMode = store.state.relayHost.isEmpty
        guard isFleetMode else { return nil }
        return store.perRelayState[descriptor.host]
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
