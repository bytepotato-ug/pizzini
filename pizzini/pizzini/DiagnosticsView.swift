import SwiftUI
import PizziniCryptoCore

/// In-app diagnostic view for debugging the group-chat plumbing
/// without wiring up Console.app. Surfaces:
///
///   * Relay connection state and identity-pub fingerprint.
///   * Contact and group counts (incl. pending invitations).
///   * Per-contact delivery-token stash level — depleted stashes
///     are the most common cause of dropped group ops / SKDMs
///     (the design's outbox+retry is deferred to v2).
///   * The most recent 200 group-flow events from
///     `ChatStore.diagEvents`, newest at the top, with category
///     coloring so receive failures stand out.
///
/// Reached from `Settings → Diagnostics`. The buffer resets on
/// app launch — this is a "what just happened" view, not an
/// audit log.
struct DiagnosticsView: View {
    @Bindable var store: ChatStore

    var body: some View {
        Form {
            Section("Identity") {
                if let myCard = store.myCard {
                    LabeledContent("Peer ID", value: short(myCard.peerId))
                } else {
                    LabeledContent("Peer ID", value: "(no card)")
                }
                LabeledContent("Relay", value: store.state.relayHost)
                LabeledContent("Connection", value: connectionLabel)
            }

            Section("Counts") {
                LabeledContent("Contacts", value: "\(store.state.contacts.count)")
                LabeledContent("Groups (joined)",
                               value: "\(store.state.groups.filter { !$0.pendingInvitation }.count)")
                LabeledContent("Pending invitations",
                               value: "\(store.state.groups.filter { $0.pendingInvitation }.count)")
            }

            Section {
                if store.state.contacts.isEmpty {
                    Text("No contacts yet.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(store.state.contacts) { contact in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(contact.displayName)
                                    .font(.body.weight(.medium))
                                Spacer()
                                tokenBadge(contact.deliveryTokensForPeer.count)
                            }
                            Text("\(short(contact.identityPub)) • session: \(contact.sessionEstablished ? "ok" : "pending")")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("Contacts (delivery tokens left)")
            } footer: {
                Text("Each group op or SKDM consumes one delivery token from the recipient's stash. Below \(Contact.refillThreshold) tokens, this device tries to refill on the next exchange. A 0 here for a recipient means this device cannot send them ANYTHING — including group invitations — until a refill round-trip completes.")
            }

            Section {
                if store.diagEvents.isEmpty {
                    Text("No events captured this session.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(store.diagEvents.reversed()) { event in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(alignment: .firstTextBaseline, spacing: 6) {
                                Text(category(event.category))
                                    .font(.caption2.weight(.semibold).monospaced())
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1)
                                    .background(Capsule().fill(categoryColor(event.category).opacity(0.18)))
                                    .foregroundStyle(categoryColor(event.category))
                                Text(timestamp(event.timestamp))
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(.secondary)
                                Spacer()
                            }
                            Text(event.message)
                                .font(.caption.monospaced())
                                .foregroundStyle(.primary)
                                .textSelection(.enabled)
                        }
                        .padding(.vertical, 2)
                    }
                }
            } header: {
                Text("Recent events (newest first)")
            } footer: {
                Text("Last \(store.diagEvents.count) events captured this session. Lines with REJECTED, NO CONTACT, NO DELIVERY TOKEN, or DROPPED tell you why a group invitation didn't reach the other device.")
            }
        }
        .navigationTitle("Diagnostics")
        .navigationBarTitleDisplayMode(.inline)
    }

    // ─── helpers ────────────────────────────────────────────────────

    private func short(_ data: Data) -> String {
        let head = data.prefix(4).map { String(format: "%02x", $0) }.joined()
        let tail = data.suffix(2).map { String(format: "%02x", $0) }.joined()
        return "\(head)…\(tail)"
    }

    private var connectionLabel: String {
        switch store.relayState {
        case .idle: return "idle"
        case .connecting: return "connecting…"
        case .connected: return "connected"
        case let .failed(msg): return "failed: \(msg)"
        }
    }

    private func category(_ raw: String) -> String {
        raw.uppercased()
    }

    private func categoryColor(_ raw: String) -> Color {
        switch raw {
        case "group": return .blue
        case "relay": return .red
        case "pair":  return .green
        default:       return .secondary
        }
    }

    private func timestamp(_ d: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter.string(from: d)
    }

    @ViewBuilder
    private func tokenBadge(_ count: Int) -> some View {
        Text("\(count) tok")
            .font(.caption2.monospaced().weight(.medium))
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(Capsule().fill(tokenColor(count).opacity(0.18)))
            .foregroundStyle(tokenColor(count))
    }

    private func tokenColor(_ count: Int) -> Color {
        if count == 0 { return .red }
        if count < Contact.refillThreshold { return .orange }
        return .green
    }
}
