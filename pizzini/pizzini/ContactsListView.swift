import PizziniCryptoCore
import SwiftUI
import UIKit

struct ContactsListView: View {
    @Bindable var store: ChatStore
    @Binding var showScanner: Bool
    @Binding var showMyQR: Bool
    @Binding var showRelaySheet: Bool
    @Binding var confirmDeleteAllChats: Bool
    @Binding var confirmReset: Bool
    let onPasteContact: (String) -> Void

    var body: some View {
        ZStack {
            if store.state.contacts.isEmpty {
                emptyState
            } else {
                list
            }
        }
        .navigationTitle("Pizzini")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button {
                    showMyQR = true
                } label: {
                    Image(systemName: "qrcode")
                }
            }
            ToolbarItem(placement: .principal) {
                relayBadge
            }
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button {
                        showScanner = true
                    } label: { Label("Scan a contact's QR", systemImage: "qrcode.viewfinder") }
                    Button {
                        if let s = UIPasteboard.general.string {
                            onPasteContact(s)
                        }
                    } label: { Label("Paste contact", systemImage: "doc.on.clipboard") }
                    Divider()
                    Button {
                        showRelaySheet = true
                    } label: {
                        Label("Relay host (\(store.state.relayHost))", systemImage: "antenna.radiowaves.left.and.right")
                    }
                    Divider()
                    Button(role: .destructive) {
                        confirmDeleteAllChats = true
                    } label: { Label("Delete all chats", systemImage: "trash") }
                    Button(role: .destructive) {
                        confirmReset = true
                    } label: { Label("Reset identity", systemImage: "arrow.counterclockwise") }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "qrcode")
                .font(.system(size: 56))
                .foregroundStyle(.tint)
            Text("No contacts yet")
                .font(.headline)
            Text("Both you and the other person scan each other's QR.\nTap the QR icon to share yours, or the ⋯ menu to scan.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var list: some View {
        List {
            ForEach(store.state.contacts) { contact in
                NavigationLink {
                    ChatView(store: store, contactID: contact.id)
                } label: {
                    ContactRow(contact: contact)
                }
                .swipeActions(edge: .trailing) {
                    Button(role: .destructive) {
                        store.deleteContact(contact)
                    } label: {
                        Label("Delete", systemImage: "trash")
                    }
                }
            }
        }
        .listStyle(.plain)
    }

    private var relayBadge: some View {
        let (text, color): (String, Color) = {
            switch store.relayState {
            case .idle:           return ("idle", .gray)
            case .connecting:     return ("connecting", .orange)
            case .connected:      return ("connected", .green)
            case .failed:         return ("failed", .red)
            }
        }()
        return HStack(spacing: 4) {
            Circle().frame(width: 6, height: 6).foregroundStyle(color)
            Text("relay \(text)")
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
        }
    }
}

private struct ContactRow: View {
    let contact: Contact

    var body: some View {
        HStack(spacing: 12) {
            statusDot
            VStack(alignment: .leading, spacing: 2) {
                Text(contact.displayName)
                    .font(.body)
                if let last = contact.log.last {
                    Text(preview(last))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                } else if !contact.sessionEstablished {
                    Text("waiting for handshake…")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
        }
        .padding(.vertical, 4)
    }

    private var statusDot: some View {
        Circle()
            .frame(width: 8, height: 8)
            .foregroundStyle(contact.sessionEstablished ? .green : .orange)
    }

    private func preview(_ msg: PersistedMessage) -> String {
        switch msg.kind {
        case .system: return msg.text
        case .preKey, .whisper:
            let prefix = msg.side == .me ? "you: " : ""
            return prefix + msg.text
        }
    }
}
