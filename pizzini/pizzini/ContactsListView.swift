import PizziniCryptoCore
import SwiftUI
import UIKit

struct ContactsListView: View {
    @Bindable var store: ChatStore
    @Binding var showScanner: Bool
    @Binding var showMyQR: Bool
    @Binding var showSettings: Bool
    let onPasteContact: (String) -> Void

    /// Confirmation-dialog state for the `+` add-contact action sheet.
    /// Local to the toolbar — no need to plumb up to ContentView.
    @State private var showAddContactDialog = false

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
                .accessibilityLabel("Show my QR")
            }
            ToolbarItem(placement: .principal) {
                relayBadge
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showSettings = true
                } label: {
                    Image(systemName: "gearshape")
                }
                .accessibilityLabel("Settings")
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showAddContactDialog = true
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("Add contact")
                // Attach the dialog to the trigger button so iOS uses
                // it as the popover anchor — placing it on the parent
                // view makes the arrow point at random screen edges.
                .confirmationDialog(
                    "Add a contact",
                    isPresented: $showAddContactDialog,
                    titleVisibility: .visible,
                ) {
                    Button { showScanner = true } label: { Text("Scan their QR") }
                    Button {
                        if let s = UIPasteboard.general.string {
                            onPasteContact(s)
                        }
                    } label: { Text("Paste from clipboard") }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text("Pair by scanning the other person's QR. They need to scan you back too.")
                }
            }
        }
    }

    // ─── Empty state ───────────────────────────────────────────────────
    // Two big primary actions stacked, plus a smaller paste fallback.
    // Replaces the previous "tap the ⋯ menu to scan" instruction
    // (forcing first-run users to discover an overflow menu before they
    // could do anything).
    private var emptyState: some View {
        VStack(spacing: 28) {
            Spacer()
            VStack(spacing: 14) {
                Image(systemName: "qrcode.viewfinder")
                    .font(.system(size: 64))
                    .foregroundStyle(.tint)
                Text("No contacts yet")
                    .font(.title3.weight(.semibold))
                Text("Pair by scanning each other's QR. Both of you have to scan; one-way scans don't unlock chat.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
            VStack(spacing: 10) {
                Button {
                    showScanner = true
                } label: {
                    Label("Scan a QR", systemImage: "qrcode.viewfinder")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                Button {
                    showMyQR = true
                } label: {
                    Label("Show my QR", systemImage: "qrcode")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)

                Button {
                    if let s = UIPasteboard.general.string {
                        onPasteContact(s)
                    }
                } label: {
                    Text("Paste contact from clipboard")
                        .font(.footnote)
                }
                .padding(.top, 4)
            }
            .padding(.horizontal, 32)
            Spacer()
            Spacer()
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

    /// Surface a connection status only when something is wrong.
    /// A persistent green "connected" pill trains the eye to ignore it,
    /// so when it eventually flips orange the user misses that too —
    /// industry pattern (Signal, WhatsApp, iMessage) is to stay silent
    /// on the happy path and only banner when reconnecting / offline.
    /// "relay" is also wire-speak; users see "connection" instead.
    @ViewBuilder
    private var relayBadge: some View {
        switch store.relayState {
        case .connected:
            EmptyView()
        case .idle, .connecting:
            HStack(spacing: 6) {
                ProgressView().controlSize(.mini)
                Text("connecting…")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .accessibilityLabel("Connecting")
        case .failed:
            HStack(spacing: 6) {
                Image(systemName: "wifi.slash")
                    .font(.caption2)
                    .foregroundStyle(.red)
                Text("no connection")
                    .font(.caption2)
                    .foregroundStyle(.red)
            }
            .accessibilityLabel("No connection — your messages will not send")
        }
    }
}

private struct ContactRow: View {
    let contact: Contact

    var body: some View {
        HStack(spacing: 12) {
            // No status dot here. A solid coloured circle next to a
            // contact's name reads as a presence/online indicator in
            // every other messenger, and Pizzini deliberately doesn't
            // leak that — the relay sees who's connected, the user's
            // contact list shouldn't. Handshake-pending state is shown
            // by an explicit hourglass + caption instead.
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    if !contact.sessionEstablished {
                        Image(systemName: "hourglass")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .accessibilityLabel("waiting for handshake")
                    }
                    Text(contact.displayName)
                        .font(unread > 0 ? .body.weight(.semibold) : .body)
                }
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
            Spacer(minLength: 8)
            if unread > 0 {
                unreadBadge
            }
        }
        .padding(.vertical, 4)
    }

    private var unread: Int { contact.unreadCount }

    private var unreadBadge: some View {
        Text("\(unread)")
            .font(.caption2.bold().monospacedDigit())
            .foregroundStyle(.white)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Capsule().fill(Color.accentColor))
            .accessibilityLabel("\(unread) unread")
    }

    private func preview(_ msg: PersistedMessage) -> String {
        switch msg.kind {
        case .system: return msg.text
        case .preKey, .whisper:
            let prefix = msg.side == .me ? "you: " : ""
            return prefix + msg.text
        case .attachment:
            let prefix = msg.side == .me ? "you: " : ""
            let name = msg.attachment?.filename ?? "file"
            // The contacts list preview doesn't show the caption in
            // its own line, but the line below is dense enough — name
            // first wins because that's what the user is looking for
            // when scanning the list.
            if msg.text.isEmpty {
                return "\(prefix)📎 \(name)"
            }
            return "\(prefix)📎 \(name) — \(msg.text)"
        }
    }
}
