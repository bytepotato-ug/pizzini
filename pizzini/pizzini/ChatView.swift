import SwiftUI
import UIKit

struct ChatView: View {
    @Bindable var store: ChatStore
    let contactID: UUID

    @State private var draft = ""
    @State private var renaming = false
    @State private var renameDraft = ""
    @State private var confirmDeleteChat = false
    @State private var confirmDeleteContact = false
    @Environment(\.dismiss) private var dismiss

    private var contact: Contact? {
        store.state.contacts.first { $0.id == contactID }
    }

    var body: some View {
        if let contact {
            VStack(spacing: 0) {
                if !contact.sessionEstablished {
                    pairingBanner
                    Divider()
                }
                messages(for: contact)
                composer(disabled: !contact.sessionEstablished)
            }
            .navigationTitle(contact.displayName)
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { store.markRead(contactID: contactID) }
            .onDisappear { store.markRead(contactID: contactID) }
            .onChange(of: contact.log.count) { _, _ in
                store.markRead(contactID: contactID)
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button {
                            renameDraft = contact.displayName
                            renaming = true
                        } label: { Label("Rename", systemImage: "pencil") }
                        Menu("Expires after") {
                            ForEach(Contact.ttlOptions, id: \.seconds) { opt in
                                Button {
                                    store.setContactTTL(contact, seconds: opt.seconds)
                                } label: {
                                    if contact.ttlSeconds == opt.seconds {
                                        Label(opt.label, systemImage: "checkmark")
                                    } else {
                                        Text(opt.label)
                                    }
                                }
                            }
                        }
                        Toggle(isOn: Binding(
                            get: { contact.readReceiptsEnabled },
                            set: { store.setReadReceipts(contact, enabled: $0) }
                        )) {
                            VStack(alignment: .leading) {
                                Text("Tell \(contact.displayName) when I read their messages")
                                Text("Off by default. Most journalists keep this off. \(contact.displayName) will see ✓✓ when their messages arrive on your phone either way.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        Button(role: .destructive) {
                            confirmDeleteChat = true
                        } label: { Label("Delete chat", systemImage: "trash") }
                        Button(role: .destructive) {
                            confirmDeleteContact = true
                        } label: { Label("Delete contact", systemImage: "person.crop.circle.badge.minus") }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .alert("Rename contact", isPresented: $renaming) {
                TextField("name", text: $renameDraft)
                    .textInputAutocapitalization(.words)
                Button("Cancel", role: .cancel) {}
                Button("Save") {
                    store.rename(contact, to: renameDraft)
                }
            }
            .confirmationDialog(
                "Delete this chat? Messages disappear; the contact stays.",
                isPresented: $confirmDeleteChat,
                titleVisibility: .visible
            ) {
                Button("Delete chat", role: .destructive) {
                    store.deleteChat(contact)
                }
                Button("Cancel", role: .cancel) {}
            }
            .confirmationDialog(
                "Delete this contact? You'll need to scan their QR again to chat.",
                isPresented: $confirmDeleteContact,
                titleVisibility: .visible
            ) {
                Button("Delete contact", role: .destructive) {
                    let captured = contact
                    dismiss()
                    store.deleteContact(captured)
                }
                Button("Cancel", role: .cancel) {}
            }
        } else {
            // Contact deleted from another path — bounce out.
            Color.clear.onAppear { dismiss() }
        }
    }

    private var pairingBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "hourglass")
                .foregroundStyle(.orange)
            Text("Waiting for them to scan you back…")
                .font(.caption)
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(Color.orange.opacity(0.10))
    }

    private func messages(for contact: Contact) -> some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 12) {
                    if contact.log.isEmpty {
                        Text(contact.sessionEstablished ? "Say hi." : "Pairing in progress.")
                            .foregroundStyle(.secondary)
                            .padding(.top, 48)
                    }
                    ForEach(contact.log) { entry in
                        ChatRow(
                            entry: entry,
                            status: entry.messageId.flatMap { store.outboxEntry(forMessageId: $0)?.status }
                        ).id(entry.id)
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 12)
            }
            .onAppear {
                // Jump (no animation) to the latest message when the
                // chat opens. Animating here looks janky because the
                // ScrollView lays out mid-scroll.
                if let last = contact.log.last {
                    proxy.scrollTo(last.id, anchor: .bottom)
                }
            }
            .onChange(of: contact.log.count) { _, _ in
                if let last = contact.log.last {
                    withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
            .scrollDismissesKeyboard(.interactively)
        }
    }

    private func composer(disabled: Bool) -> some View {
        HStack {
            TextField("type a message", text: $draft)
                .textFieldStyle(.roundedBorder)
                .submitLabel(.send)
                .disabled(disabled)
                .onSubmit { sendDraft() }
            Button {
                sendDraft()
            } label: {
                Image(systemName: "paperplane.fill")
                    .padding(.horizontal, 4)
            }
            .buttonStyle(.borderedProminent)
            .disabled(disabled || draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding()
    }

    private func sendDraft() {
        guard let contact else { return }
        store.send(draft, to: contact)
        draft = ""
    }
}

struct ChatRow: View {
    let entry: PersistedMessage
    let status: OutboxEntry.Status?

    init(entry: PersistedMessage, status: OutboxEntry.Status? = nil) {
        self.entry = entry
        self.status = status
    }

    var body: some View {
        HStack(alignment: .bottom) {
            if entry.side == .peer { Spacer(minLength: 32) }
            VStack(alignment: entry.side == .me ? .leading : .trailing, spacing: 4) {
                Text(entry.text)
                    .font(.body)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(bubbleColor)
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                metadata
            }
            if entry.side == .me { Spacer(minLength: 32) }
        }
    }

    private var bubbleColor: Color {
        switch entry.kind {
        case .system: return Color.gray.opacity(0.15)
        case .preKey, .whisper, .attachment:
            return entry.side == .me
                ? Color.blue.opacity(0.18)
                : Color.green.opacity(0.18)
        }
    }

    private var metadata: some View {
        // System rows (e.g. "Session not established yet…") get no
        // metadata — they're the chat layer talking to itself, not a
        // sent message.
        HStack(spacing: 6) {
            if entry.kind != .system {
                Text(timestampText)
                    .foregroundStyle(.secondary)
            }
            if entry.side == .me, let status, entry.kind != .system {
                statusIcon(status)
                if entry.readAt != nil, status == .delivered {
                    Text("Read").foregroundStyle(.blue)
                }
            }
        }
        .font(.caption2)
    }

    private var timestampText: String {
        entry.timestamp.formatted(date: .omitted, time: .shortened)
    }

    // Glyphs match the explainer in OnboardingView's `.icons` step —
    // change one place and you change the other, otherwise the legend
    // and the live UI drift apart.
    @ViewBuilder
    private func statusIcon(_ status: OutboxEntry.Status) -> some View {
        switch status {
        case .pending:
            Text("⏳").help("Queued — waiting for the connection")
        case .relayed:
            Text("✓").foregroundStyle(.secondary).help("Sent")
        case .delivered:
            Text("✓✓").foregroundStyle(.blue).help("Delivered to their phone")
        case .failed:
            Text("✗").foregroundStyle(.red).help("Expired before reaching them")
        }
    }
}
