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
                Divider()
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
                        ChatRow(entry: entry).id(entry.id)
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 12)
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
        case .preKey, .whisper:
            return entry.side == .me
                ? Color.blue.opacity(0.18)
                : Color.green.opacity(0.18)
        }
    }

    private var metadata: some View {
        HStack(spacing: 6) {
            Text(entry.side == .me ? "me" : "peer")
                .foregroundStyle(.secondary)
            if entry.kind != .system {
                Text("·").foregroundStyle(.tertiary)
                Text(entry.kind == .preKey ? "PreKey" : "Whisper")
                    .foregroundStyle(entry.kind == .preKey ? .orange : .green)
                Text("·").foregroundStyle(.tertiary)
                Text("\(entry.bytes) B").foregroundStyle(.secondary)
            }
        }
        .font(.caption2.monospaced())
    }
}
