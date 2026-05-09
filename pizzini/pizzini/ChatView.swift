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
    @State private var showAttachSheet = false
    @State private var showPhotoPicker = false
    @State private var showDocumentPicker = false
    @State private var attachmentDraft: AttachmentDraft?
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
                if let draft = attachmentDraft {
                    attachmentPreview(draft: draft)
                    Divider()
                }
                composer(disabled: !contact.sessionEstablished, contact: contact)
            }
            .navigationTitle(contact.displayName)
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { store.markRead(contactID: contactID) }
            .onDisappear { store.markRead(contactID: contactID) }
            .onChange(of: contact.log.count) { _, _ in
                store.markRead(contactID: contactID)
            }
            .confirmationDialog(
                "Attach a file",
                isPresented: $showAttachSheet,
                titleVisibility: .hidden
            ) {
                Button("Photo or video") { showPhotoPicker = true }
                Button("File") { showDocumentPicker = true }
                Button("Cancel", role: .cancel) {}
            }
            .sheet(isPresented: $showPhotoPicker) {
                PhotoVideoPicker(
                    onPick: { url, name in
                        showPhotoPicker = false
                        if let d = AttachmentDraft(url: url, filename: name) {
                            attachmentDraft = d
                        }
                    },
                    onCancel: { showPhotoPicker = false },
                )
            }
            .sheet(isPresented: $showDocumentPicker) {
                DocumentPicker(
                    onPick: { url, name in
                        showDocumentPicker = false
                        if let d = AttachmentDraft(url: url, filename: name) {
                            attachmentDraft = d
                        }
                    },
                    onCancel: { showDocumentPicker = false },
                )
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

    private func composer(disabled: Bool, contact: Contact) -> some View {
        HStack {
            Button {
                showAttachSheet = true
            } label: {
                Image(systemName: "paperclip")
                    .padding(.horizontal, 4)
            }
            .buttonStyle(.bordered)
            .disabled(disabled)
            .accessibilityLabel("Attach a file")

            TextField(
                attachmentDraft == nil ? "type a message" : "add a caption (optional)",
                text: $draft,
            )
                .textFieldStyle(.roundedBorder)
                .submitLabel(.send)
                .disabled(disabled)
                .onSubmit { sendDraft(contact: contact) }
            Button {
                sendDraft(contact: contact)
            } label: {
                Image(systemName: "paperplane.fill")
                    .padding(.horizontal, 4)
            }
            .buttonStyle(.borderedProminent)
            .disabled(disabled || !canSend)
        }
        .padding()
    }

    /// Send is enabled if there's an attachment OR a non-blank caption.
    /// "Bare attachment with empty caption" is a perfectly valid send.
    private var canSend: Bool {
        if attachmentDraft != nil { return true }
        return !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Pre-send banner: filename + size + tier-appropriate warning. NO
    /// image preview — the brief is explicit, parser surface is the
    /// thing we're avoiding. Filename + system icon only.
    private func attachmentPreview(draft: AttachmentDraft) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Image(systemName: iconName(forTier: draft.tier))
                    .foregroundStyle(iconColor(forTier: draft.tier))
                    .font(.title2)
                VStack(alignment: .leading, spacing: 2) {
                    Text(draft.filename)
                        .font(.subheadline)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text("\(draft.displaySize) • \(tierLabel(draft.tier))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button(role: .destructive) {
                    discardAttachmentDraft()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Remove attachment")
            }
            if let warning = AttachmentCopy.attachWarning(forTier: draft.tier) {
                Text(warning)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(Color.yellow.opacity(0.15))
                    )
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 10)
        .background(Color(uiColor: .secondarySystemBackground))
    }

    private func iconName(forTier tier: AttachmentTier) -> String {
        switch tier {
        case .textFamily: return "doc.text"
        case .archive: return "doc.zipper"
        case .mediaStripAndWarn: return "photo"
        case .authorLeakingDoc: return "doc.richtext"
        case .codeOnTap: return "exclamationmark.triangle.fill"
        }
    }

    private func iconColor(forTier tier: AttachmentTier) -> Color {
        switch tier {
        case .codeOnTap: return .red
        case .mediaStripAndWarn, .authorLeakingDoc: return .orange
        default: return .secondary
        }
    }

    private func tierLabel(_ tier: AttachmentTier) -> String {
        switch tier {
        case .textFamily: return "text"
        case .archive: return "archive"
        case .mediaStripAndWarn: return "media"
        case .authorLeakingDoc: return "document"
        case .codeOnTap: return "executable"
        }
    }

    private func discardAttachmentDraft() {
        if let url = attachmentDraft?.url {
            try? FileManager.default.removeItem(at: url)
        }
        attachmentDraft = nil
    }

    private func sendDraft(contact: Contact) {
        // Two paths share this entrypoint: bare-text and attachment+
        // optional-caption. The latter sends one chunked attachment
        // logical message; the caption (if any) is currently embedded
        // as the row's text (sender-side rendering only — receiver gets
        // the attachment row with no caption). A future task can lift
        // the caption into a paired sealed `.chat` envelope so the
        // receiver also sees it; flagged for the maintainer.
        let captionText = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        if let pending = attachmentDraft {
            store.sendFile(pending.url, to: contact, caption: captionText)
            try? FileManager.default.removeItem(at: pending.url)
            attachmentDraft = nil
            draft = ""
            return
        }
        guard !captionText.isEmpty else { return }
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
