import SwiftUI

/// Chat view for a single `ChatGroup`. Mirrors the 1:1 `ChatView`'s
/// shape — message bubbles + inline composer — but pulls from
/// `group.log` and posts via `ChatStore.sendGroupMessage(...)`.
///
/// Group-specific affordances surfaced in the toolbar:
///   - gear icon → `GroupSettingsView` (member list, add/remove,
///     rename/promote/demote, leave, delete locally).
///
/// Render-time member-name resolution (audit MEDIUM-7): `.peer` rows
/// carry a `senderPeerId` so the sender's display name is resolved
/// dynamically through `ChatStore.memberDisplayName`. Renaming a 1:1
/// contact propagates to every historical row immediately, no log
/// rewrite needed.
///
/// Auto-dismiss (audit HIGH-5): if the group disappears from state
/// (e.g. the user just tapped "Leave group" in settings), the chat
/// view dismisses itself rather than rendering a "Group missing"
/// dead-end.
struct GroupChatView: View {
    @Bindable var store: ChatStore
    let groupID: Data

    @State private var draft: String = ""
    @State private var showAttachSheet = false
    @State private var showPhotoPicker = false
    @State private var showDocumentPicker = false
    @State private var attachmentDraft: AttachmentDraft?
    @State private var faqAnchor: FAQSection?
    @FocusState private var composerFocused: Bool
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            log
                .frame(maxHeight: .infinity)
            if let draft = attachmentDraft {
                attachmentPreview(draft: draft)
                Divider()
            }
            composer
        }
        .navigationTitle(group?.displayName ?? "Group")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                NavigationLink {
                    GroupSettingsView(store: store, groupID: groupID)
                } label: {
                    Image(systemName: "gearshape")
                }
                .accessibilityLabel("Group settings")
            }
        }
        .sheet(item: $faqAnchor) { anchor in
            FAQView(initialSection: anchor) { faqAnchor = nil }
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
        .onAppear {
            // Mark the group as seen for unread tracking. If the
            // group is gone (e.g. we left from settings before this
            // re-appears), pop ourselves.
            guard let idx = store.groupIndex(forId: groupID) else {
                dismiss()
                return
            }
            store.state.groups[idx].lastSeenAt = Date()
        }
        .onChange(of: group?.id) { _, newId in
            // The group was removed from `state.groups` — most
            // commonly because the user tapped "Leave group" in
            // settings, which dismisses the settings view; we then
            // dismiss ourselves to land back on the contacts list
            // instead of rendering against a now-nil group.
            if newId == nil { dismiss() }
        }
    }

    private var group: ChatGroup? {
        store.state.groups.first(where: { $0.id == groupID })
    }

    @ViewBuilder
    private var log: some View {
        if let group {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 6) {
                        ForEach(Array(group.log.enumerated()), id: \.element.id) { idx, row in
                            let prior = idx > 0 ? group.log[idx - 1] : nil
                            GroupChatBubble(
                                message: row,
                                // Dedup the sender name when the
                                // immediately-prior row is from the same
                                // peer — adjacent bubbles read as one
                                // attributed run, matching the standard
                                // messaging-app cadence (Signal /
                                // iMessage / WhatsApp). A system row in
                                // between resets the run because the
                                // previous-row check is by senderPeerId.
                                senderName: senderName(
                                    for: row, in: group, previousRow: prior,
                                ),
                                resolveURL: { info in store.attachmentURL(for: info) },
                                quickLookEnabled: store.state.quickLookPreviewEnabled,
                                onInfoTap: { section in faqAnchor = section },
                                status: rowStatus(for: row),
                                readByAll: rowReadByAll(for: row),
                            )
                            .id(row.id)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
                .onAppear { scrollToBottom(proxy, group: group) }
                .onChange(of: group.log.count) { _, _ in
                    scrollToBottom(proxy, group: group)
                }
            }
        } else {
            // Transient state: between `state.groups.remove(at:)` and
            // the auto-dismiss `onChange` firing. Don't surface any
            // distracting UI — a blank background for one frame is
            // less jarring than a "Group missing" red flag.
            Color.clear
        }
    }

    /// Resolve the display name to render in the bubble's leading
    /// label (peer rows only). Self-attributed and system rows return
    /// nil; `GroupChatBubble` shows them without a "Name:" prefix.
    /// `previousRow` is the row immediately above this one in the log
    /// — if it's from the same peer, this returns nil too so the
    /// label appears once per run rather than once per bubble.
    private func senderName(
        for row: PersistedMessage,
        in group: ChatGroup,
        previousRow: PersistedMessage?,
    ) -> String? {
        switch row.kind {
        case .system: return nil
        case .preKey, .whisper, .attachment:
            guard row.side == .peer else { return nil }
            guard let peerId = row.senderPeerId else {
                // Pre-MEDIUM-7 row: no senderPeerId stored. Fall back
                // to whatever the row's text already includes.
                return nil
            }
            // Run-of-same-sender suppression. The check is on
            // `senderPeerId` rather than `side` so a `.me` row above a
            // `.peer` row still surfaces the peer's label, and a system
            // row above resets the run (system rows have nil
            // senderPeerId and don't match).
            if let prior = previousRow,
               prior.side == .peer,
               prior.kind != .system,
               prior.senderPeerId == peerId {
                return nil
            }
            return store.memberDisplayName(peerId, in: group)
        }
    }

    /// Roll up the per-recipient outbox status to a single indicator
    /// for `.me` group rows. Attachment rows with a `groupMessageId`
    /// use it; bare 1:1-style attachment-id-only fallback isn't
    /// applicable here because every group send carries a
    /// `groupMessageId` by construction (see `sendGroupMessage` /
    /// `shipPreparedGroupAttachment`).
    private func rowStatus(for row: PersistedMessage) -> OutboxEntry.Status? {
        guard row.side == .me, row.kind != .system,
              let gmid = row.groupMessageId
        else { return nil }
        return store.outbox.groupMessageStatus(forId: gmid)
    }

    /// True when every recipient of this `.me` group row has emitted
    /// a 0x04 readReceipt covering it. Drives the ✓✓ → 👁 swap on the
    /// rolled-up status icon. False (NOT nil) when no outbox entries
    /// remain — post-GC the row stays at ✓✓ rather than claiming
    /// "read by all" without confirmation.
    private func rowReadByAll(for row: PersistedMessage) -> Bool {
        guard row.side == .me, row.kind != .system,
              let gmid = row.groupMessageId
        else { return false }
        return store.outbox.groupMessageReadByAll(forId: gmid)
    }

    private func scrollToBottom(_ proxy: ScrollViewProxy, group: ChatGroup) {
        guard let last = group.log.last else { return }
        proxy.scrollTo(last.id, anchor: .bottom)
    }

    private var composer: some View {
        HStack(spacing: 8) {
            Button {
                showAttachSheet = true
            } label: {
                Image(systemName: "paperclip")
                    .padding(.horizontal, 4)
            }
            .buttonStyle(.bordered)
            .disabled(!canSend)
            .accessibilityLabel("Attach a file")
            .confirmationDialog(
                "Attach a file",
                isPresented: $showAttachSheet,
                titleVisibility: .hidden,
            ) {
                Button("Photo or video") { showPhotoPicker = true }
                Button("File") { showDocumentPicker = true }
                Button("Cancel", role: .cancel) {}
            }

            TextField(
                attachmentDraft == nil ? "Message" : "add a caption (optional)",
                text: $draft,
                axis: .vertical,
            )
                .textFieldStyle(.roundedBorder)
                .focused($composerFocused)
                // Multi-line composer: return inserts a newline. Don't
                // override `.submitLabel` to `.send` here — that styles
                // the keyboard's return key as a blue send glyph and
                // misleads users into thinking it'll submit (it can't,
                // axis: .vertical absorbs the keypress for the
                // newline). The visible send button next to the field
                // is the only way to send. ChatView's composer is
                // single-line and keeps `.submitLabel(.send)` because
                // there return actually submits.
            Button(action: send) {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.title2)
            }
            .disabled(!canSend || !sendEnabled)
        }
        .padding(8)
        .background(.bar)
    }

    /// True when the local user is still an active member of this
    /// group AND has minted their own sender-key chain. The composer
    /// disables Send when either is false; matches the runtime gate
    /// in `ChatStore.sendGroupMessage` / `sendGroupAttachment`
    /// (audit HIGH-3 / MEDIUM-4) — both backed by
    /// `ChatGroup.canSend(asLocal:)`.
    private var canSend: Bool {
        guard let group, let myCard = store.myCard else { return false }
        return group.canSend(asLocal: myCard.peerId)
    }

    /// Send is enabled if there's an attachment OR a non-blank caption.
    /// "Bare attachment with empty caption" is a perfectly valid send,
    /// matching the 1:1 composer behaviour.
    private var sendEnabled: Bool {
        if attachmentDraft != nil { return true }
        return !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private func send() {
        let captionText = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        if let pending = attachmentDraft {
            store.sendGroupAttachment(
                groupId: groupID,
                attachmentURL: pending.url,
                caption: captionText,
            )
            try? FileManager.default.removeItem(at: pending.url)
            attachmentDraft = nil
            draft = ""
            return
        }
        guard !captionText.isEmpty else { return }
        if store.sendGroupMessage(groupId: groupID, text: captionText) {
            draft = ""
        }
    }

    /// Pre-send banner: filename + size + tier-appropriate warning.
    /// Shape mirrors `ChatView.attachmentPreview` so a user moving
    /// between 1:1 and group chats sees identical compose-time
    /// affordances.
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
                HStack(alignment: .top, spacing: 6) {
                    Text(warning)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    if let anchor = AttachmentCopy.attachFaqAnchor(forTier: draft.tier) {
                        Button {
                            faqAnchor = anchor
                        } label: {
                            Image(systemName: "info.circle")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("More info")
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
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
}

private struct GroupChatBubble: View {
    let message: PersistedMessage
    /// Resolved sender name for `.peer` rows; nil for self-attributed
    /// and system rows. Rendered as a small caption above the bubble
    /// so renames propagate without rewriting `text`.
    let senderName: String?
    /// Resolves an attachment row's sandbox-relative path back to a
    /// concrete URL — same closure shape as `ChatRow` so the
    /// `AttachmentRowCard` Save-to-Files / Preview affordances work
    /// identically in 1:1 and group chats.
    let resolveURL: (AttachmentInfo) -> URL?
    /// Honours `state.quickLookPreviewEnabled` like the 1:1 row.
    let quickLookEnabled: Bool
    /// FAQ deep-link callback for the receive-side warning banners
    /// inside `AttachmentRowCard`.
    let onInfoTap: ((FAQSection) -> Void)?
    /// Worst-status-wins rollup across the N pairwise outbox legs of
    /// this `.me` row's group fan-out. Nil for `.peer` / `.system`
    /// rows and for `.me` rows whose backing entries have aged out
    /// of the outbox (post-GC). Drives the ⏳ / ✓ / ✓✓ indicator in
    /// the metadata strip below the bubble.
    let status: OutboxEntry.Status?
    /// True when every pairwise leg of this `.me` row has `readAt`
    /// stamped — flips the ✓✓ glyph to 👁. Mirrors the 1:1 row's
    /// "all readers confirmed" semantics; in a group, that means
    /// every recipient has emitted a 0x04 readReceipt covering this
    /// message. False when no entries exist (post-GC) so the row
    /// doesn't claim "read by all" without explicit per-recipient
    /// confirmation in hand.
    let readByAll: Bool

    var body: some View {
        HStack(alignment: .top) {
            switch message.kind {
            case .system:
                Text(message.text)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
            case .preKey, .whisper, .attachment:
                if message.side == .me {
                    Spacer(minLength: 40)
                    VStack(alignment: .trailing, spacing: 4) {
                        bubbleContent(bubbleColor: Color.accentColor.opacity(0.20))
                        metadata
                    }
                } else {
                    VStack(alignment: .leading, spacing: 2) {
                        if let name = senderName {
                            Text(name)
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .padding(.leading, 10)
                        }
                        bubbleContent(bubbleColor: Color(.secondarySystemBackground))
                        metadata
                    }
                    Spacer(minLength: 40)
                }
            }
        }
    }

    /// Timestamp + (for `.me` rows) status icon. Mirrors `ChatRow`'s
    /// metadata strip so 1:1 and group chats render the same row
    /// chrome — keeps the glyph legend in `OnboardingView` valid for
    /// both surfaces.
    private var metadata: some View {
        HStack(spacing: 6) {
            Text(message.timestamp.formatted(date: .omitted, time: .shortened))
                .foregroundStyle(.secondary)
            if message.side == .me, let status {
                ChatStatusIcon(status: status, read: readByAll)
            }
        }
        .font(.caption2)
    }

    @ViewBuilder
    private func bubbleContent(bubbleColor: Color) -> some View {
        if message.kind == .attachment, let info = message.attachment {
            AttachmentRowCard(
                info: info,
                side: message.side,
                bubbleColor: bubbleColor,
                resolveURL: resolveURL,
                captionText: message.text,
                quickLookEnabled: quickLookEnabled,
                onInfoTap: onInfoTap,
            )
        } else {
            Text(message.text)
                .font(.body)
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .textSelection(.enabled)
                .background(bubbleColor)
                .cornerRadius(12)
        }
    }
}
