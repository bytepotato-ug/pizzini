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
    @FocusState private var composerFocused: Bool
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            log
                .frame(maxHeight: .infinity)
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
                        ForEach(group.log) { row in
                            GroupChatBubble(
                                message: row,
                                senderName: senderName(for: row, in: group),
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
    private func senderName(for row: PersistedMessage, in group: ChatGroup) -> String? {
        switch row.kind {
        case .system: return nil
        case .preKey, .whisper, .attachment:
            guard row.side == .peer else { return nil }
            guard let peerId = row.senderPeerId else {
                // Pre-MEDIUM-7 row: no senderPeerId stored. Fall back
                // to whatever the row's text already includes.
                return nil
            }
            return store.memberDisplayName(peerId, in: group)
        }
    }

    private func scrollToBottom(_ proxy: ScrollViewProxy, group: ChatGroup) {
        guard let last = group.log.last else { return }
        proxy.scrollTo(last.id, anchor: .bottom)
    }

    private var composer: some View {
        HStack(spacing: 8) {
            TextField("Message", text: $draft, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .focused($composerFocused)
                .submitLabel(.send)
                .onSubmit(send)
            Button(action: send) {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.title2)
            }
            .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                || !canSend)
        }
        .padding(8)
        .background(.bar)
    }

    /// True when the local user is still an active member of this
    /// group AND has minted their own sender-key chain. The composer
    /// disables Send when either is false; matches the runtime gate
    /// in `ChatStore.sendGroupMessage` (audit HIGH-3 / MEDIUM-4).
    private var canSend: Bool {
        guard let group, let myCard = store.myCard else { return false }
        let active = group.activeMembers.contains(where: { $0.peerId == myCard.peerId })
        return active && group.myCurrentDistributionId != nil
    }

    private func send() {
        let trimmed = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        if store.sendGroupMessage(groupId: groupID, text: trimmed) {
            draft = ""
        }
    }
}

private struct GroupChatBubble: View {
    let message: PersistedMessage
    /// Resolved sender name for `.peer` rows; nil for self-attributed
    /// and system rows. Rendered as a small caption above the bubble
    /// so renames propagate without rewriting `text`.
    let senderName: String?

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
                    bubbleContent
                        .background(Color.accentColor.opacity(0.20))
                        .cornerRadius(12)
                } else {
                    VStack(alignment: .leading, spacing: 2) {
                        if let name = senderName {
                            Text(name)
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .padding(.leading, 10)
                        }
                        bubbleContent
                            .background(Color(.secondarySystemBackground))
                            .cornerRadius(12)
                    }
                    Spacer(minLength: 40)
                }
            }
        }
    }

    private var bubbleContent: some View {
        Text(message.text)
            .font(.body)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .textSelection(.enabled)
    }
}
