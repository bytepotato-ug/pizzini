import SwiftUI
import UIKit

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
    /// Deep-link target from the global search results view. Same
    /// shape and semantics as `ChatView.initialFocus` — when non-nil,
    /// `onAppear` pre-populates the in-chat find-bar with `query` and
    /// scrolls to `messageID` so a tap on a group-message result row
    /// lands the user on the cited bubble with prev/next ready.
    let initialFocus: ChatSearch.Focus?

    init(
        store: ChatStore,
        groupID: Data,
        initialFocus: ChatSearch.Focus? = nil,
    ) {
        self.store = store
        self.groupID = groupID
        self.initialFocus = initialFocus
    }

    @State private var draft: String = ""
    @State private var showAttachSheet = false
    @State private var showPhotoPicker = false
    @State private var showDocumentPicker = false
    @State private var attachmentDraft: AttachmentDraft?
    @State private var faqAnchor: FAQSection?
    @FocusState private var composerFocused: Bool
    /// In-chat find-bar state. Mirrors `ChatView`'s shape exactly —
    /// `searchQuery` is bound to `.searchable(text:isPresented:)` on
    /// the body; `searchActive` controls programmatic open/close via
    /// the toolbar magnifying-glass button + the global-search deep
    /// link. `currentMatchID` is the UUID (not index) of the focused
    /// hit so a row arriving / TTL-expiring under the user's feet
    /// doesn't shift the highlight to the wrong bubble.
    @State private var searchQuery = ""
    @State private var searchActive = false
    @State private var currentMatchID: UUID?
    @FocusState private var searchFocused: Bool
    /// iOS 18 ScrollPosition binding for the group log. Mirrors the
    /// 1:1 `ChatView.scrollPosition` — opens at-bottom via
    /// `.defaultScrollAnchor(.bottom, for: .initialOffset)`, and
    /// `send()` calls `scrollTo(edge: .bottom)` to surface a user's
    /// own row even when they were scrolled up reading history at
    /// the moment they tapped Send.
    @State private var scrollPosition = ScrollPosition(edge: .bottom)
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            if searchActive {
                customSearchBar
            }
            logSection
        }
    }

    private var logSection: some View {
        log
            // Bitchat-style panic gesture, parity with `ChatView`:
            // three fast taps on the chat-content area instantly
            // wipe this group's local log (membership + chain state
            // stay; the rest of the group sees no change). Gated
            // behind the same `panicModeEnabled` Settings toggle
            // that 1:1 honours, off by default.
            .simultaneousGesture(
                TapGesture(count: 3).onEnded {
                    guard store.state.panicModeEnabled else { return }
                    UIImpactFeedbackGenerator(style: .heavy).impactOccurred()
                    let captured = groupID
                    dismiss()
                    store.deleteGroupChat(groupId: captured)
                }
            )
            // Single-tap dismisses the keyboard. Same shape as the
            // 1:1 `ChatView` — both gestures are simultaneous, so a
            // triple-tap also dismisses on the first tap (and
            // panic-deletes on the third); on a single tap, only
            // this fires.
            .simultaneousGesture(
                TapGesture(count: 1).onEnded {
                    composerFocused = false
                }
            )
        // Composer + (optional) attachment-preview banner live in
        // `.safeAreaInset(edge: .bottom)` rather than as the tail of
        // a VStack. Two reasons, identical to the 1:1 `ChatView`:
        //
        //   1. Bottom-edge layout. Inside a VStack the composer sits
        //      ABOVE the home-indicator safe-area inset, with a
        //      visible gap of empty space between composer and
        //      indicator. In the inset, iOS treats the composer AS
        //      the bottom safe area — the composer's background
        //      extends through the indicator area and the system
        //      blurs the indicator over our background. Matches
        //      Messages / WhatsApp / Signal / Threema.
        //   2. Keyboard tracking. `.safeAreaInset` rides the iOS 18
        //      keyboardLayoutGuide, so the composer is glued to the
        //      keyboard's top edge through every transition — not
        //      animated one render-pass behind it. Combined with
        //      `.defaultScrollAnchor(.bottom, for: .sizeChanges)` on
        //      the log inside, the bottom row of chat content stays
        //      visible just above the composer as the keyboard
        //      rises and falls.
        .safeAreaInset(edge: .bottom, spacing: 0) {
            VStack(spacing: 0) {
                // Find-bar pill, parity with `ChatView`. Sits ABOVE
                // the attachment-preview banner and the composer so
                // prev/next + "n of m" stays visible while the user
                // types in either the composer or the search field.
                // Visibility driven by `searchQuery` non-empty rather
                // than `searchActive` so a deep-link arrival shows
                // the pill without forcing the search field focused.
                if !searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    findBar
                    Divider()
                }
                if let draft = attachmentDraft {
                    attachmentPreview(draft: draft)
                    Divider()
                }
                composer
            }
            .background(.bar)
        }
        // In-chat find — F-NEW-802: custom inline search bar instead
        // of `.searchable`. The drawer mount of `.searchable` left the
        // last-typed term visible across nav back-then-forward; the
        // inline bar is mounted only when `searchActive == true` and
        // explicitly cleared on Cancel. Matches the 1:1 `ChatView`
        // pattern from commit 52ac407.
        .navigationTitle(group?.displayName ?? "Group")
        .navigationBarTitleDisplayMode(.inline)
        // Hide the floating tab pill while a group chat is on screen.
        // Same reasoning as 1:1 ChatView — the composer owns the
        // bottom of the surface.
        .toolbar(.hidden, for: .tabBar)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    if searchActive {
                        cancelInlineSearch()
                    } else {
                        searchActive = true
                        searchFocused = true
                    }
                } label: {
                    Image(systemName: "magnifyingglass")
                }
                .accessibilityLabel("Find in chat")
            }
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
            guard store.groupIndex(forId: groupID) != nil else {
                dismiss()
                return
            }
            store.activeSurface = .group(groupId: groupID)
            // `markGroupRead` stamps lastSeenAt + emits 0x04 read
            // receipts to each member who's a 1:1 contact with
            // receipts toggled on. Same parity with `ChatView`'s
            // `markRead` for 1:1 chats.
            store.markGroupRead(groupID: groupID)
            applyInitialFocusIfNeeded()
        }
        .onDisappear {
            if store.activeSurface == .group(groupId: groupID) {
                store.activeSurface = .none
            }
            store.markGroupRead(groupID: groupID)
        }
        .onChange(of: group?.id) { _, newId in
            // The group was removed from `state.groups` — most
            // commonly because the user tapped "Leave group" in
            // settings, which dismisses the settings view; we then
            // dismiss ourselves to land back on the contacts list
            // instead of rendering against a now-nil group.
            if newId == nil { dismiss() }
        }
        .onChange(of: group?.log.count ?? 0) { _, _ in
            // A new row landed while the user is looking at this
            // group. Mark-read ships fresh receipts so the sender's
            // outbox flips ✓✓ → 👁 on the just-arrived message
            // without the user having to re-enter the chat — same
            // shape as `ChatView`'s 1:1 onChange.
            store.markGroupRead(groupID: groupID)
        }
        // Query change → anchor the find-bar to the newest match,
        // same shape as `ChatView`. Empty query → clear anchor.
        // Deliberately NOT also clearing on `searchActive` going
        // false (Cancel-tap): the user might want to read context
        // around the highlighted matches without ending search
        // mode entirely. The find-pill's X is the explicit exit.
        .onChange(of: searchQuery) { _, _ in
            landOnNewestMatch()
        }
    }

    private var group: ChatGroup? {
        store.state.groups.first(where: { $0.id == groupID })
    }

    @ViewBuilder
    private var log: some View {
        if let group {
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
                            previewMode: store.state.attachmentPreviewMode,
                            onInfoTap: { section in faqAnchor = section },
                            status: rowStatus(for: row),
                            readByAll: rowReadByAll(for: row),
                            // In-chat find: same shape as ChatView —
                            // yellow background on matched substrings
                            // for every hit, orange outer ring on the
                            // currently-focused match the user cycled
                            // to via prev/next. Driven by searchQuery
                            // non-empty so deep-link arrivals (where
                            // the search field is not focused) still
                            // highlight matches.
                            highlightQuery: searchQuery,
                            isFocusedMatch: row.id == currentMatchID,
                            // Render-time gate for the eye glyph
                            // (see GroupChatBubble.showReadReceipts).
                            // Groups inherit from the global toggle
                            // — no per-group override exists, so a
                            // user who flipped "Send read receipts"
                            // off in Settings sees the eyes
                            // disappear immediately even if
                            // `readByAll` was true from earlier
                            // stamps.
                            showReadReceipts: store.state.defaultReadReceiptsEnabled,
                        )
                        .id(row.id)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
            }
            // iOS 18 scroll primitives, identical shape to the 1:1
            // `ChatView.messages`. See the comment block there for
            // the full rationale; in short:
            //
            //   • `.initialOffset = .bottom` — open at the latest row.
            //   • `.sizeChanges = .bottom` — when the viewport
            //     shrinks (keyboard rises) or content grows (new
            //     row), keep the bottom of visible content stable.
            //     An at-bottom user sees the new row scroll into
            //     view; a scrolled-up-reading-history user stays
            //     where they are rather than getting yanked down.
            //   • `.scrollPosition($scrollPosition)` — programmatic
            //     hook so `send()` can `scrollTo(edge: .bottom)`
            //     after a user-initiated send, covering the case
            //     where the user was scrolled up and so the size-
            //     change anchor wouldn't reveal their own new row.
            //
            // Combined with the `.safeAreaInset(.bottom)` composer
            // on the body, this is enough to replace the previous
            // `ScrollViewReader` + 1pt-bottom-anchor + deferred
            // `proxy.scrollTo` workaround completely.
            .defaultScrollAnchor(.bottom, for: .initialOffset)
            .defaultScrollAnchor(.bottom, for: .sizeChanges)
            .scrollPosition($scrollPosition)
            .scrollDismissesKeyboard(.interactively)
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
    ///
    /// Render-time per-contact override gate, mirroring the F-405
    /// 1:1 fix: legs whose recipient is *currently* effective-off
    /// (e.g. user later flipped a member to `.alwaysOff`) are filtered
    /// out of the aggregation rather than required-and-unreadable.
    /// This matches the receive-side gate at ChatStore.swift:2564
    /// which already drops fresh receipts from those peers; without
    /// the matching read-side filter, legs stamped *before* the
    /// toggle kept lighting the eye after the user opted out.
    private func rowReadByAll(for row: PersistedMessage) -> Bool {
        guard row.side == .me, row.kind != .system,
              let gmid = row.groupMessageId
        else { return false }
        let globalDefault = store.state.defaultReadReceiptsEnabled
        let trackedLegs = store.outbox.entries.values.filter { entry in
            guard entry.groupMessageId == gmid else { return false }
            guard let cIdx = store.state.contacts.firstIndex(
                where: { $0.identityPub == entry.recipientPeerId },
            ) else { return false }
            return store.state.contacts[cIdx].effectiveReadReceiptsEnabled(
                globalDefault: globalDefault,
            )
        }
        guard !trackedLegs.isEmpty else { return false }
        return trackedLegs.allSatisfy { $0.readAt != nil }
    }

    /// Jump the chat scroll to the absolute bottom after the user
    /// hit Send. `.defaultScrollAnchor(.bottom, for: .sizeChanges)`
    /// on the log already keeps an at-bottom user pinned through a
    /// row append, but a user who scrolled up to re-read group
    /// history then sent still needs to see their own message
    /// arrive — the anchor preserves their reading position, which
    /// would otherwise hide the new row off the bottom of the
    /// viewport. Mirrors `ChatView.jumpToBottomOnSend`.
    private func jumpToBottomOnSend() {
        withAnimation { scrollPosition.scrollTo(edge: .bottom) }
    }

    // MARK: - In-chat find-bar (parity with `ChatView`)

    /// Compact navigation pill — "n of m" + chevron-up / chevron-down
    /// — docked above the composer when an in-chat search is active.
    /// See `ChatView.findBar` for the full rationale; this is the
    /// group surface's identical-shaped counterpart.
    @ViewBuilder
    private var findBar: some View {
        let matches = matchedIDs()
        HStack(spacing: 14) {
            if matches.isEmpty {
                Text("No matches")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                let displayIndex = matchedIndex(in: matches).map { $0 + 1 } ?? matches.count
                Text("\(displayIndex) of \(matches.count)")
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button { jumpToPrevMatch(in: matches) } label: {
                Image(systemName: "chevron.up")
            }
            .disabled(matches.isEmpty)
            .accessibilityLabel("Previous match")
            Button { jumpToNextMatch(in: matches) } label: {
                Image(systemName: "chevron.down")
            }
            .disabled(matches.isEmpty)
            .accessibilityLabel("Next match")
            Button {
                // Explicit exit from search mode. Parity with
                // `ChatView.findBar`'s X — separate from the system
                // Cancel button on the .searchable field so a user
                // who's unfocused the bar to read context can leave
                // search mode without having to re-focus first.
                searchQuery = ""
                currentMatchID = nil
                searchActive = false
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Exit search")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    /// All matching message IDs in the current group's log, in
    /// chronological order. Empty when the group has been removed
    /// from state under our feet. Driven by `searchQuery` rather
    /// than `searchActive` for parity with `ChatView.matchedIDs`.
    private func matchedIDs() -> [UUID] {
        guard let group else { return [] }
        return ChatSearch.findIDs(in: group.log, query: searchQuery)
    }

    /// 0-based index of `currentMatchID` within `matches`, or nil if
    /// either is absent. Drives the find-bar's "n of m" counter.
    private func matchedIndex(in matches: [UUID]) -> Int? {
        guard let id = currentMatchID else { return nil }
        return matches.firstIndex(of: id)
    }

    /// On query change, anchor the find-bar to the NEWEST match — same
    /// "read forward from history" cadence as the 1:1 chat view.
    private func landOnNewestMatch() {
        let matches = matchedIDs()
        guard let last = matches.last else {
            currentMatchID = nil
            return
        }
        currentMatchID = last
        withAnimation { scrollPosition.scrollTo(id: last, anchor: .center) }
    }

    /// Cycle to the previous (older) match. Wraps. Same semantics as
    /// `ChatView.jumpToPrevMatch`.
    private func jumpToPrevMatch(in matches: [UUID]) {
        guard !matches.isEmpty else { return }
        let current = matchedIndex(in: matches) ?? matches.count - 1
        let prev = (current - 1 + matches.count) % matches.count
        currentMatchID = matches[prev]
        withAnimation { scrollPosition.scrollTo(id: matches[prev], anchor: .center) }
    }

    /// Cycle to the next (newer) match. Wraps. Mirror of
    /// `ChatView.jumpToNextMatch`.
    private func jumpToNextMatch(in matches: [UUID]) {
        guard !matches.isEmpty else { return }
        let current = matchedIndex(in: matches) ?? 0
        let next = (current + 1) % matches.count
        currentMatchID = matches[next]
        withAnimation { scrollPosition.scrollTo(id: matches[next], anchor: .center) }
    }

    /// Honour an `initialFocus` deep-link from the global search
    /// results: same single-shot, only-once-per-view-lifetime guard
    /// as `ChatView.applyInitialFocusIfNeeded`. See that method's
    /// doc for the full rationale; in short, we pre-populate
    /// `searchQuery` (so highlights + find pill render) but
    /// deliberately leave `searchActive` false (so the keyboard
    /// doesn't pop up over the chat content the user is trying to
    /// read), and defer the scrollTo one runloop tick so the
    /// LazyVStack measurement has resolved.
    private func applyInitialFocusIfNeeded() {
        guard let focus = initialFocus, currentMatchID == nil, let group else { return }
        searchQuery = focus.query
        let matches = ChatSearch.findIDs(in: group.log, query: focus.query)
        let target = matches.contains(focus.messageID) ? focus.messageID
            : matches.last ?? focus.messageID
        currentMatchID = target
        DispatchQueue.main.async {
            withAnimation {
                scrollPosition.scrollTo(id: target, anchor: .center)
            }
        }
    }

    /// Custom inline search bar — mirror of `ChatView.customSearchBar`.
    /// Mounted only when `searchActive == true`; Cancel button clears
    /// the query state so a re-open opens with an empty field.
    private var customSearchBar: some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Find in this chat", text: $searchQuery)
                    .textFieldStyle(.plain)
                    .focused($searchFocused)
                    .submitLabel(.search)
                    .hardenedTextInput()
                if !searchQuery.isEmpty {
                    Button {
                        searchQuery = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .accessibilityLabel("Clear search")
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            Button("Cancel") {
                cancelInlineSearch()
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color(.systemBackground))
        .overlay(alignment: .bottom) { Divider() }
    }

    private func cancelInlineSearch() {
        searchActive = false
        searchQuery = ""
        searchFocused = false
    }

    private var composer: some View {
        // Same shared `MessageComposer` 1:1 ChatView uses. `canSend`
        // gates membership/sender-chain readiness (the entire
        // composer); `sendEnabled` gates draft/attachment presence
        // (just the send button). Background is supplied by the
        // outer `.safeAreaInset` VStack — see ChatView for the same
        // pattern.
        MessageComposer(
            draft: $draft,
            showAttachSheet: $showAttachSheet,
            placeholder: attachmentDraft == nil ? "Message" : "add a caption (optional)",
            composerDisabled: !canSend,
            sendDisabled: !sendEnabled,
            onSend: send,
            attachDialog: {
                Button("Photo or video") { showPhotoPicker = true }
                Button("File") { showDocumentPicker = true }
                Button("Cancel", role: .cancel) {}
            },
            focused: $composerFocused,
        )
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
            jumpToBottomOnSend()
            return
        }
        guard !captionText.isEmpty else { return }
        if store.sendGroupMessage(groupId: groupID, text: captionText) {
            draft = ""
            jumpToBottomOnSend()
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
    /// Three-tier preview opt-in, mirrors the 1:1 row.
    let previewMode: AttachmentPreviewMode
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
    /// In-chat find query. Non-nil → matched substrings in the bubble
    /// text get a yellow AttributedString background, same shape as
    /// `ChatRow.highlightQuery`.
    let highlightQuery: String?
    /// True when this row is the currently-focused match in the
    /// find-bar's prev/next cycle. Adds an outer orange ring so the
    /// user can see WHERE they landed after a chevron tap.
    let isFocusedMatch: Bool
    /// Live "do I currently honour read receipts?" flag. Groups
    /// inherit from the global `defaultReadReceiptsEnabled` toggle
    /// (no per-group override exists). When the user flips the
    /// global toggle off, the eye glyph disappears immediately
    /// even if `readByAll` is still true from earlier-stamped
    /// `readAt`s — the on-disk receipts are preserved so
    /// re-enabling restores the eye without reissuing on the
    /// wire.
    let showReadReceipts: Bool

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
                        bubbleContent(bubbleColor: Color(.systemFill))
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
                        bubbleContent(bubbleColor: Color(.secondarySystemFill))
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
                // Live render gate: the eye glyph only lights when
                // the user CURRENTLY honours receipts (global
                // toggle on) AND every leg's `readAt` is stamped.
                // Without the live gate, toggling the global
                // setting off would leave stale eyes on rows whose
                // `readAt` was stamped during an earlier on-window.
                ChatStatusIcon(
                    status: status,
                    read: showReadReceipts && readByAll,
                )
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
                previewMode: previewMode,
                onInfoTap: onInfoTap,
            )
            .overlay(focusedMatchRing)
        } else {
            bubbleText
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .textSelection(.enabled)
                .background(bubbleColor)
                .cornerRadius(12)
                .overlay(focusedMatchRing)
        }
    }

    /// Bubble text — AttributedString-highlighted when an in-chat
    /// search query is active and contains a match in `message.text`;
    /// plain `Text` otherwise. Same hookup as `ChatRow.bubbleText`,
    /// kept here as a private helper rather than a free function so
    /// the call site reads symmetrically to the 1:1 case.
    @ViewBuilder
    private var bubbleText: some View {
        if let q = highlightQuery,
           !q.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            Text(SearchHighlight.attributed(text: message.text, query: q))
                .font(.body)
        } else {
            Text(message.text)
                .font(.body)
        }
    }

    /// Outer orange ring around a focused-match bubble. Drawn ONLY
    /// when this row is the find-bar's current match; for every
    /// other matched row the per-substring yellow text-background
    /// is signal enough.
    @ViewBuilder
    private var focusedMatchRing: some View {
        if isFocusedMatch {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(Color.orange, lineWidth: 2)
        }
    }
}
