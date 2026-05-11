import SwiftUI
import UIKit
import QuickLook

struct ChatView: View {
    @Bindable var store: ChatStore
    let contactID: UUID
    /// Deep-link target from the global search results view. Nil for
    /// the normal contacts-list NavigationLink path. When non-nil,
    /// `onAppear` pre-populates the in-chat find-bar with the query
    /// and scrolls to the cited message so the user lands on the
    /// exact row that matched, with prev/next ready to cycle through
    /// other hits in the same chat.
    let initialFocus: ChatSearch.Focus?

    init(
        store: ChatStore,
        contactID: UUID,
        initialFocus: ChatSearch.Focus? = nil,
    ) {
        self.store = store
        self.contactID = contactID
        self.initialFocus = initialFocus
    }

    @State private var draft = ""
    @State private var renaming = false
    @State private var renameDraft = ""
    @State private var confirmDeleteChat = false
    @State private var confirmDeleteContact = false
    @State private var showAttachSheet = false
    @State private var showPhotoPicker = false
    @State private var showDocumentPicker = false
    @State private var attachmentDraft: AttachmentDraft?
    /// Set to a non-nil section when the user taps an (i) info button
    /// on a tier banner — both pre-send and post-receive surfaces use
    /// this to deep-link into FAQView at the right anchor.
    @State private var faqAnchor: FAQSection?
    @FocusState private var composerFocused: Bool
    /// In-chat find-bar state. Drives a CUSTOM inline search bar
    /// that the body renders at the top of the chat ONLY when
    /// `searchActive` is true. We don't use SwiftUI's `.searchable`
    /// because its `isPresented` binding controls focus, not
    /// visibility — the bar stays mounted under the nav bar
    /// regardless. `currentMatchID` tracks which hit the user has
    /// cycled to (index-by-UUID rather than by integer offset so a
    /// row arriving / TTL-expiring under the user's feet doesn't
    /// shift the highlighted "current match" to the wrong bubble).
    @State private var searchQuery = ""
    @State private var searchActive = false
    @State private var currentMatchID: UUID?
    /// Focuses the inline find-bar TextField the instant the user
    /// taps the toolbar magnifying-glass.
    @FocusState private var searchFocused: Bool
    // iOS 18 ScrollPosition binding for the message list. Two roles:
    //   1. Initial position is `.bottom`, so opening the chat lands
    //      on the latest message without any imperative `scrollTo`.
    //      `.defaultScrollAnchor(.bottom, for: .initialOffset)` on the
    //      ScrollView reads this on first layout.
    //   2. After the user hits Send we call `scrollTo(edge: .bottom)`
    //      explicitly — `.defaultScrollAnchor(.bottom, for: .sizeChanges)`
    //      already keeps an at-bottom user pinned when a new row
    //      lands, but a user who scrolled UP to read history then
    //      tapped Send still needs to see their own message arrive,
    //      and the anchor alone won't yank them down for that case.
    @State private var scrollPosition = ScrollPosition(edge: .bottom)
    @Environment(\.dismiss) private var dismiss

    private var contact: Contact? {
        store.state.contacts.first { $0.id == contactID }
    }

    var body: some View {
        if let contact {
            VStack(spacing: 0) {
                if searchActive {
                    customSearchBar
                }
                if !contact.sessionEstablished {
                    pairingBanner
                    Divider()
                }
                messages(for: contact)
                    // Bitchat-style panic gesture: three fast taps on
                    // the chat-content area instantly delete this
                    // chat (per-contact log only; contact + session
                    // stay). Gated behind the Settings toggle, off
                    // by default — accidental triggers would silently
                    // destroy history with no undo. `simultaneousGesture`
                    // means scrolling, attachment-row buttons, and
                    // (i)-info taps still work; only the specific
                    // three-taps-in-quick-succession pattern triggers.
                    .simultaneousGesture(
                        TapGesture(count: 3).onEnded {
                            guard store.state.panicModeEnabled else { return }
                            UIImpactFeedbackGenerator(style: .heavy).impactOccurred()
                            let captured = contact
                            dismiss()
                            store.deleteChat(captured)
                        }
                    )
                    // Single-tap dismisses the keyboard. Same gesture
                    // recogniser shape as the panic three-tap above —
                    // both are simultaneous, so a triple-tap also
                    // dismisses on the first tap (and panic-deletes
                    // on the third). On a single tap, only this fires.
                    .simultaneousGesture(
                        TapGesture(count: 1).onEnded {
                            composerFocused = false
                        }
                    )
            }
            // Composer + (optional) attachment-preview live in a
            // `.safeAreaInset(edge: .bottom)` rather than as the
            // tail of the VStack. Two reasons:
            //
            // 1. Bottom-edge layout. Inside a VStack, the composer
            //    sits ABOVE the home-indicator safe-area inset, with
            //    a visible gap of empty space between composer and
            //    indicator. With `.safeAreaInset`, iOS treats the
            //    composer AS the bottom inset — the composer's
            //    background extends through the indicator area and
            //    the system blurs the indicator over our background,
            //    exactly the pattern Messages / WhatsApp / Signal use.
            // 2. Keyboard. `.safeAreaInset` automatically rises with
            //    the keyboard when the composer's TextField becomes
            //    first responder; no manual keyboard-avoidance code.
            .safeAreaInset(edge: .bottom, spacing: 0) {
                VStack(spacing: 0) {
                    // Find-bar pill sits ABOVE the attachment-preview
                    // banner and the composer whenever the user has
                    // a non-empty query. Decoupled from `searchActive`
                    // (which only tracks search-field focus) so that:
                    //   • a global-search deep-link arrives with the
                    //     pill visible and the cited match highlighted
                    //     EVEN THOUGH the search field is not focused
                    //     (no keyboard hiding the chat content);
                    //   • a user who Cancels the search field to read
                    //     context still sees the prev/next pill, and
                    //     the pill's X is the explicit exit.
                    if !searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        findBar
                        Divider()
                    }
                    if let draft = attachmentDraft {
                        attachmentPreview(draft: draft)
                        Divider()
                    }
                    composer(disabled: !contact.sessionEstablished, contact: contact)
                }
                .background(.bar)
            }
            // Cover chat content during a screen recording or external
            // display. We sit inside the NavigationStack's child view
            // so the nav bar (back button, ⋯ menu) stays interactive —
            // the user can pop back out without seeing what they were
            // reading mirror to a TV.
            .screenCaptureShielded()
            .navigationTitle(contact.displayName)
            .navigationBarTitleDisplayMode(.inline)
            .onAppear {
                store.activeSurface = .oneOnOne(peerIdentity: contact.identityPub)
                store.markRead(contactID: contactID)
                applyInitialFocusIfNeeded(contact: contact)
            }
            .onDisappear {
                if store.activeSurface == .oneOnOne(peerIdentity: contact.identityPub) {
                    store.activeSurface = .none
                }
                store.markRead(contactID: contactID)
            }
            .onChange(of: contact.log.count) { _, _ in
                store.markRead(contactID: contactID)
            }
            // When the user edits the query the current match anchors
            // to the newest hit so they read forward into history with
            // ↑. Empty query → no anchor; the find pill disappears.
            // Deliberately NOT also clearing on `searchActive` going
            // false: the user might Cancel the field to read context
            // around the highlighted matches without ending search
            // mode entirely. The find-pill's X button is the explicit
            // exit path; Cancel just unfocuses the bar.
            .onChange(of: searchQuery) { _, _ in
                landOnNewestMatch(in: contact.log)
            }
            // NB: the `.confirmationDialog` for the paperclip lives on
            // the paperclip button itself (see `composer`) so iOS uses
            // the button as the popover anchor. Attaching it here at
            // the body level made the popover float at the top of the
            // screen with the arrow pointing nowhere.
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
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        if searchActive {
                            // Already open — second tap dismisses.
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

    /// Custom inline find-bar. Rolled our own because SwiftUI's
    /// `.searchable` doesn't actually hide its drawer field when
    /// `isPresented` is false — it just unfocuses. Only mounts in
    /// the view tree when `searchActive == true`, so the chat opens
    /// to a clean top edge.
    private var customSearchBar: some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Find in this chat", text: $searchQuery)
                    .textFieldStyle(.plain)
                    .focused($searchFocused)
                    .submitLabel(.search)
                    .autocorrectionDisabled(true)
                    .textInputAutocapitalization(.never)
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
        currentMatchID = nil
        searchFocused = false
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
                        status: rowStatus(forEntry: entry),
                        resolveURL: { info in store.attachmentURL(for: info) },
                        quickLookEnabled: store.state.quickLookPreviewEnabled,
                        onInfoTap: { section in faqAnchor = section },
                        // In-chat find: when the user has an active
                        // query, every matched bubble gets a yellow
                        // AttributedString highlight on the matched
                        // substrings, AND the currently-focused match
                        // (the one prev/next is anchored to) gets an
                        // extra outer orange ring so the user can see
                        // WHERE in the list they just jumped to.
                        // Decoupled from `searchActive` so a deep-link
                        // arrival shows highlights even when the
                        // search field isn't focused.
                        highlightQuery: searchQuery,
                        isFocusedMatch: entry.id == currentMatchID,
                    ).id(entry.id)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 12)
        }
        // The three iOS 18 scroll primitives that together replace the
        // old `ScrollViewReader` + 1pt-bottom-anchor + deferred
        // `proxy.scrollTo` workaround:
        //
        //   • `.initialOffset = .bottom` — open the chat with the last
        //     row already in view. Replaces `onAppear { scrollToBottom }`,
        //     which fired one runloop tick after layout and so visibly
        //     "jumped" on first appearance.
        //   • `.sizeChanges = .bottom` — keep the bottom of visible
        //     content stable when the ScrollView's viewport OR content
        //     size changes. Two cases this matters for:
        //       (a) Keyboard rises → bottom safe-area inset grows →
        //           viewport shrinks. The anchor keeps the bottom row
        //           visible just above the composer-on-keyboard instead
        //           of letting it slide behind. This is the core fix
        //           for the "keyboard rises, latest message vanishes"
        //           complaint.
        //       (b) A new row lands. If the user was at-bottom, the
        //           new row scrolls into view. If the user was scrolled
        //           up reading history, they STAY where they are — the
        //           anchor preserves the visible content rather than
        //           yanking them down. The old `onChange(log.count)`
        //           pull-to-bottom did yank, and that misbehavior is
        //           a regression we're fixing here.
        //   • `.scrollPosition($scrollPosition)` — programmatic hook so
        //     `sendDraft` can `scrollTo(edge: .bottom)` AFTER a user-
        //     initiated send. Covers the edge case where the user
        //     scrolled up, then tapped the composer + Send: the
        //     sizeChanges anchor won't reveal the new row on its own
        //     because it preserves the user's position; this jumps to
        //     bottom so they always see their own message land.
        .defaultScrollAnchor(.bottom, for: .initialOffset)
        .defaultScrollAnchor(.bottom, for: .sizeChanges)
        .scrollPosition($scrollPosition)
        .scrollDismissesKeyboard(.interactively)
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
                attachmentDraft == nil ? "type a message" : "add a caption (optional)",
                text: $draft,
            )
                .textFieldStyle(.roundedBorder)
                .focused($composerFocused)
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

    /// Resolve the right OutboxEntry.Status for a chat row. Plain chat
    /// rows look up by their own messageId; attachment rows roll up
    /// across all chunks via OutboxStore.attachmentStatus(forId:).
    private func rowStatus(forEntry entry: PersistedMessage) -> OutboxEntry.Status? {
        if entry.kind == .attachment, let aid = entry.attachment?.attachmentId {
            return store.outbox.attachmentStatus(forId: aid)
        }
        return entry.messageId.flatMap { store.outboxEntry(forMessageId: $0)?.status }
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
            jumpToBottomOnSend()
            return
        }
        guard !captionText.isEmpty else { return }
        store.send(draft, to: contact)
        draft = ""
        jumpToBottomOnSend()
    }

    /// Jump the chat scroll to the absolute bottom after the user
    /// hit Send. `.defaultScrollAnchor(.bottom, for: .sizeChanges)`
    /// already keeps an at-bottom user pinned through a row append,
    /// but a user who scrolled up to re-read history then sent still
    /// needs to see their own message arrive — the anchor preserves
    /// their reading position, which would otherwise hide the new
    /// row off the bottom of the viewport.
    private func jumpToBottomOnSend() {
        withAnimation { scrollPosition.scrollTo(edge: .bottom) }
    }

    // MARK: - In-chat find-bar

    /// Compact navigation pill docked above the composer when an
    /// in-chat search is active. Shows the current match's 1-based
    /// position out of total matches, with ↑ / ↓ chevrons to cycle.
    /// "No matches" surfaces explicitly so the user knows they're
    /// not just scrolled to an irrelevant spot — the query simply
    /// has zero hits in this chat.
    @ViewBuilder
    private var findBar: some View {
        let matches = matchedIDs(in: contact?.log ?? [])
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
                // Explicit exit from search mode. Clears the query +
                // current-match-id (which removes the highlights + the
                // pill itself) and unfocuses the search field if it
                // happened to be focused. Separate from the system
                // Cancel button on the search bar so a user who's
                // unfocused the bar to read context can still leave
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

    /// All matching message IDs for the current `searchQuery`, in
    /// chronological order. Recomputed on every read so a new row
    /// landing under the user's feet (inbound message, or our own
    /// send) is included immediately; the underlying scan is a
    /// linear pass over the in-RAM log and the cost is negligible.
    /// Driven by `searchQuery` rather than `searchActive` for the
    /// same reason as the highlights and the find-pill: a deep-link
    /// from global search produces a non-empty query without the
    /// search field being focused, and we want prev/next to work
    /// from the moment the chat opens.
    private func matchedIDs(in log: [PersistedMessage]) -> [UUID] {
        ChatSearch.findIDs(in: log, query: searchQuery)
    }

    /// 0-based index of `currentMatchID` within `matches`, or nil if
    /// either is absent or out of sync. Drives the "n of m" pill.
    private func matchedIndex(in matches: [UUID]) -> Int? {
        guard let id = currentMatchID else { return nil }
        return matches.firstIndex(of: id)
    }

    /// On query change, anchor the find-bar to the NEWEST match. The
    /// user reads-forward-from-history pattern: land on the most
    /// recent hit, ↑ goes backward in time. Mirrors the find-bar
    /// behaviour in iMessage / Mail.
    private func landOnNewestMatch(in log: [PersistedMessage]) {
        let matches = matchedIDs(in: log)
        guard let last = matches.last else {
            currentMatchID = nil
            return
        }
        currentMatchID = last
        withAnimation { scrollPosition.scrollTo(id: last, anchor: .center) }
    }

    /// Cycle to the previous (older) match. Wraps to the newest when
    /// already at the oldest, matching browser find-in-page.
    private func jumpToPrevMatch(in matches: [UUID]) {
        guard !matches.isEmpty else { return }
        let current = matchedIndex(in: matches) ?? matches.count - 1
        let prev = (current - 1 + matches.count) % matches.count
        currentMatchID = matches[prev]
        withAnimation { scrollPosition.scrollTo(id: matches[prev], anchor: .center) }
    }

    /// Cycle to the next (newer) match. Wraps to the oldest when
    /// already at the newest. Same browser-find semantics.
    private func jumpToNextMatch(in matches: [UUID]) {
        guard !matches.isEmpty else { return }
        let current = matchedIndex(in: matches) ?? 0
        let next = (current + 1) % matches.count
        currentMatchID = matches[next]
        withAnimation { scrollPosition.scrollTo(id: matches[next], anchor: .center) }
    }

    /// Honour an `initialFocus` deep-link from the global search
    /// results: pre-populate the find-bar with the result's query
    /// and scroll-snap to the cited message. Called from `onAppear`
    /// exactly once per view-lifetime; guards on `currentMatchID`
    /// being nil so a programmatic state reset that happens to
    /// re-run `onAppear` doesn't yank the user back to the original
    /// focus row after they cycled away.
    ///
    /// Deliberately does NOT set `searchActive = true`. Activating
    /// the search field would focus its TextField and raise the
    /// keyboard, hiding the chat content the user is trying to
    /// read — and the user tapped a search-result to READ context,
    /// not to keep typing. The find-pill renders off `searchQuery`'s
    /// non-empty value (not `searchActive`), so the user lands with
    /// the cited match highlighted + prev/next ready while the
    /// chat itself stays unobscured. They can tap the toolbar
    /// magnifying-glass any time to refine the query.
    private func applyInitialFocusIfNeeded(contact: Contact) {
        guard let focus = initialFocus, currentMatchID == nil else { return }
        searchQuery = focus.query
        let matches = ChatSearch.findIDs(in: contact.log, query: focus.query)
        let target = matches.contains(focus.messageID) ? focus.messageID
            : matches.last ?? focus.messageID
        currentMatchID = target
        // Defer the scrollTo to the next runloop tick so the
        // LazyVStack has measured the rows that just became visible
        // before ScrollPosition is asked to jump. Without the defer
        // the position binding sometimes computes against pre-layout
        // offsets and the target row lands clipped under the
        // nav-bar search drawer.
        DispatchQueue.main.async {
            withAnimation {
                scrollPosition.scrollTo(id: target, anchor: .center)
            }
        }
    }
}

struct ChatRow: View {
    let entry: PersistedMessage
    let status: OutboxEntry.Status?
    /// Resolves an inbound attachment's sandbox-relative path back to a
    /// concrete URL. Closure rather than direct ChatStore access so the
    /// row stays cheap to construct in tests / previews.
    let resolveURL: (AttachmentInfo) -> URL?
    /// Honours the user's `quickLookPreviewEnabled` setting — when true
    /// AND the row is an inbound attachment, we render a Preview button
    /// that opens QLPreviewController in addition to Save to Files.
    let quickLookEnabled: Bool
    /// Bubble (i) info-button taps up to the parent ChatView so it
    /// can present the FAQ sheet at the right anchor.
    let onInfoTap: ((FAQSection) -> Void)?
    /// In-chat find query. Non-nil → matched substrings in the bubble
    /// text get a yellow AttributedString background; nil → render
    /// the bubble exactly as before. The text content is unchanged
    /// either way; only the visual styling differs.
    let highlightQuery: String?
    /// True when this row is the currently-focused match in the
    /// find-bar's prev/next cycle. Adds an outer orange ring around
    /// the bubble so the user can see WHERE they landed after a
    /// chevron tap, separate from the yellow text-background that
    /// marks every match generically.
    let isFocusedMatch: Bool

    init(
        entry: PersistedMessage,
        status: OutboxEntry.Status? = nil,
        resolveURL: @escaping (AttachmentInfo) -> URL? = { _ in nil },
        quickLookEnabled: Bool = false,
        onInfoTap: ((FAQSection) -> Void)? = nil,
        highlightQuery: String? = nil,
        isFocusedMatch: Bool = false
    ) {
        self.entry = entry
        self.status = status
        self.resolveURL = resolveURL
        self.quickLookEnabled = quickLookEnabled
        self.onInfoTap = onInfoTap
        self.highlightQuery = highlightQuery
        self.isFocusedMatch = isFocusedMatch
    }

    var body: some View {
        HStack(alignment: .bottom) {
            // Standard chat-app convention: my messages on the right,
            // peer's on the left. Spacer goes BEFORE my row's content
            // (pushing it right) and AFTER the peer's (leaving it
            // anchored to the leading edge).
            if entry.side == .me { Spacer(minLength: 32) }
            VStack(alignment: entry.side == .me ? .trailing : .leading, spacing: 4) {
                if entry.kind == .attachment, let info = entry.attachment {
                    AttachmentRowCard(
                        info: info,
                        side: entry.side,
                        bubbleColor: bubbleColor,
                        resolveURL: resolveURL,
                        captionText: entry.text,
                        quickLookEnabled: quickLookEnabled,
                        onInfoTap: onInfoTap,
                    )
                    .overlay(focusedMatchRing)
                } else {
                    bubbleText
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(bubbleColor)
                        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .overlay(focusedMatchRing)
                }
                metadata
            }
            if entry.side == .peer { Spacer(minLength: 32) }
        }
    }

    /// Bubble text rendered as plain `Text` when search is inactive,
    /// or as an AttributedString (`SearchHighlight.attributed`) when
    /// the find-bar is engaged. Same font + colour either way — the
    /// only differences are the per-match yellow background runs and
    /// the forced `.primary` foreground inside those runs (so the
    /// match reads against the yellow fill regardless of light/dark
    /// mode).
    @ViewBuilder
    private var bubbleText: some View {
        if let q = highlightQuery,
           !q.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            Text(SearchHighlight.attributed(text: entry.text, query: q))
                .font(.body)
        } else {
            Text(entry.text)
                .font(.body)
        }
    }

    /// Outer orange ring around a focused-match bubble. The rounded
    /// rectangle matches the bubble's own clipShape so the ring sits
    /// flush against the bubble's edge. Drawn ONLY when this row is
    /// the find-bar's current match; for every other matched row the
    /// per-substring yellow text-background is enough signal.
    @ViewBuilder
    private var focusedMatchRing: some View {
        if isFocusedMatch {
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .strokeBorder(Color.orange, lineWidth: 2)
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
                ChatStatusIcon(status: status, read: entry.readAt != nil)
            }
        }
        .font(.caption2)
    }

    private var timestampText: String {
        entry.timestamp.formatted(date: .omitted, time: .shortened)
    }
}

/// Status indicator glyph for an outbound row. Used by `ChatRow`,
/// `GroupChatBubble`, and `OnboardingView.iconsStep` (the legend
/// that teaches the user what each glyph means). All three render
/// from the SAME `ChatStatusGlyph` view so the legend matches what
/// the user later sees in a real chat row pixel-for-pixel.
///
/// Progression: hourglass → ✓ → ✓✓ → 👁 → ✗. The eye REPLACES the
/// double-check rather than appending — one glyph scale, no
/// redundant "Read" text. Honours `Contact.readReceiptsEnabled`-off
/// by default: with no incoming readAt timestamp the eye never
/// shows, the row stays at the blue double-check.
struct ChatStatusIcon: View {
    let status: OutboxEntry.Status
    let read: Bool

    var body: some View {
        switch status {
        case .pending:   ChatStatusGlyph(kind: .pending)
        case .relayed:   ChatStatusGlyph(kind: .sent)
        case .delivered:
            if read { ChatStatusGlyph(kind: .read) }
            else    { ChatStatusGlyph(kind: .delivered) }
        case .failed:    ChatStatusGlyph(kind: .failed)
        }
    }
}

/// Single source of truth for the five status glyphs. All five
/// render as SF Symbols at the same nominal size so column
/// alignment is consistent without manual baseline tweaks. The
/// double-check (delivered, not yet read) uses two overlapping
/// `checkmark` symbols rather than a Unicode `✓✓` so it stays in
/// the same rendering pipeline as the rest.
struct ChatStatusGlyph: View {
    enum Kind: Sendable, Equatable {
        case pending, sent, delivered, read, failed
    }
    let kind: Kind

    var body: some View {
        switch kind {
        case .pending:
            // Orange to match the other "waiting" hourglass surfaces
            // in the app — the per-contact "waiting for handshake"
            // row badge and the pairing banner above the chat composer
            // both render `hourglass` in orange. Keeping this colour
            // consistent means the user learns one visual association
            // for "waiting" instead of two.
            Image(systemName: "hourglass")
                .foregroundStyle(.orange)
                .help("Queued — waiting for the connection")
        case .sent:
            Image(systemName: "checkmark")
                .foregroundStyle(.secondary)
                .help("Sent")
        case .delivered:
            DoubleCheckmark()
                .foregroundStyle(.blue)
                .help("Delivered to their phone")
        case .read:
            Image(systemName: "eye.fill")
                .foregroundStyle(.blue)
                .help("They read it")
        case .failed:
            Image(systemName: "xmark")
                .foregroundStyle(.red)
                .help("Expired before reaching them")
        }
    }
}

/// Two `checkmark` SF Symbols overlapped to read as a tidy
/// double-tick. The negative `spacing` brings the second check
/// into the first's tail, mimicking the iMessage / WhatsApp
/// rendering without falling back to a Unicode `✓✓` (which
/// renders inconsistently across iOS versions and Dynamic Type
/// sizes). Color is set by the parent via `.foregroundStyle`.
private struct DoubleCheckmark: View {
    var body: some View {
        HStack(spacing: -3) {
            Image(systemName: "checkmark")
            Image(systemName: "checkmark")
        }
    }
}

/// Card view for an attachment chat row. Renders filename + size + an
/// icon (NEVER a thumbnail — see Pegasus 2021 / "no in-app preview"
/// hard rule), tier-appropriate warning banner, and either a Save-to-
/// Files button (inbound) or a status hint (outbound — the file came
/// from the user's own picker, no need to save it again).
struct AttachmentRowCard: View {
    let info: AttachmentInfo
    let side: ChatBubbleSide
    let bubbleColor: Color
    let resolveURL: (AttachmentInfo) -> URL?
    let captionText: String
    /// User's `quickLookPreviewEnabled` setting — when true AND this is
    /// an inbound row, we render a Preview button that pops
    /// QLPreviewController. Default false (strict mode).
    let quickLookEnabled: Bool
    /// Bubble taps on the (i) info button up to the parent ChatView
    /// so the FAQ sheet is presented from a single place. Nil means
    /// "no info button" (e.g. a row in a context where deep-linking
    /// to FAQ doesn't make sense).
    let onInfoTap: ((FAQSection) -> Void)?

    @State private var presentingShare = false
    @State private var presentingPreview = false

    init(
        info: AttachmentInfo,
        side: ChatBubbleSide,
        bubbleColor: Color,
        resolveURL: @escaping (AttachmentInfo) -> URL?,
        captionText: String,
        quickLookEnabled: Bool = false,
        onInfoTap: ((FAQSection) -> Void)? = nil
    ) {
        self.info = info
        self.side = side
        self.bubbleColor = bubbleColor
        self.resolveURL = resolveURL
        self.captionText = captionText
        self.quickLookEnabled = quickLookEnabled
        self.onInfoTap = onInfoTap
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundStyle(iconColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text(info.filename)
                        .font(.subheadline.weight(.medium))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(sizeText)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            if !captionText.isEmpty {
                Text(captionText)
                    .font(.callout)
            }
            // Receive-side banner only on inbound rows — the sender
            // already saw the attach-time warning at compose time, no
            // value re-litigating it on the outbound row.
            if info.isInbound, let banner = receiveBanner {
                bannerView(banner)
            }
            // Save-to-Files / Preview show on BOTH sides as long as
            // the sandbox copy still exists. The cleanup pass GCs
            // outbound copies after the 7-day TTL same as inbound;
            // post-cleanup the row stays as a chat record but the
            // bytes are gone, and `resolveURL` will return nil.
            if resolveURL(info) != nil {
                HStack(spacing: 8) {
                    saveToFilesButton
                    if quickLookEnabled {
                        previewButton
                    }
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(bubbleColor)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .quickLookPreview(
            $presentingPreview,
            url: resolveURL(info),
        )
    }

    /// In-app preview via `QLPreviewController`. The actual rendering
    /// runs in QuickLook's XPC service, NOT in Pizzini's process —
    /// same as Save-to-Files-then-tap. The integration surface here
    /// is wider than strict mode (we hand QuickLook a file URL), but
    /// the bytes still aren't parsed by us.
    private var previewButton: some View {
        Button {
            presentingPreview = true
        } label: {
            Label("Preview", systemImage: "eye")
                .font(.callout)
        }
        .buttonStyle(.bordered)
    }

    private var icon: String {
        switch info.tier {
        case .textFamily: return "doc.text"
        case .archive: return "doc.zipper"
        case .mediaStripAndWarn: return "photo"
        case .authorLeakingDoc: return "doc.richtext"
        case .codeOnTap: return "exclamationmark.triangle.fill"
        }
    }
    private var iconColor: Color {
        if AttachmentTierClassifier.isDesktopExecutable(filename: info.filename) {
            return .red
        }
        switch info.tier {
        case .codeOnTap: return .red
        case .mediaStripAndWarn, .authorLeakingDoc: return .orange
        default: return .secondary
        }
    }

    private var sizeText: String {
        let bcf = ByteCountFormatter()
        bcf.allowedUnits = [.useKB, .useMB, .useGB]
        bcf.countStyle = .file
        return bcf.string(fromByteCount: Int64(info.byteSize))
    }

    private var receiveBanner: AttachmentCopy.ReceiveBanner? {
        AttachmentCopy.receiveWarning(
            forTier: info.tier,
            isDesktopExecutable: AttachmentTierClassifier
                .isDesktopExecutable(filename: info.filename),
        )
    }

    @ViewBuilder
    private func bannerView(_ banner: AttachmentCopy.ReceiveBanner) -> some View {
        let bg: Color = banner.tone == .danger
            ? Color.red.opacity(0.18) : Color.yellow.opacity(0.18)
        let icon = banner.tone == .danger ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill"
        let fg: Color = banner.tone == .danger ? .red : .orange
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: icon).foregroundStyle(fg)
            Text(banner.text)
                .font(.caption2)
                .frame(maxWidth: .infinity, alignment: .leading)
            // (i) button deep-links into FAQ for the curious user.
            // Hidden when the parent didn't pass an onInfoTap (e.g.
            // tests or previews) or the banner has no FAQ section.
            if let faq = banner.faqSection, let onInfoTap {
                Button {
                    onInfoTap(faq)
                } label: {
                    Image(systemName: "info.circle")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("More info")
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous).fill(bg)
        )
    }

    /// Save-to-Files button. Resolves the sandbox URL on tap and
    /// presents `UIDocumentInteractionController.presentOptionsMenu`
    /// — that's the standard iOS surface that includes "Save to
    /// Files" and "Open in…" without opening the bytes in-app. We
    /// deliberately do NOT use Quick Look (in-app preview = parser
    /// surface) and do NOT auto-open.
    private var saveToFilesButton: some View {
        Button {
            presentingShare = true
        } label: {
            Label("Save to Files", systemImage: "square.and.arrow.down")
                .font(.callout)
        }
        .buttonStyle(.bordered)
        .background(
            DocumentInteractionPresenter(
                isPresented: $presentingShare,
                url: resolveURL(info),
            )
        )
    }
}

/// SwiftUI modifier that presents `QLPreviewController` for an
/// optional URL, gated on a binding. `View.quickLookPreview(_:url:)`
/// is shipped by Apple but takes a non-optional `URL` (or expects you
/// to use the `[URL]` form) — and our resolver may legitimately return
/// nil if the sandbox copy was already GC'd post-TTL. Wrap with our
/// own modifier so a nil URL is a no-op rather than a crash.
extension View {
    fileprivate func quickLookPreview(
        _ isPresented: Binding<Bool>,
        url: URL?
    ) -> some View {
        sheet(isPresented: isPresented) {
            if let url {
                QLPreviewWrapper(url: url) {
                    isPresented.wrappedValue = false
                }
                .ignoresSafeArea()
            } else {
                Text("Attachment is no longer available on this device.")
                    .padding()
            }
        }
    }
}

private struct QLPreviewWrapper: UIViewControllerRepresentable {
    let url: URL
    let onDismiss: () -> Void

    func makeUIViewController(context: Context) -> UINavigationController {
        let preview = QLPreviewController()
        preview.dataSource = context.coordinator
        preview.delegate = context.coordinator
        let nav = UINavigationController(rootViewController: preview)
        return nav
    }

    func updateUIViewController(_ uiViewController: UINavigationController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(url: url, onDismiss: onDismiss) }

    final class Coordinator: NSObject, QLPreviewControllerDataSource, QLPreviewControllerDelegate {
        let url: URL
        let onDismiss: () -> Void
        init(url: URL, onDismiss: @escaping () -> Void) {
            self.url = url
            self.onDismiss = onDismiss
        }

        func numberOfPreviewItems(in controller: QLPreviewController) -> Int { 1 }
        func previewController(_ controller: QLPreviewController, previewItemAt index: Int) -> QLPreviewItem {
            url as NSURL
        }
        func previewControllerDidDismiss(_ controller: QLPreviewController) {
            onDismiss()
        }
    }
}

/// Bridges `UIDocumentInteractionController` into SwiftUI. Triggered by
/// flipping `isPresented` to true; the controller calls back to clear
/// the binding when dismissed. The brief specifies this controller
/// rather than ShareLink/UIActivityViewController so the user surface
/// is the focused "Save to Files / Open in…" menu rather than a
/// full share sheet.
struct DocumentInteractionPresenter: UIViewControllerRepresentable {
    @Binding var isPresented: Bool
    let url: URL?

    func makeUIViewController(context: Context) -> UIViewController {
        UIViewController()
    }

    func updateUIViewController(_ uiViewController: UIViewController, context: Context) {
        guard isPresented, let url, uiViewController.view.window != nil else { return }
        let controller = UIDocumentInteractionController(url: url)
        controller.delegate = context.coordinator
        context.coordinator.controller = controller
        let presented = controller.presentOptionsMenu(
            from: uiViewController.view.bounds,
            in: uiViewController.view,
            animated: true,
        )
        // If iOS refused the menu (no apps registered for this UTI),
        // fall back to the standard preview-options sheet so the user
        // can still pick "Save to Files".
        if !presented {
            _ = controller.presentPreview(animated: true)
        }
        DispatchQueue.main.async {
            isPresented = false
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator: NSObject, UIDocumentInteractionControllerDelegate {
        var controller: UIDocumentInteractionController?
        func documentInteractionControllerViewControllerForPreview(
            _ controller: UIDocumentInteractionController
        ) -> UIViewController {
            // Walk up to the key window's root — UIDocumentInteractionController
            // needs a presenting VC for its preview path even though we
            // primarily use presentOptionsMenu.
            let scene = UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .first(where: { $0.activationState == .foregroundActive })
            return scene?.windows.first(where: { $0.isKeyWindow })?
                .rootViewController ?? UIViewController()
        }
    }
}
