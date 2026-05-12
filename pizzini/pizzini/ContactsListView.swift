import PizziniCryptoCore
import SwiftUI
import UIKit

struct ContactsListView: View {
    @Bindable var store: ChatStore
    @Binding var showScanner: Bool
    let onPasteContact: (String) -> Void
    /// Empty-state shortcut: tell the host to switch to the Profil
    /// tab so a brand-new user can show THEIR QR to the person they
    /// want to pair with. Without it the empty-state "Show my QR"
    /// button would either disappear or open a sheet that duplicates
    /// the tab.
    let onRevealMyQR: () -> Void

    /// Confirmation-dialog state for the `+` add-contact action sheet.
    /// Local to the toolbar — no need to plumb up to ContentView.
    @State private var showAddContactDialog = false
    /// Sheet that lets the user assemble a new group (name + initial
    /// 1:1 contacts to invite). Local to the list — surfaced via the
    /// "+" toolbar menu.
    @State private var showNewGroupSheet = false
    /// `.searchable` text binding. Non-empty (after trimming) → the
    /// body swaps the normal contacts/groups list for a
    /// `SearchResultsView` that scans every chat log + name
    /// in-memory. Empty → normal list. iOS's search machinery owns
    /// the visible search field, the cancel button, and the keyboard
    /// dismissal flow; we just react to the value it produces.
    @State private var searchQuery = ""

    /// True when the user has tapped the magnifying-glass toolbar
    /// button. Drives a CUSTOM inline search bar that the body
    /// renders above the contacts list — we don't use SwiftUI's
    /// `.searchable` because its `isPresented` binding controls
    /// FOCUS, not visibility (the nav-bar-drawer search field stays
    /// mounted regardless). Cancel button on the custom bar flips
    /// this back to false and clears the query.
    @State private var searchActive = false
    /// Drives the focus on the inline TextField so the keyboard
    /// raises the instant the user taps the magnifying-glass icon,
    /// without needing a separate `.onAppear { searchFocused = true }`
    /// runloop hop.
    @FocusState private var searchFocused: Bool

    /// True when the user typed something searchable (non-blank).
    /// Computed rather than stored so a programmatic mutation to
    /// `searchQuery` flips this through `body` without a second
    /// `onChange` hop.
    private var isSearching: Bool {
        !searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        VStack(spacing: 0) {
            if searchActive {
                customSearchBar
            }
            ZStack {
                if isSearching {
                    SearchResultsView(store: store, query: searchQuery)
                } else if store.state.contacts.isEmpty, store.state.groups.isEmpty {
                    emptyState
                } else {
                    list
                }
            }
        }
        // Hide the contacts list when iOS reports a screen recording
        // or external display. The toolbar above stays interactive so
        // a user who triggered Control-Centre Record by mistake can
        // still navigate out / open Settings to disable recording.
        .screenCaptureShielded()
        .navigationTitle("Pizzini")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            // Profil + Einstellungen used to live in this toolbar (QR
            // top-leading, gear top-trailing). They moved to the
            // bottom-pill `TabView` in ContentView — keeping them here
            // would double up the navigation. What stays: `+` for
            // add-contact / new-group, relay status, search.
            ToolbarItem(placement: .topBarLeading) {
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
                    "Add a contact or group",
                    isPresented: $showAddContactDialog,
                    titleVisibility: .visible,
                ) {
                    Button { showScanner = true } label: { Text("Scan their QR") }
                    Button {
                        if let s = UIPasteboard.general.string {
                            onPasteContact(s)
                        }
                    } label: { Text("Paste from clipboard") }
                    Button {
                        showNewGroupSheet = true
                    } label: { Text("New group…") }
                        .disabled(store.state.contacts.isEmpty)
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text("Pair contacts via QR. Groups are made up of contacts you've already paired with.")
                }
            }
            ToolbarItem(placement: .principal) {
                // Brand lockup — small logo + wordmark, no inline
                // status. The live connection indicator lives in the
                // global `RelayStatusBar` strip above the nav bar
                // (ContentView), so it stays visible inside chats,
                // inside Profile, inside Settings — one canonical
                // place. The principal slot stays clean and the
                // wordmark sits centred regardless of relay state.
                // `.navigationTitle("Pizzini")` below drives the
                // back-button label on pushed surfaces (ChatView,
                // GroupChatView).
                HStack(spacing: 6) {
                    Image("AppLogo")
                        .resizable()
                        .interpolation(.high)
                        .aspectRatio(contentMode: .fit)
                        .frame(width: 24, height: 24)
                        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                        .accessibilityHidden(true)
                    Text("Pizzini")
                        .font(.headline)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Pizzini")
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    searchActive = true
                    searchFocused = true
                } label: {
                    Image(systemName: "magnifyingglass")
                }
                .accessibilityLabel("Search chats and messages")
            }
        }
    }

    // ─── Custom search bar ─────────────────────────────────────────────
    // Rolled our own rather than `.searchable` because that modifier's
    // `isPresented` binding controls focus, NOT visibility — its nav-
    // bar drawer field stays mounted regardless. This bar only exists
    // in the view tree when `searchActive` is true, so on first
    // launch the chat list opens to a clean top edge.
    private var customSearchBar: some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search chats and messages", text: $searchQuery)
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
                searchActive = false
                searchQuery = ""
                searchFocused = false
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color(.systemBackground))
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
                    onRevealMyQR()
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
            // 1) Pending invitations always pin to the top — they
            //    need an explicit user decision before the group
            //    becomes a normal chat surface. Inline Accept /
            //    Decline buttons; no nested navigation required.
            if !pendingInvitations.isEmpty {
                Section("Invitations") {
                    ForEach(pendingInvitations) { group in
                        InvitationRow(group: group, store: store)
                    }
                }
            }

            // 2) Then contacts and groups, in user-configured order.
            //    When only one section has rows (and no invitations
            //    either), render its rows without a header so the
            //    list doesn't waste a band of empty space at the
            //    top of the view.
            let multipleSections = !pendingInvitations.isEmpty
                || (!store.state.contacts.isEmpty && !acceptedGroups.isEmpty)

            if store.state.contactsBeforeGroups {
                renderContacts(withHeader: multipleSections)
                renderGroups(withHeader: multipleSections)
            } else {
                renderGroups(withHeader: multipleSections)
                renderContacts(withHeader: multipleSections)
            }
        }
        .listStyle(.plain)
        .sheet(isPresented: $showNewGroupSheet) {
            NewGroupSheet(store: store, onDismiss: { showNewGroupSheet = false })
        }
    }

    @ViewBuilder
    private func renderContacts(withHeader: Bool) -> some View {
        if !store.state.contacts.isEmpty {
            if withHeader {
                Section("Contacts") { contactsRows }
            } else {
                contactsRows
            }
        }
    }

    @ViewBuilder
    private func renderGroups(withHeader: Bool) -> some View {
        if !acceptedGroups.isEmpty {
            if withHeader {
                Section("Groups") { groupsRows }
            } else {
                groupsRows
            }
        }
    }

    @ViewBuilder
    private var contactsRows: some View {
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

    @ViewBuilder
    private var groupsRows: some View {
        ForEach(sortedGroups) { group in
            NavigationLink {
                GroupChatView(store: store, groupID: group.id)
            } label: {
                GroupRow(group: group, store: store)
            }
        }
    }

    /// Pending invitations pinned to the top — sorted by group name
    /// for stable ordering across re-renders.
    private var pendingInvitations: [ChatGroup] {
        store.state.groups
            .filter { $0.pendingInvitation }
            .sorted { $0.displayName < $1.displayName }
    }

    /// Groups the user has actually joined — pending invitations
    /// are filtered out and shown in their dedicated section.
    private var acceptedGroups: [ChatGroup] {
        store.state.groups.filter { !$0.pendingInvitation }
    }

    private var sortedGroups: [ChatGroup] {
        acceptedGroups.sorted { lhs, rhs in
            switch (lhs.lastMessageAt, rhs.lastMessageAt) {
            case let (l?, r?): return l > r
            case (_?, nil): return true
            case (nil, _?): return false
            case (nil, nil): return lhs.displayName < rhs.displayName
            }
        }
    }

    // Relay connection status used to render here as an inline
    // toolbar pill (the now-removed `relayBadge`). It moved to a
    // global `RelayStatusBar` strip above the nav bar in ContentView
    // — same signal, but visible inside chats / Profile / Settings
    // too instead of only on this screen. Keep that strip the single
    // source of truth for connection state.
}

private struct ContactRow: View {
    let contact: Contact

    var body: some View {
        HStack(spacing: 12) {
            // Leading icon mirrors the group row's three-people
            // glyph at the same size + accent colour, so the eye
            // reads contacts and groups as siblings of one list.
            // No status dot — a solid coloured circle next to a
            // contact's name reads as a presence/online indicator
            // in every other messenger, and Pizzini deliberately
            // doesn't leak that. Handshake-pending state is shown
            // by an explicit hourglass + caption instead.
            Image(systemName: "person.fill")
                .font(.title3)
                .foregroundStyle(Color.accentColor)
                .frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    if !contact.sessionEstablished {
                        Image(systemName: "hourglass")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .accessibilityLabel("waiting for handshake")
                    }
                    Text(contact.displayName)
                        // Always semibold, parity with `GroupRow.displayName`.
                        // The unread cue isn't lost — `unreadBadge` (the
                        // accent-coloured capsule with count) on the trailing
                        // edge still distinguishes unread rows; the bold
                        // contact name is a hierarchy cue (this row's TITLE)
                        // rather than a state cue (read / unread).
                        .font(.body.weight(.semibold))
                    verificationBadge
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

    /// Small in-line glyph next to the display name reflecting the
    /// `ContactVerificationState`. Verified state gets a green check
    /// seal that is the load-bearing reassurance for users scanning
    /// the list. Unverified states use distinct colours and shapes so
    /// red/green colour-blind users still see a glyph difference.
    /// Tap target is intentionally absent — the row itself navigates
    /// into the chat, where the banner offers the action.
    @ViewBuilder
    private var verificationBadge: some View {
        switch contact.verificationState {
        case .verified:
            Image(systemName: "checkmark.seal.fill")
                .font(.caption)
                .foregroundStyle(.green)
                .accessibilityLabel("verified")
        case .scannedUnverified:
            Image(systemName: "checkmark.shield")
                .font(.caption)
                .foregroundStyle(.orange)
                .accessibilityLabel("scanned but not safety-number verified")
        case .pastedUnverified:
            Image(systemName: "exclamationmark.shield.fill")
                .font(.caption)
                .foregroundStyle(.red)
                .accessibilityLabel("pasted identity, not verified — open chat to verify")
        }
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

/// One row for a group on the contacts list. Mirrors `ContactRow`'s
/// shape so the user reads the two surfaces with the same eye:
/// title (with optional pending hourglass), one-line preview of the
/// most-recent log entry. We intentionally do NOT render member
/// fingerprints / member counts / "online" indicators on the row —
/// presence and member identity belong on the group's settings
/// screen, not the list.
///
/// Takes a `store` reference so the preview prefix renders the
/// sender's *current* contact display name (audit MEDIUM-7) — a
/// rename in the contacts list immediately propagates to every
/// historical group preview without rewriting `log.text`.
private struct GroupRow: View {
    let group: ChatGroup
    let store: ChatStore

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "person.3.fill")
                .font(.title3)
                .foregroundStyle(Color.accentColor)
                .frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    if group.activeMembers.contains(where: { $0.status == .pendingSKDM }) {
                        Image(systemName: "hourglass")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .accessibilityLabel("waiting for keys to exchange")
                    }
                    Text(group.displayName)
                        .font(.body.weight(.semibold))
                }
                if let last = group.log.last {
                    Text(preview(last))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                } else {
                    Text("\(group.activeMembers.count) members — no messages yet")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 8)
        }
        .padding(.vertical, 4)
    }

    private func preview(_ msg: PersistedMessage) -> String {
        switch msg.kind {
        case .system: return msg.text
        case .preKey, .whisper, .attachment:
            switch msg.side {
            case .me:
                return "you: \(msg.text)"
            case .peer:
                if let peerId = msg.senderPeerId {
                    return "\(store.memberDisplayName(peerId, in: group)): \(msg.text)"
                }
                return msg.text
            }
        }
    }
}

/// Inline accept/decline row for a pending group invitation. Lives
/// in the contacts list's "Invitations" section so the user doesn't
/// have to navigate into a detail view to make their choice.
///
/// Long-press → context menu with "View members" pushes the
/// `GroupInvitationView` for users who want a fuller inspection
/// before deciding (member roster + verification captions).
private struct InvitationRow: View {
    let group: ChatGroup
    let store: ChatStore

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                Image(systemName: "envelope.badge")
                    .font(.title3)
                    .foregroundStyle(Color.orange)
                    .frame(width: 28)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(group.displayName)
                        .font(.body.weight(.semibold))
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 8)
            }
            HStack(spacing: 10) {
                Spacer()
                Button {
                    store.declineGroupInvitation(groupId: group.id)
                } label: {
                    Text("Decline")
                        .frame(minWidth: 70)
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .tint(.red)
                Button {
                    store.acceptGroupInvitation(groupId: group.id)
                } label: {
                    Text("Accept")
                        .frame(minWidth: 70)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }
        }
        .padding(.vertical, 4)
        .contextMenu {
            NavigationLink {
                GroupInvitationView(store: store, groupID: group.id)
            } label: {
                Label("View members", systemImage: "person.2")
            }
        }
    }

    private var subtitle: String {
        let memberCount = group.activeMembers.count
        let memberSuffix = "\(memberCount) member\(memberCount == 1 ? "" : "s")"
        guard let myCard = store.myCard,
              let myRow = group.members.first(where: { $0.peerId == myCard.peerId }),
              let addedBy = myRow.addedBy
        else { return memberSuffix }
        if let contact = store.state.contacts.first(where: { $0.identityPub == addedBy }) {
            return "invited by \(contact.displayName) — \(memberSuffix)"
        }
        return memberSuffix
    }
}
