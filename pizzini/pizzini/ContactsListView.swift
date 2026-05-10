import PizziniCryptoCore
import SwiftUI
import UIKit

struct ContactsListView: View {
    @Bindable var store: ChatStore
    @Binding var showScanner: Bool
    @Binding var showMyQR: Bool
    let onPasteContact: (String) -> Void

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

    /// True when the user typed something searchable (non-blank).
    /// Computed rather than stored so a programmatic mutation to
    /// `searchQuery` flips this through `body` without a second
    /// `onChange` hop.
    private var isSearching: Bool {
        !searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        ZStack {
            if isSearching {
                // Global search swap: replace the normal list with
                // the search-results surface. SwiftUI's `.searchable`
                // (applied below) renders the search bar in the nav
                // bar drawer above this view — the user types there,
                // we re-render here. Keeps the search keyboard / cancel
                // button / focus-state owned by SwiftUI's nav-bar
                // search machinery rather than something we own
                // manually.
                SearchResultsView(store: store, query: searchQuery)
            } else if store.state.contacts.isEmpty, store.state.groups.isEmpty {
                emptyState
            } else {
                list
            }
        }
        // Hide the contacts list when iOS reports a screen recording
        // or external display. The toolbar above stays interactive so
        // a user who triggered Control-Centre Record by mistake can
        // still navigate out / open Settings to disable recording.
        .screenCaptureShielded()
        // Global search across every chat log + chat name. Lives on
        // the root contacts list so it's reachable from anywhere via
        // the nav-stack drag-down gesture. The placement explicitly
        // hoists it INTO the nav bar drawer (default on iOS) so the
        // search field reads as part of the list's nav chrome rather
        // than a body element.
        .searchable(
            text: $searchQuery,
            placement: .navigationBarDrawer(displayMode: .automatic),
            prompt: Text("Search chats and messages"),
        )
        // Default-disable autocorrect on the search field. A user
        // searching "alice" doesn't want iOS to helpfully replace it
        // with "slice" — and an activist searching for a sensitive
        // keyword doesn't want it landing in the system's keyboard-
        // learning cache where another app or a forensic extract
        // would find it. Same posture as the chat composer.
        .autocorrectionDisabled(true)
        .textInputAutocapitalization(.never)
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
                relayBadge
            }
            ToolbarItem(placement: .topBarTrailing) {
                NavigationLink {
                    SettingsView(store: store)
                } label: {
                    Image(systemName: "gearshape")
                }
                .accessibilityLabel("Settings")
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
