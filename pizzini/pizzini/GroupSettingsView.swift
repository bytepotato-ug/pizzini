import SwiftUI

/// Settings + member management for one `ChatGroup`. Reached via the
/// gear icon in the group's chat-view toolbar.
///
/// Surfaces:
///   - Group name with admin-only inline rename.
///   - Member list with role + verification chain caption ("added by
///     X — not verified in person" if Y is not also a 1:1 contact).
///     Admins show a small badge.
///   - "Add member…" sheet (admin only) — picks from local 1:1
///     contacts not already in the group.
///   - Per-member context menu (admin only): Promote / Demote /
///     Remove with last-admin protection.
///   - "Rotate my sender key" — exposed to every active member, not
///     just admins (audit MEDIUM-3). The state machine accepts the
///     op from any active member; the UI now matches.
///   - "Leave group" with explicit confirmation. Pop-to-root flow:
///     after `leaveGroup`, the group is gone from `state.groups`;
///     `GroupChatView`'s `onChange(of:)` watcher auto-dismisses, so
///     the user lands back on the contacts list rather than on a
///     "Group missing" dead-end (audit HIGH-5).
struct GroupSettingsView: View {
    @Bindable var store: ChatStore
    let groupID: Data

    @State private var showAddMember = false
    @State private var showLeaveConfirm = false
    @State private var showRenameSheet = false
    /// Inline error banner — set by any operation that returns
    /// false from the host (e.g. last-admin demote attempt) so the
    /// user gets actionable feedback instead of silent no-ops
    /// (audit MEDIUM-4).
    @State private var errorMessage: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section("Group") {
                if let group {
                    HStack {
                        LabeledContent("Name", value: group.displayName)
                        if isAdmin {
                            Button {
                                showRenameSheet = true
                            } label: {
                                Image(systemName: "pencil")
                            }
                            .buttonStyle(.borderless)
                            .accessibilityLabel("Rename group")
                        }
                    }
                    LabeledContent("Members", value: "\(group.activeMembers.count)")
                    LabeledContent("Created", value: group.createdAt.formatted(date: .abbreviated, time: .omitted))
                }
            }
            if let errorMessage {
                Section {
                    Text(errorMessage)
                        .font(.callout)
                        .foregroundStyle(.red)
                }
            }
            membersSection
            if amStillActive {
                Section {
                    Button {
                        store.rotateMyGroupChain(groupId: groupID)
                    } label: {
                        Label("Rotate my sender key now", systemImage: "arrow.triangle.2.circlepath")
                    }
                    if anyMemberPendingSKDM {
                        Button {
                            if !store.resendMyKeys(groupId: groupID) {
                                errorMessage = "Couldn't resend keys. Try again."
                            } else {
                                errorMessage = nil
                            }
                        } label: {
                            Label("Resend my key to members waiting",
                                  systemImage: "paperplane")
                        }
                    }
                } header: {
                    Text("Sender-key hygiene")
                } footer: {
                    if anyMemberPendingSKDM {
                        Text("Members with the hourglass haven't received your sender key yet — usually a relay-delivery hiccup. \"Resend\" pushes your current chain again without rotating; \"Rotate\" mints a fresh chain (use this if you suspect this device is compromised).")
                    } else {
                        Text("Generates a fresh chain and broadcasts it to remaining members. Bounds the post-compromise window if you suspect this device is compromised.")
                    }
                }
            }
            Section {
                Button(role: .destructive) {
                    showLeaveConfirm = true
                } label: {
                    Label("Leave group", systemImage: "rectangle.portrait.and.arrow.right")
                }
            } footer: {
                Text("Removes the group from this device only. Leaving rotates your sender key first so remaining members can no longer decrypt messages with the chain you abandoned. Other members still see you as a member; ask an admin to remove you to leave properly.")
            }
        }
        .navigationTitle("Group settings")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if isAdmin {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showAddMember = true
                    } label: {
                        Image(systemName: "person.badge.plus")
                    }
                    .disabled(addCandidates.isEmpty)
                }
            }
        }
        .sheet(isPresented: $showAddMember) {
            AddMemberSheet(
                store: store,
                groupID: groupID,
                candidates: addCandidates,
                onDismiss: { showAddMember = false },
            )
        }
        .sheet(isPresented: $showRenameSheet) {
            RenameGroupSheet(
                currentName: group?.displayName ?? "",
                onSave: { newName in
                    showRenameSheet = false
                    if !store.renameGroup(groupId: groupID, newName: newName) {
                        errorMessage = "Couldn't rename the group. Try again."
                    } else {
                        errorMessage = nil
                    }
                },
                onCancel: { showRenameSheet = false },
            )
        }
        // `.alert` instead of `.confirmationDialog` because the
        // dialog's iOS 26 popover-style presentation anchors to the
        // form's origin point (top of view) rather than the
        // destructive button at the bottom — the floating sheet
        // ended up far away from the action that triggered it.
        // Alerts always center, no anchor surprises.
        .alert(
            "Leave this group on this device?",
            isPresented: $showLeaveConfirm,
        ) {
            Button("Leave group", role: .destructive) {
                store.leaveGroup(groupId: groupID)
                // Pop the settings view; `GroupChatView` watches its
                // group's existence and dismisses itself when the
                // group disappears, landing the user on the contacts
                // list.
                dismiss()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The group disappears from this device. Other members keep their copy and still see you as a member until an admin removes you.")
        }
    }

    private var group: ChatGroup? {
        store.state.groups.first(where: { $0.id == groupID })
    }

    private var isAdmin: Bool {
        guard let myCard = store.myCard, let group else { return false }
        return group.role(of: myCard.peerId) == .admin
    }

    /// True when the local user is an active member (admin or
    /// member). Used to gate the Rotate button — any active member
    /// is permitted by the state machine to rotate their own chain
    /// (audit MEDIUM-3).
    private var amStillActive: Bool {
        guard let myCard = store.myCard, let group else { return false }
        return group.activeMembers.contains(where: { $0.peerId == myCard.peerId })
    }

    /// True when there is more than one active admin — drives the
    /// availability of demote / remove actions on admin rows.
    private var hasMultipleAdmins: Bool {
        guard let group else { return false }
        return group.activeMembers.filter({ $0.role == .admin }).count > 1
    }

    /// True when any active non-self member is still in
    /// `.pendingSKDM` from our point of view — the SKDM round-trip
    /// hasn't completed yet. Drives the "Resend my key" affordance.
    private var anyMemberPendingSKDM: Bool {
        guard let group, let myCard = store.myCard else { return false }
        return group.activeMembers.contains {
            $0.peerId != myCard.peerId && $0.status == .pendingSKDM
        }
    }

    private var addCandidates: [Contact] {
        guard let group else { return [] }
        let inGroup = Set(group.activeMembers.map(\.peerId))
        return store.state.contacts.filter { !inGroup.contains($0.identityPub) }
    }

    @ViewBuilder
    private var membersSection: some View {
        if let group {
            Section("Members") {
                ForEach(group.activeMembers) { member in
                    memberRow(member, in: group)
                        .swipeActions(edge: .trailing) {
                            swipeActions(for: member)
                        }
                        .contextMenu {
                            contextMenu(for: member)
                        }
                }
            }
        }
    }

    @ViewBuilder
    private func memberRow(_ member: GroupMember, in group: ChatGroup) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "person.fill")
                .foregroundStyle(member.role == .admin ? Color.accentColor : Color.secondary)
                .frame(width: 24)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(store.memberDisplayName(member.peerId, in: group))
                        .font(.body)
                    if member.role == .admin {
                        Text("admin")
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1)
                            .background(Capsule().fill(Color.accentColor.opacity(0.15)))
                    }
                    if member.status == .pendingSKDM {
                        Image(systemName: "hourglass")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .accessibilityLabel("waiting for keys")
                    }
                }
                if let caption = verificationCaption(for: member, in: group) {
                    Text(caption)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 8)
        }
    }

    /// Audit MEDIUM-2: surface "added by X — not verified in person"
    /// when the member's identity-pub isn't in our 1:1 contacts.
    private func verificationCaption(for member: GroupMember, in group: ChatGroup) -> String? {
        guard let myCard = store.myCard else { return nil }
        // The local user's row is rendered as "you" by
        // `memberDisplayName`. Adding "verified 1:1" to "you" reads
        // as nonsense — return nil for self.
        if member.peerId == myCard.peerId { return nil }
        let inserterName = member.addedBy.flatMap { addedBy -> String? in
            if addedBy == myCard.peerId { return "you" }
            if let contact = store.state.contacts.first(where: { $0.identityPub == addedBy }) {
                return contact.displayName
            }
            return nil
        }
        if store.state.contacts.contains(where: { $0.identityPub == member.peerId }) {
            return "verified 1:1"
        }
        if let inserterName {
            return "added by \(inserterName) — not verified in person"
        }
        return "added by another admin — not verified in person"
    }

    @ViewBuilder
    private func swipeActions(for member: GroupMember) -> some View {
        if isAdmin && member.peerId != store.myCard?.peerId {
            // Last-admin protection: don't expose remove on the only
            // remaining admin. The state-machine refuses anyway, but
            // hiding the affordance avoids the "tap, see error" UX.
            let isOnlyAdmin = member.role == .admin && !hasMultipleAdmins
            if !isOnlyAdmin {
                Button(role: .destructive) {
                    if !store.removeFromGroup(groupId: groupID, peerIdentity: member.peerId) {
                        errorMessage = "Couldn't remove this member. Try again."
                    } else {
                        errorMessage = nil
                    }
                } label: {
                    Label("Remove", systemImage: "person.fill.xmark")
                }
            }
        }
    }

    @ViewBuilder
    private func contextMenu(for member: GroupMember) -> some View {
        if isAdmin && member.peerId != store.myCard?.peerId {
            switch member.role {
            case .member:
                Button {
                    if !store.promoteToAdmin(groupId: groupID, peerIdentity: member.peerId) {
                        errorMessage = "Couldn't promote this member. Try again."
                    } else {
                        errorMessage = nil
                    }
                } label: {
                    Label("Promote to admin", systemImage: "crown")
                }
            case .admin:
                if hasMultipleAdmins {
                    Button {
                        if !store.demoteFromAdmin(groupId: groupID, peerIdentity: member.peerId) {
                            errorMessage = "Couldn't demote this admin. Try again."
                        } else {
                            errorMessage = nil
                        }
                    } label: {
                        Label("Demote to member", systemImage: "person.badge.minus")
                    }
                }
            }
        }
    }
}

/// Sheet listing the 1:1 contacts not already in the group, for an
/// admin to invite. Tap a row → the AddMember op signs + broadcasts
/// immediately and the sheet dismisses.
private struct AddMemberSheet: View {
    @Bindable var store: ChatStore
    let groupID: Data
    let candidates: [Contact]
    let onDismiss: () -> Void

    var body: some View {
        NavigationStack {
            List {
                if candidates.isEmpty {
                    Text("No more contacts to add — every 1:1-paired contact is already in this group, or pair more contacts first.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                ForEach(candidates) { contact in
                    Button {
                        let _ = store.inviteToGroup(groupId: groupID, contact: contact)
                        onDismiss()
                    } label: {
                        HStack {
                            Image(systemName: "person.fill.badge.plus")
                                .foregroundStyle(.tint)
                            Text(contact.displayName)
                                .foregroundStyle(.primary)
                            Spacer()
                        }
                    }
                }
            }
            .navigationTitle("Add member")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onDismiss)
                }
            }
        }
    }
}

/// Single-field sheet for renaming the group. Admin-only — the
/// caller decides whether to surface the entry point.
private struct RenameGroupSheet: View {
    let currentName: String
    let onSave: (String) -> Void
    let onCancel: () -> Void

    @State private var draft: String

    init(currentName: String, onSave: @escaping (String) -> Void, onCancel: @escaping () -> Void) {
        self.currentName = currentName
        self.onSave = onSave
        self.onCancel = onCancel
        self._draft = State(initialValue: currentName)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("New name") {
                    TextField("Group name", text: $draft)
                        .hardenedTextInput(autocap: .words)
                }
            }
            .navigationTitle("Rename group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        onSave(draft.trimmingCharacters(in: .whitespacesAndNewlines))
                    }
                    .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                        || draft == currentName)
                }
            }
        }
    }
}
