import SwiftUI

/// Accept / decline UI for a group invitation. Reached by tapping a
/// group with `pendingInvitation == true` from the contacts list, in
/// place of `GroupChatView`.
///
/// Shows: group name, who invited me (with verification status),
/// the member roster (each row labelled "verified 1:1" or "added by
/// X — not verified in person"), and Join / Decline buttons.
///
/// Honest UX:
///
/// * The "Decline" copy says exactly what decline does — drops the
///   invitation from this device. We can't tell other members our
///   answer (peer-to-peer can't enforce removal at the other end);
///   from their view we stay `.pendingSKDM` until an admin removes
///   us or the group rotates and they manually clean up.
/// * The "Join" copy explains that joining mints + broadcasts a
///   sender-key chain. Members who haven't sent us their SKDMs yet
///   will appear with hourglasses while the SKDM round-trip
///   finishes.
struct GroupInvitationView: View {
    @Bindable var store: ChatStore
    let groupID: Data

    @State private var showDeclineConfirm = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section {
                if let group {
                    LabeledContent("Group", value: group.displayName)
                    LabeledContent("Members", value: "\(group.activeMembers.count)")
                    if let inviterName {
                        LabeledContent("Invited by", value: inviterName)
                    }
                }
            } header: {
                Text("Invitation")
            } footer: {
                Text("You were added to this group by an admin you've QR-paired with. Joining mints a sender-key chain on this device and broadcasts it to the other members so they can decrypt your messages.")
            }

            membersSection

            if invitationRevoked {
                Section {
                    Text("This invitation is no longer valid — the admin removed you from the group while you were deciding.")
                        .font(.callout)
                        .foregroundStyle(.red)
                    Button(role: .destructive) {
                        store.declineGroupInvitation(groupId: groupID)
                        dismiss()
                    } label: {
                        Label("Dismiss", systemImage: "xmark.circle")
                    }
                }
            } else {
                Section {
                    Button {
                        if store.acceptGroupInvitation(groupId: groupID) {
                            // Stay on this view — `onChange(of: pendingInvitation)`
                            // dismisses us once the host clears the flag.
                        }
                    } label: {
                        Label("Join group", systemImage: "person.badge.plus")
                    }
                    Button(role: .destructive) {
                        showDeclineConfirm = true
                    } label: {
                        Label("Decline", systemImage: "person.fill.xmark")
                    }
                }
            }
        }
        .navigationTitle("Group invitation")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog(
            "Decline this invitation?",
            isPresented: $showDeclineConfirm,
            titleVisibility: .visible,
        ) {
            Button("Decline", role: .destructive) {
                store.declineGroupInvitation(groupId: groupID)
                dismiss()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The group disappears from this device. Other members may keep showing you as pending until the admin removes you.")
        }
        .onChange(of: group?.pendingInvitation) { _, isPending in
            // Once the host clears the flag (Join succeeded), we're
            // no longer the right view for this group — pop and let
            // the contacts list re-route to GroupChatView on next
            // tap. dismiss() pops us; the user lands on the contacts
            // list, where a fresh tap on the group row navigates to
            // chat.
            if isPending == false { dismiss() }
        }
        .onChange(of: group?.id) { _, newId in
            // Group disappeared (declined or revoked).
            if newId == nil { dismiss() }
        }
    }

    private var group: ChatGroup? {
        store.state.groups.first(where: { $0.id == groupID })
    }

    /// True when the admin removed the local user while we were
    /// deciding — the invitation is no longer actionable.
    private var invitationRevoked: Bool {
        guard let group, let myCard = store.myCard else { return false }
        return !group.activeMembers.contains(where: { $0.peerId == myCard.peerId })
    }

    /// Display name of the admin who invited us (the operator on the
    /// `addedBy` field of our own member row), resolved through the
    /// 1:1-contact list. "another admin" if we somehow can't resolve.
    private var inviterName: String? {
        guard let group, let myCard = store.myCard else { return nil }
        guard let myRow = group.members.first(where: { $0.peerId == myCard.peerId }),
              let addedBy = myRow.addedBy
        else { return nil }
        if let contact = store.state.contacts.first(where: { $0.identityPub == addedBy }) {
            return contact.displayName
        }
        return "another admin"
    }

    @ViewBuilder
    private var membersSection: some View {
        if let group {
            Section("Members") {
                ForEach(group.activeMembers) { member in
                    memberRow(member, in: group)
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

    private func verificationCaption(for member: GroupMember, in group: ChatGroup) -> String? {
        guard let myCard = store.myCard else { return nil }
        if member.peerId == myCard.peerId { return nil }
        if store.state.contacts.contains(where: { $0.identityPub == member.peerId }) {
            return "verified 1:1"
        }
        let inserterName = member.addedBy.flatMap { addedBy -> String? in
            if addedBy == myCard.peerId { return "you" }
            if let contact = store.state.contacts.first(where: { $0.identityPub == addedBy }) {
                return contact.displayName
            }
            return nil
        }
        if let inserterName {
            return "added by \(inserterName) — not verified in person"
        }
        return "not verified in person"
    }
}
