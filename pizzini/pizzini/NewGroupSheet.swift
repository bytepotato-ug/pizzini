import SwiftUI

/// Sheet to assemble a new group: name + initial members. Initial
/// members come from the user's existing 1:1 contacts — Pizzini's
/// trust model dictates that you can only add people you've already
/// QR-paired with in person. The local user is implicitly added as
/// admin; the sheet doesn't surface a "you are also in this group"
/// row because that would just be noise.
///
/// Tapping Create signs a `Create` op, mints the local sender-key
/// chain, and broadcasts the op + SKDM to every invitee via
/// `ChatStore.createGroup(name:initialContacts:)`. Errors (empty
/// name, no invitees, group cap exceeded) surface inline rather than
/// as a system alert because the disabled state of the Create button
/// already encodes them.
struct NewGroupSheet: View {
    @Bindable var store: ChatStore
    let onDismiss: () -> Void

    @State private var name: String = ""
    @State private var selected: Set<Data> = []

    var body: some View {
        NavigationStack {
            Form {
                Section("Group name") {
                    TextField("e.g. field-team", text: $name)
                        .textInputAutocapitalization(.words)
                }
                Section {
                    if store.state.contacts.isEmpty {
                        Text("Pair some contacts first — groups can only invite people you've QR-paired with in person.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(store.state.contacts) { contact in
                            Button {
                                toggle(contact.identityPub)
                            } label: {
                                HStack {
                                    Image(systemName: selected.contains(contact.identityPub)
                                        ? "checkmark.circle.fill"
                                        : "circle")
                                        .foregroundStyle(selected.contains(contact.identityPub)
                                            ? Color.accentColor
                                            : Color.secondary)
                                    Text(contact.displayName)
                                        .foregroundStyle(.primary)
                                    Spacer()
                                }
                            }
                            .buttonStyle(.plain)
                        }
                    }
                } header: {
                    Text("Members")
                } footer: {
                    Text("You're added as admin automatically. Maximum \(ChatGroup.maxMembers) members per group.")
                }
            }
            .navigationTitle("New group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onDismiss)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create", action: create)
                        .disabled(!canCreate)
                }
            }
        }
    }

    private var canCreate: Bool {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return !trimmed.isEmpty
            && !selected.isEmpty
            && (selected.count + 1) <= ChatGroup.maxMembers
    }

    private func toggle(_ id: Data) {
        if selected.contains(id) {
            selected.remove(id)
        } else {
            selected.insert(id)
        }
    }

    private func create() {
        let invitees = store.state.contacts.filter { selected.contains($0.identityPub) }
        let _ = store.createGroup(name: name, initialContacts: invitees)
        onDismiss()
    }
}
