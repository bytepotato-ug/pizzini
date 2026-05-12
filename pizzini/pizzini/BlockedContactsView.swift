import SwiftUI

/// Block-list management surface. Reachable from Settings → Privacy →
/// Blocked contacts. Lists every identityPub the user has explicitly
/// blocked, with a one-tap unblock affordance. Unlike `deleteContact`,
/// blocking persists even after the contact row is gone — this is
/// where the user reviews and lifts those persistent bans.
///
/// **Design choice — show fingerprints, not names.** A blocked identity
/// has had its contact row removed (see `ChatStore.blockIdentity`), so
/// there's no display name to show. We surface the 4-byte fingerprint
/// shorthand the diagnostics surface already uses, which is enough for
/// the user to recognise *which* block they want to lift if they
/// remember why they blocked someone in the first place. A user who
/// can't tell the entries apart probably shouldn't be unblocking them
/// without re-meeting the peer.
struct BlockedContactsView: View {
    @Bindable var store: ChatStore

    var body: some View {
        Form {
            if store.state.blockedIdentities.isEmpty {
                Section {
                    Text("No one is blocked.")
                        .foregroundStyle(.secondary)
                        .font(.callout)
                } footer: {
                    Text("Block someone from a chat's ⋯ menu. Blocking removes the contact row and refuses every future BUNDLE, TOKEN, or message from that identity — including across re-pair attempts.")
                }
            } else {
                Section {
                    ForEach(store.state.blockedIdentities, id: \.self) { id in
                        HStack {
                            Image(systemName: "hand.raised.slash.fill")
                                .foregroundStyle(.red)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(fingerprint(id))
                                    .font(.callout.monospaced())
                                Text("blocked")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Unblock") {
                                store.unblockIdentity(id)
                            }
                            .buttonStyle(.borderless)
                            .foregroundStyle(.blue)
                        }
                    }
                } footer: {
                    Text("Unblocking does not restore the previous contact. They will need to scan your QR again — or you scan theirs — to re-pair. The block list is the only thing surviving the unblock; everything else was wiped when you tapped Block.")
                }
            }
        }
        .navigationTitle("Blocked contacts")
        .navigationBarTitleDisplayMode(.inline)
    }

    /// 4-byte head + 2-byte tail of the identity-pub. Matches the
    /// shorthand used in `ChatStore.short(_:)` and the diagnostics
    /// log, so an operator who has both surfaces open can correlate
    /// "the peer I blocked" with "the peer I saw bounced in diag."
    private func fingerprint(_ id: Data) -> String {
        let head = id.prefix(4).map { String(format: "%02x", $0) }.joined()
        let tail = id.suffix(2).map { String(format: "%02x", $0) }.joined()
        return "\(head)…\(tail)"
    }
}
