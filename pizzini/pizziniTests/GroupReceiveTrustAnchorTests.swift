import Foundation
import PizziniCryptoCore
import PizziniDB
import Testing
@testable import pizzini

/// Host-level coverage for the receive-side trust-anchor gates that
/// stop a malicious paired peer from forging a group invitation as a
/// third party. `GroupApplyTests` / `GroupBootstrapTests` exercise the
/// apply state machine, the codec, and the signature primitive — but
/// nothing tested the gates that actually live in
/// `ChatStore.handleGroupOp` / `ChatStore.handleGroupBootstrap`. These
/// are the checks a refactor of `ChatStoreGroups` could quietly drop
/// without any existing test going red.
///
/// Scope note: `handleGroupBootstrap`'s gates only require a non-nil
/// `myCard`, so they are exercised end-to-end here against a real
/// `ChatStore` backed by a `_bootstrapForTesting` SQLCipher store. The
/// `handleGroupOp` Create path additionally guards on
/// `!readyRelays.isEmpty` (a connected relay) at function entry, and
/// `RelayClient.state` is `private(set)` with no test seam — so the
/// Create-path gates cannot be driven to their trust-anchor checks
/// from a pure unit test today. The bootstrap path covers the
/// equivalent three forgery vectors (sender ≠ operator, operator not
/// in 1:1 contacts, operator not an active admin in its own snapshot).
@MainActor
@Suite("Group receive-side trust anchors")
struct GroupReceiveTrustAnchorTests {

    /// Build a `ChatStore` backed by a fresh in-memory-ish SQLCipher
    /// store so `loadOrCreateSession()` mints a real local identity
    /// and `myCard` is non-nil — the only precondition
    /// `handleGroupBootstrap` needs.
    private func freshStore() throws -> ChatStore {
        SQLiteStorage._resetForTesting()
        let path = NSTemporaryDirectory() + "pizzini-grp-trust-\(UUID()).sqlite"
        _ = try SQLiteStorage._bootstrapForTesting(
            path: path,
            rawKey: Data(repeating: 0xC3, count: 32),
        )
        return ChatStore()
    }

    /// Real, signed `GroupBootstrap` produced by `signer`. `members`
    /// is `(peerId, role, status)`; `addedBy` is stamped to the signer.
    private func signedBootstrap(
        by signer: Session,
        operatorIdentity: Data,
        members specs: [(Data, GroupRole, MemberStatus)],
        groupId: Data = Data(repeating: 0xAA, count: 16),
    ) throws -> GroupBootstrap {
        let signerId = try signer.identityPublic()
        let members = specs.map { peerId, role, status in
            GroupMember(
                peerId: peerId, displayName: "n", role: role,
                joinedAtEpoch: 0, status: status, addedBy: signerId,
            )
        }
        let unsigned = GroupBootstrap(
            groupId: groupId, displayName: "field-team", members: members,
            currentEpoch: 0, lastOpDigest: Data(repeating: 0xBB, count: 32),
            operatorIdentity: operatorIdentity, timestampMillis: 1_700_000_000_000,
            memberSetRoot: ChatGroup.memberSetRoot(of: members),
            signature: Data(repeating: 0, count: GroupOp.signatureSize),
        )
        let header = try unsigned.encodedHeader()
        let sig = try signer.identitySign(
            header, contextTag: Session.SignatureContext.groupBootstrap,
        )
        return GroupBootstrap.signed(
            groupId: unsigned.groupId, displayName: unsigned.displayName,
            members: unsigned.members, currentEpoch: unsigned.currentEpoch,
            lastOpDigest: unsigned.lastOpDigest,
            operatorIdentity: unsigned.operatorIdentity,
            timestampMillis: unsigned.timestampMillis,
            memberSetRoot: unsigned.memberSetRoot,
            signature: sig,
        )
    }

    /// (a) A bootstrap forwarded by someone OTHER than the operator is
    /// rejected — forwarding a group invitation is not allowed, so a
    /// malicious paired peer cannot relay an admin's snapshot and have
    /// the victim join a group the admin never invited them to.
    @Test("bootstrap forwarded by a non-operator is rejected")
    func bootstrapForwardingRejected() throws {
        let store = try freshStore()
        let me = try #require(store.myCard?.peerId)

        let admin = try Session()
        let adminId = try admin.identityPublic()
        let forwarder = try Session()
        let forwarderId = try forwarder.identityPublic()

        // Both the admin (real operator) and the forwarder are in 1:1
        // contacts — so the ONLY thing that should stop the join is
        // the sender ≠ operator gate.
        store.state.contacts.append(
            Contact(identityPub: adminId, displayName: "admin", addedVia: .qrScan))
        store.state.contacts.append(
            Contact(identityPub: forwarderId, displayName: "fwd", addedVia: .qrScan))

        let bootstrap = try signedBootstrap(
            by: admin, operatorIdentity: adminId,
            members: [(adminId, .admin, .active), (me, .member, .active)])
        let payload = GroupEnvelope.encodeBootstrap(
            groupId: bootstrap.groupId, bootstrapBytes: try bootstrap.encoded())

        // `forwarderId` is the wire-level sender, not the operator.
        store.handleGroupBootstrap(payload: payload, fromPeer: forwarderId)
        #expect(store.state.groups.isEmpty, "a forwarded bootstrap must not create a group")
    }

    /// (b) A bootstrap whose operator is not in the local 1:1 contacts
    /// is rejected — the trust anchor for a group invitation is a
    /// 1:1-paired peer; a snapshot signed by a stranger must not
    /// bootstrap a group even though its signature verifies.
    @Test("bootstrap from an operator not in 1:1 contacts is rejected")
    func bootstrapUnknownOperatorRejected() throws {
        let store = try freshStore()
        let me = try #require(store.myCard?.peerId)

        let stranger = try Session()
        let strangerId = try stranger.identityPublic()
        // Deliberately do NOT add `stranger` to contacts.

        let bootstrap = try signedBootstrap(
            by: stranger, operatorIdentity: strangerId,
            members: [(strangerId, .admin, .active), (me, .member, .active)])
        let payload = GroupEnvelope.encodeBootstrap(
            groupId: bootstrap.groupId, bootstrapBytes: try bootstrap.encoded())

        store.handleGroupBootstrap(payload: payload, fromPeer: strangerId)
        #expect(store.state.groups.isEmpty,
                "a bootstrap from a non-contact operator must not create a group")
    }

    /// (c) A bootstrap whose operator is NOT an active admin in its own
    /// member list is rejected — an operator that signs a snapshot in
    /// which they are only a plain member (or absent) had no authority
    /// to issue it.
    @Test("bootstrap whose operator is not an active admin in its own snapshot is rejected")
    func bootstrapOperatorNotAdminRejected() throws {
        let store = try freshStore()
        let me = try #require(store.myCard?.peerId)

        let signer = try Session()
        let signerId = try signer.identityPublic()
        // Signer IS a 1:1 contact and IS the wire sender + operator —
        // the only failing gate is "operator is not an active admin in
        // the snapshot": here the signer lists themselves as a plain
        // `.member`.
        store.state.contacts.append(
            Contact(identityPub: signerId, displayName: "op", addedVia: .qrScan))

        let bootstrap = try signedBootstrap(
            by: signer, operatorIdentity: signerId,
            members: [(signerId, .member, .active), (me, .member, .active)])
        let payload = GroupEnvelope.encodeBootstrap(
            groupId: bootstrap.groupId, bootstrapBytes: try bootstrap.encoded())

        store.handleGroupBootstrap(payload: payload, fromPeer: signerId)
        #expect(store.state.groups.isEmpty,
                "a bootstrap whose operator is not an active admin must not create a group")
    }

    /// Positive control: a well-formed bootstrap from a 1:1-contact
    /// admin who IS an active admin in its own snapshot, with the local
    /// user in the member list, DOES create a (pending-invitation)
    /// group — so the rejection tests above are catching the trust
    /// anchors specifically, not a blanket "bootstrap never works."
    @Test("a well-formed bootstrap from a contact admin creates a pending-invitation group")
    func wellFormedBootstrapAccepted() throws {
        let store = try freshStore()
        let me = try #require(store.myCard?.peerId)

        let admin = try Session()
        let adminId = try admin.identityPublic()
        store.state.contacts.append(
            Contact(identityPub: adminId, displayName: "admin", addedVia: .qrScan))

        let bootstrap = try signedBootstrap(
            by: admin, operatorIdentity: adminId,
            members: [(adminId, .admin, .active), (me, .member, .active)])
        let payload = GroupEnvelope.encodeBootstrap(
            groupId: bootstrap.groupId, bootstrapBytes: try bootstrap.encoded())

        store.handleGroupBootstrap(payload: payload, fromPeer: adminId)
        #expect(store.state.groups.count == 1)
        #expect(store.state.groups.first?.pendingInvitation == true)
    }
}
