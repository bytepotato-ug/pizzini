import Foundation
import PizziniCryptoCore
import Testing
@testable import pizzini

/// Pending-invitation tests for the receive-side bootstrap path.
/// Closes the auto-join gap: a `Create` op or `GroupBootstrap` no
/// longer auto-enrols the local user — they land in the group as a
/// `pendingInvitation` and the user must tap Join (or Decline) to
/// proceed.

@Suite("ChatGroup invitation state")
struct ChatGroupInvitationTests {
    @Test("ChatGroup.create defaults pendingInvitation to true (receive-side bootstrap)")
    func createDefaultsToPending() throws {
        let alice = try Session()
        let bob = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let op = try realSignedCreate(
            by: alice,
            groupId: Data(repeating: 0xAA, count: 16),
            name: "g",
            members: [(aliceId, .admin, "A"), (bobId, .member, "B")])
        let signed = try op.encoded()
        let group = try #require(ChatGroup.create(
            fromCreate: op, signedBytes: signed, localIdentityPub: bobId))
        #expect(group.pendingInvitation == true)
        // No chain yet — accepting will mint one.
        #expect(group.myCurrentDistributionId == nil)
        #expect(group.mySkdmRecipients.isEmpty)
    }

    @Test("GroupBootstrap.intoChatGroup defaults pendingInvitation to true")
    func bootstrapIntoGroupDefaultsToPending() throws {
        let alice = try Session()
        let aliceId = try alice.identityPublic()
        let bob = try Session()
        let bobId = try bob.identityPublic()
        let bootstrapMembers = [
            GroupMember(peerId: aliceId, displayName: "A", role: .admin,
                        joinedAtEpoch: 0, status: .active, addedBy: aliceId),
            GroupMember(peerId: bobId, displayName: "B", role: .member,
                        joinedAtEpoch: 0, status: .pendingSKDM, addedBy: aliceId),
        ]
        let bootstrap = GroupBootstrap(
            groupId: Data(repeating: 0xAA, count: 16),
            displayName: "g",
            members: bootstrapMembers,
            currentEpoch: 0,
            lastOpDigest: Data(repeating: 0xBB, count: 32),
            operatorIdentity: aliceId,
            timestampMillis: 1,
            memberSetRoot: ChatGroup.memberSetRoot(of: bootstrapMembers),
            signature: Data(repeating: 0, count: GroupOp.signatureSize))
        let group = try #require(bootstrap.intoChatGroup(localIdentityPub: bobId))
        #expect(group.pendingInvitation == true)
    }

    @Test("a pending-invitation ChatGroup round-trips through JSONEncoder/JSONDecoder")
    func pendingFieldRoundTrips() throws {
        let alice = Data(repeating: 0x01, count: 33)
        let group = ChatGroup(
            id: Data(repeating: 0xAA, count: 16),
            displayName: "g",
            members: [GroupMember(peerId: alice, displayName: "A", role: .admin,
                                  joinedAtEpoch: 0, status: .active)],
            createdAt: Date(timeIntervalSince1970: 0),
            currentEpoch: 0,
            lastOpDigest: Data(repeating: 0, count: 32),
            pendingOps: [],
            log: [],
            lastSeenAt: nil,
            lastMessageAt: nil,
            myCurrentDistributionId: nil,
            memberDistributionIds: [:],
            sentSinceRotation: 0,
            lastRotatedAt: Date(timeIntervalSince1970: 0),
            mySkdmRecipients: [],
            recentOpDigests: [:],
            pendingInvitation: true)
        let bytes = try JSONEncoder().encode(group)
        let decoded = try JSONDecoder().decode(ChatGroup.self, from: bytes)
        #expect(decoded.pendingInvitation == true)
    }

    @Test("legacy ChatGroup blob (no pendingInvitation key) decodes to false")
    func legacyDecodeDefaultsToFalse() throws {
        // Pre-invitation-flow blob — no `pendingInvitation` key.
        // Decoder defaults the field to false so existing groups
        // continue to behave exactly as before (auto-joined). The
        // base64 fields below were generated from a real ChatGroup
        // round-trip; tweaking them is fine for the field-default
        // sanity check.
        let json = #"""
        {
            "id": "qqqqqqqqqqqqqqqqqqqqqg==",
            "displayName": "legacy",
            "members": [
                {
                    "peerId": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                    "displayName": "alice",
                    "role": "admin",
                    "joinedAtEpoch": 0,
                    "status": "active"
                }
            ],
            "createdAt": 0,
            "currentEpoch": 0,
            "lastOpDigest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "pendingOps": [],
            "log": [],
            "memberDistributionIds": [],
            "sentSinceRotation": 0,
            "lastRotatedAt": 0,
            "recentOpDigests": {}
        }
        """#
        let data = Data(json.utf8)
        let decoded = try JSONDecoder().decode(ChatGroup.self, from: data)
        #expect(decoded.pendingInvitation == false,
                "pre-invitation-flow blobs must not auto-mark themselves pending")
    }

    @Test("apply on a pending group still mutates membership state (admin's broadcasts stay in sync)")
    func applyKeepsPendingGroupInSync() throws {
        // While the invitation is pending we still want subsequent
        // ops from the admin to apply — so when the user accepts,
        // their local ChatGroup matches the canonical chain.
        let alice = try Session()
        let bob = try Session()
        let carol = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let carolId = try carol.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)
        let createOp = try realSignedCreate(
            by: alice, groupId: groupId, name: "g",
            members: [(aliceId, .admin, "A"), (bobId, .member, "B")])
        let signed = try createOp.encoded()
        var group = try #require(ChatGroup.create(
            fromCreate: createOp, signedBytes: signed, localIdentityPub: bobId))
        #expect(group.pendingInvitation == true)
        // Admin adds Carol while Bob's invitation is pending.
        let addCarol = try realSignedOp(
            by: alice, groupId: groupId,
            epoch: group.currentEpoch + 1, parent: group.lastOpDigest,
            kind: .addMember(peerId: carolId, role: .member, displayName: "C"),
            priorMemberSetRoot: group.memberSetRoot)
        if case .applied = group.apply(addCarol) {} else {
            Issue.record("AddMember apply on pending group failed")
        }
        #expect(group.activeMembers.count == 3)
        #expect(group.role(of: carolId) == .member)
        // The pending flag is unaffected by apply — only the host
        // (acceptGroupInvitation / declineGroupInvitation) clears it.
        #expect(group.pendingInvitation == true)
    }

    @Test("RemoveMember of self while pending leaves the row .removed; UI surfaces revoked state")
    func selfRemovedWhilePending() throws {
        let alice = try Session()
        let bob = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)
        let createOp = try realSignedCreate(
            by: alice, groupId: groupId, name: "g",
            members: [
                (aliceId, .admin, "A"),
                (bobId, .member, "B"),
                // need a third member so removing Bob doesn't leave
                // 0 non-admins (irrelevant) and isn't last-admin
                (Data(repeating: 0x03, count: 33), .member, "C"),
            ])
        let signed = try createOp.encoded()
        var group = try #require(ChatGroup.create(
            fromCreate: createOp, signedBytes: signed, localIdentityPub: bobId))
        let removeOp = try realSignedOp(
            by: alice, groupId: groupId,
            epoch: group.currentEpoch + 1, parent: group.lastOpDigest,
            kind: .removeMember(peerId: bobId),
            priorMemberSetRoot: group.memberSetRoot)
        var sx = ChatGroup.ApplySideEffects(localIdentityPub: bobId)
        if case .applied = group.apply(removeOp, sideEffects: &sx) {} else {
            Issue.record("RemoveMember apply failed")
        }
        // Bob's row is now .removed; activeMembers excludes him.
        #expect(group.activeMembers.contains(where: { $0.peerId == bobId }) == false)
        // Even on a pending group, the side-effect signal fires;
        // the host's `applyPostMutationSideEffects` no-ops the chain
        // clear because there's no chain to clear yet.
        #expect(sx.requestSelfChainClear == true)
    }
}
