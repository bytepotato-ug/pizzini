import Foundation
import PizziniCryptoCore
import Testing
@testable import pizzini

/// Wire-format and trust-anchor tests for `GroupBootstrap`. Covers the
/// audit-driven HIGH-7 bootstrap envelope that lets a newly-added
/// member of an existing group reconstruct local state without an
/// op-chain replay.

@Suite("GroupBootstrap codec")
struct GroupBootstrapCodecTests {
    @Test("round-trips with all member-list fields")
    func roundTrip() throws {
        let alice = try Session()
        let bob = try Session()
        let carol = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let carolId = try carol.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)
        let members: [GroupMember] = [
            GroupMember(peerId: aliceId, displayName: "Alice", role: .admin,
                        joinedAtEpoch: 0, status: .active, addedBy: aliceId),
            GroupMember(peerId: bobId, displayName: "Bob", role: .member,
                        joinedAtEpoch: 0, status: .active, addedBy: aliceId),
            GroupMember(peerId: carolId, displayName: "Carol", role: .member,
                        joinedAtEpoch: 1, status: .pendingSKDM, addedBy: aliceId),
        ]
        let bootstrap = GroupBootstrap(
            groupId: groupId,
            displayName: "field-team",
            members: members,
            currentEpoch: 1,
            lastOpDigest: Data(repeating: 0xBB, count: 32),
            operatorIdentity: aliceId,
            timestampMillis: 1_700_000_000_000,
            signature: Data(repeating: 0x00, count: GroupOp.signatureSize),
        )
        let bytes = try bootstrap.encoded()
        let decoded = try #require(GroupBootstrap.decode(bytes))
        #expect(decoded == bootstrap)
    }

    @Test("addedBy nil-vs-present round-trip")
    func addedByOptionalRoundTrip() throws {
        let alice = try Session()
        let aliceId = try alice.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)
        let members: [GroupMember] = [
            // addedBy populated.
            GroupMember(peerId: aliceId, displayName: "Alice", role: .admin,
                        joinedAtEpoch: 0, status: .active, addedBy: aliceId),
            // addedBy nil — pre-audit blob shape.
            GroupMember(peerId: Data(repeating: 0x05, count: 33), displayName: "x",
                        role: .member, joinedAtEpoch: 5, status: .removed, addedBy: nil),
        ]
        let bootstrap = GroupBootstrap(
            groupId: groupId, displayName: "g", members: members,
            currentEpoch: 5, lastOpDigest: Data(repeating: 0xBB, count: 32),
            operatorIdentity: aliceId, timestampMillis: 1,
            signature: Data(repeating: 0, count: GroupOp.signatureSize))
        let decoded = try #require(GroupBootstrap.decode(try bootstrap.encoded()))
        #expect(decoded.members[0].addedBy == aliceId)
        #expect(decoded.members[1].addedBy == nil)
    }

    @Test("rejects an unknown bootstrap-version byte")
    func rejectsBadVersion() throws {
        var bytes = try minimalBootstrap().encoded()
        bytes[0] = 0xFF
        #expect(GroupBootstrap.decode(bytes) == nil)
    }

    @Test("rejects trailing junk")
    func rejectsTrailingJunk() throws {
        var bytes = try minimalBootstrap().encoded()
        bytes.append(0xDE)
        #expect(GroupBootstrap.decode(bytes) == nil)
    }

    @Test("rejects truncated body")
    func rejectsTruncated() throws {
        var bytes = try minimalBootstrap().encoded()
        bytes.removeLast(GroupOp.signatureSize) // strip signature
        #expect(GroupBootstrap.decode(bytes) == nil)
    }

    private func minimalBootstrap() throws -> GroupBootstrap {
        let alice = try Session()
        let aliceId = try alice.identityPublic()
        let members: [GroupMember] = [
            GroupMember(peerId: aliceId, displayName: "A", role: .admin,
                        joinedAtEpoch: 0, status: .active),
        ]
        return GroupBootstrap(
            groupId: Data(repeating: 0xAA, count: 16),
            displayName: "g", members: members,
            currentEpoch: 0, lastOpDigest: Data(repeating: 0xBB, count: 32),
            operatorIdentity: aliceId, timestampMillis: 1,
            signature: Data(repeating: 0x77, count: GroupOp.signatureSize))
    }
}

@Suite("GroupBootstrap signature verification")
struct GroupBootstrapSignatureTests {
    @Test("a real signature verifies against the operator's identity-public")
    func validSignature() throws {
        let alice = try Session()
        let aliceId = try alice.identityPublic()
        let bob = try Session()
        let bobId = try bob.identityPublic()
        let bootstrap = try realSignedBootstrap(
            by: alice, members: [
                (aliceId, .admin, .active),
                (bobId, .member, .pendingSKDM),
            ])
        #expect(try bootstrap.verifySignature() == true)
    }

    @Test("a flipped header bit breaks verification")
    func tamperedHeader() throws {
        let alice = try Session()
        let aliceId = try alice.identityPublic()
        let original = try realSignedBootstrap(
            by: alice, members: [(aliceId, .admin, .active)])
        var bytes = try original.encoded()
        // Flip a bit in the header (avoid the trailing 64-byte signature).
        bytes[1] ^= 0x01
        let tampered = try #require(GroupBootstrap.decode(bytes))
        #expect(try tampered.verifySignature() == false)
    }

    @Test("signing as Alice but claiming Bob fails to verify")
    func wrongSigner() throws {
        let alice = try Session()
        let bob = try Session()
        let bobId = try bob.identityPublic()
        // Build a bootstrap header claiming Bob, sign with Alice.
        let unsigned = GroupBootstrap(
            groupId: Data(repeating: 0xAA, count: 16),
            displayName: "g",
            members: [GroupMember(peerId: bobId, displayName: "B", role: .admin,
                                  joinedAtEpoch: 0, status: .active)],
            currentEpoch: 0, lastOpDigest: Data(repeating: 0xBB, count: 32),
            operatorIdentity: bobId, timestampMillis: 1,
            signature: Data(repeating: 0, count: GroupOp.signatureSize))
        let header = try unsigned.encodedHeader()
        let aliceSig = try alice.identitySign(header)
        let tampered = GroupBootstrap.signed(
            groupId: unsigned.groupId, displayName: unsigned.displayName,
            members: unsigned.members, currentEpoch: unsigned.currentEpoch,
            lastOpDigest: unsigned.lastOpDigest,
            operatorIdentity: unsigned.operatorIdentity,
            timestampMillis: unsigned.timestampMillis, signature: aliceSig)
        #expect(try tampered.verifySignature() == false)
    }
}

@Suite("GroupBootstrap intoChatGroup")
struct GroupBootstrapProjectionTests {
    @Test("projects to a ChatGroup with all fields populated")
    func projectsToChatGroup() throws {
        let alice = try Session()
        let aliceId = try alice.identityPublic()
        let bob = try Session()
        let bobId = try bob.identityPublic()
        let bootstrap = try realSignedBootstrap(
            by: alice, members: [
                (aliceId, .admin, .active),
                (bobId, .member, .pendingSKDM),
            ])
        let group = try #require(bootstrap.intoChatGroup(localIdentityPub: bobId))
        #expect(group.id == bootstrap.groupId)
        #expect(group.displayName == bootstrap.displayName)
        #expect(group.currentEpoch == bootstrap.currentEpoch)
        #expect(group.lastOpDigest == bootstrap.lastOpDigest)
        #expect(group.activeMembers.count == 2)
        #expect(group.role(of: aliceId) == .admin)
        #expect(group.role(of: bobId) == .member)
        #expect(group.myCurrentDistributionId == nil,
                "newcomer mints their own chain after bootstrap")
        #expect(group.mySkdmRecipients.isEmpty)
    }

    @Test("rejects when local user not in members")
    func rejectsLocalUserMissing() throws {
        let alice = try Session()
        let aliceId = try alice.identityPublic()
        let bob = try Session()
        let bobId = try bob.identityPublic()
        // Alice signs a bootstrap that doesn't include Bob.
        let bootstrap = try realSignedBootstrap(
            by: alice, members: [(aliceId, .admin, .active)])
        #expect(bootstrap.intoChatGroup(localIdentityPub: bobId) == nil)
    }
}

// ─── helpers ──────────────────────────────────────────────────────────

private func realSignedBootstrap(
    by signer: Session,
    members specs: [(Data, GroupRole, MemberStatus)],
    groupId: Data = Data(repeating: 0xAA, count: 16),
) throws -> GroupBootstrap {
    let signerId = try signer.identityPublic()
    let members = specs.map { (peerId, role, status) in
        GroupMember(peerId: peerId, displayName: "n", role: role,
                    joinedAtEpoch: 0, status: status, addedBy: signerId)
    }
    let unsigned = GroupBootstrap(
        groupId: groupId, displayName: "g", members: members,
        currentEpoch: 0, lastOpDigest: Data(repeating: 0xBB, count: 32),
        operatorIdentity: signerId, timestampMillis: 1_700_000_000_000,
        signature: Data(repeating: 0, count: GroupOp.signatureSize))
    let header = try unsigned.encodedHeader()
    let sig = try signer.identitySign(header)
    return GroupBootstrap.signed(
        groupId: unsigned.groupId, displayName: unsigned.displayName,
        members: unsigned.members, currentEpoch: unsigned.currentEpoch,
        lastOpDigest: unsigned.lastOpDigest,
        operatorIdentity: unsigned.operatorIdentity,
        timestampMillis: unsigned.timestampMillis, signature: sig)
}
