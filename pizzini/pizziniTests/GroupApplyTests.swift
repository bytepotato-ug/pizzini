import Foundation
import PizziniCryptoCore
import Testing
@testable import pizzini

/// Apply / replay state-machine tests for `ChatGroup`. Covers the
/// slice-3 contract:
///
///   - bootstrap from a real signed Create op,
///   - linear-chain happy path (each op advances `currentEpoch` and
///     updates `lastOpDigest`),
///   - admin-only authorisation (RotateSenderKey is the only kind a
///     non-admin member is allowed to perform),
///   - hash-chain integrity (mismatched parentDigest → equivocation),
///   - past-epoch divergence (different signed op at an already-
///     applied epoch → equivocation),
///   - duplicate idempotency (re-receive of the same signed op is a
///     no-op),
///   - future-epoch queueing + drain on parent arrival,
///   - signature rejection,
///   - last-admin protection (cannot brick the group),
///   - removed-member peerId is dropped from `memberDistributionIds`.
///
/// All helpers below construct REAL signed ops via `Session.identitySign`
/// and verify with the new `pizzini_verify_identity_signature` FFI, so
/// these tests exercise the whole crypto + codec + state-machine
/// stack end-to-end.

@Suite("ChatGroup.create bootstrap")
struct ChatGroupCreateTests {
    @Test("create from a valid signed Create op installs members and digest")
    func happyPath() throws {
        let alice = try Session()
        let bob = try Session()
        let carol = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let carolId = try carol.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)

        let op = try realSignedCreate(
            by: alice,
            groupId: groupId,
            name: "field-team",
            members: [
                (aliceId, .admin, "Alice"),
                (bobId, .member, "Bob"),
                (carolId, .member, "Carol"),
            ],
        )
        let signed = try op.encoded()
        let group = try #require(ChatGroup.create(
            fromCreate: op,
            signedBytes: signed,
            localIdentityPub: bobId,
        ))
        #expect(group.id == groupId)
        #expect(group.displayName == "field-team")
        #expect(group.members.count == 3)
        #expect(group.activeMembers.count == 3)
        #expect(group.role(of: aliceId) == .admin)
        #expect(group.role(of: bobId) == .member)
        #expect(group.currentEpoch == 0)
        #expect(group.lastOpDigest.count == 32)
        #expect(group.pendingOps.isEmpty)
    }

    @Test("operator missing from initialMembers is rejected")
    func operatorNotInMembers() throws {
        let alice = try Session()
        let bob = try Session()
        let bobId = try bob.identityPublic()
        let op = try realSignedCreate(
            by: alice,
            groupId: Data(repeating: 0xAA, count: 16),
            name: "x",
            members: [(bobId, .admin, "Bob")],
        )
        let signed = try op.encoded()
        #expect(ChatGroup.create(fromCreate: op, signedBytes: signed, localIdentityPub: bobId) == nil)
    }

    @Test("create overrides the operator's declared role to admin")
    func operatorAlwaysAdmin() throws {
        let alice = try Session()
        let aliceId = try alice.identityPublic()
        // Alice declares herself as a plain member in the Create op
        // payload — the bootstrap constructor must override to .admin
        // so the group always has at least one admin to mutate it.
        let op = try realSignedCreate(
            by: alice,
            groupId: Data(repeating: 0xAA, count: 16),
            name: "x",
            members: [(aliceId, .member, "Alice")],
        )
        let signed = try op.encoded()
        let group = try #require(ChatGroup.create(
            fromCreate: op,
            signedBytes: signed,
            localIdentityPub: aliceId,
        ))
        #expect(group.role(of: aliceId) == .admin)
    }

    @Test("duplicate peerId in initialMembers is rejected")
    func duplicateMember() throws {
        let alice = try Session()
        let aliceId = try alice.identityPublic()
        let op = try realSignedCreate(
            by: alice,
            groupId: Data(repeating: 0xAA, count: 16),
            name: "x",
            members: [(aliceId, .admin, "Alice"), (aliceId, .member, "Alice2")],
        )
        let signed = try op.encoded()
        #expect(ChatGroup.create(fromCreate: op, signedBytes: signed, localIdentityPub: aliceId) == nil)
    }
}

@Suite("ChatGroup.apply happy path")
struct ChatGroupApplyHappyTests {
    @Test("apply AddMember advances epoch and inserts the new member")
    func addMember() throws {
        var env = try Env.bootstrap()
        let dave = try Session()
        let daveId = try dave.identityPublic()
        let op = try env.adminSign(
            kind: .addMember(peerId: daveId, role: .member, displayName: "Dave"),
        )
        let outcome = env.group.apply(op)
        env.expectApplied(outcome, atEpoch: 1)
        #expect(env.group.activeMembers.count == 4)
        #expect(env.group.role(of: daveId) == .member)
        #expect(env.group.lastOpDigest == (try op.digest()))
    }

    @Test("apply Rename mutates the displayName")
    func rename() throws {
        var env = try Env.bootstrap()
        let op = try env.adminSign(kind: .rename(newName: "new-team-name"))
        env.expectApplied(env.group.apply(op), atEpoch: 1)
        #expect(env.group.displayName == "new-team-name")
    }

    @Test("apply RemoveMember marks the row .removed and drops its dist_id")
    func removeMember() throws {
        var env = try Env.bootstrap()
        // Seed Bob's dist_id so we can confirm it gets dropped.
        env.group.memberDistributionIds[env.bobId] = UUID()
        let op = try env.adminSign(kind: .removeMember(peerId: env.bobId))
        env.expectApplied(env.group.apply(op), atEpoch: 1)
        #expect(env.group.activeMembers.contains(where: { $0.peerId == env.bobId }) == false)
        #expect(env.group.members.contains(where: {
            $0.peerId == env.bobId && $0.status == .removed
        }))
        #expect(env.group.memberDistributionIds[env.bobId] == nil)
    }

    @Test("apply RotateSenderKey updates memberDistributionIds for the operator")
    func rotateSenderKey() throws {
        var env = try Env.bootstrap()
        let newDist = UUID()
        // Bob is a non-admin member but RotateSenderKey is allowed for
        // any active member — they're rotating their own chain.
        let op = try env.bobSign(kind: .rotateSenderKey(newDistributionId: newDist))
        env.expectApplied(env.group.apply(op), atEpoch: 1)
        #expect(env.group.memberDistributionIds[env.bobId] == newDist)
    }

    @Test("a chain of ops advances currentEpoch monotonically")
    func chain() throws {
        var env = try Env.bootstrap()
        let dave = try Session()
        let daveId = try dave.identityPublic()
        let eve = try Session()
        let eveId = try eve.identityPublic()

        let op1 = try env.adminSign(
            kind: .addMember(peerId: daveId, role: .member, displayName: "Dave"),
        )
        env.expectApplied(env.group.apply(op1), atEpoch: 1)

        let op2 = try env.adminSign(
            kind: .addMember(peerId: eveId, role: .member, displayName: "Eve"),
        )
        env.expectApplied(env.group.apply(op2), atEpoch: 2)

        let op3 = try env.adminSign(kind: .rename(newName: "expanded"))
        env.expectApplied(env.group.apply(op3), atEpoch: 3)

        #expect(env.group.currentEpoch == 3)
        #expect(env.group.activeMembers.count == 5)
        #expect(env.group.displayName == "expanded")
    }
}

@Suite("ChatGroup.apply rejections")
struct ChatGroupApplyRejectionTests {
    @Test("groupId mismatch is rejected as malformed")
    func groupIdMismatch() throws {
        var env = try Env.bootstrap()
        let op = try env.adminSignForGroup(
            groupId: Data(repeating: 0xFF, count: 16),
            kind: .rename(newName: "x"),
            epoch: 1,
            parent: env.group.lastOpDigest,
        )
        if case .rejectedMalformed = env.group.apply(op) {} else {
            Issue.record("expected rejectedMalformed for groupId mismatch")
        }
    }

    @Test("a foreign-signed op is rejected as bad signature")
    func badSignature() throws {
        var env = try Env.bootstrap()
        // Sign with Bob's identity but claim to be Alice.
        let unsigned = GroupOp(
            groupId: env.group.id,
            epoch: 1,
            parentDigest: env.group.lastOpDigest,
            operatorIdentity: env.aliceId,
            timestampMillis: env.now,
            priorMemberSetRoot: env.group.memberSetRoot,
            kind: .rename(newName: "fake"),
            signature: Data(repeating: 0, count: GroupOp.signatureSize),
        )
        let header = try unsigned.encodedHeader()
        let bobSig = try env.bob.identitySign(header, contextTag: Session.SignatureContext.groupOp)
        let op = GroupOp(
            groupId: unsigned.groupId,
            epoch: unsigned.epoch,
            parentDigest: unsigned.parentDigest,
            operatorIdentity: unsigned.operatorIdentity,
            timestampMillis: unsigned.timestampMillis,
            priorMemberSetRoot: unsigned.priorMemberSetRoot,
            kind: unsigned.kind,
            signature: bobSig,
        )
        #expect(env.group.apply(op) == .rejectedSignature)
    }

    @Test("a non-admin trying to AddMember is rejected as unauthorised")
    func nonAdminCannotAddMember() throws {
        var env = try Env.bootstrap()
        let dave = try Session()
        let daveId = try dave.identityPublic()
        // Bob is not an admin (Env makes Alice the only admin).
        let op = try env.bobSign(kind: .addMember(peerId: daveId, role: .member, displayName: "Dave"))
        #expect(env.group.apply(op) == .rejectedAuthorization)
    }

    @Test("Ghost-member op (wrong priorMemberSetRoot) is rejected with rejectedMemberSetMismatch")
    func ghostMemberOpIsRejected() throws {
        var env = try Env.bootstrap()
        // Simulate the ghost-member attack: an admin's local view
        // *thinks* it has an extra (attacker-controlled) member
        // that nobody else sees. The op they sign witnesses that
        // ghosted view via `priorMemberSetRoot`. From the bob/carol
        // side, the local view is the honest member list, so the
        // root mismatch surfaces and the op is refused.
        let ghost = Data(repeating: 0xEE, count: 33)
        var ghostedMembers = env.group.members
        ghostedMembers.append(GroupMember(
            peerId: ghost,
            displayName: "ghost",
            role: .member,
            joinedAtEpoch: 0,
            status: .active,
            addedBy: env.aliceId,
        ))
        let ghostRoot = ChatGroup.memberSetRoot(of: ghostedMembers)
        // Sanity: ghost-rooted hash differs from the honest local one.
        #expect(ghostRoot != env.group.memberSetRoot)
        let op = try realSignedOp(
            by: env.alice,
            groupId: env.group.id,
            epoch: env.group.currentEpoch + 1,
            parent: env.group.lastOpDigest,
            kind: .rename(newName: "ghost-issued"),
            priorMemberSetRoot: ghostRoot,
        )
        switch env.group.apply(op) {
        case let .rejectedMemberSetMismatch(local, claimed):
            #expect(local == env.group.memberSetRoot)
            #expect(claimed == ghostRoot)
        default:
            Issue.record("expected rejectedMemberSetMismatch")
        }
        // Group state unchanged — the op did not advance the epoch.
        #expect(env.group.currentEpoch == 0)
        #expect(env.group.displayName != "ghost-issued")
    }

    @Test("a parentDigest mismatch at the next epoch is equivocation")
    func parentDigestMismatchIsEquivocation() throws {
        var env = try Env.bootstrap()
        // Forge a parent digest pointing at random bytes instead of
        // the real bootstrap digest.
        let op = try env.adminSignForGroup(
            groupId: env.group.id,
            kind: .rename(newName: "fork"),
            epoch: 1,
            parent: Data(repeating: 0xCC, count: 32),
        )
        if case .rejectedEquivocation = env.group.apply(op) {} else {
            Issue.record("expected rejectedEquivocation")
        }
    }

    @Test("re-applying the same op is a duplicate, not equivocation")
    func reAppliedOpIsDuplicate() throws {
        var env = try Env.bootstrap()
        let op = try env.adminSign(kind: .rename(newName: "v1"))
        env.expectApplied(env.group.apply(op), atEpoch: 1)
        // Idempotent re-receive: same bytes, same digest. Drop, do not warn.
        #expect(env.group.apply(op) == .rejectedDuplicate)
    }

    @Test("a different op at an already-applied epoch is equivocation")
    func divergentPastEpochIsEquivocation() throws {
        var env = try Env.bootstrap()
        let op1 = try env.adminSign(kind: .rename(newName: "v1"))
        env.expectApplied(env.group.apply(op1), atEpoch: 1)
        // A second op at the SAME epoch with different content. Even
        // though it's correctly chained from the bootstrap (parent =
        // initial digest), our `recentOpDigests` cache catches the
        // divergence at epoch 1.
        let op2 = try env.adminSignForGroup(
            groupId: env.group.id,
            kind: .rename(newName: "v2"),
            epoch: 1,
            parent: GroupOp.zeroParentDigest, // doesn't matter — we're past this epoch
        )
        if case let .rejectedEquivocation(epoch) = env.group.apply(op2) {
            #expect(epoch == 1)
        } else {
            Issue.record("expected rejectedEquivocation at epoch 1")
        }
    }

    @Test("RemoveMember of the last admin is rejected as malformed")
    func cannotRemoveLastAdmin() throws {
        var env = try Env.bootstrap()
        let op = try env.adminSign(kind: .removeMember(peerId: env.aliceId))
        if case .rejectedMalformed = env.group.apply(op) {} else {
            Issue.record("expected rejectedMalformed for last-admin removal")
        }
    }

    @Test("DemoteAdmin of the last admin is rejected as malformed")
    func cannotDemoteLastAdmin() throws {
        var env = try Env.bootstrap()
        let op = try env.adminSign(kind: .demoteAdmin(peerId: env.aliceId))
        if case .rejectedMalformed = env.group.apply(op) {} else {
            Issue.record("expected rejectedMalformed for last-admin demotion")
        }
    }
}

@Suite("ChatGroup.apply queueing and replay")
struct ChatGroupApplyQueueTests {
    @Test("a future-epoch op is queued, not applied")
    func futureEpochQueues() throws {
        var env = try Env.bootstrap()
        // op@1 must be queued as op@2 because op@1 hasn't arrived yet.
        let dave = try Session()
        let daveId = try dave.identityPublic()
        let op2 = try env.adminSignForGroup(
            groupId: env.group.id,
            kind: .addMember(peerId: daveId, role: .member, displayName: "Dave"),
            epoch: 2,
            parent: Data(repeating: 0xEE, count: 32), // pretend it chains from op@1
        )
        let outcome = env.group.apply(op2)
        if case let .queued(epoch) = outcome {
            #expect(epoch == 2)
        } else {
            Issue.record("expected queued(epoch: 2)")
        }
        #expect(env.group.currentEpoch == 0)
        #expect(env.group.pendingOps.count == 1)
    }

    @Test("queued op drains when the missing parent arrives")
    func drainOnParent() throws {
        var env = try Env.bootstrap()
        let dave = try Session()
        let daveId = try dave.identityPublic()

        // First send op@1 (Rename), THEN derive op@2's parent from
        // it, but apply op@2 BEFORE op@1.
        let op1 = try env.adminSign(kind: .rename(newName: "stage-1"))
        let op1Digest = try op1.digest()
        let op2 = try env.adminSignForGroup(
            groupId: env.group.id,
            kind: .addMember(peerId: daveId, role: .member, displayName: "Dave"),
            epoch: 2,
            parent: op1Digest,
        )

        // op@2 arrives first → queued.
        env.expectQueued(env.group.apply(op2), atEpoch: 2)
        #expect(env.group.currentEpoch == 0)
        #expect(env.group.pendingOps.count == 1)

        // op@1 arrives → applied, then op@2 drains automatically.
        env.expectApplied(env.group.apply(op1), atEpoch: 1)
        #expect(env.group.currentEpoch == 2)
        #expect(env.group.activeMembers.count == 4)
        #expect(env.group.pendingOps.isEmpty)
        #expect(env.group.displayName == "stage-1")
    }

    @Test("the queue is bounded — a flood of future-epoch ops doesn't grow unboundedly")
    func boundedQueue() throws {
        var env = try Env.bootstrap()
        // The cap is 1024 in the implementation. Push 1100 distinct
        // future-epoch ops and confirm the queue doesn't exceed cap.
        for i in 0..<1100 {
            let op = try env.adminSignForGroup(
                groupId: env.group.id,
                kind: .rename(newName: "noise-\(i)"),
                epoch: UInt64(i + 100), // far enough in the future to never apply
                parent: Data(repeating: 0xDD, count: 32),
            )
            _ = env.group.apply(op)
        }
        #expect(env.group.pendingOps.count <= 1024)
    }

    @Test("a 5-deep chain in REVERSE order drains via the sorted replay path")
    func reverseOrderChainDrains() throws {
        // Audit HIGH-6: replayPending sorts by epoch ascending and
        // walks forward, so a queue of [op5, op4, op3, op2, op1]
        // (signed as a hash chain) drains all five when op1 finally
        // arrives. The previous pre-audit implementation would still
        // have drained them but at O(N²) work — this test pins the
        // correctness; the perf is observed via the sorted walk.
        var env = try Env.bootstrap()
        let op1 = try env.adminSign(kind: .rename(newName: "v1"))
        let d1 = try op1.digest()
        let op2 = try env.adminSignForGroup(
            groupId: env.group.id, kind: .rename(newName: "v2"), epoch: 2, parent: d1)
        let d2 = try op2.digest()
        let op3 = try env.adminSignForGroup(
            groupId: env.group.id, kind: .rename(newName: "v3"), epoch: 3, parent: d2)
        let d3 = try op3.digest()
        let op4 = try env.adminSignForGroup(
            groupId: env.group.id, kind: .rename(newName: "v4"), epoch: 4, parent: d3)
        let d4 = try op4.digest()
        let op5 = try env.adminSignForGroup(
            groupId: env.group.id, kind: .rename(newName: "v5"), epoch: 5, parent: d4)

        // Apply in reverse order; ops 5..2 queue.
        env.expectQueued(env.group.apply(op5), atEpoch: 5)
        env.expectQueued(env.group.apply(op4), atEpoch: 4)
        env.expectQueued(env.group.apply(op3), atEpoch: 3)
        env.expectQueued(env.group.apply(op2), atEpoch: 2)
        #expect(env.group.pendingOps.count == 4)

        // op1 arrives — drain everything.
        env.expectApplied(env.group.apply(op1), atEpoch: 1)
        #expect(env.group.currentEpoch == 5)
        #expect(env.group.pendingOps.isEmpty)
        #expect(env.group.displayName == "v5")
    }
}

@Suite("ChatGroup post-audit invariants")
struct ChatGroupPostAuditTests {
    @Test("AddMember populates `addedBy` with the operator")
    func addMemberAddedByPopulated() throws {
        var env = try Env.bootstrap()
        let dave = try Session()
        let daveId = try dave.identityPublic()
        let op = try env.adminSign(
            kind: .addMember(peerId: daveId, role: .member, displayName: "Dave"),
        )
        env.expectApplied(env.group.apply(op), atEpoch: 1)
        let dave_row = env.group.members.first(where: { $0.peerId == daveId })
        #expect(dave_row?.addedBy == env.aliceId)
    }

    @Test("Create populates `addedBy` for every initial member with the operator")
    func createAddedByPopulated() throws {
        let env = try Env.bootstrap()
        for member in env.group.members {
            #expect(member.addedBy == env.aliceId,
                    "every initial member should be addedBy the creator")
        }
    }

    @Test("Re-adding a previously-removed member enforces the member cap (HIGH-4)")
    func reAddRespectsCap() throws {
        // Build a group at the cap (50 members), remove one, fill
        // the slot with a different new member, then try to re-add
        // the removed one. The state machine must reject.
        let alice = try Session()
        let aliceId = try alice.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)

        // Build 50 members: Alice + 49 others.
        var initial: [(Data, GroupRole, String)] = [(aliceId, .admin, "Alice")]
        var sessions: [Session] = []
        for i in 0..<49 {
            let s = try Session()
            sessions.append(s)
            let id = try s.identityPublic()
            initial.append((id, .member, "M\(i)"))
        }
        let createOp = try realSignedCreate(
            by: alice, groupId: groupId, name: "max", members: initial)
        let signed = try createOp.encoded()
        var group = try #require(ChatGroup.create(
            fromCreate: createOp, signedBytes: signed, localIdentityPub: aliceId))
        #expect(group.activeMembers.count == 50)

        // Remove M0.
        let removed = try sessions[0].identityPublic()
        let removeOp = try realSignedOp(
            by: alice, groupId: groupId, epoch: group.currentEpoch + 1,
            parent: group.lastOpDigest, kind: .removeMember(peerId: removed),
            priorMemberSetRoot: group.memberSetRoot)
        if case .applied = group.apply(removeOp) {} else {
            Issue.record("remove failed")
        }
        #expect(group.activeMembers.count == 49)

        // Add a fresh new member to fill the slot back to 50.
        let newSession = try Session()
        let newId = try newSession.identityPublic()
        let addOp = try realSignedOp(
            by: alice, groupId: groupId, epoch: group.currentEpoch + 1,
            parent: group.lastOpDigest,
            kind: .addMember(peerId: newId, role: .member, displayName: "fresh"),
            priorMemberSetRoot: group.memberSetRoot)
        if case .applied = group.apply(addOp) {} else {
            Issue.record("add fresh failed")
        }
        #expect(group.activeMembers.count == 50)

        // Now re-add M0 — must be rejected as cap exceeded.
        let readdOp = try realSignedOp(
            by: alice, groupId: groupId, epoch: group.currentEpoch + 1,
            parent: group.lastOpDigest,
            kind: .addMember(peerId: removed, role: .member, displayName: "M0-redux"),
            priorMemberSetRoot: group.memberSetRoot)
        if case let .rejectedMalformed(reason) = group.apply(readdOp) {
            #expect(reason.contains("cap"))
        } else {
            Issue.record("expected rejectedMalformed for cap-exceeding re-add")
        }
        #expect(group.activeMembers.count == 50)
    }

    @Test("RemoveMember of another member sets requestSelfRotation when local user is still active")
    func removeOtherSetsRotationFlag() throws {
        var env = try Env.bootstrap()
        // Bob is the local user (Env passes bobId as localIdentityPub
        // in the bootstrap constructor — but the side-effects flag is
        // computed against ApplySideEffects.localIdentityPub which we
        // pass in at apply time).
        let op = try env.adminSign(kind: .removeMember(peerId: env.carolId))
        var sx = ChatGroup.ApplySideEffects(localIdentityPub: env.bobId)
        env.expectApplied(env.group.apply(op, sideEffects: &sx), atEpoch: 1)
        #expect(sx.requestSelfRotation == true,
                "Bob is still active and Carol was removed — Bob must rotate")
        #expect(sx.requestSelfChainClear == false)
    }

    @Test("RemoveMember of self sets requestSelfChainClear, not requestSelfRotation")
    func removeSelfSetsChainClear() throws {
        var env = try Env.bootstrap()
        // Alice (admin) removes Bob. Bob applies the op and the flag
        // should say "clear my chain", not "rotate".
        let op = try env.adminSign(kind: .removeMember(peerId: env.bobId))
        var sx = ChatGroup.ApplySideEffects(localIdentityPub: env.bobId)
        env.expectApplied(env.group.apply(op, sideEffects: &sx), atEpoch: 1)
        #expect(sx.requestSelfChainClear == true)
        #expect(sx.requestSelfRotation == false)
    }

    @Test("AddMember collects the new peer in newActiveMembers")
    func addMemberCollectsNewActiveMembers() throws {
        var env = try Env.bootstrap()
        let dave = try Session()
        let daveId = try dave.identityPublic()
        let op = try env.adminSign(
            kind: .addMember(peerId: daveId, role: .member, displayName: "Dave"))
        // Apply as Bob — Bob's view should treat Dave as a "new
        // active member I should ship my SKDM to."
        var sx = ChatGroup.ApplySideEffects(localIdentityPub: env.bobId)
        env.expectApplied(env.group.apply(op, sideEffects: &sx), atEpoch: 1)
        #expect(sx.newActiveMembers.contains(daveId))
        #expect(sx.newActiveMembers.contains(env.bobId) == false,
                "self should never appear in newActiveMembers")
    }

    @Test("AddMember does NOT collect self in newActiveMembers when self is added")
    func addMemberDoesNotCollectSelf() throws {
        var env = try Env.bootstrap()
        // Alice removes Bob, then re-adds Bob. From Bob's
        // localIdentityPub-perspective, the re-add is "self" and
        // should not appear in newActiveMembers (the bidirectional
        // SKDM hook would otherwise try to ship our SKDM to ourselves).
        let removeOp = try env.adminSign(kind: .removeMember(peerId: env.bobId))
        var sx1 = ChatGroup.ApplySideEffects(localIdentityPub: env.bobId)
        env.expectApplied(env.group.apply(removeOp, sideEffects: &sx1), atEpoch: 1)

        let addOp = try env.adminSign(
            kind: .addMember(peerId: env.bobId, role: .member, displayName: "Bob"))
        var sx2 = ChatGroup.ApplySideEffects(localIdentityPub: env.bobId)
        env.expectApplied(env.group.apply(addOp, sideEffects: &sx2), atEpoch: 2)
        #expect(sx2.newActiveMembers.contains(env.bobId) == false)
    }

    @Test("Equivocation epoch is mirrored into ApplySideEffects")
    func equivocationEpochOnSideEffects() throws {
        var env = try Env.bootstrap()
        let op1 = try env.adminSign(kind: .rename(newName: "v1"))
        env.expectApplied(env.group.apply(op1), atEpoch: 1)
        let divergent = try env.adminSignForGroup(
            groupId: env.group.id, kind: .rename(newName: "v2"),
            epoch: 1, parent: GroupOp.zeroParentDigest)
        var sx = ChatGroup.ApplySideEffects()
        if case .rejectedEquivocation = env.group.apply(divergent, sideEffects: &sx) {
            #expect(sx.equivocationEpoch == 1)
        } else {
            Issue.record("expected rejectedEquivocation")
        }
    }

    @Test("applyAlreadyParked guard refuses to apply an out-of-order op")
    func applyAlreadyParkedGuard() throws {
        // Forge a queue entry that mismatches the actual applied
        // chain so applyAlreadyParked gets called with epoch ≠
        // currentEpoch+1. The defensive guard should refuse
        // (audit LOW-1). We exercise this indirectly via
        // replayPending: queue several ops and confirm the chain
        // applies cleanly, with no spurious "applied" outcomes for
        // ops whose epoch is wrong relative to the live state.
        var env = try Env.bootstrap()
        let op1 = try env.adminSign(kind: .rename(newName: "v1"))
        let d1 = try op1.digest()
        let op2 = try env.adminSignForGroup(
            groupId: env.group.id, kind: .rename(newName: "v2"), epoch: 2, parent: d1)
        // Queue a poisoned op at epoch 999 with random parent;
        // replayPending must NOT apply it.
        let poison = try env.adminSignForGroup(
            groupId: env.group.id, kind: .rename(newName: "POISON"),
            epoch: 999, parent: Data(repeating: 0xDE, count: 32))
        env.expectQueued(env.group.apply(poison), atEpoch: 999)
        env.expectQueued(env.group.apply(op2), atEpoch: 2)
        env.expectApplied(env.group.apply(op1), atEpoch: 1)
        // After draining, op2 is applied, poison stays in the queue
        // (epoch 999 still in the future), and the rename is "v2".
        #expect(env.group.currentEpoch == 2)
        #expect(env.group.displayName == "v2")
        #expect(env.group.pendingOps.count == 1, "poison stays queued")
    }

    @Test("RemoveMember drops the target's `mySkdmRecipients` entry")
    func removeMemberDropsSkdmRecipient() throws {
        var env = try Env.bootstrap()
        // Pretend we already shipped our SKDM to Carol.
        env.group.mySkdmRecipients.insert(env.carolId)
        let op = try env.adminSign(kind: .removeMember(peerId: env.carolId))
        env.expectApplied(env.group.apply(op), atEpoch: 1)
        #expect(env.group.mySkdmRecipients.contains(env.carolId) == false,
                "removed peer must be dropped so a re-add ships a fresh SKDM")
    }
}

// ─── Test helpers ─────────────────────────────────────────────────────

/// Fresh 3-member group: Alice (admin), Bob (member), Carol (member),
/// constructed from a real signed Create op. Use `adminSign(...)` to
/// build subsequent ops chained from the latest `lastOpDigest`.
private struct Env {
    let alice: Session
    let bob: Session
    let carol: Session
    let aliceId: Data
    let bobId: Data
    let carolId: Data
    let groupId: Data
    /// Stable timestamp so digests are deterministic across reruns
    /// where time would otherwise vary.
    let now: UInt64 = 1_700_000_000_000
    var group: ChatGroup

    static func bootstrap() throws -> Env {
        let alice = try Session()
        let bob = try Session()
        let carol = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let carolId = try carol.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)
        let op = try realSignedCreate(
            by: alice,
            groupId: groupId,
            name: "field-team",
            members: [
                (aliceId, .admin, "Alice"),
                (bobId, .member, "Bob"),
                (carolId, .member, "Carol"),
            ],
        )
        let signed = try op.encoded()
        guard let group = ChatGroup.create(
            fromCreate: op,
            signedBytes: signed,
            localIdentityPub: bobId,
        ) else {
            throw EnvError.bootstrapFailed
        }
        return Env(
            alice: alice,
            bob: bob,
            carol: carol,
            aliceId: aliceId,
            bobId: bobId,
            carolId: carolId,
            groupId: groupId,
            group: group,
        )
    }

    func adminSign(kind: GroupOpKind) throws -> GroupOp {
        try realSignedOp(
            by: alice,
            groupId: groupId,
            epoch: group.currentEpoch + 1,
            parent: group.lastOpDigest,
            kind: kind,
            priorMemberSetRoot: group.memberSetRoot,
        )
    }

    func bobSign(kind: GroupOpKind) throws -> GroupOp {
        try realSignedOp(
            by: bob,
            groupId: groupId,
            epoch: group.currentEpoch + 1,
            parent: group.lastOpDigest,
            kind: kind,
            priorMemberSetRoot: group.memberSetRoot,
        )
    }

    func adminSignForGroup(
        groupId: Data,
        kind: GroupOpKind,
        epoch: UInt64,
        parent: Data,
    ) throws -> GroupOp {
        try realSignedOp(
            by: alice,
            groupId: groupId,
            epoch: epoch,
            parent: parent,
            kind: kind,
            priorMemberSetRoot: group.memberSetRoot,
        )
    }

    func expectApplied(_ outcome: ChatGroup.ApplyOutcome, atEpoch epoch: UInt64) {
        if case let .applied(seen) = outcome {
            #expect(seen == epoch)
        } else {
            Issue.record("expected applied(epoch: \(epoch)) but got \(outcome)")
        }
    }

    func expectQueued(_ outcome: ChatGroup.ApplyOutcome, atEpoch epoch: UInt64) {
        if case let .queued(seen) = outcome {
            #expect(seen == epoch)
        } else {
            Issue.record("expected queued(epoch: \(epoch)) but got \(outcome)")
        }
    }

    enum EnvError: Error { case bootstrapFailed }
}

func realSignedCreate(
    by signer: Session,
    groupId: Data,
    name: String,
    members: [(Data, GroupRole, String)],
) throws -> GroupOp {
    let identity = try signer.identityPublic()
    let initialMembers = members.map { GroupOpInitialMember(
        peerId: $0.0,
        role: $0.1,
        displayName: $0.2,
    )}
    return try realSignedOp(
        by: signer,
        groupId: groupId,
        epoch: 0,
        parent: GroupOp.zeroParentDigest,
        kind: .create(name: name, initialMembers: initialMembers),
        operatorIdentity: identity,
        // Create op witnesses an empty pre-state — the group does
        // not exist yet.
        priorMemberSetRoot: ChatGroup.memberSetRoot(of: []),
    )
}

/// `priorMemberSetRoot` defaults to the empty-set root,
/// which works for codec-only tests that never run the op through
/// `apply`. Tests that exercise the apply path MUST pass the
/// current `group.memberSetRoot` explicitly; otherwise the apply
/// will fail with `.rejectedMemberSetMismatch` — by design.
func realSignedOp(
    by signer: Session,
    groupId: Data,
    epoch: UInt64,
    parent: Data,
    kind: GroupOpKind,
    operatorIdentity: Data? = nil,
    priorMemberSetRoot: Data = ChatGroup.memberSetRoot(of: []),
) throws -> GroupOp {
    let identity = try operatorIdentity ?? signer.identityPublic()
    let unsigned = GroupOp(
        groupId: groupId,
        epoch: epoch,
        parentDigest: parent,
        operatorIdentity: identity,
        timestampMillis: 1_700_000_000_000,
        priorMemberSetRoot: priorMemberSetRoot,
        kind: kind,
        signature: Data(repeating: 0, count: GroupOp.signatureSize),
    )
    let header = try unsigned.encodedHeader()
    let sig = try signer.identitySign(header, contextTag: Session.SignatureContext.groupOp)
    return GroupOp(
        groupId: unsigned.groupId,
        epoch: unsigned.epoch,
        parentDigest: unsigned.parentDigest,
        operatorIdentity: unsigned.operatorIdentity,
        timestampMillis: unsigned.timestampMillis,
        priorMemberSetRoot: unsigned.priorMemberSetRoot,
        kind: unsigned.kind,
        signature: sig,
    )
}
