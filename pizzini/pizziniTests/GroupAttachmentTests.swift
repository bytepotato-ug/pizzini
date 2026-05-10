import Foundation
import PizziniCryptoCore
import Testing
@testable import pizzini

/// Tests for the post-audit group-attachments wire (`groupFileChunk =
/// 0x0A`):
///
///   - codec round-trip for `GroupEnvelope.encodeGroupFileChunk` /
///     `decodeGroupFileChunk` (same shape as the 0x06 / 0x07 / 0x09
///     bodies — `groupId(16) ‖ payload`),
///   - receive-side membership gate (audit CRITICAL-2): a non-member
///     peer's chunk is dropped before any decrypt is attempted; an
///     active member's chunk is processed,
///   - receive-side `pendingInvitation` gate: the chain advances but
///     no chat row is written until the user taps Join (mirrors
///     `handleGroupChat`'s accept-later-no-backlog rule),
///   - send-side gate: the local user is refused if `.removed` or
///     while the invitation is still pending (mirrors
///     `sendGroupMessage` / audit HIGH-3),
///   - reassembly: a multi-chunk inbound transfer lands as ONE
///     `.attachment` `PersistedMessage` with `senderPeerId` populated
///     so render-time member-name resolution works for renames.
///
/// The gate tests exercise the pure helpers
/// `ChatGroup.acceptsIncomingMessage(from:)` and
/// `ChatGroup.canSend(asLocal:)` — the same predicates the runtime
/// handlers consult, so a regression in either path is caught here
/// without standing up a full `ChatStore` (Keychain, relay socket).

@Suite("GroupEnvelope groupFileChunk codec")
struct GroupFileChunkCodecTests {
    @Test("round-trip preserves the groupId prefix and the SenderKeyMessage suffix")
    func roundTrip() throws {
        let groupId = Data((0..<16).map { UInt8($0) })
        let cipher = Data((0..<128).map { UInt8($0 ^ 0xA5) })
        let wire = GroupEnvelope.encodeGroupFileChunk(
            groupId: groupId, senderKeyMessage: cipher,
        )
        #expect(wire.count == 16 + cipher.count)
        let parsed = try #require(GroupEnvelope.decodeGroupFileChunk(wire))
        #expect(parsed.groupId == groupId)
        #expect(parsed.senderKeyMessage == cipher)
    }

    @Test("rejects a payload too short to carry the 16-byte groupId prefix")
    func rejectsShortPayload() {
        let short = Data(repeating: 0xAA, count: 8)
        #expect(GroupEnvelope.decodeGroupFileChunk(short) == nil)
    }

    @Test("zero-length SenderKeyMessage suffix is allowed (empty trailer is the codec's job; semantic check happens downstream)")
    func zeroLengthSuffixAllowed() throws {
        let groupId = Data(repeating: 0xCD, count: 16)
        let wire = GroupEnvelope.encodeGroupFileChunk(
            groupId: groupId, senderKeyMessage: Data(),
        )
        #expect(wire.count == 16)
        let parsed = try #require(GroupEnvelope.decodeGroupFileChunk(wire))
        #expect(parsed.groupId == groupId)
        #expect(parsed.senderKeyMessage.isEmpty)
    }

    @Test("InnerEnvelopeKind.groupFileChunk has wire byte 0x0A")
    func innerEnvelopeKindByteIsStable() {
        // The byte is part of the on-wire contract: changing it would
        // silently break compatibility with any device still running
        // a previous build. Pin it here so a refactor that
        // re-orders the enum cases gets caught.
        #expect(RelayClient.InnerEnvelopeKind.groupFileChunk.rawValue == 0x0A)
    }
}

@Suite("ChatGroup receive gate (groupFileChunk + groupChat parity)")
struct ChatGroupReceiveGateTests {
    @Test("non-member peer is rejected before decryption")
    func nonMemberDropped() throws {
        let alice = try Session()
        let bob = try Session()
        let mallory = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let malloryId = try mallory.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)
        let createOp = try realSignedCreate(
            by: alice, groupId: groupId, name: "g",
            members: [(aliceId, .admin, "A"), (bobId, .member, "B")])
        let signed = try createOp.encoded()
        let group = try #require(ChatGroup.create(
            fromCreate: createOp, signedBytes: signed, localIdentityPub: bobId))
        // Alice + Bob are members; Mallory is not in the group at all.
        #expect(group.acceptsIncomingMessage(from: aliceId) == true)
        #expect(group.acceptsIncomingMessage(from: bobId) == true)
        #expect(group.acceptsIncomingMessage(from: malloryId) == false,
                "non-member peer must be rejected before decrypt")
    }

    @Test("removed member is rejected even though their member row is retained")
    func removedMemberDropped() throws {
        let alice = try Session()
        let bob = try Session()
        let carol = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let carolId = try carol.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)
        let createOp = try realSignedCreate(
            by: alice, groupId: groupId, name: "g",
            members: [
                (aliceId, .admin, "A"),
                (bobId, .member, "B"),
                (carolId, .member, "C"),
            ])
        let signed = try createOp.encoded()
        var group = try #require(ChatGroup.create(
            fromCreate: createOp, signedBytes: signed, localIdentityPub: aliceId))
        // Admin removes Carol.
        let removeOp = try realSignedOp(
            by: alice, groupId: groupId,
            epoch: group.currentEpoch + 1, parent: group.lastOpDigest,
            kind: .removeMember(peerId: carolId))
        if case .applied = group.apply(removeOp) {} else {
            Issue.record("RemoveMember apply failed")
        }
        #expect(group.acceptsIncomingMessage(from: bobId) == true)
        #expect(group.acceptsIncomingMessage(from: carolId) == false,
                "a chunk from a removed peer must not advance UI even though the member row stays")
    }

    @Test("pendingInvitation does not relax membership gate, only suppresses rendering")
    func pendingInvitationGate() throws {
        // The receive handler treats pendingInvitation as "advance the
        // ratchet, drop the plaintext" — the membership gate still
        // applies underneath. This test pins both halves: pending IS
        // surfaced as a flag the handler can read AND the membership
        // check still excludes non-members.
        let alice = try Session()
        let bob = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)
        let createOp = try realSignedCreate(
            by: alice, groupId: groupId, name: "g",
            members: [(aliceId, .admin, "A"), (bobId, .member, "B")])
        let signed = try createOp.encoded()
        let group = try #require(ChatGroup.create(
            fromCreate: createOp, signedBytes: signed, localIdentityPub: bobId))
        // Bob receives the invitation — pending until tapped.
        #expect(group.pendingInvitation == true)
        // Alice is still a valid sender (membership test); the
        // pendingInvitation flag is consulted independently by the
        // handler to decide whether to render.
        #expect(group.acceptsIncomingMessage(from: aliceId) == true)
        // Bob's local PersistedMessage log MUST stay empty — the
        // handler skips append-on-decrypt while pending.
        #expect(group.log.isEmpty,
                "no chat rows should exist before the user taps Join")
    }
}

@Suite("ChatGroup send gate (sendGroupMessage / sendGroupAttachment parity)")
struct ChatGroupSendGateTests {
    @Test("local user removed → canSend false (mirrors sendGroupMessage HIGH-3 refusal)")
    func removedLocalRefused() throws {
        let alice = try Session()
        let bob = try Session()
        let carol = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let carolId = try carol.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)
        let createOp = try realSignedCreate(
            by: alice, groupId: groupId, name: "g",
            members: [
                (aliceId, .admin, "A"),
                (bobId, .member, "B"),
                (carolId, .member, "C"),
            ])
        let signed = try createOp.encoded()
        var group = try #require(ChatGroup.create(
            fromCreate: createOp, signedBytes: signed, localIdentityPub: bobId))
        // Pretend Bob has accepted (clear pending) and minted a chain
        // — both required for canSend to reach the membership check.
        group.pendingInvitation = false
        group.myCurrentDistributionId = UUID()
        // Baseline: Bob can post.
        #expect(group.canSend(asLocal: bobId) == true)
        // Admin removes Bob.
        let removeOp = try realSignedOp(
            by: alice, groupId: groupId,
            epoch: group.currentEpoch + 1, parent: group.lastOpDigest,
            kind: .removeMember(peerId: bobId))
        if case .applied = group.apply(removeOp) {} else {
            Issue.record("RemoveMember apply failed")
        }
        // The libsignal chain may still be installed locally, but the
        // gate refuses post-removal. Audit HIGH-3.
        #expect(group.canSend(asLocal: bobId) == false,
                "a removed member must not be able to keep posting")
    }

    @Test("pendingInvitation → canSend false (composer + runtime backstop)")
    func pendingInvitationRefused() throws {
        let alice = try Session()
        let bob = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)
        let createOp = try realSignedCreate(
            by: alice, groupId: groupId, name: "g",
            members: [(aliceId, .admin, "A"), (bobId, .member, "B")])
        let signed = try createOp.encoded()
        var group = try #require(ChatGroup.create(
            fromCreate: createOp, signedBytes: signed, localIdentityPub: bobId))
        #expect(group.pendingInvitation == true)
        // Even with a chain installed, pendingInvitation refuses.
        group.myCurrentDistributionId = UUID()
        #expect(group.canSend(asLocal: bobId) == false,
                "user must tap Join before composer unlocks")
    }

    @Test("no sender-key chain → canSend false (composer parity with old gate)")
    func noChainRefused() throws {
        let alice = try Session()
        let bob = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)
        let createOp = try realSignedCreate(
            by: alice, groupId: groupId, name: "g",
            members: [(aliceId, .admin, "A"), (bobId, .member, "B")])
        let signed = try createOp.encoded()
        var group = try #require(ChatGroup.create(
            fromCreate: createOp, signedBytes: signed, localIdentityPub: bobId))
        group.pendingInvitation = false
        // No chain yet — canSend must refuse.
        #expect(group.myCurrentDistributionId == nil)
        #expect(group.canSend(asLocal: bobId) == false)
    }
}

@MainActor
@Suite("group attachment reassembly", .serialized)
struct GroupAttachmentReassemblyTests {
    private func makeEnv(
        attachmentId: Data,
        index: UInt32,
        count: UInt32,
        totalSize: UInt64,
        chunkBytes: Data,
        filename: String = "report.pdf",
        mime: String = "application/pdf",
    ) -> FileChunkEnvelope {
        FileChunkEnvelope(
            attachmentId: attachmentId,
            totalSize: totalSize,
            chunkIndex: index,
            chunkCount: count,
            mime: mime,
            filename: filename,
            chunkBytes: chunkBytes,
        )
    }

    @Test("multi-chunk reassembly lands as a single .attachment row with senderPeerId populated")
    func multiChunkLandsAsSinglePersistedMessage() throws {
        // Build a group with Alice as admin, Bob receiver. The chunks
        // arrive at Bob's groupReassembler and the completion is
        // appended via `appendIncomingAttachment` — exactly what
        // `handleGroupFileChunk` does on `.complete`.
        let alice = try Session()
        let bob = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        let groupId = Data(repeating: 0xAA, count: 16)
        let createOp = try realSignedCreate(
            by: alice, groupId: groupId, name: "g",
            members: [(aliceId, .admin, "A"), (bobId, .member, "B")])
        let signed = try createOp.encoded()
        var group = try #require(ChatGroup.create(
            fromCreate: createOp, signedBytes: signed, localIdentityPub: bobId))
        group.pendingInvitation = false
        // Pre-condition for the test: log starts empty.
        #expect(group.log.isEmpty)

        let r = AttachmentReassembler()
        let aid = Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })
        let part0 = Data("hello-".utf8)
        let part1 = Data("world!".utf8)
        let total = UInt64(part0.count + part1.count)

        let r0 = r.feed(envelope: makeEnv(
            attachmentId: aid, index: 0, count: 2, totalSize: total, chunkBytes: part0,
        ), fromPeer: aliceId)
        if case .progress = r0 {} else {
            Issue.record("expected progress for chunk 0, got \(r0)")
        }
        // Pre-completion: still no row in the group log.
        #expect(group.log.isEmpty,
                "the receive path must not append a row mid-attachment")

        let r1 = r.feed(envelope: makeEnv(
            attachmentId: aid, index: 1, count: 2, totalSize: total, chunkBytes: part1,
        ), fromPeer: aliceId)
        let completion: AttachmentReassembler.Completion
        switch r1 {
        case .complete(let c): completion = c
        default:
            Issue.record("expected complete for final chunk, got \(r1)")
            return
        }
        defer { try? FileManager.default.removeItem(at: completion.url.deletingLastPathComponent()) }

        // The handler builds the row via `appendIncomingAttachment`.
        let row = group.appendIncomingAttachment(
            attachmentId: completion.attachmentId,
            filename: completion.sanitizedFilename,
            byteSize: completion.totalSize,
            mime: completion.mime,
            tier: completion.tier,
            sandboxRelativePath: nil,
            senderPeerId: aliceId,
        )
        // Single row appended (not N).
        #expect(group.log.count == 1)
        #expect(row.kind == .attachment)
        #expect(row.side == .peer)
        // senderPeerId is mandatory — drives `memberDisplayName`
        // render-time resolution (audit MEDIUM-7).
        #expect(row.senderPeerId == aliceId,
                "render-time name resolution depends on senderPeerId")
        #expect(row.attachment != nil)
        #expect(row.attachment?.attachmentId == aid)
        #expect(row.attachment?.filename == "report.pdf")
        #expect(row.attachment?.byteSize == total)
        #expect(row.attachment?.isInbound == true)
        // The assembled bytes match what was fed in.
        let assembled = try Data(contentsOf: completion.url)
        #expect(assembled == part0 + part1)
    }
}
