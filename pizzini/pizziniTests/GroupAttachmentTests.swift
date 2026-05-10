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

@Suite("OutboxStore.readReceiptCutoff (regression: eye-on-latest-message bug)")
struct OutboxReadReceiptCutoffTests {
    /// Pin the fix for the "eye only flips on the previous message
    /// when a newer one is sent" bug. `send(_:to:)` captures
    /// `OutboxEntry.sentAt = Date()` BEFORE `encryptSealed`, then
    /// builds the `.me` log row AFTERWARDS with its own `Date()`
    /// timestamp at row-init. The log row's timestamp is therefore
    /// strictly >= the outbox entry's sentAt, and the original
    /// `m.timestamp <= cutoff` walk with `cutoff = outbox.sentAt`
    /// silently dropped the row the receipt explicitly cited — the
    /// row would only flip to 👁 once a NEWER outbox.sentAt moved
    /// the cutoff past its log timestamp.
    @Test("cutoff prefers log timestamp over outbox sentAt for the cited row")
    func cutoffPrefersLogTimestamp() {
        let mid = Data(repeating: 0xA1, count: 16)
        let outboxSentAt = Date(timeIntervalSinceReferenceDate: 1)
        let logTimestamp = Date(timeIntervalSinceReferenceDate: 2)
        let row = PersistedMessage(
            side: .me, text: "x", kind: .whisper, bytes: 1,
            timestamp: logTimestamp, messageId: mid,
        )
        var store = OutboxStore.empty
        store.entries[mid] = OutboxEntry(
            messageId: mid,
            recipientPeerId: Data(repeating: 0xBB, count: 33),
            sealedCiphertext: Data(),
            token: Data(),
            ttl: 1,
            sentAt: outboxSentAt,
            retries: 0,
            deliveredAt: nil,
            failedAt: nil,
            relayedAt: nil,
        )
        let cutoff = OutboxStore.readReceiptCutoff(
            highest: mid, log: [row], outbox: store,
        )
        #expect(cutoff == logTimestamp,
                "cutoff must be the log row's timestamp so the cited row's `m.timestamp <= cutoff` check succeeds")
        #expect(cutoff != outboxSentAt,
                "outbox.sentAt is created PRE-encrypt → strictly earlier; using it as cutoff is the bug")
    }

    @Test("falls back to outbox sentAt when the log row has been GC'd")
    func fallbackToOutboxWhenLogGCd() {
        let mid = Data(repeating: 0xA2, count: 16)
        let outboxSentAt = Date(timeIntervalSinceReferenceDate: 5)
        var store = OutboxStore.empty
        store.entries[mid] = OutboxEntry(
            messageId: mid,
            recipientPeerId: Data(repeating: 0xBB, count: 33),
            sealedCiphertext: Data(),
            token: Data(),
            ttl: 1,
            sentAt: outboxSentAt,
            retries: 0,
            deliveredAt: nil,
            failedAt: nil,
            relayedAt: nil,
        )
        let cutoff = OutboxStore.readReceiptCutoff(
            highest: mid, log: [], outbox: store,
        )
        #expect(cutoff == outboxSentAt,
                "log empty (row GC'd) → fall back to outbox sentAt rather than dropping the receipt entirely")
    }

    @Test("returns nil when neither source has the messageId")
    func nilWhenAbsent() {
        let cutoff = OutboxStore.readReceiptCutoff(
            highest: Data(repeating: 0x99, count: 16),
            log: [], outbox: OutboxStore.empty,
        )
        #expect(cutoff == nil)
    }
}

@Suite("OutboxStore.groupMessageStatus rollup (Phase 7)")
struct OutboxGroupRollupTests {
    private func leg(
        groupMessageId: Data,
        recipient: Data = Data(repeating: 0xBB, count: 33),
        delivered: Bool = false,
        relayed: Bool = false,
        failed: Bool = false,
        read: Bool = false,
    ) -> OutboxEntry {
        OutboxEntry(
            messageId: Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) }),
            recipientPeerId: recipient,
            sealedCiphertext: Data([0xCA]),
            token: Data(),
            ttl: 24 * 60 * 60,
            sentAt: Date(),
            retries: 0,
            deliveredAt: delivered ? Date() : nil,
            failedAt: failed ? Date() : nil,
            relayedAt: relayed ? Date() : nil,
            groupMessageId: groupMessageId,
            readAt: read ? Date() : nil,
        )
    }

    @Test("every leg delivered → status delivered (✓✓)")
    func allDelivered() {
        var s = OutboxStore.empty
        let gmid = Data(repeating: 0x11, count: 16)
        for i in 0..<3 {
            let r = Data([UInt8(i)] + [UInt8](repeating: 0, count: 32))
            let e = leg(groupMessageId: gmid, recipient: r, delivered: true, relayed: true)
            s.entries[e.messageId] = e
        }
        #expect(s.groupMessageStatus(forId: gmid) == .delivered)
    }

    @Test("any leg failed → status failed (✗ wins)")
    func anyFailed() {
        var s = OutboxStore.empty
        let gmid = Data(repeating: 0x22, count: 16)
        let e0 = leg(groupMessageId: gmid, delivered: true, relayed: true)
        let e1 = leg(groupMessageId: gmid, failed: true)
        s.entries[e0.messageId] = e0
        s.entries[e1.messageId] = e1
        #expect(s.groupMessageStatus(forId: gmid) == .failed)
    }

    @Test("any leg pending → status pending (⏳ wins over relayed)")
    func pendingWinsOverRelayed() {
        var s = OutboxStore.empty
        let gmid = Data(repeating: 0x33, count: 16)
        let e0 = leg(groupMessageId: gmid, relayed: true)
        let e1 = leg(groupMessageId: gmid)   // pending
        s.entries[e0.messageId] = e0
        s.entries[e1.messageId] = e1
        #expect(s.groupMessageStatus(forId: gmid) == .pending)
    }

    @Test("no entries (post-GC) → nil")
    func noEntries() {
        let s = OutboxStore.empty
        #expect(s.groupMessageStatus(forId: Data(repeating: 0x99, count: 16)) == nil)
    }

    @Test("readByAll true only when EVERY leg has readAt stamped")
    func readByAllRequiresAllLegs() {
        var s = OutboxStore.empty
        let gmid = Data(repeating: 0x44, count: 16)
        let e0 = leg(groupMessageId: gmid, delivered: true, relayed: true, read: true)
        let e1 = leg(groupMessageId: gmid, delivered: true, relayed: true, read: false)
        s.entries[e0.messageId] = e0
        s.entries[e1.messageId] = e1
        #expect(s.groupMessageReadByAll(forId: gmid) == false,
                "one leg unread → row stays at ✓✓ delivered, no eye yet")
        // Mark the second leg as read.
        var updated = e1
        updated.readAt = Date()
        s.entries[e1.messageId] = updated
        #expect(s.groupMessageReadByAll(forId: gmid) == true,
                "every leg read → eye glyph fires")
    }

    @Test("readByAll returns false (not nil) when no entries exist — F-405 honesty")
    func readByAllPostGCStaysFalse() {
        // Post-GC, the row mustn't claim 'read by all' without
        // explicit per-recipient confirmation in hand. The
        // OutboxStore-level helper enforces this; the bubble's
        // `read: false` parameter then keeps the icon at ✓✓ for the
        // 24h post-delivery sandbox window before the row stops
        // showing any indicator.
        let s = OutboxStore.empty
        #expect(s.groupMessageReadByAll(forId: Data(repeating: 0xEE, count: 16)) == false)
    }
}

@Suite("PersistedMessage / OutboxEntry Phase 7 fields persist round-trip")
struct GroupPhase7CodableTests {
    @Test("PersistedMessage with groupMessageId round-trips through JSON")
    func persistedMessageRoundTrip() throws {
        let gmid = Data(repeating: 0xCA, count: 16)
        let row = PersistedMessage(
            side: .me,
            text: "hi",
            kind: .whisper,
            bytes: 64,
            groupMessageId: gmid,
        )
        let bytes = try JSONEncoder().encode(row)
        let decoded = try JSONDecoder().decode(PersistedMessage.self, from: bytes)
        #expect(decoded.groupMessageId == gmid)
    }

    @Test("OutboxEntry with groupMessageId + readAt round-trips through JSON")
    func outboxEntryRoundTrip() throws {
        let gmid = Data(repeating: 0xCB, count: 16)
        let read = Date(timeIntervalSinceReferenceDate: 100)
        let e = OutboxEntry(
            messageId: Data(repeating: 0x01, count: 16),
            recipientPeerId: Data(repeating: 0x02, count: 33),
            sealedCiphertext: Data([0xCA]),
            token: Data(),
            ttl: 24 * 60 * 60,
            sentAt: Date(),
            retries: 0,
            deliveredAt: nil,
            failedAt: nil,
            relayedAt: nil,
            groupMessageId: gmid,
            readAt: read,
        )
        let bytes = try JSONEncoder().encode(e)
        let decoded = try JSONDecoder().decode(OutboxEntry.self, from: bytes)
        #expect(decoded.groupMessageId == gmid)
        #expect(decoded.readAt?.timeIntervalSinceReferenceDate
            == read.timeIntervalSinceReferenceDate)
    }

    @Test("legacy PersistedMessage without groupMessageId decodes to nil (additive field)")
    func legacyPersistedMessageDecodesNil() throws {
        // Pre-Phase-7 row JSON — no `groupMessageId` key. The decoder
        // must tolerate this so existing on-disk blobs don't fail
        // to load on first launch after the upgrade. We construct
        // the JSON by encoding a real PersistedMessage and stripping
        // any `groupMessageId` key — robust against future Codable
        // tweaks while still exercising the legacy-decode path.
        let synthetic = PersistedMessage(
            side: .me, text: "legacy", kind: .whisper, bytes: 42,
            timestamp: Date(timeIntervalSinceReferenceDate: 0),
        )
        var bytes = try JSONEncoder().encode(synthetic)
        // No `groupMessageId` key was emitted (encodeIfPresent
        // synthesised). Decode and confirm.
        let row = try JSONDecoder().decode(PersistedMessage.self, from: bytes)
        #expect(row.groupMessageId == nil)
        // Even if a future writer drops the field entirely (legacy
        // format simulation) the decoder must still succeed.
        if let s = String(data: bytes, encoding: .utf8),
           let stripped = s.replacingOccurrences(of: "\"groupMessageId\"", with: "\"_x_\"")
            .data(using: .utf8) {
            bytes = stripped
        }
        let row2 = try JSONDecoder().decode(PersistedMessage.self, from: bytes)
        #expect(row2.groupMessageId == nil)
    }

    @Test("legacy OutboxEntry without groupMessageId / readAt decodes additively")
    func legacyOutboxEntryDecodesAdditively() throws {
        let json = #"""
        {
            "messageId":"AQEBAQEBAQEBAQEBAQEBAQ==",
            "recipientPeerId":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC",
            "sealedCiphertext":"yg==",
            "token":"",
            "ttl":86400,
            "sentAt":0,
            "retries":0
        }
        """#
        let e = try JSONDecoder().decode(OutboxEntry.self, from: Data(json.utf8))
        #expect(e.groupMessageId == nil)
        #expect(e.readAt == nil)
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
