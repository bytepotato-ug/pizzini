import Foundation
import Testing
@testable import pizzini

/// JSON `Codable` round-trip tests for `ChatGroup`, `GroupMember`,
/// and `PersistedMessage` post-audit additions. Closes audit gaps
/// "no JSONEncoder round-trip test for ChatGroup" and locks in the
/// shape of the new fields:
///
///   - `ChatGroup.mySkdmRecipients` (HIGH-2 plumbing)
///   - `GroupMember.addedBy` (MEDIUM-2 caption)
///   - `PersistedMessage.senderPeerId` (MEDIUM-7 render-time names)
///
/// `[Data: UUID]` and `Set<Data>` round-trip through JSON's
/// alternating-array / array-of-base64 conventions; the tests verify
/// the actual on-disk shape doesn't lose data.

@Suite("ChatGroup persistence")
struct ChatGroupPersistenceTests {
    @Test("ChatGroup round-trips through JSONEncoder/JSONDecoder with all fields populated")
    func fullRoundTrip() throws {
        let alice = Data(repeating: 0x01, count: 33)
        let bob = Data(repeating: 0x02, count: 33)
        let aliceDist = UUID()
        let bobDist = UUID()
        let group = ChatGroup(
            id: Data(repeating: 0xAA, count: 16),
            displayName: "round-trip",
            members: [
                GroupMember(peerId: alice, displayName: "Alice", role: .admin,
                            joinedAtEpoch: 0, status: .active, addedBy: alice),
                GroupMember(peerId: bob, displayName: "Bob", role: .member,
                            joinedAtEpoch: 1, status: .pendingSKDM, addedBy: alice),
            ],
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            currentEpoch: 5,
            lastOpDigest: Data(repeating: 0xCC, count: 32),
            pendingOps: [Data([0xDE, 0xAD, 0xBE, 0xEF])],
            log: [
                PersistedMessage(side: .me, text: "hi", kind: .whisper, bytes: 100),
                PersistedMessage(side: .peer, text: "hello back", kind: .whisper,
                                 bytes: 100, senderPeerId: bob),
            ],
            lastSeenAt: Date(timeIntervalSince1970: 1_700_001_000),
            lastMessageAt: Date(timeIntervalSince1970: 1_700_002_000),
            myCurrentDistributionId: aliceDist,
            memberDistributionIds: [alice: aliceDist, bob: bobDist],
            sentSinceRotation: 17,
            lastRotatedAt: Date(timeIntervalSince1970: 1_700_003_000),
            mySkdmRecipients: [bob],
            recentOpDigests: ["0": Data(repeating: 0x00, count: 32),
                              "5": Data(repeating: 0xCC, count: 32)],
        )

        let encoded = try JSONEncoder().encode(group)
        let decoded = try JSONDecoder().decode(ChatGroup.self, from: encoded)

        #expect(decoded.id == group.id)
        #expect(decoded.displayName == group.displayName)
        #expect(decoded.members.count == 2)
        #expect(decoded.members[0].addedBy == alice)
        #expect(decoded.members[1].addedBy == alice)
        #expect(decoded.currentEpoch == 5)
        #expect(decoded.lastOpDigest == group.lastOpDigest)
        #expect(decoded.pendingOps == group.pendingOps)
        #expect(decoded.log.count == 2)
        #expect(decoded.log[1].senderPeerId == bob)
        #expect(decoded.myCurrentDistributionId == aliceDist)
        #expect(decoded.memberDistributionIds[alice] == aliceDist)
        #expect(decoded.memberDistributionIds[bob] == bobDist)
        #expect(decoded.sentSinceRotation == 17)
        #expect(decoded.mySkdmRecipients == [bob])
        #expect(decoded.recentOpDigests["0"] == Data(repeating: 0x00, count: 32))
        #expect(decoded.recentOpDigests["5"] == Data(repeating: 0xCC, count: 32))
    }

    @Test("pre-audit ChatGroup blob (no `mySkdmRecipients`) decodes with default")
    func backCompatNoSkdmRecipients() throws {
        // Build a JSON blob in the pre-audit shape: every required
        // field present, but no `mySkdmRecipients` key. The decoder's
        // `decodeIfPresent` fallback should populate it with `[]`.
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
        #expect(decoded.mySkdmRecipients.isEmpty)
        #expect(decoded.members[0].addedBy == nil,
                "pre-audit GroupMember blobs lacked addedBy; default is nil")
    }

    @Test("Set<Data> mySkdmRecipients survives ordering changes through JSON")
    func setOrderingAgnostic() throws {
        // Sets have no encode order — round-trip must still decode
        // back to the same set regardless of how JSONEncoder emits
        // the array elements.
        let a = Data([0x01])
        let b = Data([0x02])
        let c = Data([0x03])
        let group = makeMinimalGroup(skdmRecipients: [a, b, c])
        let bytes = try JSONEncoder().encode(group)
        let decoded = try JSONDecoder().decode(ChatGroup.self, from: bytes)
        #expect(decoded.mySkdmRecipients == [a, b, c])
    }

    @Test("memberDistributionIds round-trips with multiple Data keys")
    func memberDistributionIdsRoundTrip() throws {
        let alice = Data(repeating: 0x01, count: 33)
        let bob = Data(repeating: 0x02, count: 33)
        let carol = Data(repeating: 0x03, count: 33)
        let aliceUUID = UUID()
        let bobUUID = UUID()
        let carolUUID = UUID()
        let group = makeMinimalGroup(
            memberDistributionIds: [alice: aliceUUID, bob: bobUUID, carol: carolUUID])
        let decoded = try JSONDecoder().decode(
            ChatGroup.self, from: try JSONEncoder().encode(group))
        #expect(decoded.memberDistributionIds.count == 3)
        #expect(decoded.memberDistributionIds[alice] == aliceUUID)
        #expect(decoded.memberDistributionIds[bob] == bobUUID)
        #expect(decoded.memberDistributionIds[carol] == carolUUID)
    }

    @Test("recentOpDigests window self-trims at the configured ceiling")
    func recentOpDigestsTrimsAtWindow() throws {
        // Insert N+10 entries; the window should hold at most N
        // (steady-state, not oscillate to 2N as the pre-audit
        // implementation did — audit LOW-3).
        var group = makeMinimalGroup()
        let cap = ChatGroup.recentOpDigestsWindow
        for i in 0..<(cap + 10) {
            group.recordDigest(Data(repeating: UInt8(i & 0xFF), count: 32),
                               atEpoch: UInt64(i))
        }
        #expect(group.recentOpDigests.count <= cap)
        #expect(group.recentOpDigests.count >= cap - 10,
                "the window keeps the most recent ~cap entries")
    }
}

@Suite("PersistedMessage senderPeerId persistence")
struct PersistedMessageSenderPeerIdTests {
    @Test("PersistedMessage with senderPeerId round-trips")
    func roundTrip() throws {
        let bob = Data(repeating: 0x02, count: 33)
        let row = PersistedMessage(
            side: .peer, text: "hello", kind: .whisper, bytes: 50,
            senderPeerId: bob)
        let bytes = try JSONEncoder().encode(row)
        let decoded = try JSONDecoder().decode(PersistedMessage.self, from: bytes)
        #expect(decoded.senderPeerId == bob)
        #expect(decoded.text == "hello")
    }

    @Test("legacy PersistedMessage without senderPeerId decodes with nil")
    func legacyDecode() throws {
        // No `senderPeerId` key — decoder must default to nil.
        let json = #"""
        {
            "id": "00000000-0000-0000-0000-000000000000",
            "side": "peer",
            "text": "legacy",
            "kind": "whisper",
            "bytes": 0,
            "timestamp": 0
        }
        """#
        let data = Data(json.utf8)
        let decoded = try JSONDecoder().decode(PersistedMessage.self, from: data)
        #expect(decoded.senderPeerId == nil)
        #expect(decoded.text == "legacy")
    }
}

// ─── helpers ──────────────────────────────────────────────────────────

private func makeMinimalGroup(
    skdmRecipients: Set<Data> = [],
    memberDistributionIds: [Data: UUID] = [:],
) -> ChatGroup {
    let alice = Data(repeating: 0x01, count: 33)
    return ChatGroup(
        id: Data(repeating: 0xAA, count: 16),
        displayName: "g",
        members: [
            GroupMember(peerId: alice, displayName: "a", role: .admin,
                        joinedAtEpoch: 0, status: .active),
        ],
        createdAt: Date(timeIntervalSince1970: 0),
        currentEpoch: 0,
        lastOpDigest: Data(repeating: 0, count: 32),
        pendingOps: [],
        log: [],
        lastSeenAt: nil,
        lastMessageAt: nil,
        myCurrentDistributionId: nil,
        memberDistributionIds: memberDistributionIds,
        sentSinceRotation: 0,
        lastRotatedAt: Date(timeIntervalSince1970: 0),
        mySkdmRecipients: skdmRecipients,
        recentOpDigests: [:])
}
