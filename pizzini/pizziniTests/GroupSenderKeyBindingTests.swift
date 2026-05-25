import Foundation
import Testing
@testable import pizzini

/// F-GRP-05: a `(sender, distribution_id)` must map to at most one local
/// group, so a malicious shared-group member can't reuse one
/// distribution-id across two groups to render a single sender-key chain
/// in both transcripts (the F-GRP-01 splice, resurfaced via id reuse).
@Suite("Group sender-key cross-group binding")
struct GroupSenderKeyBindingTests {
    private func group(id: UInt8, dist: [Data: UUID]) -> ChatGroup {
        ChatGroup(
            id: Data(repeating: id, count: 16),
            displayName: "g",
            members: [],
            createdAt: Date(timeIntervalSince1970: 0),
            currentEpoch: 0,
            lastOpDigest: Data(repeating: 0, count: 32),
            pendingOps: [],
            log: [],
            lastSeenAt: nil,
            lastMessageAt: nil,
            myCurrentDistributionId: nil,
            memberDistributionIds: dist,
            sentSinceRotation: 0,
            lastRotatedAt: Date(timeIntervalSince1970: 0),
            mySkdmRecipients: [],
            recentOpDigests: [:],
        )
    }

    @Test("a distribution-id already bound to the sender in a DIFFERENT group is a collision")
    func crossGroupReuseDetected() {
        let mallory = Data(repeating: 0xAB, count: 33)
        let d = UUID()
        let g1 = group(id: 0x01, dist: [mallory: d])   // already bound in G1
        let g2 = group(id: 0x02, dist: [:])            // target (G2)
        #expect(ChatStore.distributionIdCollidesAcrossGroups(
            [g1, g2], targetGroupId: g2.id, sender: mallory, dist: d,
        ))
    }

    @Test("re-binding the same id in the SAME group (rotation/re-enrol) is not a collision")
    func sameGroupRebindAllowed() {
        let mallory = Data(repeating: 0xAB, count: 33)
        let d = UUID()
        let g1 = group(id: 0x01, dist: [mallory: d])
        #expect(!ChatStore.distributionIdCollidesAcrossGroups(
            [g1], targetGroupId: g1.id, sender: mallory, dist: d,
        ))
    }

    @Test("a fresh per-group distribution-id is not a collision (honest path)")
    func distinctIdsNoCollision() {
        let mallory = Data(repeating: 0xAB, count: 33)
        let g1 = group(id: 0x01, dist: [mallory: UUID()])
        let g2 = group(id: 0x02, dist: [:])
        #expect(!ChatStore.distributionIdCollidesAcrossGroups(
            [g1, g2], targetGroupId: g2.id, sender: mallory, dist: UUID(),
        ))
    }

    @Test("the same id bound to a DIFFERENT sender is not this sender's collision")
    func otherSenderIdNotCollision() {
        let mallory = Data(repeating: 0xAB, count: 33)
        let alice = Data(repeating: 0x01, count: 33)
        let d = UUID()
        let g1 = group(id: 0x01, dist: [alice: d])     // bound to Alice, not Mallory
        let g2 = group(id: 0x02, dist: [:])
        #expect(!ChatStore.distributionIdCollidesAcrossGroups(
            [g1, g2], targetGroupId: g2.id, sender: mallory, dist: d,
        ))
    }
}
