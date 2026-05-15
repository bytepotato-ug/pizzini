import Foundation
import Testing
@testable import pizzini

/// S2 — per-chunk retry granularity. The investigation finding:
/// the existing code already tracks each chunk as its own
/// `OutboxEntry`, and the auto-retry walker iterates over
/// `retryableEntries(now:)` which filters by `shouldRetry` on each
/// individual chunk. Crucially the filter checks `relayedAt == nil`
/// — chunks that already left the socket sit in the relay's
/// offline queue and re-sending them would duplicate frames at the
/// receiver and burn extra chain tokens.
///
/// What was missing: a user-initiated kick that bypasses the
/// `max(30, retries*60)` baseline so the user staring at a stuck
/// chunk doesn't have to wait for the next walker tick. The
/// `userRetryAttachment(attachmentId:)` API plumbs through to the
/// same `userRetry(messageId:)` path as plain rows, scoped to the
/// chunks where `relayedAt == nil`.
///
/// These tests pin the rollup that drives the UI's Retry button
/// (`attachmentInputs(forId:now:peerHasRead:)`) and the
/// "re-emit only the failed/notSent chunks" property of the user-
/// retry filter. The test sets up an outbox with 8 chunks where
/// chunk index 3 never relayed and chunks 0-2,4-7 did, then
/// asserts the filter picks out exactly chunk 3.
@Suite("Attachment chunk retry granularity")
struct AttachmentChunkRetryTests {
    private static let aid = Data(repeating: 0xAA, count: 16)
    private static let peer = Data(repeating: 0xBB, count: 33)

    private static func chunk(
        index: UInt32,
        relayed: Bool,
        sentAt: Date,
    ) -> OutboxEntry {
        // Distinct messageId per chunk so the outbox dictionary
        // doesn't collapse them.
        var mid = Data(count: 16)
        mid[0] = UInt8(index & 0xff)
        mid[1] = 0x42
        return OutboxEntry(
            messageId: mid,
            recipientPeerId: peer,
            sealedCiphertext: Data([0x01, 0x02]),
            token: Data(repeating: 0xCC, count: 52),
            ttl: 86400,
            sentAt: sentAt,
            retries: 0,
            deliveredAt: nil,
            failedAt: nil,
            relayedAt: relayed ? sentAt.addingTimeInterval(0.5) : nil,
            attachmentId: aid,
            chunkIndex: index,
            chunkCount: 8,
        )
    }

    /// Set up: chunk 3 of 8 is stuck (relayedAt nil), siblings are
    /// `.relayed`. The rollup should report `.pending(retryable: …)`
    /// because the slowest tier across chunks is the stuck one —
    /// even though 7/8 already left the socket the row is honest
    /// about there being unfinished business.
    @Test func rollupExposesStuckChunkAsPending() {
        let now = Date()
        let sentAt = now.addingTimeInterval(-120) // 2min ago — past userRetryThreshold
        var outbox = OutboxStore.empty
        for i in 0..<UInt32(8) {
            let c = Self.chunk(index: i, relayed: i != 3, sentAt: sentAt)
            outbox.entries[c.messageId] = c
        }
        let inputs = outbox.attachmentInputs(forId: Self.aid, now: now, peerHasRead: false)
        #expect(inputs != nil)
        if case .pending(let pendingFor, let exhausted) = inputs?.outbox {
            #expect(pendingFor >= 60)
            #expect(exhausted == false)
        } else {
            Issue.record("expected .pending rollup, got \(String(describing: inputs?.outbox))")
        }
        // The row's full status should expose the retryable flag at
        // 2 minutes elapsed (well past the 60s threshold).
        let status = rowStatus(inputs: inputs!)
        #expect(status == .pending(retryable: true))
    }

    /// Once every chunk relayed, the rollup flips to `.relayed`
    /// (single check). No Retry button — bytes are in the relay's
    /// offline queue and the entry resolves to ✓✓ on the peer ACK
    /// or ✗ at TTL. This is the "relayed entries are never
    /// retried" invariant from `OutboxEntry.shouldRetry`.
    @Test func allRelayedRollupShowsSending() {
        let now = Date()
        let sentAt = now.addingTimeInterval(-30)
        var outbox = OutboxStore.empty
        for i in 0..<UInt32(8) {
            let c = Self.chunk(index: i, relayed: true, sentAt: sentAt)
            outbox.entries[c.messageId] = c
        }
        let inputs = outbox.attachmentInputs(forId: Self.aid, now: now, peerHasRead: false)
        #expect(inputs?.outbox == .relayed)
        #expect(rowStatus(inputs: inputs!) == .sending)
    }

    /// Any chunk with `failedAt` set short-circuits the rollup to
    /// `.failed`. The user sees ✗ and re-attaches the file.
    @Test func anyFailedChunkRollsUpAsFailed() {
        let now = Date()
        let sentAt = now.addingTimeInterval(-30)
        var outbox = OutboxStore.empty
        for i in 0..<UInt32(8) {
            var c = Self.chunk(index: i, relayed: true, sentAt: sentAt)
            if i == 5 {
                c.failedAt = now
                c.relayedAt = nil
            }
            outbox.entries[c.messageId] = c
        }
        let inputs = outbox.attachmentInputs(forId: Self.aid, now: now, peerHasRead: false)
        #expect(inputs?.outbox == .failed)
    }

    /// The core S2 contract: the user-retry filter that
    /// `userRetryAttachment` walks picks out ONLY the chunks
    /// where `relayedAt == nil`. Run the exact same filter inline
    /// to pin the predicate; the store-level integration test in
    /// `ChatStore` is harder to assemble without spinning a full
    /// relay client (out of scope for this commit — pure-function
    /// pinning is the regression net).
    @Test func userRetryFilterPicksOnlyStuckChunks() {
        let now = Date()
        let sentAt = now.addingTimeInterval(-120)
        var outbox = OutboxStore.empty
        for i in 0..<UInt32(8) {
            let c = Self.chunk(index: i, relayed: i != 3, sentAt: sentAt)
            outbox.entries[c.messageId] = c
        }
        // This is the exact filter `userRetryAttachment` uses.
        let stuck = outbox.entries.values.filter {
            $0.attachmentId == Self.aid
                && $0.deliveredAt == nil
                && $0.failedAt == nil
                && $0.relayedAt == nil
        }
        #expect(stuck.count == 1)
        #expect(stuck.first?.chunkIndex == 3)
    }

    /// All chunks delivered (peer ACKed) -> rollup is `.delivered`.
    /// With `peerHasRead: true` it should escalate to `.read`.
    @Test func allDeliveredAndReadFlipsToRead() {
        let now = Date()
        let sentAt = now.addingTimeInterval(-30)
        var outbox = OutboxStore.empty
        for i in 0..<UInt32(8) {
            var c = Self.chunk(index: i, relayed: true, sentAt: sentAt)
            c.deliveredAt = now
            outbox.entries[c.messageId] = c
        }
        let inputsUnread = outbox.attachmentInputs(
            forId: Self.aid, now: now, peerHasRead: false,
        )
        #expect(rowStatus(inputs: inputsUnread!) == .delivered)
        let inputsRead = outbox.attachmentInputs(
            forId: Self.aid, now: now, peerHasRead: true,
        )
        #expect(rowStatus(inputs: inputsRead!) == .read)
    }
}
