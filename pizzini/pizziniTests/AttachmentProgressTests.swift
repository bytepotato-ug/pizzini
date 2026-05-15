import Foundation
import Testing
@testable import pizzini

/// U4 — pin the chunked-attachment progress percentage. The pure
/// function `attachmentProgressPercent(chunksAcked:totalChunks:)`
/// drives the thin progress bar at the bottom of an outbound
/// attachment bubble. Four canonical samples: 0%, 50%, 100%, and
/// the divide-by-zero / empty-chunks-array edge.
///
/// The bar tracks bytes-leaving-the-device (relayed + delivered),
/// not peer ACKs alone, because the user is staring at the UI
/// during upload and the relay-handoff tier is the latency-
/// sensitive one (peer ACKs depend on the recipient being online,
/// which is out of the sender's hands).
@Suite("attachmentProgressPercent")
struct AttachmentProgressTests {
    @Test func zeroPercentWhenNoChunksAcked() {
        #expect(attachmentProgressPercent(chunksAcked: 0, totalChunks: 8) == 0.0)
    }

    @Test func halfWhenHalfAcked() {
        #expect(attachmentProgressPercent(chunksAcked: 4, totalChunks: 8) == 0.5)
    }

    @Test func fullWhenAllAcked() {
        #expect(attachmentProgressPercent(chunksAcked: 8, totalChunks: 8) == 1.0)
    }

    /// Divide-by-zero edge: a zero-chunk attachment makes no
    /// sense at the wire layer, but a defensive `0.0` keeps the
    /// progress-bar caller from crashing if the chunked-attachment
    /// rollup somehow returns total=0 (e.g. mid-GC). The UI
    /// caller already gates on `total > 0` before showing the
    /// bar, but the pure function defends in depth. Pin the
    /// over-clamp and the under-clamp too — a stale acked count
    /// vs. a fresh total shouldn't push the bar past 100% or
    /// below 0%.
    @Test func zeroTotalReturnsZero() {
        #expect(attachmentProgressPercent(chunksAcked: 0, totalChunks: 0) == 0.0)
        #expect(attachmentProgressPercent(chunksAcked: 99, totalChunks: 8) == 1.0)
        #expect(attachmentProgressPercent(chunksAcked: -3, totalChunks: 8) == 0.0)
    }

    /// `OutboxStore.attachmentChunkCounts(forId:)` is the
    /// production caller; pin its counters against a synthetic
    /// 8-chunk outbox so a future tweak in the count semantics
    /// surfaces here. Mix one of each tier.
    @Test func chunkCountsPickPerTier() {
        let aid = Data(repeating: 0xAA, count: 16)
        let peer = Data(repeating: 0xBB, count: 33)
        var outbox = OutboxStore.empty
        let now = Date()

        func chunk(index: UInt32, configure: (inout OutboxEntry) -> Void) -> OutboxEntry {
            var mid = Data(count: 16); mid[0] = UInt8(index)
            var c = OutboxEntry(
                messageId: mid,
                recipientPeerId: peer,
                sealedCiphertext: Data([0x01]),
                token: Data(repeating: 0xCC, count: 52),
                ttl: 86400,
                sentAt: now,
                retries: 0,
                deliveredAt: nil,
                failedAt: nil,
                relayedAt: nil,
                attachmentId: aid,
                chunkIndex: index,
                chunkCount: 8,
            )
            configure(&c)
            return c
        }

        // 1 pending, 2 relayed, 3 delivered, 2 failed
        outbox.entries[chunk(index: 0) { _ in }.messageId] = chunk(index: 0) { _ in }
        outbox.entries[chunk(index: 1) { $0.relayedAt = now }.messageId] =
            chunk(index: 1) { $0.relayedAt = now }
        outbox.entries[chunk(index: 2) { $0.relayedAt = now }.messageId] =
            chunk(index: 2) { $0.relayedAt = now }
        outbox.entries[chunk(index: 3) { $0.deliveredAt = now }.messageId] =
            chunk(index: 3) { $0.deliveredAt = now }
        outbox.entries[chunk(index: 4) { $0.deliveredAt = now }.messageId] =
            chunk(index: 4) { $0.deliveredAt = now }
        outbox.entries[chunk(index: 5) { $0.deliveredAt = now }.messageId] =
            chunk(index: 5) { $0.deliveredAt = now }
        outbox.entries[chunk(index: 6) { $0.failedAt = now }.messageId] =
            chunk(index: 6) { $0.failedAt = now }
        outbox.entries[chunk(index: 7) { $0.failedAt = now }.messageId] =
            chunk(index: 7) { $0.failedAt = now }

        let counts = outbox.attachmentChunkCounts(forId: aid)
        #expect(counts.total == 8)
        #expect(counts.pending == 1)
        #expect(counts.relayed == 2)
        #expect(counts.delivered == 3)
        #expect(counts.failed == 2)

        // 5/8 chunks acked (relayed + delivered) = 0.625
        let pct = attachmentProgressPercent(
            chunksAcked: counts.relayed + counts.delivered,
            totalChunks: counts.total,
        )
        #expect(pct == 0.625)
    }
}
