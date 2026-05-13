import Foundation

/// Per-(peer, messageId) sliding-window suppressor for sealed-frame
/// duplicate-ACK re-emissions.
///
/// **Why this exists.** The relay's outbound queue is at-least-once:
/// after our reconnect (foreground from background, network handoff,
/// app-switch resume, etc.) it re-delivers every still-unexpired
/// frame in its queue. For an active conversation that's potentially
/// thousands of frames. Libsignal's ratchet correctly flags each
/// re-delivery as `isDuplicate=true`. `ChatStore.handleSealedFrame`'s
/// response — re-emit an ACK so the sender's outbox flips ✓→✓✓ — is
/// correct in the abstract but catastrophic in the redelivery
/// scenario, because every ACK we emit burns one v2 delivery-token
/// from our outbound hash-chain to that peer. The chain length is
/// 16,384. A 7,000-frame redelivery exhausts ~43% of the chain in
/// seconds; sustained churn finishes the chain entirely and every
/// further duplicate logs `cannot emit ACK …: chain missing or
/// exhausted` while the peer keeps retrying, perpetuating the storm
/// at both ends. The captured `xcode logs.rtfd` from 2026-05-13
/// showed exactly this: 22,088 duplicate-frame detections, 5,704
/// chain-exhaustion lines, all from a single peer after a couple of
/// foreground/background cycles.
///
/// The suppressor records every (peer, messageId) pair we've ACK'd.
/// On a duplicate inbound frame, the handler checks the suppressor:
/// if the message was ACK'd within `ttl`, the re-emission is
/// dropped. The original ACK is already in every ready relay's
/// queue (sealed-sender SENDs fan out across all ready relays at
/// emit time), so the peer will see ✓✓ as soon as any of those
/// queues delivers — we don't need to keep minting fresh ACKs.
///
/// Bounded by `capacity` (FIFO eviction) so a pathological peer
/// can't grow this map without bound. Time-bounded by `ttl` so a
/// genuine lost-ACK case — original never reached peer — eventually
/// allows one fresh emit and gives delivery another chance.
///
/// **Thread isolation:** value type, not `Sendable` by design;
/// callers must carry their own isolation. The `ChatStore` host
/// uses MainActor isolation, so every mutation runs on the main
/// actor and no cross-thread synchronisation is needed.
struct DuplicateAckSuppressor {
    /// 10 min is the chosen TTL. Storm bursts finish in seconds; 10
    /// min is comfortably longer than any plausible burst. If our
    /// original ACK genuinely never reached the peer (e.g. our
    /// connection dropped before any relay queue accepted it), the
    /// peer's outbox keeps retrying until either (a) a later replay
    /// of our ACK gets through, or (b) the per-message TTL expires
    /// and they mark the send failed. 10 min vs. infinity here is
    /// the tradeoff: long enough to silence storms; short enough
    /// that a genuine ACK-loss case eventually triggers a fresh
    /// re-emit and gives delivery another chance.
    static let defaultTTL: TimeInterval = 600

    /// 4096 entries × ~50 bytes/entry = ~200 KB. Comfortably bounds
    /// memory regardless of conversation depth or peer behaviour.
    /// At chain length 16,384, this cap leaves room for ~25% of the
    /// chain's worth of distinct messageIds to be tracked at once —
    /// many times the active working set of any normal conversation.
    static let defaultCapacity: Int = 4096

    private var entries: [Data: Date] = [:]
    /// Insertion order, FIFO. `order.count == entries.count` is an
    /// invariant: we only append to `order` on a fresh insert, never
    /// on a timestamp bump. Timestamp updates leave the entry in
    /// place — we accept "FIFO by first-seen" rather than strict
    /// LRU because the cap is coarse and the simpler bookkeeping
    /// has no observable downside in this use case.
    private var order: [Data] = []
    private let ttl: TimeInterval
    private let capacity: Int

    init(ttl: TimeInterval = defaultTTL, capacity: Int = defaultCapacity) {
        precondition(ttl > 0, "TTL must be positive")
        precondition(capacity > 0, "Capacity must be positive")
        self.ttl = ttl
        self.capacity = capacity
    }

    /// Read-only check: should the caller suppress an ACK emission
    /// for this (peer, messageId) pair? `true` iff we've already
    /// recorded an emission within `ttl`. Does NOT mutate state —
    /// callers must follow up with `record` after a successful
    /// emit so the next duplicate is dropped.
    func shouldSuppress(
        peer: Data,
        messageId: Data,
        now: Date = Date()
    ) -> Bool {
        let key = Self.key(peer: peer, messageId: messageId)
        guard let last = entries[key] else { return false }
        return now.timeIntervalSince(last) < ttl
    }

    /// Record that we emitted an ACK for this (peer, messageId)
    /// pair. Subsequent calls to `shouldSuppress` within `ttl`
    /// return `true`. Re-recording an existing pair refreshes the
    /// timestamp but does not change its position in the FIFO —
    /// see the `order` field comment for why.
    mutating func record(
        peer: Data,
        messageId: Data,
        now: Date = Date()
    ) {
        let key = Self.key(peer: peer, messageId: messageId)
        if entries[key] == nil {
            order.append(key)
        }
        entries[key] = now
        evictIfOverCapacity()
    }

    /// Test-observable: current entry count.
    var count: Int { entries.count }

    /// Test hook + recovery path: drop stale entries whose
    /// timestamp is older than `ttl`. Called nowhere in production
    /// (the bounded map and `shouldSuppress`'s TTL gate are
    /// sufficient on their own), but exposed so tests can pin the
    /// TTL semantics deterministically without sleeping.
    mutating func purgeExpired(now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-ttl)
        var keep: [Data] = []
        keep.reserveCapacity(order.count)
        for key in order {
            if let stamp = entries[key], stamp > cutoff {
                keep.append(key)
            } else {
                entries.removeValue(forKey: key)
            }
        }
        order = keep
    }

    private mutating func evictIfOverCapacity() {
        while order.count > capacity {
            let oldest = order.removeFirst()
            entries.removeValue(forKey: oldest)
        }
    }

    /// Compose the dictionary key from `peer ‖ messageId`. Both
    /// inputs are fixed-width in production (peer = 32-byte
    /// identity_pub, messageId = 16-byte UUID) so there's no
    /// length-prefix ambiguity to worry about.
    private static func key(peer: Data, messageId: Data) -> Data {
        var k = Data(capacity: peer.count + messageId.count)
        k.append(peer)
        k.append(messageId)
        return k
    }
}
