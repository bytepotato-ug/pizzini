import Foundation
import Testing
@testable import pizzini

@Suite("Outbox state machine")
struct OutboxTests {
    private func sample(retries: Int = 0, sentAt: Date = Date()) -> OutboxEntry {
        OutboxEntry(
            messageId: Data(repeating: 0xAA, count: 16),
            recipientPeerId: Data(repeating: 0xBB, count: 33),
            sealedCiphertext: Data([0xCA, 0xFE]),
            token: Data(repeating: 0xCC, count: 84),
            ttl: 24 * 60 * 60,
            sentAt: sentAt,
            retries: retries,
            deliveredAt: nil,
            failedAt: nil,
            relayedAt: nil
        )
    }

    @Test("OutboxEntry encodes / decodes with every field set")
    func codableRoundTrip() throws {
        var e = sample()
        e.relayedAt = Date(timeIntervalSinceReferenceDate: 1)
        e.deliveredAt = Date(timeIntervalSinceReferenceDate: 2)
        e.failedAt = Date(timeIntervalSinceReferenceDate: 3)
        let data = try JSONEncoder().encode(e)
        let decoded = try JSONDecoder().decode(OutboxEntry.self, from: data)
        #expect(decoded.messageId == e.messageId)
        #expect(decoded.recipientPeerId == e.recipientPeerId)
        #expect(decoded.sealedCiphertext == e.sealedCiphertext)
        #expect(decoded.token == e.token)
        #expect(decoded.ttl == e.ttl)
        // JSONEncoder rounds Date to second-precision differently across
        // platforms; equality on epoch-seconds is the safe check.
        #expect(decoded.relayedAt?.timeIntervalSinceReferenceDate ==
                e.relayedAt?.timeIntervalSinceReferenceDate)
        #expect(decoded.deliveredAt?.timeIntervalSinceReferenceDate ==
                e.deliveredAt?.timeIntervalSinceReferenceDate)
        #expect(decoded.failedAt?.timeIntervalSinceReferenceDate ==
                e.failedAt?.timeIntervalSinceReferenceDate)
        #expect(decoded.retries == e.retries)
    }

    @Test("status reflects deliveredAt / failedAt / relayedAt precedence")
    func statusPrecedence() {
        var e = sample()
        #expect(e.status == .pending)
        e.relayedAt = Date()
        #expect(e.status == .relayed)
        e.deliveredAt = Date()
        #expect(e.status == .delivered)
        e.deliveredAt = nil
        e.failedAt = Date()
        #expect(e.status == .failed)
    }

    @Test("shouldRetry waits 30s on first attempt, then increments")
    func retryBackoff() {
        let now = Date()
        let e0 = sample(retries: 0, sentAt: now.addingTimeInterval(-29))
        #expect(!e0.shouldRetry(now: now))
        let e1 = sample(retries: 0, sentAt: now.addingTimeInterval(-31))
        #expect(e1.shouldRetry(now: now))
        // Second retry: floor of 60s.
        let e2 = sample(retries: 1, sentAt: now.addingTimeInterval(-59))
        #expect(!e2.shouldRetry(now: now))
        let e3 = sample(retries: 1, sentAt: now.addingTimeInterval(-61))
        #expect(e3.shouldRetry(now: now))
    }

    @Test("shouldRetry stops at maxRetries")
    func retryCap() {
        let e = sample(retries: OutboxEntry.maxRetries, sentAt: Date(timeIntervalSinceNow: -3600))
        #expect(!e.shouldRetry(now: Date()))
    }

    @Test("hasExpired fires after ttl elapses without ACK")
    func ttlExpiry() {
        let now = Date()
        let young = sample(sentAt: now.addingTimeInterval(-(60 * 60)))      // 1h old, 24h ttl
        #expect(!young.hasExpired(now: now))
        var old = sample(sentAt: now.addingTimeInterval(-(25 * 60 * 60)))   // 25h old
        #expect(old.hasExpired(now: now))
        // …unless we already ACKed.
        old.deliveredAt = now.addingTimeInterval(-100)
        #expect(!old.hasExpired(now: now))
    }
}

@Suite("Contact read-receipt + TTL settings")
struct ContactSettingsTests {
    @Test("readReceiptsEnabled defaults off")
    func readReceiptsDefault() {
        let c = Contact(identityPub: Data(repeating: 1, count: 33), displayName: "x")
        #expect(c.readReceiptsEnabled == false)
    }

    @Test("ttlSeconds defaults to 1 day")
    func ttlDefault() {
        let c = Contact(identityPub: Data(repeating: 1, count: 33), displayName: "x")
        #expect(c.ttlSeconds == Contact.defaultTTLSeconds)
        #expect(c.ttlSeconds == 24 * 60 * 60)
    }
}
