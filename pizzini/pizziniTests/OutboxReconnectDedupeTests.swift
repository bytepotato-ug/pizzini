// S4: dedupe contract on the CLIENT side of a relay reconnect.
//
// The relay-side dedupe (in `relay/src/main.rs`) is the
// belt-and-braces — it stops the recipient seeing the same
// message twice when a reconnect retry lands the same SEND on
// the same relay. The CLIENT side of the contract is just as
// load-bearing: the outbox-state cache that decides whether a
// retry fires at all MUST survive socket teardown.
//
// In this codebase that cache is `OutboxEntry.relayedAt` /
// `.deliveredAt` / `.failedAt`, persisted to SQLCipher. The retry
// walk (`shouldRetry`) reads those flags every time it considers
// re-broadcasting. The contract: once the entry is "relayed" or
// "delivered" or "failed", `shouldRetry` returns false — period,
// across any number of socket lifecycles.
//
// This test pins that contract via Codable round-trip (the same
// path SQLCipher persistence uses). If a future refactor changes
// the persistence shape and silently drops one of those Dates,
// the retry walk would re-broadcast already-delivered SENDs after
// every reconnect — the exact duplicate-delivery failure mode the
// dedupe layer exists to prevent.

import Foundation
import Testing
@testable import pizzini

@Suite("Outbox state survives relay reconnect (S4 client-side)")
struct OutboxReconnectDedupeTests {

    private static func makeEntry(
        relayedAt: Date?,
        deliveredAt: Date?,
        failedAt: Date?,
    ) -> OutboxEntry {
        OutboxEntry(
            messageId: Data(repeating: 0xAB, count: 16),
            recipientPeerId: Data(repeating: 0xCD, count: 33),
            sealedCiphertext: Data(repeating: 0xEF, count: 256),
            token: Data(repeating: 0x42, count: 52),
            ttl: 7 * 24 * 60 * 60,
            sentAt: Date().addingTimeInterval(-120),
            retries: 0,
            deliveredAt: deliveredAt,
            failedAt: failedAt,
            relayedAt: relayedAt,
        )
    }

    private static func roundTripJSON(_ entry: OutboxEntry) throws -> OutboxEntry {
        let data = try JSONEncoder().encode(entry)
        return try JSONDecoder().decode(OutboxEntry.self, from: data)
    }

    // MARK: - The four state pins

    /// A relayed entry never retries after a simulated socket
    /// round-trip. Without this guarantee a reconnect would
    /// re-broadcast an already-accepted SEND and rely on the
    /// relay's dedupe layer to absorb the duplicate; the client
    /// side must hold its end of that contract.
    @Test func relayedEntrySurvivesReconnectAndDoesNotRetry() throws {
        let now = Date()
        let entry = Self.makeEntry(
            relayedAt: now.addingTimeInterval(-90),
            deliveredAt: nil,
            failedAt: nil,
        )
        let restored = try Self.roundTripJSON(entry)
        #expect(restored.relayedAt != nil)
        #expect(restored.shouldRetry(now: now) == false)
    }

    /// A delivered entry (end-to-end ACK in hand) never retries
    /// across a reconnect. This is the canonical "we already saw
    /// the ACK for this message_id" case the brief calls out.
    @Test func deliveredEntrySurvivesReconnectAndDoesNotRetry() throws {
        let now = Date()
        let entry = Self.makeEntry(
            relayedAt: now.addingTimeInterval(-90),
            deliveredAt: now.addingTimeInterval(-30),
            failedAt: nil,
        )
        let restored = try Self.roundTripJSON(entry)
        #expect(restored.deliveredAt != nil)
        #expect(restored.shouldRetry(now: now) == false)
    }

    /// A failed entry never retries either — terminal states are
    /// terminal regardless of socket state.
    @Test func failedEntrySurvivesReconnectAndDoesNotRetry() throws {
        let now = Date()
        let entry = Self.makeEntry(
            relayedAt: nil,
            deliveredAt: nil,
            failedAt: now.addingTimeInterval(-10),
        )
        let restored = try Self.roundTripJSON(entry)
        #expect(restored.failedAt != nil)
        #expect(restored.shouldRetry(now: now) == false)
    }

    /// The negative pin: an entry that NEVER reached a relay is
    /// the ONLY case where a reconnect-driven retry should fire.
    /// `relayedAt == nil` AND retry baseline elapsed → shouldRetry
    /// is true; the retry walk picks it up after the reconnect.
    @Test func unrelayedEntryDoesRetryAfterBaselineElapsed() throws {
        // sentAt is 120s ago; baseline for retries=0 is 30s; so
        // shouldRetry is true.
        let now = Date()
        let entry = Self.makeEntry(
            relayedAt: nil,
            deliveredAt: nil,
            failedAt: nil,
        )
        let restored = try Self.roundTripJSON(entry)
        #expect(restored.relayedAt == nil)
        #expect(restored.shouldRetry(now: now) == true)
    }
}
