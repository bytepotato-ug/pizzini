import Testing
import Foundation
@testable import pizzini

@Suite("Outbox ACK recipient scoping (F-PAIR-01)")
struct OutboxAckScopingTests {
    // An ACK from contact X may only confirm delivery of an entry addressed
    // TO X. A messageId is 16 random bytes sealed only to the recipient, so
    // a different contact should never be able to flip a ✓✓ even if it knew
    // the id — the predicate is the authorisation backstop.
    @Test("ACK from the addressed recipient is accepted")
    func ackFromRecipientAccepted() {
        let peer = Data(repeating: 0xA1, count: 33)
        #expect(ChatStore.ackMayMarkEntry(entryRecipient: peer, ackSender: peer))
    }

    @Test("ACK from a different contact is rejected")
    func ackFromOtherContactRejected() {
        let recipient = Data(repeating: 0xA1, count: 33)
        let other = Data(repeating: 0xB2, count: 33)
        #expect(!ChatStore.ackMayMarkEntry(entryRecipient: recipient, ackSender: other))
    }

    @Test("a one-byte difference is rejected")
    func ackNearMissRejected() {
        var recipient = Data(repeating: 0x05, count: 33)
        var other = recipient
        other[32] ^= 0x01
        #expect(!ChatStore.ackMayMarkEntry(entryRecipient: recipient, ackSender: other))
        // sanity: identical still accepted
        recipient[0] = 0x05
        #expect(ChatStore.ackMayMarkEntry(entryRecipient: recipient, ackSender: recipient))
    }
}
