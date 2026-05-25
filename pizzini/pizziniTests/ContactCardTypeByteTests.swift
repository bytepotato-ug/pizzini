import Testing
import Foundation
@testable import pizzini

@Suite("ContactCard IdentityKey type-byte validation (F-PAIR-02)")
struct ContactCardTypeByteTests {
    /// 33-byte peer id (0,1,…,32) with a chosen first byte, rendered into the
    /// `pizzini1://<hex>@host:port` card form. Bytes are distinct, so the
    /// entropy floor is satisfied and parsing reaches the type-byte check.
    private func cardString(firstByte: UInt8) -> String {
        var bytes: [UInt8] = (0...32).map { UInt8($0) } // 33 bytes
        bytes[0] = firstByte
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        return "pizzini1://\(hex)@relay.example:1"
    }

    @Test("rejects a non-0x05 IdentityKey type byte")
    func rejectsWrongTypeByte() {
        #expect(throws: ContactCardDecodeError.self) {
            try ContactCard.validate(cardString(firstByte: 0x01))
        }
    }

    @Test("accepts a well-formed 0x05-prefixed identity")
    func acceptsValidCard() throws {
        let card = try ContactCard.validate(cardString(firstByte: 0x05))
        #expect(card.peerId.count == 33)
        #expect(card.peerId.first == 0x05)
    }
}
