import Testing
import Foundation
@testable import PizziniCryptoCore

@Suite("PizziniCryptoCore FFI")
struct PizziniCryptoCoreTests {
    @Test("version is non-empty and matches semver-ish shape")
    func version() {
        let v = PizziniCryptoCore.version
        #expect(!v.isEmpty)
        // Crate version is "0.0.0" today — at minimum, three dot-separated parts.
        #expect(v.split(separator: ".").count >= 3)
    }

    @Test("generate produces a non-empty serialized keypair")
    func generate() throws {
        let kp = try IdentityKeyPair.generate()
        #expect(!kp.bytes.isEmpty)
    }

    @Test("two generations produce different keypairs")
    func freshness() throws {
        let a = try IdentityKeyPair.generate()
        let b = try IdentityKeyPair.generate()
        #expect(a.bytes != b.bytes)
    }

    @Test("loopback first message is PreKey and round-trips")
    func loopbackPreKey() throws {
        let s = try LoopbackSession()
        let r = try s.aliceSend("hello over PQXDH")
        #expect(r.messageType == .preKey)
        #expect(String(data: r.decrypted, encoding: .utf8) == "hello over PQXDH")
        #expect(r.ciphertext.count > 0)
    }

    @Test("loopback flips to Whisper after a Bob reply")
    func loopbackWhisper() throws {
        let s = try LoopbackSession()
        _ = try s.aliceSend("first")
        let bobReply = try s.bobSend("ack")
        #expect(bobReply.messageType == .whisper)
        let r3 = try s.aliceSend("second")
        #expect(r3.messageType == .whisper)
        #expect(String(data: r3.decrypted, encoding: .utf8) == "second")
    }
}
