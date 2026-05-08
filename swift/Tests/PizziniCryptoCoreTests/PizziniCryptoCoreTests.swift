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

    @Test("two Session instances exchange messages via wire bytes")
    func sessionRoundTrip() throws {
        let alice = try Session()
        let bob = try Session()

        let bobBundle = try bob.publishBundle()
        let bobId = try bob.identityPublic()
        let aliceId = try alice.identityPublic()

        try alice.initiateSession(peerIdentity: bobId, bundle: bobBundle)

        let m1 = try alice.encrypt(peerIdentity: bobId, plaintext: Data("hi bob".utf8))
        #expect(m1.messageType == .preKey)
        let pt1 = try bob.decrypt(peerIdentity: aliceId, ciphertext: m1.ciphertext, isPreKey: true)
        #expect(String(data: pt1, encoding: .utf8) == "hi bob")

        let m2 = try bob.encrypt(peerIdentity: aliceId, plaintext: Data("hi alice".utf8))
        #expect(m2.messageType == .whisper)
        let pt2 = try alice.decrypt(peerIdentity: bobId, ciphertext: m2.ciphertext, isPreKey: false)
        #expect(String(data: pt2, encoding: .utf8) == "hi alice")
    }

    @Test("Session rehydrates from saved identity seed")
    func sessionRehydrate() throws {
        let s = try Session()
        let seed = try s.identityKeypairBytes()
        let pubA = try s.identityPublic()

        let s2 = try Session(identitySeed: seed)
        let pubB = try s2.identityPublic()
        #expect(pubA == pubB)
    }
}
