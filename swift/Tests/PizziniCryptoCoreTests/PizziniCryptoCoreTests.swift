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

    @Test("Session serialize/init(serialized:) keeps the ratchet alive")
    func sessionSerializeContinuesRatchet() throws {
        let alice = try Session()
        let bob = try Session()
        let bobBundle = try bob.publishBundle()
        let bobId = try bob.identityPublic()
        let aliceId = try alice.identityPublic()

        try alice.initiateSession(peerIdentity: bobId, bundle: bobBundle)
        let m1 = try alice.encrypt(peerIdentity: bobId, plaintext: Data("hi".utf8))
        _ = try bob.decrypt(peerIdentity: aliceId, ciphertext: m1.ciphertext, isPreKey: true)
        let m2 = try bob.encrypt(peerIdentity: aliceId, plaintext: Data("yo".utf8))
        _ = try alice.decrypt(peerIdentity: bobId, ciphertext: m2.ciphertext, isPreKey: false)

        let snapshot = try alice.serialize()
        let alice2 = try Session(serialized: snapshot)
        let m3 = try alice2.encrypt(peerIdentity: bobId, plaintext: Data("still here".utf8))
        #expect(m3.messageType == .whisper)
        let pt = try bob.decrypt(peerIdentity: aliceId, ciphertext: m3.ciphertext, isPreKey: false)
        #expect(String(data: pt, encoding: .utf8) == "still here")
    }

    @Test("forgetPeer drops the session — encrypt fails afterwards")
    func sessionForgetPeer() throws {
        let alice = try Session()
        let bob = try Session()
        let bobId = try bob.identityPublic()
        try alice.initiateSession(peerIdentity: bobId, bundle: try bob.publishBundle())
        _ = try alice.encrypt(peerIdentity: bobId, plaintext: Data("hi".utf8))
        try alice.forgetPeer(peerIdentity: bobId)
        #expect(throws: (any Error).self) {
            _ = try alice.encrypt(peerIdentity: bobId, plaintext: Data("again".utf8))
        }
    }

    @Test("encryptSealed/decryptSealed round-trip a sealed-sender SEND")
    func sealedSenderRoundTrip() throws {
        let alice = try Session()
        let bob = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        try alice.initiateSession(peerIdentity: bobId, bundle: try bob.publishBundle())
        // Pre-trust Alice on Bob's side (mirrors what addContact does
        // after a QR scan).
        try bob.registerPeer(peerIdentity: aliceId)

        let messageId = Data((0..<16).map { UInt8($0) })
        let payload = Data("first sealed".utf8)
        let sealed = try alice.encryptSealed(
            peer: bobId, messageId: messageId, plaintext: payload
        )
        let received = try bob.decryptSealed(sealed)
        #expect(received.peer == aliceId)
        #expect(received.messageId == messageId)
        #expect(received.plaintext == payload)
    }

    @Test("decryptSealed throws for a sender we don't trust yet")
    func sealedSenderUnknownSender() throws {
        let alice = try Session()
        let bob = try Session()
        let bobId = try bob.identityPublic()
        try alice.initiateSession(peerIdentity: bobId, bundle: try bob.publishBundle())
        // Note: do NOT pre-register Alice on Bob's side.
        let sealed = try alice.encryptSealed(
            peer: bobId,
            messageId: Data(repeating: 0, count: 16),
            plaintext: Data("surprise".utf8),
        )
        #expect(throws: (any Error).self) {
            _ = try bob.decryptSealed(sealed)
        }
    }

    @Test("delivery-token verify key is deterministic per identity")
    func deliveryTokenVerifyKey() throws {
        let s = try Session()
        let key1 = try s.deliveryTokenVerifyKey()
        let seed = try s.identityKeypairBytes()
        let s2 = try Session(identitySeed: seed)
        #expect(try s2.deliveryTokenVerifyKey() == key1)
        #expect(key1.count == 33)
    }
}
