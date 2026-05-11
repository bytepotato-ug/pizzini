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
        #expect(received.isDuplicate == false)
    }

    @Test("decryptSealed flags a replayed SEND as duplicate without throwing")
    func sealedSenderDuplicate() throws {
        let alice = try Session()
        let bob = try Session()
        let aliceId = try alice.identityPublic()
        let bobId = try bob.identityPublic()
        try alice.initiateSession(peerIdentity: bobId, bundle: try bob.publishBundle())
        try bob.registerPeer(peerIdentity: aliceId)

        let messageId = Data(repeating: 0xFE, count: 16)
        let sealed = try alice.encryptSealed(
            peer: bobId, messageId: messageId, plaintext: Data("once".utf8)
        )
        let first = try bob.decryptSealed(sealed)
        #expect(first.isDuplicate == false)
        let second = try bob.decryptSealed(sealed)
        #expect(second.isDuplicate == true)
        #expect(second.plaintext.isEmpty)
        #expect(second.peer == aliceId)
        #expect(second.messageId == messageId)
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

    // MARK: - Argon2id KDF (SQLCipher key derivation)

    @Test("Argon2id derive is deterministic for fixed inputs")
    func argon2idDeterministic() throws {
        let salt = Data(repeating: 0x42, count: 16)
        let pass = Data("correct-horse-battery-staple".utf8)
        // Test-fixture params (tiny) — the production params would
        // take ~250 ms and pad the test suite for no benefit. The
        // Rust-side test pins the upstream-crate output for the
        // production-shape inputs; this test pins the Swift bridge.
        let params = Argon2id.Params(memoryKiB: 64, timeIterations: 2, parallelism: 1)
        let a = try Argon2id.derive(passphrase: pass, salt: salt, params: params, outputLength: 32)
        let b = try Argon2id.derive(passphrase: pass, salt: salt, params: params, outputLength: 32)
        #expect(a == b)
        #expect(a.count == 32)
        #expect(a != Data(repeating: 0, count: 32))
    }

    @Test("Argon2id derive distinguishes salts")
    func argon2idSaltSensitive() throws {
        let pass = Data("shared".utf8)
        let params = Argon2id.Params(memoryKiB: 64, timeIterations: 2, parallelism: 1)
        let a = try Argon2id.derive(
            passphrase: pass, salt: Data(repeating: 0x01, count: 16),
            params: params, outputLength: 32,
        )
        let b = try Argon2id.derive(
            passphrase: pass, salt: Data(repeating: 0x02, count: 16),
            params: params, outputLength: 32,
        )
        #expect(a != b)
    }

    @Test("Argon2id derive throws on too-short salt")
    func argon2idGuardSalt() {
        let params = Argon2id.Params(memoryKiB: 64, timeIterations: 2, parallelism: 1)
        #expect(throws: CryptoCoreError.self) {
            try Argon2id.derive(
                passphrase: Data("x".utf8),
                salt: Data(repeating: 0, count: 8),  // < 16 byte floor
                params: params,
                outputLength: 32,
            )
        }
    }

    @Test("safety number is 60 digits formatted as 12 × 5 groups")
    func safetyNumberShape() throws {
        let alice = try Session()
        let bob = try Session()
        let sas = SafetyNumber.derive(
            localIdentity: try alice.identityPublic(),
            peerIdentity: try bob.identityPublic()
        )
        // 60 digits + 11 single-space separators = 71 chars.
        #expect(sas.count == 71)
        let groups = sas.split(separator: " ")
        #expect(groups.count == 12)
        for g in groups {
            #expect(g.count == 5)
            #expect(g.allSatisfy { $0.isASCII && $0.isNumber })
        }
    }

    @Test("safety number is order-independent")
    func safetyNumberSymmetric() throws {
        let alice = try Session()
        let bob = try Session()
        let aId = try alice.identityPublic()
        let bId = try bob.identityPublic()
        let a = SafetyNumber.derive(localIdentity: aId, peerIdentity: bId)
        let b = SafetyNumber.derive(localIdentity: bId, peerIdentity: aId)
        #expect(a == b, "Alice and Bob must compute the same SAS regardless of side")
    }

    @Test("safety number changes when either identity is substituted")
    func safetyNumberDetectsSubstitution() throws {
        let alice = try Session()
        let bob = try Session()
        let mallory = try Session()
        let aId = try alice.identityPublic()
        let bId = try bob.identityPublic()
        let mId = try mallory.identityPublic()
        let real = SafetyNumber.derive(localIdentity: aId, peerIdentity: bId)
        let mitm = SafetyNumber.derive(localIdentity: aId, peerIdentity: mId)
        #expect(real != mitm, "If MITM swapped Bob for themselves, SAS must diverge")
    }
}
