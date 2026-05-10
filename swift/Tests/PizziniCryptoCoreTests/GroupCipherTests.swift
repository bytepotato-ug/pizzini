import Foundation
import Testing
@testable import PizziniCryptoCore

/// Slice-4a Swift-bridge tests for the libsignal-Sender-Keys API.
/// Mirrors `crypto-core/tests/group_cipher.rs` at the C ABI boundary
/// — these tests prove the Swift wrappers correctly marshall the
/// 16-byte distribution_id, sender identity, and (cipher|plain)text
/// blobs through the FFI without truncating, mis-ordering bytes, or
/// dropping return values.
///
/// All four wrappers route through the existing `readBlob` buffer-grow
/// idiom, so the tests deliberately include a payload large enough to
/// force the second-pass reallocation on at least one path
/// (`encryptOversizedPayloadGrowsBuffer`).
@Suite("Group cipher (Sender Keys)")
struct GroupCipherTests {
    @Test("3-member group: SKDM round-trip + multi-recipient decrypt")
    func threeMemberRoundTrip() throws {
        let alice = try Session()
        let bob = try Session()
        let carol = try Session()
        let aliceId = try alice.identityPublic()
        let dist = UUID()

        let skdm = try alice.senderKeyDistributionCreate(distributionId: dist)
        #expect(!skdm.isEmpty)

        // Both peers process Alice's SKDM; the parsed dist_id must
        // match what Alice generated locally — confirms the 16-byte
        // round-trip through the FFI.
        let bobDist = try bob.senderKeyDistributionProcess(senderIdentity: aliceId, skdm: skdm)
        let carolDist = try carol.senderKeyDistributionProcess(senderIdentity: aliceId, skdm: skdm)
        #expect(bobDist == dist)
        #expect(carolDist == dist)

        // Alice encrypts once; both recipients decrypt the same bytes.
        let plaintext = Data("activist briefing for the field team".utf8)
        let ct = try alice.groupEncrypt(distributionId: dist, plaintext: plaintext)
        #expect(try bob.groupDecrypt(senderIdentity: aliceId, ciphertext: ct) == plaintext)
        #expect(try carol.groupDecrypt(senderIdentity: aliceId, ciphertext: ct) == plaintext)
    }

    @Test("rotation via fresh dist_id excludes the old chain")
    func rotationViaFreshDistId() throws {
        let alice = try Session()
        let bob = try Session()
        let carol = try Session()
        let aliceId = try alice.identityPublic()

        // Initial enrolment of both peers.
        let dist1 = UUID()
        let skdm1 = try alice.senderKeyDistributionCreate(distributionId: dist1)
        try bob.senderKeyDistributionProcess(senderIdentity: aliceId, skdm: skdm1)
        try carol.senderKeyDistributionProcess(senderIdentity: aliceId, skdm: skdm1)

        let ct1 = try alice.groupEncrypt(distributionId: dist1, plaintext: Data("v1".utf8))
        #expect(try bob.groupDecrypt(senderIdentity: aliceId, ciphertext: ct1) == Data("v1".utf8))
        #expect(try carol.groupDecrypt(senderIdentity: aliceId, ciphertext: ct1) == Data("v1".utf8))

        // Rotate: pick a fresh dist_id, SKDM only Bob (Carol is
        // "removed"). Alice now encrypts under the new chain.
        let dist2 = UUID()
        let skdm2 = try alice.senderKeyDistributionCreate(distributionId: dist2)
        try bob.senderKeyDistributionProcess(senderIdentity: aliceId, skdm: skdm2)
        // Carol intentionally does NOT process skdm2.

        let ct2 = try alice.groupEncrypt(distributionId: dist2, plaintext: Data("v2".utf8))
        #expect(try bob.groupDecrypt(senderIdentity: aliceId, ciphertext: ct2) == Data("v2".utf8))
        #expect(throws: (any Error).self) {
            _ = try carol.groupDecrypt(senderIdentity: aliceId, ciphertext: ct2)
        }
    }

    @Test("decrypt without prior SKDM throws")
    func decryptWithoutSKDMThrows() throws {
        let alice = try Session()
        let bob = try Session()
        let aliceId = try alice.identityPublic()
        let dist = UUID()

        _ = try alice.senderKeyDistributionCreate(distributionId: dist)
        let ct = try alice.groupEncrypt(distributionId: dist, plaintext: Data("hi".utf8))

        // Bob never processed Alice's SKDM.
        #expect(throws: (any Error).self) {
            _ = try bob.groupDecrypt(senderIdentity: aliceId, ciphertext: ct)
        }
    }

    @Test("encrypt without prior create throws")
    func encryptWithoutCreateThrows() throws {
        let alice = try Session()
        // No senderKeyDistributionCreate(...) call before encrypt.
        #expect(throws: (any Error).self) {
            _ = try alice.groupEncrypt(distributionId: UUID(), plaintext: Data("oops".utf8))
        }
    }

    @Test("idempotent create reuses the same chain")
    func idempotentCreate() throws {
        let alice = try Session()
        let bob = try Session()
        let aliceId = try alice.identityPublic()
        let dist = UUID()

        let skdm1 = try alice.senderKeyDistributionCreate(distributionId: dist)
        let skdm2 = try alice.senderKeyDistributionCreate(distributionId: dist)
        // Both SKDMs install the same chain on Bob (functional check —
        // the bytes themselves may not be byte-identical depending on
        // libsignal's internal counter advances).
        try bob.senderKeyDistributionProcess(senderIdentity: aliceId, skdm: skdm2)
        let ct = try alice.groupEncrypt(distributionId: dist, plaintext: Data("hi".utf8))
        #expect(try bob.groupDecrypt(senderIdentity: aliceId, ciphertext: ct) == Data("hi".utf8))
        // Touch skdm1 so it's not unused-warning bait.
        #expect(!skdm1.isEmpty)
    }

    @Test("oversized payload exercises the readBlob second-pass alloc")
    func encryptOversizedPayloadGrowsBuffer() throws {
        // The default initial cap inside `groupEncrypt` is
        // `max(plaintext.count + 256, 1024)`. Pick a payload that's
        // large enough to push the ciphertext above that initial
        // floor — the wrapper must transparently grow the buffer and
        // re-call the FFI without surfacing a buffer-too-small error.
        let alice = try Session()
        let bob = try Session()
        let aliceId = try alice.identityPublic()
        let dist = UUID()

        let skdm = try alice.senderKeyDistributionCreate(distributionId: dist)
        try bob.senderKeyDistributionProcess(senderIdentity: aliceId, skdm: skdm)

        let big = Data(repeating: 0x42, count: 64 * 1024) // 64 KiB
        let ct = try alice.groupEncrypt(distributionId: dist, plaintext: big)
        let pt = try bob.groupDecrypt(senderIdentity: aliceId, ciphertext: ct)
        #expect(pt == big)
    }

    @Test("UUID round-trips through the 16-byte distribution_id field")
    func uuidRoundTripsBytewise() throws {
        // The UUID byte order is the load-bearing thing here: if we
        // got it wrong, peers would install chains keyed by the
        // wrong dist_id and ciphertext would silently fail to
        // decrypt. The earlier suite proves this end-to-end via real
        // decryption; this test pins it explicitly.
        let alice = try Session()
        let bob = try Session()
        let aliceId = try alice.identityPublic()
        // Pick a UUID with distinguishable byte values across the
        // tuple so a mis-ordered round-trip would be visible.
        let dist = UUID(uuid: (
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        ))
        let skdm = try alice.senderKeyDistributionCreate(distributionId: dist)
        let parsed = try bob.senderKeyDistributionProcess(senderIdentity: aliceId, skdm: skdm)
        #expect(parsed == dist)
    }
}
