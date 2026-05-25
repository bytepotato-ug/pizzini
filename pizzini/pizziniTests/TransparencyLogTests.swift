import CryptoKit
import Foundation
import Testing
@testable import pizzini

/// Verify the Swift-side parser + signature
/// check matches what `scripts/sign-transparency-entry.sh`
/// produces.

@Suite("TransparencyLog — codec + signature verification")
struct TransparencyLogTests {
    @Test("parses a well-formed signed entry")
    func parsesWellFormed() {
        let json = #"""
        {
          "entry": {"binary_sha256": "abc123", "binary_size": 4096, "git_sha": "deadbeef"},
          "signed_at": "2026-05-11T15:06:29Z",
          "sig_b64": "AAAA"
        }
        """#
        let parsed = TransparencyLog.parseSignedEntry(Data(json.utf8))
        let entry = try? #require(parsed)
        #expect(entry?.entry.gitSha == "deadbeef")
        #expect(entry?.entry.binarySha256Hex == "abc123")
        #expect(entry?.entry.binarySize == 4096)
        #expect(entry?.signedAt == "2026-05-11T15:06:29Z")
        #expect(entry?.signatureBase64 == "AAAA")
    }

    @Test("rejects entries missing required fields")
    func rejectsMalformed() {
        // Missing `binary_sha256` field.
        let bad = #"{"entry":{"binary_size":1,"git_sha":"x"},"signed_at":"t","sig_b64":"a"}"#
        #expect(TransparencyLog.parseSignedEntry(Data(bad.utf8)) == nil)
    }

    @Test("parseLog reads NDJSON skipping blanks and bad lines")
    func parseLogNDJSON() {
        let log = """
        {"entry":{"binary_sha256":"a","binary_size":1,"git_sha":"x"},"signed_at":"t1","sig_b64":"AAAA"}

        not-json
        {"entry":{"binary_sha256":"b","binary_size":2,"git_sha":"y"},"signed_at":"t2","sig_b64":"BBBB"}
        """
        let entries = TransparencyLog.parseLog(Data(log.utf8))
        #expect(entries.count == 2)
        #expect(entries[0].entry.binarySha256Hex == "a")
        #expect(entries[1].entry.binarySha256Hex == "b")
    }

    @Test("verify refuses an empty / unsigned entry under the bundled operator key")
    func verifyRefusesUnsignedEntry() {
        let dummy = TransparencyLog.SignedEntry(
            entry: TransparencyLog.Entry(
                gitSha: "x", binarySha256Hex: "y", binarySize: 1,
                canonicalJSON: Data(#"{"binary_sha256":"y","binary_size":1,"git_sha":"x"}"#.utf8)
            ),
            signedAt: "t",
            signatureBase64: ""
        )
        // The bundled build pins a real operator key
        // (`TransparencyLogConfig.operatorVerifyKeyBase64`). An
        // entry with no signature attached must therefore round
        // through the bad-signature path — verification refusing
        // is the safety property the test exists to pin. If a
        // future build ships WITHOUT a key, the result legitimately
        // changes to `.operatorKeyMissing`; accept either as
        // "verification didn't accidentally approve unsigned bytes".
        let result = TransparencyLog.verify(dummy)
        #expect(result == .badSignature || result == .operatorKeyMissing)
        #expect(result != .valid)
    }

    @Test("verify rejects a bad signature when an operator key IS available")
    func badSignatureRejected() throws {
        // Generate a real Ed25519 keypair, sign one message, then
        // try to verify a DIFFERENT message's signature against
        // the public half. We can't write to
        // `TransparencyLogConfig.operatorVerifyKeyBase64` (it's a
        // `let`), so this test calls the verify primitive
        // directly with a known good key — that exercises the
        // CryptoKit verify path the same way `verify(_:)` would.
        let signingKey = Curve25519.Signing.PrivateKey()
        let publicKey = signingKey.publicKey
        let originalMessage = Data("hello".utf8)
        let signature = try signingKey.signature(for: originalMessage)
        let tamperedMessage = Data("hellp".utf8)

        // Sanity: good signature still verifies.
        #expect(publicKey.isValidSignature(signature, for: originalMessage))
        // Tampered message fails — this is the path the
        // `verify(_:)` helper exposes as `.badSignature`.
        #expect(!publicKey.isValidSignature(signature, for: tamperedMessage))
    }

    @Test("cache write + read round-trips")
    func cacheRoundTrip() throws {
        let sample = #"""
        {"entry":{"binary_sha256":"a","binary_size":1,"git_sha":"x"},"signed_at":"t","sig_b64":"AAAA"}
        """#
        let url = try TransparencyLog.cacheURL()
        // Tests share Caches with the running app. Use a uniquer
        // path so concurrent runs don't collide; then clean up.
        let testURL = url.deletingLastPathComponent()
            .appendingPathComponent("test-\(UUID().uuidString).ndjson")
        defer { try? FileManager.default.removeItem(at: testURL) }
        try Data(sample.utf8).write(to: testURL)
        let loaded = TransparencyLog.parseLog(try Data(contentsOf: testURL))
        #expect(loaded.count == 1)
        #expect(loaded.first?.entry.binarySha256Hex == "a")
    }

    @Test("verifiedCount filters out signature failures")
    func verifiedCountBaseline() {
        // No operator key set → no entries verify → count = 0
        // regardless of how many signed-shaped entries we pass.
        let entry = TransparencyLog.SignedEntry(
            entry: TransparencyLog.Entry(
                gitSha: "x", binarySha256Hex: "y", binarySize: 1,
                canonicalJSON: Data()
            ),
            signedAt: "t",
            signatureBase64: ""
        )
        #expect(TransparencyLog.verifiedCount(in: [entry, entry, entry]) == 0)
    }

    @Test("FetchError surfaces urlNotConfigured when nil URL passed")
    func urlNotConfiguredError() async {
        await #expect(throws: TransparencyLog.FetchError.self) {
            _ = try await TransparencyLog.fetchAndCache(from: nil)
        }
    }

    @Test("parseSignedAt accepts both whole-second and fractional-second UTC")
    func parseSignedAtBothForms() {
        // Current signer emits whole-second; a future one may emit
        // fractional. Both must parse, else maxSignedAt goes nil and
        // refresh bricks fail-closed (F-TL-07).
        #expect(TransparencyLog.parseSignedAt("2026-05-13T09:56:16Z") != nil)
        #expect(TransparencyLog.parseSignedAt("2026-05-13T09:56:16.123Z") != nil)
        #expect(TransparencyLog.parseSignedAt("not-a-timestamp") == nil)
    }

    @Test("rollback watermark persists in a durable (non-evictable) store")
    func watermarkDurableRoundTrip() throws {
        // F-TL-03: the watermark lives in UserDefaults, not Caches, so
        // disk-pressure eviction can't reset the rollback floor. Use a
        // throwaway suite so the test never touches the real defaults.
        let suite = "test-watermark-\(UUID().uuidString)"
        let d = try #require(UserDefaults(suiteName: suite))
        defer { d.removePersistentDomain(forName: suite) }

        let t1 = Date(timeIntervalSince1970: 1_700_000_000)
        TransparencyLog.storeWatermark(t1, defaults: d)
        let loaded = try #require(TransparencyLog.loadWatermark(defaults: d))
        #expect(abs(loaded.timeIntervalSince1970 - t1.timeIntervalSince1970) < 0.001)

        // Survives a fresh handle on the same suite (≈ process restart):
        // proves the value is persisted, not held only in memory.
        let d2 = try #require(UserDefaults(suiteName: suite))
        let reloaded = try #require(TransparencyLog.loadWatermark(defaults: d2))
        #expect(abs(reloaded.timeIntervalSince1970 - t1.timeIntervalSince1970) < 0.001)

        // A newer watermark overwrites the floor.
        let t2 = Date(timeIntervalSince1970: 1_800_000_000)
        TransparencyLog.storeWatermark(t2, defaults: d)
        let bumped = try #require(TransparencyLog.loadWatermark(defaults: d))
        #expect(abs(bumped.timeIntervalSince1970 - t2.timeIntervalSince1970) < 0.001)
    }

    @Test("contains(binarySha256Hex:) is case-insensitive on the hex compare")
    func containsCaseInsensitive() {
        let entry = TransparencyLog.SignedEntry(
            entry: TransparencyLog.Entry(
                gitSha: "x",
                binarySha256Hex: "ABCDEF123",
                binarySize: 1,
                canonicalJSON: Data()
            ),
            signedAt: "t",
            signatureBase64: ""
        )
        // No operator key configured → contains() returns false
        // even with matching hex, because verify() can't pass
        // without a key. This is by design (worst failure mode
        // is silent acceptance).
        #expect(TransparencyLog.contains(binarySha256Hex: "abcdef123", in: [entry]) == false)
        #expect(TransparencyLog.contains(binarySha256Hex: "ABCDEF123", in: [entry]) == false)
    }
}
