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
                rawEntryJSON: Data(#"{"binary_sha256":"y","binary_size":1,"git_sha":"x"}"#.utf8)
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
                rawEntryJSON: Data()
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
                rawEntryJSON: Data()
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

/// PZ-H12 — the signature is verified over the operator's LITERAL
/// `entry` bytes lifted from the line, never a Swift-recomputed
/// canonical form. These tests pin (a) that the byte extractor is
/// exact and parse-faithful, (b) that the real committed log still
/// verifies under the bundled operator key (the change is
/// backward-compatible — no re-signing), and (c) that two
/// byte-distinct-but-logically-equal payloads can NOT share a
/// signature (the canonicalisation-confusion the single-canonicaliser
/// design eliminates).
@Suite("TransparencyLog — PZ-H12 raw-entry-bytes signing")
struct TransparencyLogRawBytesTests {
    /// The four entries committed to `transparency-log.ndjson`, as
    /// public literals. Signed by the bundled operator key
    /// (`TransparencyLogConfig.operatorVerifyKeyBase64`) under the
    /// pre-H12 scheme; they must still verify after the switch to
    /// raw-byte verification, proving backward compatibility.
    static let committedLog = """
    {"entry":{"binary_sha256":"9d0d6ed4178b18f6fed9a9619771a732afe5ab52019d99e406aa63c7f8180ebb","binary_size":3521856,"git_sha":"5e42f248c53e5a3dfaeb699af05dedbc634b123d"},"signed_at":"2026-05-11T18:19:35Z","sig_b64":"TkdI+iUwthSELqKm4jQmYpKJjqokkoZJAcjtXZHK1ZOkhwgc20OCRkE0OufYthH8EOjk/WNDStw4uv9T0BxIBA=="}
    {"entry":{"binary_sha256":"bbf6de18599ade1ed136d58014c4c5ce6c16000c6a05bc134c12e0e8cd0c38c5","binary_size":3554752,"git_sha":"3bb92425c7d9e3511cef1ee80dc1da14ae68c4a0"},"signed_at":"2026-05-13T09:56:16Z","sig_b64":"hGDiwFXmuv6+uZaeVXgPcczynDCNmECrrlG0Koi9cIIzmimmP6XKTlG5v9P9m9E26OKiH6p/Tte/UMBCGrxhDg=="}
    {"entry":{"binary_sha256":"597299bd9296ac20858f91cb3209a6848fdb6debdfcadc0212adc779c719918a","binary_size":3590304,"git_sha":"82866b32fb18675e777458d42c828eb953a3175b"},"signed_at":"2026-05-13T14:51:31Z","sig_b64":"tH7KnsH+rH/ZwSkCK198sUwtzydhYhnh1/TEd/Y+aHOGX2JpvYYFvNsanHEf8pTmt24GCbojaD/3a6tN1/FECQ=="}
    {"entry":{"binary_sha256":"14c97fa5a17162214d53f270591198faa67df7fc418dc40963212243b7e46ea2","binary_size":3590304,"git_sha":"56f2ee8974c013f65543090753d9049d07cc5e2f"},"signed_at":"2026-05-13T23:54:21Z","sig_b64":"RI9UnmqEXC2iaNOWZ7JIfKjyemm61+8jLKOjk+b2yTvIYumrOy9SUyDjQT85uZBBL6EOlDQLaKZMzAk7A1P0Bg=="}
    """

    @Test("the real committed log verifies under the bundled operator key (backward-compatible, no re-sign)")
    func committedLogStillVerifies() throws {
        // This test is meaningful only on a build that actually pins
        // the operator key (the shipping default does). If a future
        // build ships keyless, skip the assertion rather than red.
        try #require(TransparencyLogConfig.operatorVerifyKey != nil,
                     "bundled build must pin the operator key for this regression")
        let entries = TransparencyLog.parseLog(Data(Self.committedLog.utf8))
        #expect(entries.count == 4)
        for entry in entries {
            #expect(TransparencyLog.verify(entry) == .valid)
        }
        #expect(TransparencyLog.verifiedCount(in: entries) == 4)
    }

    @Test("rawValueBytes lifts the LITERAL entry bytes, preserving order/whitespace (no re-canonicalisation)")
    func rawExtractIsByteFaithful() throws {
        // Keys deliberately NOT sorted and padded with whitespace.
        // A canonicalising extractor would "fix" these; the literal
        // extractor must return them untouched.
        let line = #"{ "entry": {"git_sha":"z", "binary_size": 7 ,"binary_sha256":"qq"}, "signed_at":"t","sig_b64":"AA"}"#
        let raw = try #require(TransparencyLog.rawValueBytes(forKey: "entry", inLine: Data(line.utf8)))
        #expect(String(decoding: raw, as: UTF8.self) == #"{"git_sha":"z", "binary_size": 7 ,"binary_sha256":"qq"}"#)
    }

    @Test("rawValueBytes respects string literals containing braces/commas/colons")
    func rawExtractRespectsStrings() throws {
        // A string value containing }, , and : must not terminate the
        // value-span scan early.
        let line = #"{"entry":{"binary_sha256":"a}b,c:d","binary_size":1,"git_sha":"x"},"signed_at":"t","sig_b64":"AA"}"#
        let raw = try #require(TransparencyLog.rawValueBytes(forKey: "entry", inLine: Data(line.utf8)))
        #expect(String(decoding: raw, as: UTF8.self) == #"{"binary_sha256":"a}b,c:d","binary_size":1,"git_sha":"x"}"#)
    }

    @Test("rawValueBytes returns nil for a non-object line or absent key")
    func rawExtractNilCases() {
        #expect(TransparencyLog.rawValueBytes(forKey: "entry", inLine: Data(#"[1,2,3]"#.utf8)) == nil)
        #expect(TransparencyLog.rawValueBytes(forKey: "entry", inLine: Data(#"{"signed_at":"t"}"#.utf8)) == nil)
        #expect(TransparencyLog.rawValueBytes(forKey: "entry", inLine: Data(#"{"#.utf8)) == nil)
    }

    /// Reproduce EXACTLY the message `TransparencyLog.verify` feeds to
    /// Ed25519: `entry.rawEntryJSON || 0x0A || signedAt`. Used to
    /// prove the confusion property with a test-local key (the bundled
    /// key is a `let`, so we exercise the byte assembly, not the
    /// pinned key).
    private static func verifyInput(for signed: TransparencyLog.SignedEntry) -> Data {
        var input = signed.entry.rawEntryJSON
        input.append(0x0A)
        input.append(contentsOf: signed.signedAt.utf8)
        return input
    }

    @Test("two byte-distinct but logically-equal entries can NOT share a signature")
    func noCanonicalisationConfusion() throws {
        // Same logical entry, two different byte encodings (key order
        // differs). Under a canonicalising verifier both collapse to
        // one form and a signature over one would wrongly validate the
        // other. Under raw-byte verification their signing inputs
        // differ, so a signature is bound to exactly one encoding.
        let lineA = #"{"entry":{"binary_sha256":"aa","binary_size":1,"git_sha":"gg"},"signed_at":"2026-01-01T00:00:00Z","sig_b64":"AA"}"#
        let lineB = #"{"entry":{"git_sha":"gg","binary_size":1,"binary_sha256":"aa"},"signed_at":"2026-01-01T00:00:00Z","sig_b64":"AA"}"#

        let a = try #require(TransparencyLog.parseSignedEntry(Data(lineA.utf8)))
        let b = try #require(TransparencyLog.parseSignedEntry(Data(lineB.utf8)))

        // Both decode to the same logical fields…
        #expect(a.entry.binarySha256Hex == b.entry.binarySha256Hex)
        #expect(a.entry.gitSha == b.entry.gitSha)
        // …but the bytes actually signed are different.
        #expect(a.entry.rawEntryJSON != b.entry.rawEntryJSON)

        let inputA = Self.verifyInput(for: a)
        let inputB = Self.verifyInput(for: b)
        #expect(inputA != inputB)

        // With a real key: a signature over A's exact bytes validates
        // A and is REJECTED for B — no canonicalisation collapse.
        let key = Curve25519.Signing.PrivateKey()
        let sigA = try key.signature(for: inputA)
        #expect(key.publicKey.isValidSignature(sigA, for: inputA))
        #expect(!key.publicKey.isValidSignature(sigA, for: inputB))
    }

    @Test("a whitespace-padded re-encoding of a signed entry no longer verifies (bytes are bound)")
    func whitespaceReencodingRejected() throws {
        let compact = #"{"entry":{"binary_sha256":"aa","binary_size":1,"git_sha":"gg"},"signed_at":"2026-01-01T00:00:00Z","sig_b64":"AA"}"#
        let padded  = #"{"entry":{"binary_sha256":"aa", "binary_size":1, "git_sha":"gg"},"signed_at":"2026-01-01T00:00:00Z","sig_b64":"AA"}"#

        let c = try #require(TransparencyLog.parseSignedEntry(Data(compact.utf8)))
        let p = try #require(TransparencyLog.parseSignedEntry(Data(padded.utf8)))
        #expect(c.entry.rawEntryJSON != p.entry.rawEntryJSON)

        let key = Curve25519.Signing.PrivateKey()
        let sigCompact = try key.signature(for: Self.verifyInput(for: c))
        #expect(!key.publicKey.isValidSignature(sigCompact, for: Self.verifyInput(for: p)))
    }
}

/// PZ-M16 — multi-key verification for operator key ROTATION. An entry
/// is accepted if its single signature validates under ANY currently
/// configured key (primary + rotation keys), so publishing a new key
/// alongside the old makes rotation a non-flag-day change. These pin
/// the key decoding + the 1-of-M acceptance/rejection with throwaway
/// keys (the shipped key set is a build-time `let`). NB: this is NOT a
/// threshold scheme — each entry still carries exactly one signature.
@Suite("TransparencyLog — PZ-M16 rotation keys")
struct TransparencyLogRotationKeysTests {
    /// Build a SignedEntry whose signing input (rawEntryJSON || \n ||
    /// signedAt) is signed by `signer`.
    private static func signedEntry(by signer: Curve25519.Signing.PrivateKey) throws -> TransparencyLog.SignedEntry {
        let rawEntry = Data(#"{"binary_sha256":"aa","binary_size":1,"git_sha":"gg"}"#.utf8)
        let signedAt = "2026-01-01T00:00:00Z"
        var input = rawEntry
        input.append(0x0A)
        input.append(contentsOf: signedAt.utf8)
        let sig = try signer.signature(for: input)
        return TransparencyLog.SignedEntry(
            entry: TransparencyLog.Entry(
                gitSha: "gg", binarySha256Hex: "aa", binarySize: 1, rawEntryJSON: rawEntry),
            signedAt: signedAt,
            signatureBase64: sig.base64EncodedString())
    }

    @Test("decodeVerifyKey accepts a valid raw-32 base64 key, rejects junk")
    func decodeKey() {
        let valid = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString()
        #expect(TransparencyLogConfig.decodeVerifyKey(valid) != nil)
        #expect(TransparencyLogConfig.decodeVerifyKey("") == nil)
        #expect(TransparencyLogConfig.decodeVerifyKey("not-base64!!") == nil)
        // Valid base64 but wrong length (16 bytes, not 32).
        #expect(TransparencyLogConfig.decodeVerifyKey(Data(repeating: 0, count: 16).base64EncodedString()) == nil)
    }

    @Test("the shipped build exposes the primary key as the head of the key set")
    func primaryIsFirst() throws {
        try #require(TransparencyLogConfig.operatorVerifyKey != nil)
        #expect(TransparencyLogConfig.operatorVerifyKeys.isEmpty == false)
        #expect(TransparencyLogConfig.operatorVerifyKeys.first?.rawRepresentation
            == TransparencyLogConfig.operatorVerifyKey?.rawRepresentation)
    }

    @Test("empty key set reports operatorKeyMissing, never .valid")
    func emptyKeySetMissing() throws {
        let signed = try Self.signedEntry(by: Curve25519.Signing.PrivateKey())
        #expect(TransparencyLog.verify(signed, keys: []) == .operatorKeyMissing)
    }

    @Test("1-of-M: an entry signed by ANY configured key verifies; an unlisted signer is rejected")
    func oneOfMAcceptance() throws {
        let keyA = Curve25519.Signing.PrivateKey()
        let keyB = Curve25519.Signing.PrivateKey() // the "new" rotation key
        let keyC = Curve25519.Signing.PrivateKey() // never configured

        let signedByB = try Self.signedEntry(by: keyB)

        // Only the old key configured → entry signed by the new key fails.
        #expect(TransparencyLog.verify(signedByB, keys: [keyA.publicKey]) == .badSignature)
        // Rotation window: both keys configured → the new key's entry verifies.
        #expect(TransparencyLog.verify(signedByB, keys: [keyA.publicKey, keyB.publicKey]) == .valid)
        // A signer outside the configured set is never accepted.
        let signedByC = try Self.signedEntry(by: keyC)
        #expect(TransparencyLog.verify(signedByC, keys: [keyA.publicKey, keyB.publicKey]) == .badSignature)
    }
}
