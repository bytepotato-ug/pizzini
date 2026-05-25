import Testing
import PizziniTor

/// F-TOR-03: `primeOnions` re-validates onion labels through
/// `TorController.isCanonicalOnionHost` before a speculative HSFETCH, so
/// a future caller handing raw/BYO strings can't push a malformed label
/// into a control-port lookup.
@Suite("primeOnions canonical re-validation")
struct PrimeOnionsValidationTests {
    private var validOnion: String { String(repeating: "a", count: 56) + ".onion" }

    @Test("accepts a canonical 56-char v3 onion host")
    func acceptsCanonical() {
        #expect(TorController.isCanonicalOnionHost(validOnion))
        // Case-folds: uppercase resolves to the same canonical host.
        #expect(TorController.isCanonicalOnionHost(validOnion.uppercased()))
        // Full base32 alphabet (a–z, 2–7) is accepted.
        #expect(TorController.isCanonicalOnionHost(
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
        ))
    }

    @Test("rejects non-onion and look-alike hosts")
    func rejectsNonOnion() {
        #expect(!TorController.isCanonicalOnionHost("evil.com"))
        #expect(!TorController.isCanonicalOnionHost("127.0.0.1"))
        // `evil.com.onion`: the label before `.onion` isn't 56 base32 chars.
        #expect(!TorController.isCanonicalOnionHost("evil.com.onion"))
        #expect(!TorController.isCanonicalOnionHost(""))
    }

    @Test("rejects wrong-length and out-of-alphabet labels")
    func rejectsBadLabel() {
        #expect(!TorController.isCanonicalOnionHost(String(repeating: "a", count: 55) + ".onion"))
        #expect(!TorController.isCanonicalOnionHost(String(repeating: "a", count: 57) + ".onion"))
        // '1', '8', '9', '0' are NOT in the base32 onion alphabet.
        #expect(!TorController.isCanonicalOnionHost(String(repeating: "1", count: 56) + ".onion"))
    }
}
