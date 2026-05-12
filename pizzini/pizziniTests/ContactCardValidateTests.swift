import Foundation
import Testing
@testable import pizzini

/// Strict-validation tests for `ContactCard.validate(_:)`.
///
/// `validate` is the single chokepoint that decides whether a string
/// from the user's clipboard (or QR scanner) becomes a contact in
/// their address book. Every rejection rule here corresponds to a
/// distinct user-facing error message in the alert flow, so a
/// regression that quietly broadens what gets accepted would also
/// be a regression in the safety story.
///
/// Conventions:
/// - "good" peerId: 66 lowercase hex chars derived from a known-
///   real libsignal IdentityKey wire form (33 bytes), with non-zero
///   bytes throughout so the entropy-floor checks don't trip.
/// - Tests cover both `validate` (which throws with a reason) and
///   `decode` (the legacy nil-on-failure wrapper) for symmetry.
@Suite("ContactCard.validate")
struct ContactCardValidateTests {

    /// A well-formed, entropy-rich 33-byte peerId in hex (66 chars).
    private static let goodPeerHex =
        "05421b53f999deced2d6c8d3a6bbc24047e17864cf7f82daf2588971f625431059"
    private static let goodCard =
        "pizzini1://\(goodPeerHex)@:7777"

    // ─── happy path ──────────────────────────────────────────────────

    @Test func happyPathRoundTrip() throws {
        let card = try ContactCard.validate(Self.goodCard)
        #expect(card.peerId.count == 33)
        #expect(card.host == "")
        #expect(card.port == 7777)
    }

    @Test func happyPathWithBundledFleetEmptyHost() throws {
        // Empty host between `@` and `:` is the fleet-mode sentinel —
        // the iOS app routes via RelayRegistry.trusted, not the
        // card's host. validate must accept it.
        let s = "pizzini1://\(Self.goodPeerHex)@:7777"
        let card = try ContactCard.validate(s)
        #expect(card.host == "")
    }

    @Test func happyPathWithCustomHost() throws {
        let s = "pizzini1://\(Self.goodPeerHex)@example.onion:7777"
        let card = try ContactCard.validate(s)
        #expect(card.host == "example.onion")
    }

    @Test func happyPathTrimsLeadingAndTrailingWhitespace() throws {
        let s = "  \(Self.goodCard)\n"
        let card = try ContactCard.validate(s)
        #expect(card.port == 7777)
    }

    @Test func happyPathUppercaseHexNormalises() throws {
        let upper = Self.goodPeerHex.uppercased()
        let s = "pizzini1://\(upper)@:7777"
        let card = try ContactCard.validate(s)
        #expect(card.peerId.count == 33)
    }

    // ─── bounded input ───────────────────────────────────────────────

    @Test func rejectsExcessivelyLongInput() {
        // 4 KiB + 1 byte. Even if the prefix is valid the size cap
        // fires first so a 4 MB clipboard paste can't pin the parser.
        let huge = "pizzini1://" + String(repeating: "a", count: 4096)
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(huge)
        }
        #expect(ContactCard.decode(huge) == nil)
    }

    // ─── empty ───────────────────────────────────────────────────────

    @Test func rejectsEmptyString() {
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate("")
        }
    }

    @Test func rejectsWhitespaceOnly() {
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate("   \n\t  ")
        }
    }

    // ─── scheme ──────────────────────────────────────────────────────

    @Test func rejectsWrongScheme() {
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate("http://\(Self.goodPeerHex)@:7777")
        }
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate("pizzini2://\(Self.goodPeerHex)@:7777")
        }
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(Self.goodPeerHex) // no scheme at all
        }
    }

    // ─── peerId length + alphabet ────────────────────────────────────

    @Test func rejectsShortPeerId() {
        // 64 hex chars = 32 bytes (Ed25519 raw point but missing the
        // libsignal type-byte prefix). Real libsignal IdentityKey is
        // 33 bytes / 66 chars.
        let shortHex = String(Self.goodPeerHex.dropFirst(2))
        let s = "pizzini1://\(shortHex)@:7777"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    @Test func rejectsLongPeerId() {
        let longHex = Self.goodPeerHex + "ab"
        let s = "pizzini1://\(longHex)@:7777"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    @Test func rejectsOddLengthPeerId() {
        // 67 chars — not a whole number of bytes.
        let oddHex = Self.goodPeerHex + "a"
        let s = "pizzini1://\(oddHex)@:7777"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    @Test func rejectsNonHexInPeerId() {
        // Same length, but contains a non-hex char.
        let bogus = String(Self.goodPeerHex.dropLast(1)) + "z"
        let s = "pizzini1://\(bogus)@:7777"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    // ─── peerId entropy floor ────────────────────────────────────────

    @Test func rejectsAllZeroPeerId() {
        let zeros = String(repeating: "0", count: 66)
        let s = "pizzini1://\(zeros)@:7777"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    @Test func rejectsAllSameBytePeerId() {
        // Every byte 0xAB.
        let ab = String(repeating: "ab", count: 33)
        let s = "pizzini1://\(ab)@:7777"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    // ─── separators ──────────────────────────────────────────────────

    @Test func rejectsMissingAt() {
        let s = "pizzini1://\(Self.goodPeerHex):7777"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    @Test func rejectsMultipleAts() {
        // `evil@host@:7777` — the second `@` could be smuggling.
        let s = "pizzini1://\(Self.goodPeerHex)@evil@:7777"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    @Test func rejectsMissingPort() {
        let s = "pizzini1://\(Self.goodPeerHex)@example.onion"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    @Test func rejectsMultipleColonsInHost() {
        // `evil:something:7777` — extra colons in the host part are
        // ambiguous and could be exploited by a host that pretends to
        // be a port-like fragment.
        let s = "pizzini1://\(Self.goodPeerHex)@evil:bogus:7777"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    // ─── port ────────────────────────────────────────────────────────

    @Test func rejectsZeroPort() {
        let s = "pizzini1://\(Self.goodPeerHex)@:0"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    @Test func rejectsNegativePort() {
        let s = "pizzini1://\(Self.goodPeerHex)@:-1"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    @Test func rejectsOverflowPort() {
        // 65536 is one above UInt16.max.
        let s = "pizzini1://\(Self.goodPeerHex)@:65536"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    @Test func rejectsNonNumericPort() {
        let s = "pizzini1://\(Self.goodPeerHex)@:abcd"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    @Test func acceptsBoundaryPorts() throws {
        let one = "pizzini1://\(Self.goodPeerHex)@:1"
        let max = "pizzini1://\(Self.goodPeerHex)@:65535"
        #expect(try ContactCard.validate(one).port == 1)
        #expect(try ContactCard.validate(max).port == 65535)
    }

    // ─── homograph / NFKC ────────────────────────────────────────────

    @Test func rejectsNonAsciiInScheme() {
        // U+FF12 FULLWIDTH DIGIT TWO renders like an ASCII "2" but is
        // a different codepoint. The NFKC + printable-ASCII gate must
        // reject this even though it visually reads as a valid prefix.
        let look = "pizzini\u{FF12}://\(Self.goodPeerHex)@:7777"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(look)
        }
    }

    @Test func rejectsNonAsciiInBody() {
        let s = "pizzini1://\(Self.goodPeerHex)@é:7777"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    @Test func rejectsControlCharacters() {
        let s = "pizzini1://\(Self.goodPeerHex)@:7777\u{0007}"
        #expect(throws: ContactCardDecodeError.self) {
            _ = try ContactCard.validate(s)
        }
    }

    // ─── legacy `decode` wrapper ─────────────────────────────────────

    @Test func decodeWrapperReturnsNilOnFailure() {
        #expect(ContactCard.decode("garbage") == nil)
        #expect(ContactCard.decode("") == nil)
    }

    @Test func decodeWrapperReturnsCardOnSuccess() {
        let card = ContactCard.decode(Self.goodCard)
        #expect(card != nil)
        #expect(card?.port == 7777)
    }
}
