// Tests for the strict OnionHost validator/canonicaliser — the single
// chokepoint for the D1 "Tor-only" posture. Any host the app dials
// must round-trip through `OnionHost.canonical`; these tests pin the
// rule set against the byte-level adversarial inputs the previous
// `.hasSuffix(".onion")` check used to silently fall through to a
// clearnet dial.

import Foundation
import Testing
@testable import PizziniCryptoCore

@Suite("OnionHost canonicaliser — D1 Tor-only chokepoint")
struct OnionHostTests {
    /// A real, valid v3 onion address (the bundled production relay).
    /// Used as the "happy path" baseline so the rejection tests have
    /// something to compare against.
    private static let goodOnion =
        "pizzini2rblrswjmq7axintrq55lhnqwudf7vawckrt3toqps26vxxyd.onion"

    @Test("valid v3 onion canonicalises to itself")
    func validV3RoundTrips() {
        let canonical = OnionHost.canonical(Self.goodOnion)
        #expect(canonical == Self.goodOnion)
        #expect(OnionHost.isValid(Self.goodOnion))
    }

    @Test("uppercase ASCII is folded to lowercase canonical form")
    func uppercaseFolded() {
        let upper = Self.goodOnion.uppercased()
        let canonical = OnionHost.canonical(upper)
        #expect(canonical == Self.goodOnion)
        // And the validator agrees.
        #expect(OnionHost.isValid(upper))
    }

    @Test("trailing-suffix poisoning — `evil.com.onion` — rejected")
    func evilDotComDotOnion() {
        #expect(OnionHost.canonical("evil.com.onion") == nil)
        #expect(!OnionHost.isValid("evil.com.onion"))
    }

    @Test("subdomain of a v3 — `x.<56chars>.onion` — rejected")
    func subdomainRejected() {
        let subdomain = "x." + Self.goodOnion
        #expect(OnionHost.canonical(subdomain) == nil)
    }

    @Test("legacy v2 (16 chars) is rejected outright")
    func v2Rejected() {
        // 16-char base32 label — the v2 hidden-service shape.
        let v2 = "abcdefghijklmnop.onion"
        #expect(OnionHost.canonical(v2) == nil)
    }

    @Test("label too short / too long rejected")
    func wrongLengthRejected() {
        #expect(OnionHost.canonical("abc.onion") == nil)
        #expect(OnionHost.canonical(String(repeating: "a", count: 57) + ".onion") == nil)
    }

    @Test("non-base32 character in the label rejected")
    func badAlphabetRejected() {
        // Replace the first char of a good onion with '1' (not in the
        // base32 alphabet `[a-z2-7]`).
        let mutated = "1" + Self.goodOnion.dropFirst()
        #expect(OnionHost.canonical(mutated) == nil)
    }

    @Test("clearnet host with `.onion` literal in middle — rejected")
    func clearnetWithOnionInMiddle() {
        #expect(OnionHost.canonical(".onion.example.com") == nil)
        #expect(OnionHost.canonical("foo.bar.onion") == nil)
    }

    @Test("empty string and bare `.onion` rejected")
    func emptyAndBareRejected() {
        #expect(OnionHost.canonical("") == nil)
        #expect(OnionHost.canonical(".onion") == nil)
        #expect(OnionHost.canonical("onion") == nil)
    }

    @Test("Unicode look-alike dot (U+3002 ideographic full stop) rejected")
    func unicodeLookalikeDotRejected() {
        // `pizzini2…vxxyd` + IDEOGRAPHIC FULL STOP + `onion`. A naive
        // `.hasSuffix(".onion")` would skip this (the suffix isn't a
        // dot at all), but a String NFKC-normalised by a downstream
        // resolver could fold the codepoint into '.' and resolve
        // a clearnet DNS name. The validator rejects any input that
        // doesn't equal its NFKC-normalised form.
        let lookalike = String(Self.goodOnion.dropLast(".onion".count))
            + "\u{3002}onion"
        #expect(OnionHost.canonical(lookalike) == nil)
    }

    @Test("full-width ASCII digits (U+FF11 etc.) rejected")
    func fullwidthAsciiRejected() {
        let fullwidth = "ｐｉｚｚｉｎｉ" + String(Self.goodOnion.dropFirst("pizzini".count))
        #expect(OnionHost.canonical(fullwidth) == nil)
    }

    @Test("trailing whitespace — caller is expected to have trimmed; validator rejects raw")
    func trailingWhitespaceRejected() {
        // The contract is "callers trim before calling canonical()";
        // raw whitespace in the input is invalid because space is
        // outside the printable-ASCII range we allow.
        let withSpace = Self.goodOnion + " "
        #expect(OnionHost.canonical(withSpace) == nil)
    }

    @Test("i2p .b32.i2p address — rejected (different anonymity network)")
    func i2pRejected() {
        let i2p = String(repeating: "a", count: 52) + ".b32.i2p"
        #expect(OnionHost.canonical(i2p) == nil)
    }

    @Test("IPv4 literal rejected")
    func ipv4Rejected() {
        #expect(OnionHost.canonical("127.0.0.1") == nil)
        #expect(OnionHost.canonical("192.168.1.1") == nil)
    }

    @Test("localhost rejected")
    func localhostRejected() {
        #expect(OnionHost.canonical("localhost") == nil)
    }
}
