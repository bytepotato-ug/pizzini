// Bundled allowlist of trusted production relays. The list is
// compile-time, signed-as-code under the iOS app's binary identity,
// and never fetched at runtime — see `docs/relay-architecture.md`
// **D5** for why a remote-update channel is deliberately not added.
//
// Reaching this list directly is an explicit choice over typing onion
// addresses (D5 again): a 56-character base32 onion is a paste-attack
// surface plus a memorability disaster. Users see country labels;
// the actual onion is internal.
//
// **D3 (app-side fanout).** The iOS host (`ChatStore`) opens a
// `RelayClient` per descriptor in parallel. Outbound SENDs/ACKs/etc.
// fan out across every connected relay. The first relay that
// delivers wins; libsignal's `SealedSenderResult.isDuplicate` drops
// the redundant copies on receive. With stateless relays + no
// cross-relay federation, two peers must share at least one alive
// trusted onion for routing to succeed — fanout makes that the
// default state, not the lucky one.
//
// **Adding a relay.** Append a `RelayDescriptor` here, ship a release.
// No remote update path: an adversary who pwns the app store still
// has to defeat code-signing to swap relays.
//
// **Removing a relay.** Same: delete the line, ship a release. Old
// app builds keep dialling the removed onion until they update; that
// is the safe failure mode — the relay just stops answering on its
// end and the app fails over to the surviving entries.

import Foundation

/// Identity of a single trusted relay in the bundled fleet. The
/// label is the user-facing string the UI displays (country name);
/// the host is the actual onion address that `RelayClient` dials.
/// Stable across releases — once an onion is published in the
/// allowlist, removing it is a breaking change for pre-existing
/// paired contacts whose state pre-dates the change.
public struct RelayDescriptor: Sendable, Equatable, Hashable, Codable {
    /// User-facing country label per `docs/relay-architecture.md` D4.
    /// Picked at relay-deploy time; intentionally decoupled from the
    /// onion vanity prefix (which is a stable numeric token, not a
    /// country code) so a relay can be re-jurisdictioned without
    /// invalidating its cryptographic identity.
    public let label: String

    /// Onion v3 hostname (without `.onion` for brevity? No — keep the
    /// suffix so `RelayClient.connect` can apply its
    /// `.hasSuffix(".onion")` Tor-routing trigger uniformly).
    public let host: String

    /// TCP port the relay listens on inside the onion. All bundled
    /// relays use the same port for now; if a future relay ships on
    /// a different port the field stays per-descriptor.
    public let port: UInt16

    public init(label: String, host: String, port: UInt16 = 7777) {
        self.label = label
        self.host = host
        self.port = port
    }
}

/// Strict validator + canonicaliser for Tor v3 onion addresses.
///
/// The single chokepoint for the D1 "Tor-only" posture. Any host the
/// app is about to dial — bundled fleet entry, BYO override pasted by
/// the user, or value migrated off the legacy `relay_host` setting —
/// must pass this check before reaching `RelayClient.connect`. A
/// failure here means the address is rejected and the app falls back
/// to the bundled fleet rather than transparently downgrading to a
/// clear-text TCP dial.
///
/// Rules (all must hold; rejection on any miss):
///
///   1. ASCII-only. NFKC-normalise then verify every codepoint is a
///      printable ASCII byte (`0x21..=0x7E`). Defeats Unicode look-alike
///      / homograph attacks where a glyph that *renders* as the dot
///      between the v3 label and `onion` is in fact a different
///      codepoint (U+3002, U+FF0E, U+FE52, U+2024, etc.) that would
///      sail through a naive `.hasSuffix(".onion")` check yet resolve
///      as a public DNS name once handed to NWConnection.
///
///   2. Single label, single dot. Exactly `<56-char base32>.onion` with
///      one literal `.`. No subdomains (`x.foo.onion` is rejected — the
///      relay is reached by its v3 service id, period); no
///      `evil.com.onion` style trailing-suffix poisoning.
///
///   3. v3 only. The label is exactly 56 lowercase base32 characters
///      (`[a-z2-7]{56}`). Legacy v2 (16 chars) is rejected outright —
///      v2 hidden services are deprecated and unreachable on a modern
///      tor.
///
///   4. Case-insensitive on input; the canonical form returned is
///      always lowercase. RFC 3986 lets the host component be
///      case-insensitive but tor's introspection paths and our own
///      per-host UI key off the literal string, so we settle the
///      ambiguity at the door.
///
/// The function returns `nil` for any invalid input. Callers must
/// treat `nil` as "not safe to dial directly — use fleet".
public enum OnionHost {
    /// Validate + canonicalise. Returns the lowercase ASCII form on
    /// success or `nil` if the input fails any of the rules above.
    /// Whitespace must already have been trimmed by the caller; this
    /// function does not trim (callers usually want to know if a
    /// stray space was the only delta, e.g. for "did you mean…" UI).
    public static func canonical(_ raw: String) -> String? {
        // NFKC normalisation collapses look-alike forms (full-width
        // ASCII, ligatures, ideographic stops, etc.) into their
        // closest plain-ASCII representation before we run the
        // ASCII check. An input that NFKC-folds to a valid onion
        // is still suspicious — we therefore additionally require
        // that the ORIGINAL bytes were already ASCII; otherwise
        // an attacker could submit a glyph that renders as a v3
        // onion but normalises only after this guard.
        let nfkc = raw.precomposedStringWithCompatibilityMapping
        guard nfkc == raw else { return nil }
        let lowered = raw.lowercased()
        // ASCII printable range only. Bytes outside `0x21..=0x7E`
        // (controls, space, high-bit) are unconditionally invalid.
        for scalar in lowered.unicodeScalars {
            let v = scalar.value
            if v < 0x21 || v > 0x7E { return nil }
        }
        // Exactly one '.', and it sits between the v3 label and "onion".
        let parts = lowered.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2, parts[1] == "onion" else { return nil }
        let label = parts[0]
        guard label.count == 56 else { return nil }
        let alphabet: Set<Character> = Set("abcdefghijklmnopqrstuvwxyz234567")
        for ch in label where !alphabet.contains(ch) { return nil }
        return lowered
    }

    /// Convenience: does `raw` describe a valid v3 onion?
    public static func isValid(_ raw: String) -> Bool {
        canonical(raw) != nil
    }
}

/// Compile-time fleet of trusted relays. Each iOS build ships with
/// this exact set baked in; the build's code-signature transitively
/// signs the list.
public enum RelayRegistry {
    /// Production-trusted relays. Ordered for human readability — the
    /// fanout code treats the set as unordered. Today's fleet is a
    /// single onion in DE while the CH/IS/PA buildout proceeds (per
    /// the README Status checklist); the multi-relay fanout code is
    /// in place from day one so the second + third relays add
    /// without further client work.
    public static let trusted: [RelayDescriptor] = [
        // pizzini-relay-de01 — Hetzner FSN1, operator: bytepotato-ceo.
        // Onion key fingerprinted in the transparency log; the live
        // binary's SHA-256 should match the latest signed entry in
        // `transparency-log.ndjson`.
        RelayDescriptor(
            label: "Relay Germany",
            host: "pizzini2rblrswjmq7axintrq55lhnqwudf7vawckrt3toqps26vxxyd.onion",
            port: 7777
        ),
        // pizzini-relay-no01 — Hetzner-hosted, operator: bytepotato-ceo.
        // Onion key fingerprinted in the transparency log; binary
        // SHA-256 matches the DE relay byte-for-byte (deployed from
        // a mirrored copy of /usr/local/bin/pizzini-relay rather than
        // a fresh build, so the same transparency-log entry vouches
        // for both).
        RelayDescriptor(
            label: "Relay Norway",
            host: "pizzini3gqotemflwi3i5sq73bqntk4thllpmfu6fmnbezlprsy5wmid.onion",
            port: 7777
        ),
        // pizzini-relay-us01 — Hetzner-hosted, operator: bytepotato-ceo.
        // Same binary SHA-256 as DE + NO (mirror-deployed; one
        // transparency-log entry covers all three).
        RelayDescriptor(
            label: "Relay USA",
            host: "pizzini4cape4upnom4xbaugbyewdlcey5wnczcnxwuwibd3butsuyad.onion",
            port: 7777
        ),
        // Future:
        // RelayDescriptor(label: "Relay Iceland", host: "pizzini5…onion", port: 7777),
        // RelayDescriptor(label: "Relay Panama",  host: "pizzini6…onion", port: 7777),
    ]
}
