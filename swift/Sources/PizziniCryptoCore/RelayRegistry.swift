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
        // Future:
        // RelayDescriptor(label: "Relay Switzerland", host: "pizzini3…onion", port: 7777),
        // RelayDescriptor(label: "Relay Iceland",     host: "pizzini4…onion", port: 7777),
        // RelayDescriptor(label: "Relay Panama",      host: "pizzini5…onion", port: 7777),
    ]
}
