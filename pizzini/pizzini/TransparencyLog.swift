import CryptoKit
import Foundation
import PizziniTor

/// Client-side parser + verifier for the
/// operator-signed transparency log of relay binary deploys.
///
/// **The trust chain end-to-end:**
///
///   1. Pizzini is open source (AGPL).
///   2. `scripts/build-relay-release.sh` produces a deterministic
///      binary and prints `{git_sha, binary_sha256, binary_size}`.
///   3. The operator signs that JSON with their offline Ed25519
///      key via `scripts/sign-transparency-entry.sh` and appends
///      the signed entry to a public log file (NDJSON).
///   4. The relay's `STATUS_RESPONSE` frame reports the SHA-256 of
///      `/proc/self/exe` at runtime (already
///      shipped).
///   5. This module fetches/loads the log, verifies every entry's
///      Ed25519 signature against the operator's pinned public key
///      (`TransparencyLogConfig.operatorVerifyKey`), and exposes a
///      `contains(binarySha256:)` predicate the
///      `RelayAttestationView` uses to colour the UI green/red.
///
/// **What this defends against**: an operator with their relay
/// host compromised cannot make the running binary look
/// legitimate to clients — to do so they would need access to
/// the offline-stored operator signing key. Even a malicious
/// operator can't backdate signatures (each entry carries a
/// `signed_at` timestamp covered by the signature). On top of
/// that, `fetchAndCache` enforces monotonic ordering: it persists
/// the highest `signed_at` it has ever observed and rejects a
/// fetched log whose maximum `signed_at` regresses — so an
/// attacker who serves a strictly-older but otherwise-valid log
/// slice (same SHAs, same count, older timestamps) is caught even
/// though the count-based rollback guard would not see it.
///
/// **What this does NOT defend against**: an attacker who
/// exfiltrates the operator's signing key. Defence-in-depth
/// recommendations live in `scripts/generate-operator-key.sh`'s
/// header comments (offline key generation, two-factor controls,
/// rotation plan).
enum TransparencyLog {
    /// One entry — the structured `{git_sha, binary_sha256, ...}`
    /// JSON line produced by `scripts/build-relay-release.sh`,
    /// before the signature wrapper is layered on top.
    struct Entry: Equatable, Sendable {
        let gitSha: String
        let binarySha256Hex: String
        let binarySize: Int
        /// The operator's LITERAL `entry`-value bytes, lifted
        /// verbatim out of the NDJSON line (PZ-H12). The signature
        /// is verified over these exact bytes — never a
        /// Swift-recomputed canonical form. There is therefore
        /// exactly ONE canonicaliser in the whole system: the
        /// signer's `jq -cS`. The verifier reads bytes; it does not
        /// re-derive them. This kills the prior jq-vs-Swift
        /// two-canonicaliser hazard, where a divergence between the
        /// producer's `jq -cS` and the verifier's
        /// `JSONSerialization.sortedKeys` could either reject a
        /// genuine entry (availability) or let two byte-distinct
        /// payloads share one signature (confusion).
        let rawEntryJSON: Data
    }

    /// One signed log line. `entry.rawEntryJSON || "\n" || signedAt`
    /// is the message the Ed25519 signature covers — the literal
    /// `entry` bytes from the line, a newline, then the `signed_at`
    /// string. `signed_at` stays inside the signed message so a
    /// malicious operator still cannot backdate (or forward-date,
    /// to defeat the monotonic rollback floor) an entry. See
    /// `scripts/sign-transparency-entry.sh` for the producer side.
    struct SignedEntry: Equatable, Sendable {
        let entry: Entry
        let signedAt: String
        let signatureBase64: String
    }

    /// Verification outcomes. Cases ordered by severity for tests
    /// that want "must be at most X" assertions.
    enum VerificationResult: Sendable, Equatable {
        /// Entry validates against the pinned operator key.
        case valid
        /// Entry's JSON was malformed (missing fields, wrong shape).
        case malformedEntry(String)
        /// Signature failed cryptographic verification.
        case badSignature
        /// `TransparencyLogConfig.operatorVerifyKey` is unset.
        /// Treated as a verification failure so an unconfigured
        /// app doesn't accidentally show "verified" for entries
        /// it can't actually check.
        case operatorKeyMissing
    }

    /// Parse a single signed-entry JSON object. Returns nil for
    /// malformed input; pair with `verify` for full validation.
    static func parseSignedEntry(_ json: Data) -> SignedEntry? {
        guard let raw = try? JSONSerialization.jsonObject(with: json) as? [String: Any] else {
            return nil
        }
        guard let entryDict = raw["entry"] as? [String: Any],
              let signedAt = raw["signed_at"] as? String,
              let sig = raw["sig_b64"] as? String
        else { return nil }
        // PZ-H12: capture the operator's literal `entry`-value bytes
        // from the line. The signature is checked against these,
        // not against a re-serialisation of `entryDict` (which
        // `JSONSerialization` cannot reproduce byte-for-byte).
        guard let rawEntry = rawValueBytes(forKey: "entry", inLine: json),
              let entry = decodeEntry(entryDict, rawEntryJSON: rawEntry)
        else { return nil }
        return SignedEntry(entry: entry, signedAt: signedAt, signatureBase64: sig)
    }

    /// Parse an NDJSON-style log (one signed entry per line,
    /// blank lines ignored). Lines that don't parse are dropped
    /// with an NSLog diagnostic and don't fail the whole load —
    /// future format additions shouldn't brick an old client.
    static func parseLog(_ data: Data) -> [SignedEntry] {
        var entries: [SignedEntry] = []
        var lineStart = data.startIndex
        var i = data.startIndex
        while i < data.endIndex {
            if data[i] == 0x0A {  // newline
                let line = data[lineStart..<i]
                if !line.isEmpty,
                   let entry = parseSignedEntry(Data(line))
                {
                    entries.append(entry)
                }
                lineStart = data.index(after: i)
            }
            i = data.index(after: i)
        }
        // Last line might not have a trailing newline.
        if lineStart < data.endIndex {
            let line = data[lineStart..<data.endIndex]
            if let entry = parseSignedEntry(Data(line)) {
                entries.append(entry)
            }
        }
        return entries
    }

    /// Verify one signed entry against the configured operator verify
    /// key(s). The signature covers
    /// `rawEntryJSON || "\n" || signedAt` — the operator's literal
    /// `entry` bytes (lifted from the line, never re-canonicalised),
    /// a newline, then `signed_at`. Matches the exact byte pattern
    /// the signer assembled in `sign-transparency-entry.sh`.
    ///
    /// PZ-M16: an entry is `.valid` if its single signature validates
    /// under ANY currently-accepted key (primary + rotation keys),
    /// which is what makes a key rotation a non-flag-day change — old
    /// and new keys both verify during the transition window. This is
    /// 1-of-M, NOT an N-of-M *threshold*: each entry still carries
    /// exactly one `sig_b64`. A true threshold (require N independent
    /// operator signatures per entry) is a deliberately-deferred
    /// design decision because it is wire-breaking — it adds a
    /// `sig_b64` array to the entry schema and forces every signer +
    /// the Swift parser + the bash verifier to change together.
    static func verify(_ signed: SignedEntry) -> VerificationResult {
        verify(signed, keys: TransparencyLogConfig.operatorVerifyKeys)
    }

    /// Key-set-injectable core of `verify` (PZ-M16). Exposed so the
    /// 1-of-M rotation acceptance can be unit-tested with throwaway
    /// keys — the shipped `operatorVerifyKeys` is a `let` derived from
    /// build-time constants and can't be mutated at runtime.
    static func verify(
        _ signed: SignedEntry,
        keys: [Curve25519.Signing.PublicKey],
    ) -> VerificationResult {
        guard !keys.isEmpty else {
            return .operatorKeyMissing
        }
        guard let sig = Data(base64Encoded: signed.signatureBase64) else {
            return .badSignature
        }
        var input = signed.entry.rawEntryJSON
        input.append(0x0A) // newline separator — see signer script
        input.append(contentsOf: signed.signedAt.utf8)
        return keys.contains { $0.isValidSignature(sig, for: input) } ? .valid : .badSignature
    }

    /// Convenience: does `log` contain any verified entry whose
    /// `binarySha256Hex` matches `sha256Hex`? Case-insensitive on
    /// the hex compare so a relay reporting upper-case or the log
    /// containing lower-case don't accidentally miss each other.
    static func contains(binarySha256Hex sha256Hex: String, in log: [SignedEntry]) -> Bool {
        let needle = sha256Hex.lowercased()
        return log.contains { entry in
            guard verify(entry) == .valid else { return false }
            return entry.entry.binarySha256Hex.lowercased() == needle
        }
    }

    // MARK: - private

    /// Decode the display fields from the already-parsed `entry`
    /// dict, pairing them with the operator's `rawEntryJSON` bytes
    /// captured separately from the line. The dict is used ONLY to
    /// surface git_sha / sha / size in the UI — never to
    /// reconstruct the signed message (that is `rawEntryJSON`,
    /// PZ-H12).
    private static func decodeEntry(_ dict: [String: Any], rawEntryJSON: Data) -> Entry? {
        guard let gitSha = dict["git_sha"] as? String,
              let sha = dict["binary_sha256"] as? String,
              let size = (dict["binary_size"] as? Int)
                ?? (dict["binary_size"] as? Double).map({ Int($0) })
        else { return nil }
        return Entry(
            gitSha: gitSha,
            binarySha256Hex: sha,
            binarySize: size,
            rawEntryJSON: rawEntryJSON
        )
    }

    /// Lift the LITERAL bytes of a top-level object member's value
    /// out of a single NDJSON line, without parsing into Foundation
    /// types and re-serialising (PZ-H12). For
    /// `{"entry":<V>,"signed_at":…}` and key `"entry"` this returns
    /// exactly `<V>` — the bytes the operator's `jq -cS` emitted and
    /// signed. Returns nil if the line is not a top-level object or
    /// the key is absent.
    ///
    /// This is a minimal, allocation-light JSON value-span scanner.
    /// It respects string literals (so braces/colons/commas inside a
    /// string value don't confuse the walk) and backslash escapes.
    /// It does NOT validate the whole document — `parseSignedEntry`
    /// has already run `JSONSerialization` for that; here we only
    /// need the byte range of one value.
    static func rawValueBytes(forKey key: String, inLine line: Data) -> Data? {
        let b = [UInt8](line)
        let n = b.count
        var i = 0

        func isWS(_ c: UInt8) -> Bool { c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D }
        func skipWS() { while i < n, isWS(b[i]) { i += 1 } }

        // Scan a string starting at b[i] == '"'; return index just
        // past the closing quote, or nil if unterminated.
        func scanStringEnd(from start: Int) -> Int? {
            var j = start + 1
            while j < n {
                let c = b[j]
                if c == 0x5C { j += 2; continue } // backslash: skip escaped byte
                if c == 0x22 { return j + 1 }     // closing quote
                j += 1
            }
            return nil
        }

        // Scan any JSON value starting at index i; return index just
        // past its last byte, or nil on malformed input.
        func scanValueEnd(from start: Int) -> Int? {
            guard start < n else { return nil }
            switch b[start] {
            case 0x22: // string
                return scanStringEnd(from: start)
            case 0x7B, 0x5B: // object '{' or array '['
                let open = b[start]
                let close: UInt8 = open == 0x7B ? 0x7D : 0x5D
                var depth = 0
                var j = start
                var inStr = false
                while j < n {
                    let c = b[j]
                    if inStr {
                        if c == 0x5C { j += 2; continue }
                        if c == 0x22 { inStr = false }
                    } else if c == 0x22 {
                        inStr = true
                    } else if c == open {
                        depth += 1
                    } else if c == close {
                        depth -= 1
                        if depth == 0 { return j + 1 }
                    }
                    j += 1
                }
                return nil // unbalanced
            default: // number / true / false / null — read to delimiter
                var j = start
                while j < n {
                    let c = b[j]
                    if c == 0x2C || c == 0x7D || c == 0x5D || isWS(c) { break }
                    j += 1
                }
                return j > start ? j : nil
            }
        }

        skipWS()
        guard i < n, b[i] == 0x7B else { return nil } // top-level object
        i += 1
        let keyBytes = [UInt8](key.utf8)
        while true {
            skipWS()
            if i < n, b[i] == 0x7D { return nil } // end of object, key not found
            guard i < n, b[i] == 0x22, let keyEnd = scanStringEnd(from: i) else { return nil }
            // Member keys in this log are simple ASCII (no escapes),
            // so a direct byte compare of the quoted span's interior
            // is exact.
            let thisKey = Array(b[(i + 1)..<(keyEnd - 1)])
            i = keyEnd
            skipWS()
            guard i < n, b[i] == 0x3A else { return nil } // ':'
            i += 1
            skipWS()
            let valStart = i
            guard let valEnd = scanValueEnd(from: valStart) else { return nil }
            if thisKey == keyBytes {
                return Data(b[valStart..<valEnd])
            }
            i = valEnd
            skipWS()
            if i < n, b[i] == 0x2C { i += 1; continue } // next member
            return nil // no more members
        }
    }
}

/// Per-deployment configuration for the transparency log. The
/// operator edits this file (or patches it at build time) with
/// their actual verify key + log URL before distributing the iOS
/// app. Default values are intentionally blank so an
/// unconfigured build refuses to claim "verified" for any entry —
/// the worst failure mode for a transparency-log feature is
/// silently approving everything.
enum TransparencyLogConfig {
    /// Operator's PRIMARY (current) Ed25519 public key, base64 of the
    /// raw 32-byte form (the same string
    /// `scripts/generate-operator-key.sh` prints under "Raw
    /// Ed25519 public key (base64)"). Empty default = no log
    /// verification (UI renders "not configured").
    nonisolated static let operatorVerifyKeyBase64: String = "QlHwZ2S6RoU2B4J7ucPYAZueCIbiJaFZsyVawnhylpg="

    /// PZ-M16 — additional operator verify keys accepted DURING A KEY
    /// ROTATION, base64 raw-32 each. This is the multi-key verify
    /// capability `scripts/generate-operator-key.sh` says to ship
    /// "before rotating": to rotate, publish the new public key here
    /// (or move the retiring key here) so entries signed under EITHER
    /// the primary or any listed key verify while the transition
    /// completes, then drop the retired key on the next app release.
    ///
    /// Trust model: an entry is accepted if its signature validates
    /// under the primary OR any key in this list (1-of-M) — the
    /// standard rotation window where old and new keys both sign. This
    /// is intentionally NOT an N-of-M *threshold* (which would require
    /// several signatures per entry and is wire-breaking — it changes
    /// the signed-entry schema; see the note on `verify`). Default is
    /// empty, so a non-rotating deployment behaves EXACTLY as the
    /// single-key build did — adding a key here is the only way to
    /// widen the accepted set.
    nonisolated static let operatorRotationVerifyKeysBase64: [String] = []

    /// Public URL of the operator's NDJSON transparency log file.
    /// MUST be hosted on infrastructure **independent of the
    /// relay** (GitHub Pages, IPFS, an operator-owned static
    /// site) — fetching the log through the same channel that
    /// serves a potentially-tampered binary would defeat the
    /// purpose. TLS is sufficient for transport integrity; the
    /// E2E signature provides cryptographic integrity.
    /// Empty default = no automatic fetch (UI renders
    /// "log URL not configured").
    ///
    /// Points at the canonical iOS repo's raw view. The repo IS the
    /// source of truth for the signed log — entries are appended via
    /// `scripts/sign-transparency-entry.sh` and committed alongside
    /// the binary SHA they attest to. The fetch is Tor-routed for
    /// `.onion` hosts via `torSession`; for this clearnet GitHub
    /// host the fetch goes through `URLSession.shared` (documented
    /// IP-leak trade-off, see `fetchAndCache` comment).
    nonisolated static let logURLString: String = "https://raw.githubusercontent.com/bytepotato-ug/pizzini/main/transparency-log.ndjson"

    /// Decode one base64 raw-32 Ed25519 public key, or nil if the
    /// string is empty / malformed / the wrong length.
    nonisolated static func decodeVerifyKey(_ base64: String) -> Curve25519.Signing.PublicKey? {
        let trimmed = base64.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let raw = Data(base64Encoded: trimmed),
              raw.count == 32,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw)
        else { return nil }
        return key
    }

    /// All currently-accepted operator verify keys: the primary plus
    /// any rotation keys (PZ-M16), malformed/empty entries dropped.
    /// `verify` accepts an entry whose signature validates under ANY
    /// of these. Empty = no log verification (UI renders "not
    /// configured"); the worst failure mode is silently approving
    /// everything, so an unconfigured build returns an empty set and
    /// `verify` reports `.operatorKeyMissing`.
    nonisolated static var operatorVerifyKeys: [Curve25519.Signing.PublicKey] {
        ([operatorVerifyKeyBase64] + operatorRotationVerifyKeysBase64)
            .compactMap(decodeVerifyKey)
    }

    /// Decoded PRIMARY key, or nil if unset/malformed. Retained for
    /// the "is the log feature configured at all?" checks in the UI
    /// (`RelayAttestationView`, `ChatStore`) and tests; equivalent to
    /// `operatorVerifyKeys.first`. `verify` itself uses the full
    /// `operatorVerifyKeys` set.
    nonisolated static var operatorVerifyKey: Curve25519.Signing.PublicKey? {
        operatorVerifyKeys.first
    }

    /// Decoded log URL. `https://` is accepted for any host. `http://`
    /// is accepted ONLY for a `.onion` host (PZ-M20): a Tor hidden
    /// service already provides end-to-end transport confidentiality and
    /// cryptographic authentication of the onion address, so a clearnet
    /// active attacker can't substitute the body, and entries are
    /// Ed25519-signed on top. Clearnet `http://` stays rejected — there
    /// an attacker could swap the response. This lets the log fetch move
    /// onto an operator `.onion` mirror (killing the GitHub reconnect
    /// beacon) without requiring TLS termination on the hidden service.
    nonisolated static var logURL: URL? {
        let trimmed = logURLString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let url = URL(string: trimmed),
              urlSchemeIsAcceptable(url)
        else { return nil }
        return url
    }

    /// Pure scheme/host gate for the log URL, extracted so the
    /// onion-only `http://` exception can be unit-tested.
    nonisolated static func urlSchemeIsAcceptable(_ url: URL) -> Bool {
        switch url.scheme?.lowercased() {
        case "https":
            return true
        case "http":
            return url.host?.hasSuffix(".onion") == true
        default:
            return false
        }
    }
}

// MARK: - TransparencyLog network fetch + on-disk cache

extension TransparencyLog {
    /// Failure modes surfaced to the host. Each maps cleanly to a
    /// UI string — the UI doesn't need to know about HTTP status
    /// codes, just whether the user should retry / wait / panic.
    enum FetchError: Error, Equatable, Sendable {
        /// `TransparencyLogConfig.logURLString` is empty or not
        /// HTTPS. Treated as user-actionable (operator should
        /// configure the build) rather than a transient network
        /// failure.
        case urlNotConfigured
        /// HTTP layer rejected the request (non-2xx status,
        /// timeout, DNS failure, etc.). The wrapped String is
        /// developer-facing.
        case http(String)
        /// Body downloaded but produced zero valid signed entries
        /// (parse / signature errors only). Treated separately
        /// from `http` because the network worked; the data did
        /// not.
        case empty
        /// **Rollback defence.** Newly-fetched log has fewer
        /// VALID entries than the previously-cached one, OR is
        /// missing a previously-known SHA. Returned by
        /// `fetchAndCache` so the host can surface a stronger
        /// warning than a normal load failure ("an attacker may
        /// be feeding you a stale log").
        case rollback
        /// Filesystem error while writing or reading the cache.
        case cache(String)
    }

    /// Path of the persistent on-disk cache. Lives in
    /// `Library/Caches/` so iOS may evict it under disk pressure
    /// (recoverable — a re-fetch replays the public log) and so
    /// it is **never** included in iCloud / Finder backups —
    /// matching the chat DB's anti-backup posture.
    static func cacheURL() throws -> URL {
        let cachesDir = try FileManager.default.url(
            for: .cachesDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        return cachesDir.appendingPathComponent("pizzini-transparency-log.ndjson", isDirectory: false)
    }

    /// Load the cached log from disk, if any. Returns an empty
    /// array on first launch / missing cache / parse failure —
    /// the caller can immediately call `fetchAndCache` to
    /// repopulate, and rendering an empty log is the same as
    /// "not yet fetched" semantically.
    static func loadCachedLog() -> [SignedEntry] {
        guard let url = try? cacheURL(),
              let data = try? Data(contentsOf: url)
        else { return [] }
        return parseLog(data)
    }

    /// UserDefaults key holding the highest `signed_at` ever observed
    /// across every fetched log, as a `timeIntervalSince1970` Double.
    /// Stored in UserDefaults — NOT the evictable `Library/Caches` dir —
    /// so iOS reclaiming disk space can't silently reset the rollback
    /// floor (F-TL-03). The floor must be at least as durable as the
    /// decision it gates; the log cache itself stays in Caches because
    /// it is re-fetchable, but the rollback floor is not.
    private static let watermarkDefaultsKey = "pizzini.transparencyLog.signedAtWatermark"

    /// Legacy sidecar location for the watermark (pre-F-TL-03, in
    /// `Library/Caches`). Read once on migration so an app upgrade
    /// doesn't momentarily drop the floor to nil; never written.
    private static func legacyWatermarkURL() throws -> URL {
        let cachesDir = try FileManager.default.url(
            for: .cachesDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true,
        )
        return cachesDir.appendingPathComponent("pizzini-transparency-log-watermark", isDirectory: false)
    }

    /// Parse an entry's `signed_at` (RFC3339 UTC, e.g.
    /// `2026-05-13T09:56:16Z`) into a `Date`. Returns nil for any
    /// unparseable value — a log whose newest entry has an
    /// unparseable timestamp cannot be monotonicity-checked, which
    /// `fetchAndCache` treats as a hard reject (fail-closed).
    static func parseSignedAt(_ raw: String) -> Date? {
        // Whole-second UTC is what the current signer emits
        // (sign-transparency-entry.sh). Accept fractional seconds too so
        // a future signer that emits e.g. `…:16.123Z` doesn't make
        // `maxSignedAt` nil and brick refresh fail-closed (F-TL-07) —
        // `.withFractionalSeconds` parses ONLY the fractional form, so we
        // try the plain form first and fall back.
        let fmt = ISO8601DateFormatter()
        fmt.formatOptions = [.withInternetDateTime]
        if let date = fmt.date(from: raw) { return date }
        fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fmt.date(from: raw)
    }

    /// Highest `signed_at` across `log`'s VALID entries, or nil if
    /// the log has no valid entries or none with a parseable
    /// timestamp.
    private static func maxSignedAt(in log: [SignedEntry]) -> Date? {
        log.compactMap { entry -> Date? in
            guard verify(entry) == .valid else { return nil }
            return parseSignedAt(entry.signedAt)
        }.max()
    }

    /// Read the persisted high-water `signed_at`, if any. Prefers the
    /// durable UserDefaults value; on first run after the F-TL-03
    /// upgrade it falls back to (migrates from) the legacy Caches
    /// sidecar so the floor isn't momentarily lost across the update.
    /// `defaults` is injectable for tests.
    static func loadWatermark(defaults: UserDefaults = .standard) -> Date? {
        if let epoch = defaults.object(forKey: watermarkDefaultsKey) as? Double {
            return Date(timeIntervalSince1970: epoch)
        }
        guard let url = try? legacyWatermarkURL(),
              let data = try? Data(contentsOf: url),
              let text = String(data: data, encoding: .utf8),
              let epoch = TimeInterval(text.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return nil }
        return Date(timeIntervalSince1970: epoch)
    }

    /// Persist `date` as the new high-water `signed_at` in the durable
    /// (non-evictable) store. `defaults` is injectable for tests.
    static func storeWatermark(_ date: Date, defaults: UserDefaults = .standard) {
        defaults.set(date.timeIntervalSince1970, forKey: watermarkDefaultsKey)
    }

    /// Count entries in `log` whose signature passes against the
    /// configured operator key. Used by the rollback guard +
    /// returned to the host so the UI can render
    /// "N verified entries". Linear in `log.count` × Ed25519
    /// verify cost (~30 µs each) — fine for the realistic log
    /// size of dozens of entries.
    static func verifiedCount(in log: [SignedEntry]) -> Int {
        log.filter { verify($0) == .valid }.count
    }

    /// Fetch the configured log URL, parse, and persist to the
    /// on-disk cache. Returns the loaded entries on success.
    /// Rejects (without overwriting the cache) if the new log
    /// represents a rollback vs the existing cache.
    ///
    /// `urlSession` is injectable for tests. Production callers
    /// pass `nil` and the session is built based on the URL host:
    ///
    ///   • `.onion` host → Tor SOCKS5 (default `OnionTrafficOnly`).
    ///   • Clearnet host → `URLSession.shared`. The Tor daemon
    ///     refuses clearnet via the SOCKS port at the proxy layer
    ///     (defence-in-depth in case RelayClient forgets to dial
    ///     an `.onion`), so a Tor-routed fetch of a github.com log
    ///     URL fails with "Refusing to connect to non-hidden-
    ///     service hostname." Until the operator ships an onion
    ///     mirror of the transparency log, we accept the IP-leak
    ///     trade-off for content-signed integrity. See
    ///     the threat-model doc, "Known limitations".
    static func fetchAndCache(
        from url: URL? = TransparencyLogConfig.logURL,
        urlSession: URLSession? = nil,
    ) async throws -> [SignedEntry] {
        guard let url else { throw FetchError.urlNotConfigured }

        // Modest 30 s timeout. Transparency logs are NDJSON text
        // files in the hundreds of KB range at most; anything
        // slower than that is probably the wrong host.
        var request = URLRequest(url: url)
        request.timeoutInterval = 30
        request.cachePolicy = .reloadIgnoringLocalCacheData

        let session: URLSession
        if let urlSession {
            session = urlSession
        } else if url.host?.hasSuffix(".onion") == true {
            // Onion target: route through Tor SOCKS so the relay
            // operator + every middle-man hop sees only "a Tor exit
            // fetched the log." The signed-entry chain protects
            // integrity end-to-end.
            do {
                session = try torSession()
            } catch {
                throw FetchError.http("Tor not ready: \(error.localizedDescription)")
            }
        } else {
            // Clearnet target: use an isolated, cookie-less session
            // rather than `URLSession.shared`. The Tor daemon's
            // `OnionTrafficOnly` flag (see
            // PizziniTor/TorController.makeConfiguration) refuses
            // clearnet on the SOCKS port outright, so trying Tor
            // here would produce a hard error. The IP-leak is
            // documented in the threat model; the isolated session
            // keeps this fetch unlinkable to the captive-portal probe
            // (no shared cookie jar — F-TOR-02).
            session = ClearnetSession.make()
        }
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw FetchError.http("network error: \(error.localizedDescription)")
        }
        guard let http = response as? HTTPURLResponse else {
            throw FetchError.http("non-HTTP response")
        }
        guard (200...299).contains(http.statusCode) else {
            throw FetchError.http("HTTP \(http.statusCode)")
        }

        let entries = parseLog(data)
        guard !entries.isEmpty else { throw FetchError.empty }
        let validEntries = entries.filter { verify($0) == .valid }
        guard !validEntries.isEmpty else { throw FetchError.empty }

        // Rollback defence. If we've previously cached a log
        // with N valid entries, refuse to overwrite with a log
        // that has fewer than N — this catches an attacker
        // serving a truncated / older version of the log to
        // make a tampered binary "fit" by claiming the
        // operator's matching entry hadn't been published yet.
        //
        // Note: monotonicity-by-count is a coarse check. A
        // future improvement is monotonicity-by-content: refuse
        // to overwrite if ANY previously-cached valid SHA is
        // absent from the new log. We do that here too — it
        // catches the case where the attacker replaces (not
        // truncates) the log.
        let cached = loadCachedLog()
        let cachedValid = cached.filter { verify($0) == .valid }
        if !cachedValid.isEmpty {
            if validEntries.count < cachedValid.count {
                throw FetchError.rollback
            }
            let newShas = Set(validEntries.map { $0.entry.binarySha256Hex.lowercased() })
            let missing = cachedValid
                .map { $0.entry.binarySha256Hex.lowercased() }
                .first(where: { !newShas.contains($0) })
            if missing != nil {
                throw FetchError.rollback
            }
        }

        // Monotonic-timestamp rollback defence. The count + missing-SHA
        // guard above does not catch an attacker who serves a
        // strictly-older but otherwise-valid log slice — same count,
        // same SHAs, older `signed_at` values. Persist the highest
        // `signed_at` ever observed and refuse a fetched log whose
        // newest valid entry's `signed_at` regresses below it. A log
        // whose newest entry has an unparseable timestamp cannot be
        // checked, so it is rejected (fail-closed) rather than
        // accepted unchecked.
        guard let newMax = maxSignedAt(in: entries) else {
            throw FetchError.rollback
        }
        if let watermark = loadWatermark(), newMax < watermark {
            throw FetchError.rollback
        }

        // Persist. Atomic write so a crash mid-write leaves the
        // old cache intact, not a half-truncated file.
        do {
            let target = try cacheURL()
            try data.write(to: target, options: [.atomic])
        } catch {
            throw FetchError.cache("write failed: \(error.localizedDescription)")
        }
        // Advance the high-water mark only after the cache write
        // landed — if the write failed we did not actually accept
        // this log, so the watermark must not move.
        storeWatermark(newMax)

        return entries
    }

    /// Build a `URLSession` that routes an onion-hosted transparency
    /// log request through Tor's local SOCKS5 port. The Tor daemon
    /// must be bootstrapped — this throws otherwise. The default
    /// GitHub-hosted log is clearnet and deliberately uses
    /// `URLSession.shared` above; an operator-provided onion mirror
    /// reaches this helper instead.
    ///
    /// The session is constructed on every fetch (rather than
    /// cached) so a Tor restart with a new SOCKS port — rare, but
    /// possible after a network swap — is automatically picked up
    /// without a stale-handle bug.
    private static func torSession() throws -> URLSession {
        let port = TorController.shared.socksPort
        let config = URLSessionConfiguration.ephemeral
        // `kCFNetworkProxies*` are macOS-only constants; on iOS the
        // same dictionary still works at runtime when we supply the
        // string keys directly. `URLSessionConfiguration` forwards
        // them to CFNetwork's stream layer, and the documented
        // SOCKS5 handshake fires on connect.
        config.connectionProxyDictionary = [
            "SOCKSEnable": 1,
            "SOCKSProxy": "127.0.0.1",
            "SOCKSPort": Int(port),
            "kCFStreamPropertySOCKSVersion": "kCFStreamSocketSOCKSVersion5",
        ]
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        return URLSession(configuration: config)
    }
}
