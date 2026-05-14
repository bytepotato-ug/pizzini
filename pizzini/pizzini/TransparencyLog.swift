import CryptoKit
import Foundation
import PizziniTor

/// USP #1, second half: client-side parser + verifier for the
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
///      `/proc/self/exe` at runtime (USP #1 first half — already
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
        /// Canonical bytes the signature was computed over —
        /// `compact-jq(entry)`. Stored alongside the decoded
        /// fields so verification can replay the exact input
        /// bytes the signer fed to openssl, byte-for-byte.
        let canonicalJSON: Data
    }

    /// One signed log line. `entry.canonicalJSON || "\n" || signedAt`
    /// is the message the Ed25519 signature covers. See
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
        guard let entry = decodeEntry(entryDict) else { return nil }
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

    /// Verify one signed entry against the pinned operator
    /// verify key. The signature covers
    /// `canonicalJSON || "\n" || signedAt` — the exact byte
    /// pattern the signer assembled in
    /// `sign-transparency-entry.sh`.
    static func verify(_ signed: SignedEntry) -> VerificationResult {
        guard let publicKey = TransparencyLogConfig.operatorVerifyKey else {
            return .operatorKeyMissing
        }
        guard let sig = Data(base64Encoded: signed.signatureBase64) else {
            return .badSignature
        }
        var input = signed.entry.canonicalJSON
        input.append(0x0A) // newline separator — see signer script
        input.append(contentsOf: signed.signedAt.utf8)
        return publicKey.isValidSignature(sig, for: input) ? .valid : .badSignature
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

    private static func decodeEntry(_ dict: [String: Any]) -> Entry? {
        guard let gitSha = dict["git_sha"] as? String,
              let sha = dict["binary_sha256"] as? String,
              let size = (dict["binary_size"] as? Int)
                ?? (dict["binary_size"] as? Double).map({ Int($0) })
        else { return nil }
        // Re-serialise the entry dict in canonical (sorted-keys,
        // compact) form so the signature input matches what
        // `sign-transparency-entry.sh` produced via `jq -cS`. We
        // can't reuse the input bytes directly because
        // `JSONSerialization` doesn't preserve the original
        // ordering — we have to canonicalise ourselves to be
        // sure.
        guard let canonical = canonicalJSON(dict) else { return nil }
        return Entry(
            gitSha: gitSha,
            binarySha256Hex: sha,
            binarySize: size,
            canonicalJSON: canonical
        )
    }

    /// Sorted-keys, no-whitespace JSON serialisation matching
    /// `jq -cS`. JSONSerialization's `.sortedKeys` option gives
    /// us this directly when `.withoutEscapingSlashes` is added
    /// (`/` would otherwise be escaped to `\/` on older runtimes;
    /// jq doesn't escape it, so we must match).
    private static func canonicalJSON(_ value: Any) -> Data? {
        guard JSONSerialization.isValidJSONObject(value) else { return nil }
        let options: JSONSerialization.WritingOptions = [
            .sortedKeys,
            .withoutEscapingSlashes,
        ]
        return try? JSONSerialization.data(withJSONObject: value, options: options)
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
    /// Operator's Ed25519 public key, base64 of the raw 32-byte
    /// form (the same string
    /// `scripts/generate-operator-key.sh` prints under "Raw
    /// Ed25519 public key (base64)"). Empty default = no log
    /// verification (UI renders "not configured").
    nonisolated static let operatorVerifyKeyBase64: String = "QlHwZ2S6RoU2B4J7ucPYAZueCIbiJaFZsyVawnhylpg="

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

    /// Decoded form. Returns nil for unset / malformed keys —
    /// the verifier propagates this to
    /// `VerificationResult.operatorKeyMissing` so the UI can
    /// surface "transparency log not configured" rather than a
    /// confusing "signature invalid".
    nonisolated static var operatorVerifyKey: Curve25519.Signing.PublicKey? {
        let trimmed = operatorVerifyKeyBase64
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let raw = Data(base64Encoded: trimmed),
              raw.count == 32,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw)
        else { return nil }
        return key
    }

    /// Decoded log URL. Only `https://` is accepted — a plain
    /// `http://` URL would let an active network attacker
    /// substitute the response body without our signature check
    /// catching it (the attacker still couldn't forge entries,
    /// but they could deliver a truncated/empty body which we'd
    /// have to reject anyway). Rejecting at the parse layer is
    /// the clean place.
    nonisolated static var logURL: URL? {
        let trimmed = logURLString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let url = URL(string: trimmed),
              url.scheme?.lowercased() == "https"
        else { return nil }
        return url
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

    /// Sidecar file holding the highest `signed_at` ever observed
    /// across every fetched log. Lives next to the log cache in
    /// `Library/Caches/` — both share the same durability (iOS may
    /// evict either under disk pressure, which simply restarts the
    /// monotonicity tracking, the same way it restarts the
    /// count-based rollback guard).
    private static func watermarkURL() throws -> URL {
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
    private static func parseSignedAt(_ raw: String) -> Date? {
        let fmt = ISO8601DateFormatter()
        fmt.formatOptions = [.withInternetDateTime]
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

    /// Read the persisted high-water `signed_at`, if any.
    private static func loadWatermark() -> Date? {
        guard let url = try? watermarkURL(),
              let data = try? Data(contentsOf: url),
              let text = String(data: data, encoding: .utf8),
              let epoch = TimeInterval(text.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return nil }
        return Date(timeIntervalSince1970: epoch)
    }

    /// Persist `date` as the new high-water `signed_at`. Best-effort:
    /// a write failure just means the next fetch re-evaluates against
    /// the prior (or absent) watermark.
    private static func storeWatermark(_ date: Date) {
        guard let url = try? watermarkURL() else { return }
        let text = String(date.timeIntervalSince1970)
        try? Data(text.utf8).write(to: url, options: [.atomic])
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
    ///     `docs/threat-model.md` "Known limitations".
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
            // Clearnet target: fall through to `URLSession.shared`.
            // The Tor daemon's `OnionTrafficOnly` flag (see
            // PizziniTor/TorController.makeConfiguration) refuses
            // clearnet on the SOCKS port outright, so trying Tor
            // here would produce a hard error. The IP-leak is
            // documented in the threat model.
            session = .shared
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

    /// Build a `URLSession` that routes every request through Tor's
    /// local SOCKS5 port. The Tor daemon must be bootstrapped — this
    /// throws otherwise. Audit notes that the transparency-log fetch
    /// was the only non-Tor egress in the app; the fix routes it
    /// through the same anonymising plane the relay traffic already
    /// uses, so a Cloudflare/GitHub observer learns nothing more
    /// about the user than "a Tor exit fetched the log."
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
