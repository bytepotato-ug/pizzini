import Foundation
import os.log
import PizziniCryptoCore
import PizziniTor
import SwiftUI
import UIKit
import UniformTypeIdentifiers
import UserNotifications

/// Coordinator: owns the libsignal `Session`, the `RelayClient`, the
/// `AppState` (relay host + contacts), and the rules for who's allowed to
/// talk to us.
///
/// Trust model: messages are only accepted from peers whose QR has been
/// scanned (i.e. identity_pub is in `state.contacts`). Inbound frames from
/// unknown identities are dropped before reaching libsignal. The Rust
/// store mirrors the peers list via `registerPeer` / `forgetPeer` so the
/// trusted set survives `serialize`/`init(serialized:)`.
@MainActor
@Observable
final class ChatStore: NSObject {
    /// SwiftUI's `@State private var store = ChatStore()` autoclosure can
    /// fire multiple times before the framework settles which instance to
    /// retain. With a singleton, every fire returns the same coordinator —
    /// `init` runs exactly once, so we open exactly one relay connection.
    static let shared = ChatStore()

    private static let relayPort: UInt16 = 7777

    // Public, observable.
    var relayState: RelayClient.State = .idle
    /// Per-relay connection state, keyed by `RelayDescriptor.host`.
    /// `RelayClient` itself is a plain final class (it lives in
    /// PizziniCryptoCore which doesn't depend on SwiftUI/Observation),
    /// so its `state` var doesn't trigger SwiftUI redraws. This dict
    /// IS observed (member of @Observable ChatStore), so Settings →
    /// Relays gets the per-row colored badge to update live as each
    /// client crosses through `.connectingToTor → .connecting →
    /// .connected`. Mirrored from the delegate's `didChange`.
    var perRelayState: [String: RelayClient.State] = [:]
    /// USP #1: most-recent self-attestation snapshot from the relay
    /// (binary SHA-256, git commit, dirty bit, crate version).
    /// Refreshed on every successful (re)connect; rendered in
    /// Settings → Relay info so users can compare the running
    /// binary against the operator-published transparency-log
    /// entry. `nil` until the first STATUS_RESPONSE lands.
    var relayStatus: RelayStatus?
    /// USP #1 second half: cached transparency-log entries loaded
    /// from disk on launch and refreshed in the background on
    /// every successful relay (re)connect. Reads pass through
    /// `TransparencyLog.contains(binarySha256Hex:in:)` to drive
    /// the Settings → Relay attestation badge. Empty if the
    /// operator hasn't configured a log URL, or if the cache is
    /// empty pre-first-fetch.
    var transparencyLog: [TransparencyLog.SignedEntry] = []
    /// Wall-clock of the last successful transparency-log fetch.
    /// Surfaced in Settings → Relay attestation so the user can
    /// tell stale cache from fresh. `nil` if no fetch has ever
    /// succeeded.
    var transparencyLogLastFetched: Date?
    /// Last error from the transparency-log fetcher, if any.
    /// `nil` when the most recent fetch (or the lack of one,
    /// when no URL is configured) is in the expected state.
    var transparencyLogError: TransparencyLog.FetchError?
    /// Persisted app state. Module-internal access (the default) so
    /// extensions in `ChatStoreGroups.swift` can mutate group rows
    /// directly; the iOS app target is a single module so the UI
    /// surfaces also see the setter — they drive mutation through
    /// ChatStore methods by convention rather than language guard.
    var state: AppState
    /// Internal-not-`private(set)` so the group fan-out extension in
    /// `ChatStoreGroups.swift` can stamp per-leg outbox entries
    /// directly. Mutation is still by-convention through ChatStore
    /// methods (extensions count as part of the type for our purposes
    /// — there's no out-of-module consumer).
    var outbox: OutboxStore
    private(set) var initError: String?

    /// In-memory ring buffer of recent group-flow events. NOT
    /// persisted — this is a runtime diagnostic, not an audit log.
    /// `DiagnosticsView` (Settings → Diagnostics) renders the
    /// buffer so users can see why a group invitation didn't show
    /// up without having to wire up Console.app. Capped at
    /// `diagBufferCap` entries; oldest evictions are silent.
    private(set) var diagEvents: [DiagEvent] = []
    private let diagBufferCap = 200

    /// One entry in the diagnostic ring buffer. The `category`
    /// string is a one-word tag (`group`, `relay`, `pair`) so the
    /// view can colour-code; `message` is human-readable text;
    /// `timestamp` drives the most-recent-first sort.
    struct DiagEvent: Identifiable, Sendable {
        let id = UUID()
        let timestamp: Date
        let category: String
        let message: String
    }

    /// Append a diagnostic event to the in-memory ring buffer AND
    /// emit the same text via os_log at .debug level (only enabled
    /// on a debug build / when the user has attached Console.app
    /// to a non-release build, mirroring DeviceIntegrity's logging
    /// policy at F-NEW-905). Trims the buffer to `diagBufferCap`
    /// from the front. Always called from `@MainActor`-bound code
    /// so the array mutation is race-free.
    ///
    /// NSLog had been the historical choice, but NSLog lines from
    /// release builds remain in `sysdiagnose` archives a coercer
    /// can exfiltrate over Lightning. os_log .debug is dropped at
    /// the kernel level on release devices.
    func diagLog(_ category: String, _ message: String) {
        os_log(.debug, "[pizzini.%{public}@] %{public}@", category, message)
        diagEvents.append(DiagEvent(
            timestamp: Date(),
            category: category,
            message: message,
        ))
        if diagEvents.count > diagBufferCap {
            diagEvents.removeFirst(diagEvents.count - diagBufferCap)
        }
    }
    /// True iff the most recent attempt to persist the libsignal session
    /// blob to Keychain failed. F-602 fix-review: the audit's deeper
    /// recommendation was to "block further encrypts behind a 'Keychain
    /// unavailable; tap to retry' UI guard rather than letting in-memory
    /// drift further". A flag drives a banner in ContentView that warns
    /// the user — chronic write failure means a force-quit will roll
    /// the on-disk session back to the last successful persist, and the
    /// next outbound encrypt will reuse a counter the peer has already
    /// consumed. Cleared the next time persistSession succeeds.
    private(set) var keychainWriteFailing: Bool = false
    var myCard: ContactCard? {
        guard let myId = myIdentityPublicCached else { return nil }
        // Privacy-narrowing: refuse to encode a BYO custom relay
        // into outbound QRs. A BYO host is the user's own choice for
        // *their* routing and is allowed to be anything (dev
        // 127.0.0.1, community-run onions). Encoding it into a card
        // a stranger then scans pins them to the same relay — for a
        // journalist on a community relay pairing with a source,
        // that narrows the source's anonymity set to "uses the same
        // relay as this journalist." Always emit the bundled-fleet
        // sentinel (empty host) instead; the peer's app will use its
        // own fleet picker (`RelayRegistry.trusted`). The
        // *informational* host comment at addContact (line 818) is
        // load-bearing for this — peers ignore the host anyway, but
        // we now strip it at emit time so a future regression can't
        // silently widen the leak.
        return ContactCard(peerId: myId, host: "", port: Self.relayPort)
    }

    // Internal — module-level access so extensions
    // (`ChatStoreGroups.swift`) can drive sealed-sender sends and
    // sign group ops without re-piping every call through a
    // proliferation of public methods. Still hidden from any
    // out-of-module consumer.
    var session: Session?
    /// **D3 (app-side fanout).** One `RelayClient` per trusted onion
    /// in the bundled fleet (`RelayRegistry.trusted`), connected in
    /// parallel. Outbound SENDs / ACKs / BUNDLEs fan out across every
    /// element in `readyRelays`. Inbound dedup is handled at the
    /// libsignal layer via `SealedSenderResult.isDuplicate`, so the
    /// receiver naturally drops the copy-of-N copies that arrive on
    /// the alternate routes.
    ///
    /// When `state.relayHost` is a non-empty BYO override (D5
    /// fallback), this array holds exactly one client pointing at the
    /// override host. When empty, it holds one client per bundled
    /// descriptor.
    var relays: [RelayClient] = []
    /// Parallel array — `relayDescriptors[i]` is the descriptor that
    /// `relays[i]` was built from. Lets the `didChange` delegate
    /// look up which descriptor a client belongs to without storing
    /// the descriptor on the RelayClient itself (which lives in a
    /// SwiftUI-free crypto-core module).
    private var relayDescriptors: [RelayDescriptor] = []
    /// Subset of `relays` currently in `.connected`. Send-fanout
    /// targets this set; if it's empty the call is a no-op (the
    /// outbox retry walk picks it back up once a relay reconnects).
    var readyRelays: [RelayClient] {
        relays.filter { $0.state == .connected }
    }
    /// Primary push-token holder. APNs registrations target ONE relay
    /// at a time — registering on N relays would mean N "New message"
    /// pushes per send while the recipient is offline (each relay
    /// independently fires the wake-up). Re-armed in
    /// `electPushPrimary` whenever the current primary drops below
    /// `.connected`.
    private weak var pushPrimary: RelayClient?
    private var myIdentityPublicCached: Data?
    /// Latest APNs token. Stashed so a relay-host change (which builds
    /// a fresh `RelayClient`) re-publishes the token automatically.
    private var pushTokenCached: Data?
    /// Periodic retry/TTL-expiry walk. Re-armed in `connectRelay` so
    /// each fresh socket gets one timer; cancelled on disconnect.
    private var retryTimer: Timer?
    /// Auto-reconnect task scheduled when the aggregate relay state
    /// transitions to `.failed`. Covers the steady-state cases where
    /// the network glitched (carrier handoff, captive portal,
    /// tor circuit died) — the user shouldn't have to manually
    /// reconnect for any of those. Cold-launch first-attempt success
    /// is delivered upstream by `TorController.prepareHiddenService`,
    /// not by this mechanism. Cancelled on teardown and on any
    /// non-failed state transition.
    private var autoReconnectTask: Task<Void, Never>?
    /// Current backoff for `autoReconnectTask`. Starts at the
    /// floor, doubles on each consecutive failure, capped at the
    /// ceiling. Reset to the floor on `.connected`. The exponential
    /// backoff is the contract that lets us auto-retry aggressively
    /// without pounding the network if the user's offline for an
    /// extended period.
    private var autoReconnectBackoff: TimeInterval = autoReconnectBackoffFloor
    /// 5 s production floor. A real failure (broken network, tor down,
    /// relay down) shouldn't get hammered at sub-second cadence —
    /// the auto-reconnect is a self-healing convenience, not a
    /// busy-wait. Cold-launch first-attempt success is delivered by
    /// `TorController.prepareHiddenService(_:)`, not by aggressive
    /// retrying: by the time the first SOCKS5 CONNECT goes out, tor
    /// already has the HS descriptor cached.
    private static let autoReconnectBackoffFloor: TimeInterval = 5
    private static let autoReconnectBackoffCeiling: TimeInterval = 60
    /// Phase 2 attachment reassembly state. Lives in-process: a force-
    /// quit while a partial inbound is in flight loses the in-RAM
    /// indices but the per-chunk files stay on disk under
    /// `attachments/incoming/{aid}/`. The next push-driven launch
    /// re-emits ACKs for any chunks that arrive again, and the 24h
    /// disk TTL eventually GCs orphaned partials.
    private let reassembler = AttachmentReassembler()
    /// Group-attachment reassembly state. A separate instance from the
    /// 1:1 `reassembler` so a paired peer who simultaneously ships a
    /// 1:1 file and a group file with colliding `attachmentId` (16
    /// random bytes — collision probability ~2^-128, but the audit-
    /// era code partitions trust surfaces explicitly) cannot confuse
    /// the dispatcher about which log row a completion belongs to.
    /// Internal-not-private so `ChatStoreGroups.swift` can feed
    /// chunks; on completion the host drains the corresponding entry
    /// from `groupAttachmentRouting` to look up the destination
    /// group.
    let groupReassembler = AttachmentReassembler()
    /// Which chat surface the user is currently looking at, if any.
    /// Used by the receive path to suppress the in-app haptic when a
    /// message arrives in the chat the user is already in (the
    /// haptic only fires for messages landing in a *different* chat
    /// while the app is foregrounded, matching the
    /// privacy-first messengers' "no in-app banner, optional sound"
    /// posture). Updated by `ChatView.onAppear/onDisappear` and
    /// `GroupChatView.onAppear/onDisappear`.
    enum ActiveSurface: Equatable, Sendable {
        case none
        case oneOnOne(peerIdentity: Data)
        case group(groupId: Data)
    }
    var activeSurface: ActiveSurface = .none
    /// Most-recent identityPub the user attempted to add via QR/paste
    /// but was rejected because the peer is on the block list. The
    /// scan/paste UI reads this on change to surface "this contact is
    /// blocked — unblock first" rather than silently no-op'ing the
    /// add. Cleared by the UI on dismissal.
    var lastBlockedAddAttempt: Data?
    /// First-chunk capture of `(peer + attachmentId) → groupId` so a
    /// later completion knows which `ChatGroup.log` to append to.
    /// Set on every accepted group-file-chunk; verified for stability
    /// on every subsequent chunk (a sender flipping the groupId mid-
    /// transfer is hostile and the chunk is dropped). Drained on
    /// completion or stale-cleanup. Internal-not-private so the group
    /// receive handler can mutate it.
    var groupAttachmentRouting: [Data: Data] = [:]

    override init() {
        self.state = Storage.loadAppState()
        self.outbox = Storage.loadOutbox()
        // USP #1 second half: pre-load any previously-cached
        // transparency-log entries so the Settings panel can
        // render an immediate answer without waiting for the
        // first reconnect to repopulate.
        self.transparencyLog = TransparencyLog.loadCachedLog()
        super.init()
        // Migration: pre-fleet installs persisted dev hosts like
        // `127.0.0.1`. Per `docs/relay-architecture.md` D1 every
        // production relay is Tor-only, so a legitimate BYO value
        // is a strictly-validated v3 onion. Anything else (LAN IPs,
        // hostnames, localhost, mixed-case ASCII, Unicode look-alike
        // glyphs, `evil.com.onion`-style trailing-suffix poisoning,
        // i2p .b32.i2p addresses, …) is migrated to fleet mode so
        // we never silently downgrade the user to a non-Tor path.
        //
        // The previous suffix-only check (`.hasSuffix(".onion")`)
        // was bypassable. We now run `OnionHost.canonical` which
        // applies the full validator set; if the persisted value
        // does not canonicalise to itself (or fails outright) we
        // reset to fleet.
        //
        // Must run AFTER super.init() — `self.state =` on an
        // NSObject subclass is illegal until then.
        let trimmed = self.state.relayHost.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty, OnionHost.canonical(trimmed) != trimmed {
            // Diagnostic ONLY: the rejected literal value is NOT
            // logged. A pre-pasted LAN host could carry private
            // identifiers (internal hostnames, user-specific paths
            // a sysdiagnose collector would surface); the byte
            // count is enough for "did the migration fire" without
            // leaking the input.
            pzLog("[pizzini] migrating legacy relayHost (len=\(trimmed.count)) → fleet mode")
            self.state.relayHost = ""
            Storage.upsertSettings(self.state)
        } else if !trimmed.isEmpty, trimmed != self.state.relayHost {
            // Canonicalisation succeeded but the stored value had
            // trailing whitespace or capitalisation; rewrite the
            // canonical form so every later compare/key hits the
            // same string.
            self.state.relayHost = trimmed
            Storage.upsertSettings(self.state)
        }
        do {
            let s = try Storage.loadOrCreateSession()
            self.session = s
            self.myIdentityPublicCached = try s.identityPublic()
            connectRelay()
        } catch {
            self.initError = String(describing: error)
        }
        refreshAppBadge()
    }

    /// USP #1 second half: refresh the transparency log from the
    /// operator's configured public URL. Idempotent — safe to
    /// call on every reconnect plus a manual button. Network
    /// failures and rollback rejections surface via
    /// `transparencyLogError` so the UI can render an explicit
    /// state.
    ///
    /// Runs as a detached task because the call site is the
    /// MainActor-isolated `relayClient(_:didChange:)` handler;
    /// we don't want the HTTP round-trip blocking the UI.
    func refreshTransparencyLog() {
        guard TransparencyLogConfig.logURL != nil else {
            // No URL configured — leave the cached log + error
            // state alone; the UI's "not configured" branch
            // covers this case explicitly.
            return
        }
        Task { @MainActor in
            do {
                let fresh = try await TransparencyLog.fetchAndCache()
                self.transparencyLog = fresh
                self.transparencyLogLastFetched = Date()
                self.transparencyLogError = nil
                pzLog(
                    "[pizzini.translog] refreshed: \(fresh.count) entries, \(TransparencyLog.verifiedCount(in: fresh)) verified",
                )
            } catch let err as TransparencyLog.FetchError {
                self.transparencyLogError = err
                pzLog("[pizzini.translog] fetch failed: \(err)")
            } catch {
                self.transparencyLogError = .http(error.localizedDescription)
                pzLog("[pizzini.translog] fetch failed (unexpected): \(error)")
            }
        }
    }

    /// Outbox entry for `messageId`, if any. Used by the chat row to
    /// pick its status icon.
    func outboxEntry(forMessageId id: Data) -> OutboxEntry? {
        outbox.entries[id]
    }

    /// Forwards the APNs device token to the relay so it can wake us
    /// when a SEND lands while we're disconnected. Called by
    /// `AppDelegate` once iOS has issued a token. With multi-relay
    /// fanout (D3), the token registers on exactly ONE relay — see
    /// `pushPrimary` for the elect / re-elect rules.
    func publishPushToken(_ token: Data) {
        pushTokenCached = token
        pushPrimary?.registerPush(token: token)
    }

    // MARK: - Relay

    /// Build a target list for the current connect cycle.
    ///
    /// **Fleet mode (D5 default):** when `state.relayHost` is empty,
    /// connect to every entry in `RelayRegistry.trusted`.
    /// **BYO mode (D5 fallback):** when `state.relayHost` is set,
    /// connect to just that one host. Used by dev/test (127.0.0.1)
    /// and by communities running their own relay. BYO disables the
    /// fleet — D3 fanout only spans the bundled list, not the
    /// user-typed override.
    private func relayTargets() -> [RelayDescriptor] {
        let trimmed = state.relayHost.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return RelayRegistry.trusted
        }
        // D1 Tor-only: a BYO override that doesn't canonicalise to a
        // valid v3 onion gets rejected; the fleet stays the fallback.
        // The init-time migration above usually wipes such a value
        // first, but we double-guard here in case `setRelayHost` is
        // ever bypassed (e.g. a future direct mutation of `state`).
        guard let canonical = OnionHost.canonical(trimmed) else {
            pzLog("[pizzini] BYO relayHost (len=\(trimmed.count)) failed onion validation; using fleet")
            return RelayRegistry.trusted
        }
        return [RelayDescriptor(label: "Custom relay", host: canonical, port: Self.relayPort)]
    }

    private func connectRelay() {
        guard let session else { return }
        // Wipe the previous fleet completely before standing up new
        // clients. The clear-delegate-before-disconnect dance from
        // the single-relay era is preserved (see comment in
        // `teardownRelay`); without it, a dying client's `.idle`
        // callback can clobber the fresh fleet's aggregated state
        // moments after we've replaced it.
        teardownRelay(keepRetryTimer: true)
        guard
            let myId = myIdentityPublicCached ?? (try? session.identityPublic()),
            let verifyKey = try? session.deliveryTokenVerifyKey()
        else {
            return
        }
        let targets = relayTargets()
        // Strong capture for HELLO signing — RelayClient lifetime is
        // bounded by the fleet we're building; `teardownRelay` clears
        // the array on identity reset, and the captured closure is
        // then harmless.
        let signingSession = session
        for descriptor in targets {
            let client = RelayClient(
                myIdentity: myId,
                myDeliveryTokenVerifyKey: verifyKey,
                signer: { payload in
                    // F-NEW-101: HELLO signatures are domain-separated
                    // by the `hello` context tag. The FFI prepends
                    // `u16(tag_len) || tag` before signing.
                    try? signingSession.identitySign(
                        payload,
                        contextTag: Session.SignatureContext.hello,
                    )
                },
            )
            client.delegate = self
            relays.append(client)
            relayDescriptors.append(descriptor)
            perRelayState[descriptor.host] = .idle
            pzLog("[pizzini] connecting to \(descriptor.label) @ \(descriptor.host):\(descriptor.port)")
            client.connect(to: descriptor.host, port: descriptor.port)
        }
        // Push primary is re-elected lazily as relays cross into
        // `.connected`; the first one to land wins. See
        // `electPushPrimary` / the `didChange` delegate path.
        pushPrimary = nil
        scheduleRetryTimer()
    }

    /// Elect the push-token primary. Called whenever a relay
    /// transitions in or out of `.connected`. Picks the first ready
    /// relay (deterministic per session, since `relays` retains the
    /// `relayTargets()` order) and registers our cached APNs token
    /// against it. Idempotent — re-electing the same primary is a
    /// no-op.
    ///
    /// On reshuffle (the previous primary dropped, a new one took
    /// its place) the OLD primary is sent a DEREGISTER_PUSH frame
    /// while it's still connected. Without that, the relay's
    /// persistent push-token store on the old primary keeps our
    /// token until the 30-day TTL purge — and since every connected
    /// relay independently evaluates `maybe_send_push` on every
    /// inbound SEND for us, the user would get N duplicate APNs
    /// wake-ups per message until the TTL expired. If the old
    /// primary is unreachable (already torn down, lost connection)
    /// the DEREGISTER is silently skipped — that's tolerable
    /// because the next legitimate REGISTER_PUSH to that relay
    /// overwrites the stale token, and the relay's TTL purge
    /// reaps anything else within 30 days.
    private func electPushPrimary() {
        let firstReady = readyRelays.first
        guard firstReady !== pushPrimary else { return }
        let oldPrimary = pushPrimary
        pushPrimary = firstReady
        // Best-effort DEREGISTER to the previous primary. We do it
        // before the new register so the relay-side ordering
        // mirrors the client-side intent: "drop the OLD, then
        // start the NEW".
        oldPrimary?.deregisterPush()
        if let token = pushTokenCached, let primary = firstReady {
            primary.registerPush(token: token)
        }
    }

    /// Aggregate the per-relay states into the single value the UI
    /// reads via `relayState`. Rules, in priority order:
    ///   1. **Any** ready → `.connected`.
    ///   2. **Any** in `.connectingToTor` → take the max progress
    ///      across the fleet. (In practice every client shares the
    ///      same `TorController` singleton, so progress is uniform;
    ///      `max` is the safe choice if that ever changes.)
    ///   3. **Any** `.connecting` → `.connecting`.
    ///   4. **All** failed → `.failed(merged-message)`.
    ///   5. Otherwise → `.idle`.
    ///
    /// "Any ready wins" is the contract D3 hangs on — the user only
    /// cares that we can send + receive, not how many redundant routes
    /// are alive.
    private func aggregateRelayState() -> RelayClient.State {
        guard !relays.isEmpty else { return .idle }
        if relays.contains(where: { $0.state == .connected }) {
            return .connected
        }
        let torProgresses: [Int] = relays.compactMap { client in
            if case let .connectingToTor(p) = client.state { return p }
            return nil
        }
        if let p = torProgresses.max() {
            return .connectingToTor(progress: p)
        }
        if relays.contains(where: { $0.state == .connecting }) {
            return .connecting
        }
        let failures: [String] = relays.compactMap { client in
            if case let .failed(msg) = client.state { return msg }
            return nil
        }
        if failures.count == relays.count, let first = failures.first {
            // De-dup identical messages (e.g. "Tor bootstrap failed:
            // …" reported by N clients sharing one TorController),
            // preserving the FLEET order so the rendered string is
            // stable across re-renders. Using `Set` would shuffle
            // the dedup output every time the view recomputed,
            // producing visible flicker in DiagnosticsView /
            // Settings → Relays.
            var seen = Set<String>()
            var unique: [String] = []
            for msg in failures where seen.insert(msg).inserted {
                unique.append(msg)
            }
            // Bound the joined string so a runaway NWError
            // description (NWConnection occasionally yields
            // multi-hundred-byte messages embedding onion
            // hostnames and POSIX strerror strings) cannot
            // unboundedly inflate the user-visible diagnostic.
            // 240 chars is enough for two full RFC 1928 §6
            // names plus a separator without overrunning the
            // single-line Settings row. Anything longer is
            // truncated with an ellipsis; the full per-relay
            // error remains visible on each relay's expand row.
            let joined = unique.count == 1
                ? first
                : unique.joined(separator: " / ")
            let bounded = Self.boundedFailureString(joined)
            return .failed(bounded)
        }
        return .idle
    }

    /// Hard cap on the user-visible aggregated failure string. See
    /// `aggregateRelayState`. Public-on-the-class for tests.
    static let maxAggregatedFailureLength: Int = 240
    static func boundedFailureString(_ s: String) -> String {
        if s.count <= maxAggregatedFailureLength { return s }
        let head = s.prefix(maxAggregatedFailureLength - 1)
        return "\(head)…"
    }

    /// **D3 broadcaster.** Invoke `body` on every currently-ready
    /// relay. Returns the count for callers that want to know whether
    /// at least one delivery path succeeded.
    ///
    /// The "currently-ready" set is sampled once and held for the
    /// duration of the call — a relay that drops mid-loop is treated
    /// as still-ready (NWConnection's send completion will surface
    /// the error and the retry walk picks it up later); a relay that
    /// arrives mid-loop misses this round (it'll catch the next
    /// outbox tick). Both behaviours match the single-relay semantics
    /// the call-sites were originally written against.
    @discardableResult
    func broadcastToRelays(_ body: (RelayClient) -> Void) -> Int {
        let ready = readyRelays
        for r in ready { body(r) }
        return ready.count
    }

    private func scheduleRetryTimer() {
        retryTimer?.invalidate()
        // 30s matches the OutboxEntry.shouldRetry minimum baseline so
        // every wake-up is actionable on at least the freshest entry.
        let timer = Timer(timeInterval: 30, repeats: true) { [weak self] _ in
            guard let self else { return }
            DispatchQueue.main.async {
                self.runRetryWalk()
            }
        }
        timer.tolerance = 5
        RunLoop.main.add(timer, forMode: .common)
        retryTimer = timer
    }

    /// Drive the auto-reconnect state machine from each per-relay
    /// `.didChange` event. The contract:
    ///
    ///   * On the FIRST transition into `.failed` (i.e. the previous
    ///     aggregate was not failed), arm `autoReconnectTask` with
    ///     the current `autoReconnectBackoff`, then double the
    ///     backoff for the next attempt (capped at the ceiling).
    ///   * On transition into `.connected`, reset the backoff to
    ///     the floor and cancel any pending task.
    ///   * Other transitions are no-ops — a flap within `.connecting`
    ///     states is normal during a Tor bootstrap and shouldn't
    ///     accumulate backoff.
    ///
    /// The handler runs on MainActor (called from the `relayClient`
    /// delegate hop), so direct property mutation is sound.
    private func handleAggregateRelayStateTransition(
        from prev: RelayClient.State,
        to next: RelayClient.State,
    ) {
        switch next {
        case .connected:
            autoReconnectTask?.cancel()
            autoReconnectTask = nil
            autoReconnectBackoff = Self.autoReconnectBackoffFloor
        case .failed:
            // Already failed previously? Don't double-arm — there's
            // already a task in flight. (The existing task will
            // re-fire connectRelay on its own deadline.)
            if case .failed = prev { return }
            let delay = autoReconnectBackoff
            pzLog("[pizzini] aggregate state .failed; auto-reconnecting in \(Int(delay)) s")
            autoReconnectBackoff = min(
                autoReconnectBackoff * 2,
                Self.autoReconnectBackoffCeiling,
            )
            autoReconnectTask?.cancel()
            autoReconnectTask = Task { @MainActor [weak self] in
                let nanos = UInt64(delay * 1_000_000_000)
                try? await Task.sleep(nanoseconds: nanos)
                guard let self else { return }
                if Task.isCancelled { return }
                // Re-check state — the user might have manually
                // reconnected, or the prior attempt might have
                // self-recovered between schedule and fire.
                if case .failed = self.relayState {
                    pzLog("[pizzini] auto-reconnect firing")
                    self.connectRelay()
                }
            }
        case .idle, .connecting, .connectingToTor:
            // No-op. A transient drop through `.connecting` between
            // two `.connected` states is normal during Tor circuit
            // rebuilds; the backoff stays where it is so the NEXT
            // genuine failure doesn't restart from 5 s.
            break
        }
    }

    /// Force-rebuild every RelayClient. Bound to the Settings →
    /// Relays → "Reconnect now" button AND the contacts-toolbar
    /// "tap to reconnect" pill. Useful when a Tor circuit gets
    /// stuck on a slow guard and the user wants to retry without
    /// re-launching. Tor itself stays bootstrapped if it was
    /// already (the second `connect()` reuses the cached SOCKS
    /// port), so the second cycle is sub-5 s on healthy networks.
    ///
    /// Tap-spam defence: a manual reconnect is meaningful only when
    /// the aggregate state is `.failed`. If it's `.connected`,
    /// there's nothing to retry; if it's `.connecting` or
    /// `.connectingToTor`, a previous reconnect (or the initial
    /// connect) is already mid-flight and a second teardown would
    /// drop the in-flight Tor handshake / SOCKS retry it would
    /// otherwise complete. Either way, no-op silently. The button
    /// is hidden by ContactsListView in those states; this is
    /// belt-and-braces in case a future call site forgets the
    /// guard.
    func forceReconnectRelays() {
        switch relayState {
        case .failed:
            pzLog("[pizzini] manual reconnect requested")
            // Reset auto-reconnect backoff: the user's explicit
            // intervention means the NEXT failure should retry
            // quickly, not wait for the accumulated 60 s cap.
            autoReconnectBackoff = Self.autoReconnectBackoffFloor
            connectRelay()
        case .connected, .connecting, .connectingToTor, .idle:
            pzLog("[pizzini] reconnect requested but state is \(relayState); ignoring")
        }
    }

    /// Apply a BYO relay-host override (D5 fallback). Pass an empty
    /// string to clear the override and fall back to the bundled
    /// fleet. Non-empty values must canonicalise to a valid v3
    /// onion (`OnionHost.canonical`); anything else is rejected so
    /// the user can never accidentally downgrade the app to a
    /// clear-text TCP dial. Returns `true` on success, `false` on
    /// validation failure (the existing setting is left untouched).
    @discardableResult
    func setRelayHost(_ host: String) -> Bool {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            guard !state.relayHost.isEmpty else { return true }
            state.relayHost = ""
            Storage.upsertSettings(state)
            connectRelay()
            return true
        }
        guard let canonical = OnionHost.canonical(trimmed) else {
            return false
        }
        guard canonical != state.relayHost else { return true }
        state.relayHost = canonical
        Storage.upsertSettings(state)
        connectRelay()
        return true
    }

    /// Cleanly tear down the relay socket as the app moves to
    /// background. iOS suspends networking shortly after background;
    /// keeping a half-dead NWConnection across suspension produces
    /// stale `.failed` callbacks that surface only on the *next*
    /// foreground (red → green → red flapping). Closing here avoids
    /// the race entirely.
    ///
    /// Tor is held open for `torBackgroundGrace` seconds after the
    /// relay socket closes. That window covers the existing
    /// `retryTimer` outbox-drain ticks that may want to reopen the
    /// relay one last time before iOS suspends us. If iOS suspends
    /// us before the grace expires, the scheduled stop never fires
    /// — that's fine, the singleton's pendingBootstrap is cleared
    /// on the next foreground bootstrap() call.
    func disconnectForBackground() {
        guard !relays.isEmpty else { return }
        pzLog("[pizzini] backgrounding — relay teardown scheduled in \(Int(Self.backgroundRelayGrace)) s, tor stop in \(Int(Self.torBackgroundGrace)) s")
        scheduleRelayTeardown()
        scheduleTorBackgroundStop()
    }

    /// Background grace before the RELAY SOCKET is torn down.
    /// Shorter than `torBackgroundGrace` because we want to give
    /// iOS room to soft-background us briefly (app-switcher peek,
    /// Control Centre pull-down, glancing at a push notification)
    /// without firing a teardown → reconnect cycle the user sees
    /// as a "Connecting…" flash on the global status bar. 10 s is
    /// well inside iOS's "definitely not suspended yet" envelope
    /// (~30 s on healthy devices); if the user comes back within
    /// the window AND the socket is still `.connected`, we skip
    /// the reconnect entirely and the foreground transition is
    /// visually instant.
    private static let backgroundRelayGrace: TimeInterval = 10

    /// Background grace before Tor itself is stopped. 30 s lines up
    /// with iOS's standard "soft background" allowance and the
    /// 30-second retry-walk cadence in `scheduleRetryTimer`.
    private static let torBackgroundGrace: TimeInterval = 30

    /// Pending background-stop. Re-entering foreground cancels it so
    /// we don't tear down Tor right after the user comes back. The
    /// concrete value is a `DispatchWorkItem` we can cancel by
    /// reference — `asyncAfter` alone has no cancellation handle.
    private var torStopWorkItem: DispatchWorkItem?

    /// Pending relay-socket teardown. Same cancellation pattern as
    /// `torStopWorkItem`. Distinct from it because the relay-socket
    /// grace is shorter (10 s) than the tor grace (30 s) — we want
    /// to tolerate a quick app-switcher peek without a reconnect
    /// flash, but a longer background should still let the socket
    /// die cleanly before iOS suspends us.
    private var relayTeardownWorkItem: DispatchWorkItem?

    private func scheduleTorBackgroundStop() {
        torStopWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard self != nil else { return }
            pzLog("[pizzini] tor stop (background grace expired)")
            TorController.shared.stop()
        }
        torStopWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.torBackgroundGrace, execute: work)
    }

    private func cancelTorBackgroundStop() {
        torStopWorkItem?.cancel()
        torStopWorkItem = nil
    }

    private func scheduleRelayTeardown() {
        relayTeardownWorkItem?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            guard !self.relays.isEmpty else { return }
            pzLog("[pizzini] relay teardown (background grace expired)")
            self.teardownRelay()
            self.relayTeardownWorkItem = nil
        }
        relayTeardownWorkItem = work
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.backgroundRelayGrace, execute: work)
    }

    private func cancelRelayTeardown() {
        relayTeardownWorkItem?.cancel()
        relayTeardownWorkItem = nil
    }

    /// F-704: shared disconnect path used by `disconnectForBackground`
    /// AND `resetIdentity`. The earlier asymmetry — where `resetIdentity`
    /// only called `relay?.disconnect()` and relied on the next
    /// `connectRelay()` to clear delegate / timer / `self.relay` — was
    /// not exploitable but was a refactor trip-wire: any future `await`
    /// inserted between disconnect and reconnect could let a queued
    /// retry tick fire on the OLD client with the new outbox state. Make
    /// the cleanup symmetric and explicit.
    private func teardownRelay(keepRetryTimer: Bool = false) {
        for r in relays {
            r.delegate = nil
            r.disconnect()
        }
        relays.removeAll()
        relayDescriptors.removeAll()
        perRelayState.removeAll()
        pushPrimary = nil
        relayState = .idle
        if !keepRetryTimer {
            retryTimer?.invalidate()
            retryTimer = nil
        }
        // Cancel any pending auto-reconnect task — `connectRelay()`
        // (the only caller besides the cleanup paths) will fire its
        // own fresh attempt synchronously, and on `resetIdentity`
        // we don't want a stale auto-reconnect resurrecting the
        // fleet after the wipe.
        autoReconnectTask?.cancel()
        autoReconnectTask = nil
    }

    /// Foreground-entry handler. Three cases:
    ///
    /// 1. **Inside the relay grace window AND socket still
    ///    `.connected`.** The teardown timer hadn't fired yet, the
    ///    socket survived the brief background (iOS hasn't suspended
    ///    us in this window), and there's nothing to do — cancel the
    ///    teardown, leave the live socket in place. User gets
    ///    visually instant foreground entry, no `Connecting…` flash.
    ///
    /// 2. **Inside the window BUT socket isn't `.connected`.** The
    ///    socket dropped during background (rare — usually means a
    ///    cover-frame send failed mid-suspend, surfacing as `.failed`
    ///    later). Cancel the teardown, then do a full reconnect.
    ///
    /// 3. **Grace window expired (teardown already ran, relays
    ///    empty), or we never backgrounded with a socket alive.**
    ///    Standard reconnect path.
    func reconnectAfterBackground() {
        // Always cancel the tor-stop — Tor is a fleet-wide singleton
        // we want to keep alive across any foreground transition.
        cancelTorBackgroundStop()

        // Case 1: grace window still active + healthy socket.
        if let pendingTeardown = relayTeardownWorkItem,
           !pendingTeardown.isCancelled,
           !relays.isEmpty,
           case .connected = relayState
        {
            cancelRelayTeardown()
            pzLog("[pizzini] foreground within grace window — relay socket kept alive")
            return
        }

        // Case 2 + 3: teardown if anything's still hanging around,
        // then full reconnect. `teardownRelay` is safe to call with
        // an empty relays array; `connectRelay` is idempotent
        // against in-flight state.
        cancelRelayTeardown()
        if !relays.isEmpty {
            teardownRelay()
        }
        pzLog("[pizzini] relay reconnect on foreground")
        connectRelay()
    }

    // MARK: - Contacts

    func contact(forIdentity peerId: Data) -> Contact? {
        state.contacts.first { $0.identityPub == peerId }
    }

    private func contactIndex(forIdentity peerId: Data) -> Int? {
        state.contacts.firstIndex { $0.identityPub == peerId }
    }

    /// Result of running a freshly-pasted clipboard string through
    /// `evaluatePastedContact(_:)`. Distinct cases so the calling
    /// view can show a precise alert for every failure path instead
    /// of the historic silent return.
    enum ContactCardPasteOutcome: Equatable {
        /// Syntactically + semantically OK. Caller should drive the
        /// name-prompt flow, then `addContact(card:displayName:source:)`.
        case ready(ContactCard)
        /// Clipboard was empty or whitespace-only.
        case empty
        /// `ContactCard.validate(_:)` threw — `reason` is the user-
        /// facing one-line explanation.
        case malformed(reason: String)
        /// The peerId matches the user's own identity. Pairing with
        /// yourself doesn't make sense; tell the user clearly.
        case selfPaste
        /// peerId is in the block list. UI surfaces a "unblock first"
        /// hint instead of silently swallowing the add.
        case blocked
        /// peerId already exists in `state.contacts`. We don't append
        /// a second row, but we DO retry the bundle exchange in case
        /// the first-contact handshake stalled. `name` is the existing
        /// row's display name so the alert can say "Already paired
        /// with Alice."
        case alreadyPaired(name: String)
    }

    /// Single chokepoint that converts a raw clipboard string into one
    /// of the outcomes above. Runs `ContactCard.validate` for syntax,
    /// then layers on the four semantic checks (self / blocked /
    /// duplicate / OK).
    ///
    /// Why this lives on the store rather than on `ContactCard`:
    /// the syntactic check is pure (no state) and stays on
    /// `ContactCard`; the semantic checks need `state.contacts`,
    /// `blockedIdentities`, and `myIdentityPublicCached`, all of
    /// which are store-local. Mixing the two would force every UI
    /// surface that wants the strict parse (tests, future tooling)
    /// to spin up a full ChatStore.
    func evaluatePastedContact(_ raw: String) -> ContactCardPasteOutcome {
        // Early-exit for the common "menu hit with empty clipboard"
        // case so we don't burn an audit-log line on it.
        if raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            pzLog("[pizzini.paste] clipboard empty")
            return .empty
        }
        let card: ContactCard
        do {
            card = try ContactCard.validate(raw)
        } catch {
            // `validate` uses typed throws, so `error` is statically
            // `ContactCardDecodeError`. A future widening of that
            // signature would force this site to compile-fail on
            // `error.reason`, which is the signal we want anyway.
            pzLog("[pizzini.paste] malformed: \(error.reason)")
            return .malformed(reason: error.reason)
        }
        // Self-paste — the peerId matches our own identity.
        if let myId = myIdentityPublicCached, myId == card.peerId {
            pzLog("[pizzini.paste] rejected: self-paste")
            return .selfPaste
        }
        // Block list.
        if isIdentityBlocked(card.peerId) {
            pzLog("[pizzini.paste] rejected: identity is in block list")
            return .blocked
        }
        // Duplicate. Mirror the QR-scan idempotency: re-request the
        // bundle so a stalled first-contact handshake gets retried,
        // but don't append a second row. Only fire the bundle retry
        // when the relay fleet is currently up — otherwise it's
        // queued silently and would just look like a no-op.
        if let existing = state.contacts.first(where: { $0.identityPub == card.peerId }) {
            if relayState == .connected {
                requestBundleWithHashcash(fromPeer: card.peerId)
            }
            pzLog("[pizzini.paste] already paired with \(self.short(card.peerId))")
            return .alreadyPaired(name: existing.displayName)
        }
        pzLog("[pizzini.paste] ready: peer=\(self.short(card.peerId))")
        return .ready(card)
    }

    /// Commit a freshly-scanned (or pasted) contact. Idempotent on
    /// `card.peerId`: re-adding the same QR is a no-op apart from a bundle
    /// retry. Eagerly requests the peer's bundle if the relay is up.
    ///
    /// `displayName` is what the host (UI) collected from the user at
    /// pairing time. Empty/whitespace falls back to the fingerprint
    /// default so the row is still distinguishable.
    ///
    /// `source` records how the identity bytes reached the device.
    /// Mandatory at the call site — UI shows different verification
    /// affordances for `.qrScan` vs `.pastedText`. The value is fixed
    /// on first insert and *not* updated on re-add: re-scanning a
    /// previously-pasted contact would otherwise quietly upgrade
    /// trust without the safety-number step (see upsertContact in
    /// SQLiteStorage).
    ///
    /// Note: `card.host` is *informational* — it's the address the peer
    /// uses to reach the relay. We never adopt it as our own relay host;
    /// scanning a sim's `127.0.0.1` QR from a real iPhone would otherwise
    /// silently break our connection.
    func addContact(card: ContactCard, displayName: String?, source: ContactSource) {
        guard let session else { return }
        // Block list is a strict gate: the user has previously said
        // "never again" about this identityPub. Refuse the add. The
        // caller (QRScannerView / paste) is responsible for surfacing
        // the rejection — `addContact` is fire-and-forget today, so
        // we publish via `lastBlockedAddAttempt` for the UI to read.
        if isIdentityBlocked(card.peerId) {
            lastBlockedAddAttempt = card.peerId
            return
        }
        if state.contacts.contains(where: { $0.identityPub == card.peerId }) {
            requestBundleWithHashcash(fromPeer: card.peerId)
            return
        }
        let trimmed = (displayName ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let name = trimmed.isEmpty ? Contact.defaultName(for: card.peerId) : trimmed
        let contact = Contact(identityPub: card.peerId, displayName: name, addedVia: source)
        state.contacts.append(contact)
        try? session.registerPeer(peerIdentity: card.peerId)
        Storage.upsertContact(contact)
        persistSession()
        refreshAppBadge()
        if relayState == .connected {
            requestBundleWithHashcash(fromPeer: card.peerId)
        }
    }

    /// Mark a contact as out-of-band verified — the user has compared
    /// the symmetric safety number with the peer over a channel an
    /// attacker on the original sharing path cannot impersonate (in
    /// person, voice call). Idempotent; calling on an already-verified
    /// contact updates the timestamp.
    func markVerified(contactId: UUID, at when: Date = Date()) {
        guard let idx = state.contacts.firstIndex(where: { $0.id == contactId }) else { return }
        state.contacts[idx].verifiedAt = when
        Storage.upsertContact(state.contacts[idx])
    }

    /// Reverse the verification, e.g. the user pressed "doesn't match"
    /// on the SAS screen, or chose to revoke trust after the fact.
    /// Leaves `addedVia` alone — provenance is permanent.
    func clearVerification(contactId: UUID) {
        guard let idx = state.contacts.firstIndex(where: { $0.id == contactId }) else { return }
        state.contacts[idx].verifiedAt = nil
        Storage.upsertContact(state.contacts[idx])
    }

    /// Symmetric 60-digit safety number for the (local, peer) identity
    /// pair, grouped for display. Returns nil only if our local
    /// identity hasn't loaded yet (relay-host swap mid-launch, init
    /// failure) — in normal operation this resolves the moment the
    /// chat screen is reachable.
    ///
    /// Pure derivation: stable across calls, independent of which side
    /// computes it. Both peers see the same string if no MITM is in
    /// their session.
    func safetyNumber(for contact: Contact) -> String? {
        guard let myId = myIdentityPublicCached else { return nil }
        return SafetyNumber.derive(localIdentity: myId, peerIdentity: contact.identityPub)
    }

    /// Compute the BLAKE3 hashcash on a background queue (~1s on a
    /// modern phone) and ship the BUNDLE_REQUEST. Async — bundle exchange
    /// is rare so the latency is acceptable; the alternative would be a
    /// pre-warmed nonce cache, which would freeze on first launch instead.
    ///
    /// F-303 fix: re-derive the hour bucket INSIDE the dispatch closure
    /// right before computing the proof, in case iOS suspended the queue
    /// (e.g. user backgrounded the app mid-PoW) and the originally
    /// captured hour is stale by the time we resume. Capture `relay`
    /// weakly via `self.relay` so an instance swap (relay-host change /
    /// reconnect) doesn't ship the proof to a torn-down client.
    private func requestBundleWithHashcash(fromPeer peer: Data) {
        guard !relays.isEmpty else { return }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            // Re-derive hour bucket here. If suspended for ≥1h between
            // request scheduling and PoW completion, the bucket would
            // otherwise be stale and the relay would reject.
            let challenge = Self.hashcashChallenge(
                for: peer,
                hour: Self.currentHourBucket(),
            )
            let nonce = Hashcash.compute(challenge: challenge)
            DispatchQueue.main.async {
                // D3 fanout: dispatch the BUNDLE_REQUEST to every
                // currently-ready relay. The peer-owner is connected
                // to some subset of the fleet; broadcasting maximises
                // the chance one of them carries the request through.
                // The peer's response is idempotent — if multiple
                // relays forward the request, the peer's
                // `lastBundleServedAt` cooldown collapses the
                // responses to one.
                guard let self else { return }
                self.broadcastToRelays { $0.requestBundle(fromPeer: peer, hashcashNonce: nonce) }
            }
        }
    }

    /// Pure deterministic helper — `nonisolated` so the F-303 dispatch
    /// closure (which runs on `DispatchQueue.global`) can call it
    /// without a MainActor hop. Strict concurrency would otherwise
    /// reject the call site.
    nonisolated private static func currentHourBucket() -> UInt64 {
        UInt64(Date().timeIntervalSince1970) / 3600
    }

    /// Domain-separation tag baked into the hashcash challenge digest.
    /// MUST match `HASHCASH_CHALLENGE_TAG` in `relay/src/main.rs` byte
    /// for byte. F-301. `nonisolated` so the F-303 background dispatch
    /// can read it without a MainActor hop — it's an immutable Sendable
    /// constant.
    nonisolated private static let hashcashChallengeTag = Data("pizzini.hashcash.bundle.v1".utf8)

    /// F-402: BUNDLE_RESPONSE wire size for the decoy path. A real
    /// Pizzini bundle is 1858 bytes (kyber1024 PK 1568 + 4× signatures
    /// 64 each + 4× public keys 33 each + headers/IDs); we round up to
    /// 1860 to absorb future tweaks below detection.
    private static let decoyBundleSize = 1860

    /// Per-unknown-peer cooldown on the decoy emission. Mirrors the
    /// `Contact.chainServeCooldown` on the recognised-peer branch so the
    /// timing asymmetry between known and unknown is preserved only
    /// for the FIRST request in a cooldown window. Subsequent
    /// requests in the same cooldown silently drop on BOTH branches
    /// (the recognised-peer branch already early-returns at line
    /// `lastBundleServedAt < cooldown` — we add the symmetric
    /// short-circuit on the decoy branch here).
    private static let decoyPerPeerCooldown: TimeInterval = 6 * 60 * 60

    /// Aggregate cap on ALL decoy emissions per minute, across all
    /// unknown-peer ids. Defends against the attacker who rotates
    /// `from_id` every request to defeat the per-peer cooldown
    /// (F-NEW-202): even if every iteration uses a fresh peer-id,
    /// no more than `decoyAggregateBudgetPerMinute` decoys ever
    /// leave the device per minute.
    private static let decoyAggregateBudgetPerMinute: Int = 1

    /// In-memory state for the decoy cooldown. Process-lifetime
    /// (resets across cold launches). The TTL of an entry is
    /// `decoyPerPeerCooldown`; pruned lazily on access.
    private var decoyLastEmitByPeer: [Data: Date] = [:]
    /// Timestamps of recent decoy emissions for the aggregate-budget
    /// check. Pruned to entries newer than 60s on access.
    private var decoyAggregateRecent: [Date] = []
    /// Pacing budget for the real BUNDLE_RESPONSE + TOKEN_ISSUE path on
    /// a modern phone — kyber1024 keygen + 1024 XEd25519 signatures
    /// runs ~1s. Decoy waits within this window before emitting so the
    /// relay can't time-distinguish "Y is in Alice's contacts" from
    /// "Y is not". 50ms jitter prevents a learned-fixed-1s signature.
    private static let decoyEmitDelay: ClosedRange<Duration> = .milliseconds(900) ... .milliseconds(1100)

    @MainActor
    private func emitBundleResponseDecoy(toFakePeer fromPeer: Data, via client: RelayClient) {
        // F-NEW-202 cooldown — TWO gates, both required to ship a decoy:
        //
        // (a) Per-unknown-peer cooldown. Prevents a single attacker
        //     identity from sustaining a stream of ~88 KB outbound
        //     decoys against the victim by re-shipping BUNDLE_REQUEST
        //     under the same `from_id`.
        // (b) Aggregate budget across ALL unknown peers. Defends
        //     against the rotating-`from_id` attacker who otherwise
        //     defeats (a) by minting a fresh peer-id per iteration.
        //
        // The COMBINATION is what bounds the leak: an attacker who
        // rotates ids is rate-limited by (b); an attacker who reuses
        // an id is rate-limited by (a). Either way, sustained
        // outbound is bounded to ~88 KB per (decoyAggregateBudget /
        // minute) ≈ 88 KB/min worst case rather than 88 KB/iteration.
        let now = Date()
        if let last = decoyLastEmitByPeer[fromPeer],
           now.timeIntervalSince(last) < ChatStore.decoyPerPeerCooldown {
            pzLog("[pizzini] BUNDLE_REQUEST decoy from \(short(fromPeer)) suppressed by per-peer cooldown")
            return
        }
        // Prune aggregate window to entries in the last 60s.
        decoyAggregateRecent.removeAll { now.timeIntervalSince($0) >= 60 }
        if decoyAggregateRecent.count >= ChatStore.decoyAggregateBudgetPerMinute {
            pzLog("[pizzini] BUNDLE_REQUEST decoy from \(short(fromPeer)) suppressed by aggregate budget")
            return
        }
        decoyLastEmitByPeer[fromPeer] = now
        decoyAggregateRecent.append(now)
        // Capture the client and target before we go async — the iOS
        // app may reset identity / swap the relay before our delay
        // fires; if so, drop silently rather than ship to a stale
        // client.
        let target = fromPeer
        Task { @MainActor [weak self, weak client] in
            // Random sleep within the budget so the decoy doesn't have
            // a fixed-latency fingerprint. Even if iOS suspends mid-
            // sleep, we still want to ship on resume to keep the
            // wire-shape consistent — the leak is the asymmetry, not
            // the precise timing.
            let nanos = UInt64.random(in: 900_000_000 ... 1_100_000_000)
            try? await Task.sleep(nanoseconds: nanos)
            guard let self else { return }
            guard let client else { return }
            // After the await we may also have lost the connection or
            // had identity reset. emitDecoyOnSocket guards on those.
            self.emitDecoyOnSocket(toPeer: target, via: client)
            _ = ChatStore.decoyEmitDelay  // silence unused range
        }
    }

    @MainActor
    private func emitDecoyOnSocket(toPeer: Data, via client: RelayClient) {
        // Random bytes shaped to match a real BUNDLE_RESPONSE payload.
        // The recipient (the malicious relay or its colluding client)
        // can't decrypt — bundle decoder rejects on the version byte
        // mismatch — but the relay's outbound observation is identical
        // to the real-contact path.
        var decoyBundle = Data(count: ChatStore.decoyBundleSize)
        _ = decoyBundle.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, buf.count, buf.baseAddress!)
        }
        client.sendBundle(toPeer: toPeer, bundle: decoyBundle)
        // Real pair-time path after the bundle is a single sealed
        // SEND carrying a chainSeedDelivery (88-byte plaintext body
        // wrapped in sealed-sender envelope). A future refinement can
        // emit a matching-size decoy SEND; for the current internal
        // build a bundle-shaped decoy alone is the v2 equivalent of
        // the legacy paired decoy.
    }

    /// Hashcash challenge layout, mirroring `relay::build_hashcash_challenge`:
    /// `BLAKE3(tag || u16_be(peer_id_len) || peer_id || hour_bucket_be_u64)`.
    /// F-301: domain-separated and length-prefixed. CryptoKit doesn't
    /// expose BLAKE3, so the iOS side reaches into the
    /// `pizzini_blake3_hash` FFI rather than maintaining a parallel
    /// pure-Swift hasher.
    ///
    /// `nonisolated` so the F-303 dispatch closure (background queue,
    /// not MainActor) can call it directly — pure function of its
    /// arguments, no MainActor state touched.
    nonisolated private static func hashcashChallenge(for peer: Data, hour: UInt64) -> Data {
        var input = Data()
        input.append(hashcashChallengeTag)
        var peerLenBE = UInt16(peer.count).bigEndian
        withUnsafeBytes(of: &peerLenBE) { input.append(contentsOf: $0) }
        input.append(peer)
        var hourBE = hour.bigEndian
        withUnsafeBytes(of: &hourBE) { input.append(contentsOf: $0) }
        return blake3(input)
    }

    /// Pure FFI wrapper — `nonisolated` for the same reason as
    /// `hashcashChallenge`: called from `hashcashChallenge` which is
    /// itself reachable from the F-303 background dispatch closure.
    nonisolated private static func blake3(_ input: Data) -> Data {
        Blake3.hash(input)
    }

    func send(_ text: String, to contact: Contact) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let session,
              !readyRelays.isEmpty,
              let idx = contactIndex(forIdentity: contact.identityPub)
        else { return }
        guard contact.sessionEstablished else {
            appendSystem("Session not established yet — waiting for the other side to scan you.", to: idx)
            return
        }
        // v2 hash-chained tokens: derive one from the outbound chain,
        // ship the sealed envelope with the 52-byte token blob. If
        // the chain is missing (e.g. session established but the
        // peer's `chainSeedDelivery` hasn't landed yet), queue the
        // text and refresh the bundle — the peer's response carries
        // a fresh chain, drainPendingV2Sends re-submits the message
        // once it installs.
        if let v2Token = mintV2DeliveryToken(forContactAt: idx) {
            sendV2(
                trimmed: trimmed,
                forContactAt: idx,
                contact: contact,
                session: session,
                v2Token: v2Token,
            )
        } else {
            refreshChainAndQueue(text: trimmed, forContactAt: idx)
        }
    }

    /// Encrypt + ship one text SEND using a pre-minted v2 token.
    /// Mirrors the legacy spend-then-send shape but the chain
    /// advance is already persisted by `mintV2DeliveryToken` before
    /// we get here.
    @MainActor
    private func sendV2(
        trimmed: String,
        forContactAt idx: Int,
        contact: Contact,
        session: Session,
        v2Token: HashChainToken.Token
    ) {
        let messageId = Self.makeMessageId()
        var inner = Data([RelayClient.InnerEnvelopeKind.chat.rawValue])
        inner.append(Data(trimmed.utf8))
        let sealed: Data
        do {
            sealed = try session.encryptSealed(
                peer: contact.identityPub,
                messageId: messageId,
                plaintext: inner,
            )
        } catch {
            appendSystem("Encrypt failed: \(error)", to: idx)
            return
        }
        let ttl = state.contacts[idx].ttlSeconds
        let now = Date()
        let wireToken = HashChainToken.encode(v2Token)
        var entry = OutboxEntry(
            messageId: messageId,
            recipientPeerId: contact.identityPub,
            sealedCiphertext: sealed,
            token: wireToken,
            ttl: TimeInterval(ttl),
            sentAt: now,
            retries: 0,
            deliveredAt: nil,
            failedAt: nil,
            relayedAt: nil,
        )
        outbox.entries[messageId] = entry
        Storage.upsertOutboxEntry(entry)
        persistSession()
        broadcastToRelays {
            $0.sendSealed(
                toPeer: contact.identityPub,
                sealedCiphertext: sealed,
                ttlSeconds: ttl,
                token: wireToken,
            )
        }
        entry.relayedAt = now
        // F-505 parity with v1: scrub the token blob once relayed.
        entry.token = Data()
        outbox.entries[messageId] = entry
        Storage.upsertOutboxEntry(entry)
        let logEntry = PersistedMessage(
            side: .me,
            text: trimmed,
            kind: state.contacts[idx].sessionEstablished ? .whisper : .preKey,
            bytes: sealed.count,
            messageId: messageId,
        )
        state.contacts[idx].log.append(logEntry)
        state.contacts[idx].lastMessageAt = logEntry.timestamp
        persistContactSliceAndAppended(logEntry, at: idx)
        // v2 rotation: if the chain just crossed the 80% mark, the
        // *recipient* (us) of any next v2 token presentation would
        // start watching for the new one. The chain owner (peer) is
        // the one who mints — we can't do it locally. Best we can do
        // here is log so a future telemetry pass surfaces the cadence.
        if let chain = state.contacts[idx].outboundTokenChain, chain.shouldRotate {
            pzLog("[pizzini] v2 chain crossing rotation threshold for \(self.short(contact.identityPub))")
        }
    }

    /// Send a file attachment to `contact`. Phase 2 wire path: chunked
    /// sealed envelopes (`.fileChunk` inner kind) keyed by a shared
    /// `attachmentId`. Each chunk consumes one v2 hash-chain token
    /// (52-byte presentation); a 10 MB file is ~160 chunks. Default
    /// chain length 16384 covers thousands of attachments before
    /// `Chain.shouldRotate` flips and the peer re-mints.
    ///
    /// Strip + chunk + encrypt happens off the main thread so the UI
    /// stays responsive even on a multi-MB attachment with AVAsset
    /// passes that take a couple of seconds. The post-prepared chunks
    /// are submitted from the main actor as a sequence of
    /// `relay.sendSealed` calls — one OutboxEntry per chunk, all
    /// sharing the attachmentId for UI rollup via
    /// `OutboxStore.attachmentStatus(forId:)`.
    func sendFile(_ url: URL, to contact: Contact, caption: String?) {
        // Existence guards — the actual session/relay handles are
        // re-fetched on the MainActor hop in `shipPreparedAttachment`,
        // so we only need to know they exist before kicking off the
        // off-main read + strip pass.
        guard session != nil,
              !relays.isEmpty,
              let idx = contactIndex(forIdentity: contact.identityPub)
        else { return }
        guard contact.sessionEstablished else {
            appendSystem("Session not established yet — waiting for the other side to scan you.", to: idx)
            return
        }

        // Sanitize the filename right at the boundary; we re-sanitize
        // on receive too (defence in depth) but the sender side gets a
        // clean rendering immediately and the wire bytes can never
        // carry an RTL-override / path-separator name.
        let rawFilename = url.lastPathComponent
        let safeName = FilenameSanitizer.sanitize(rawFilename)
        if AttachmentTierClassifier.isBlockedAtSend(filename: safeName) {
            appendSystem(
                "Can't send \(safeName): files of this type can run when tapped on iOS. Pizzini blocks them at send.",
                to: idx,
            )
            return
        }

        // Preserve the recipient and contact identity OUT of the
        // background closure — we'll re-resolve on the main hop after.
        let peerId = contact.identityPub
        let mime = mimeTypeForFilename(safeName)
        let tier = AttachmentTierClassifier.tier(forFilename: safeName)
        let ttlForChunks = state.contacts[idx].ttlSeconds
        let captionText = caption?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            // Off-main: read + (optionally) strip metadata. Tier-3
            // strip on a 4K video can take seconds — keeping the UI
            // responsive while it runs is non-negotiable.
            let raw: Data
            do {
                raw = try Data(contentsOf: url, options: [.mappedIfSafe])
            } catch {
                Task { @MainActor [weak self] in
                    self?.appendSystem("Couldn't read \(safeName): \(error)", to: idx)
                }
                return
            }
            let bytes: Data
            do {
                bytes = try MetadataStripper.stripped(
                    raw, filename: safeName, mimeType: mime
                )
            } catch {
                Task { @MainActor [weak self] in
                    self?.appendSystem("Strip failed for \(safeName): \(error)", to: idx)
                }
                return
            }
            // Generate the attachmentId on the background hop — it's
            // just 16 random bytes, no actor state needed.
            var aidBytes = [UInt8](repeating: 0, count: 16)
            _ = aidBytes.withUnsafeMutableBufferPointer { ptr in
                SecRandomCopyBytes(kSecRandomDefault, ptr.count, ptr.baseAddress!)
            }
            let attachmentId = Data(aidBytes)
            // Slice into chunks. Last chunk may be shorter than the
            // target plaintext size; everything's u64 so a 4 GB-class
            // attachment still indexes cleanly.
            let chunkSize = FileChunkEnvelope.maxChunkPlaintextBytes
            let totalSize = bytes.count
            let chunkCount = max(1, (totalSize + chunkSize - 1) / chunkSize)
            if UInt32(chunkCount) > FileChunkEnvelope.maxChunkCount {
                Task { @MainActor [weak self] in
                    self?.appendSystem(
                        "\(safeName) is too large (\(totalSize) bytes; max \(FileChunkEnvelope.maxChunkPlaintextBytes * Int(FileChunkEnvelope.maxChunkCount)).",
                        to: idx,
                    )
                }
                return
            }
            var working: [Data] = []
            working.reserveCapacity(chunkCount)
            for i in 0..<chunkCount {
                let start = i * chunkSize
                let end = min(start + chunkSize, totalSize)
                working.append(bytes.subdata(in: start..<end))
            }
            // Stage a copy of the post-strip bytes under the outbound
            // sandbox so the sender's row can present Save-to-Files /
            // Preview after send. Subject to the 7d sandbox TTL like
            // inbound attachments — chat row stays past that, just
            // without the bytes. Failure to write is non-fatal: the
            // chunked send still proceeds, the row just won't have a
            // viewable URL on the sender side.
            let outboundRelPath: String? = {
                guard let dir = try? AttachmentSandbox.outboundDirectory(
                    forAttachmentId: attachmentId,
                ) else { return nil }
                let url = dir.appending(path: safeName, directoryHint: .notDirectory)
                do {
                    try bytes.write(
                        to: url,
                        options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication],
                    )
                } catch {
                    pzLog("[pizzini] outbound sandbox write failed: \(error)")
                    return nil
                }
                guard let root = try? AttachmentSandbox.root() else { return nil }
                let rootPath = root.path.hasSuffix("/") ? root.path : root.path + "/"
                return url.path.hasPrefix(rootPath)
                    ? String(url.path.dropFirst(rootPath.count))
                    : nil
            }()
            // Swift 6 strict-concurrency: a `Task { @MainActor in ... }`
            // closure runs on a different executor and can't capture a
            // `var`. Bind the prepared chunks to an immutable `let`
            // first so the capture is a deep-copy of a Sendable [Data].
            let preparedChunks = working
            Task { @MainActor [weak self] in
                self?.shipPreparedAttachment(
                    contactId: peerId,
                    attachmentId: attachmentId,
                    sanitizedFilename: safeName,
                    mime: mime,
                    tier: tier,
                    chunks: preparedChunks,
                    totalSize: UInt64(totalSize),
                    ttl: ttlForChunks,
                    captionText: captionText,
                    sandboxRelPath: outboundRelPath,
                )
            }
        }
    }

    /// Main-actor continuation of `sendFile`: encrypts + dispatches each
    /// chunk + records the chat row. Split out so the background read /
    /// strip / chunk pass is a single self-contained closure.
    @MainActor
    private func shipPreparedAttachment(
        contactId: Data,
        attachmentId: Data,
        sanitizedFilename: String,
        mime: String,
        tier: AttachmentTier,
        chunks: [Data],
        totalSize: UInt64,
        ttl: UInt32,
        captionText: String,
        sandboxRelPath: String?,
    ) {
        guard let session,
              !readyRelays.isEmpty,
              let idx = contactIndex(forIdentity: contactId)
        else { return }
        // Token availability check — refuse the whole attachment up
        // front rather than ship N chunks then bail mid-send. A 10 MB
        // file = ~160 chunks; if the stash has 50 we should request a
        // refill and abort, not trickle 50 partial chunks the receiver
        // can't reassemble.
        // v2 cutover: under the flag, a file send needs a chain with
        // at least `chunks.count` remaining tokens. Missing or
        // under-supplied chain → request a fresh bundle (the peer
        // answers with a new chain seed) and bail. The user
        // re-attaches the file once the new chain lands.
        let remaining = state.contacts[idx].outboundTokenChain.map {
            $0.length - ($0.nextIndex - 1)
        } ?? 0
        if remaining < chunks.count {
            let msg = remaining == 0
                ? "Refreshing connection — re-attach this file once it's back online."
                : "Chain almost spent — \(remaining) tokens left, need \(chunks.count). Refreshing."
            appendSystem(msg, to: idx)
            requestBundleWithHashcash(fromPeer: state.contacts[idx].identityPub)
            return
        }

        let chunkCountU32 = UInt32(chunks.count)
        let now = Date()
        // Encrypt + ship each chunk. We persist + send in one pass —
        // crash mid-loop leaves outbox entries the retry walk re-sends
        // on next launch (each chunk is its own OutboxEntry, so partial
        // progress is a first-class state).
        for i in 0..<chunks.count {
            let envelope = FileChunkEnvelope(
                attachmentId: attachmentId,
                totalSize: totalSize,
                chunkIndex: UInt32(i),
                chunkCount: chunkCountU32,
                mime: mime,
                filename: sanitizedFilename,
                chunkBytes: chunks[i],
            )
            var inner = Data([RelayClient.InnerEnvelopeKind.fileChunk.rawValue])
            inner.append(envelope.encode())

            let messageId = Self.makeMessageId()
            do {
                let sealed = try session.encryptSealed(
                    peer: contactId,
                    messageId: messageId,
                    plaintext: inner,
                )
                // Mint a v2 token after successful encrypt so an
                // encrypt failure doesn't burn one. The chain
                // remaining-tokens guard above ensures this can only
                // fail under contention with another sender path; if
                // so, we abort the rest of the attachment and ask
                // the peer for a fresh chain.
                guard let v2 = mintV2DeliveryToken(forContactAt: idx) else {
                    appendSystem(
                        "Chain exhausted mid-attachment after \(i)/\(chunks.count) chunks. Re-send to refresh.",
                        to: idx,
                    )
                    requestBundleWithHashcash(fromPeer: contactId)
                    return
                }
                let token = HashChainToken.encode(v2)
                var entry = OutboxEntry(
                    messageId: messageId,
                    recipientPeerId: contactId,
                    sealedCiphertext: sealed,
                    token: token,
                    ttl: TimeInterval(ttl),
                    sentAt: now,
                    retries: 0,
                    deliveredAt: nil,
                    failedAt: nil,
                    relayedAt: nil,
                    attachmentId: attachmentId,
                    chunkIndex: UInt32(i),
                    chunkCount: chunkCountU32,
                )
                outbox.entries[messageId] = entry
                Storage.upsertOutboxEntry(entry)
                persistSession()
                broadcastToRelays {
                    $0.sendSealed(
                        toPeer: contactId,
                        sealedCiphertext: sealed,
                        ttlSeconds: ttl,
                        token: token,
                    )
                }
                entry.relayedAt = now
                entry.token = Data() // F-505: scrub once relayed
                outbox.entries[messageId] = entry
                Storage.upsertOutboxEntry(entry)
            } catch {
                appendSystem("Encrypt failed at chunk \(i)/\(chunks.count): \(error)", to: idx)
                return
            }
        }

        // Record one chat row (not N — the user sees one attachment).
        let info = AttachmentInfo(
            attachmentId: attachmentId,
            filename: sanitizedFilename,
            byteSize: totalSize,
            mime: mime,
            tier: tier,
            sandboxRelativePath: sandboxRelPath,
            isInbound: false,
        )
        let row = PersistedMessage(
            side: .me,
            text: captionText,
            kind: .attachment,
            bytes: Int(totalSize),
            attachment: info,
        )
        state.contacts[idx].log.append(row)
        state.contacts[idx].lastMessageAt = row.timestamp
        persistContactSliceAndAppended(row, at: idx)
        // v2 rotation: if the chain just crossed the 80% mark, log so
        // future telemetry can surface the cadence. Rotation itself
        // is recipient-initiated (the peer minted this chain, so only
        // they can replace it); we rely on `requestBundleWithHashcash`
        // in the eventually-exhausted path to trigger their re-issue.
        if let chain = state.contacts[idx].outboundTokenChain, chain.shouldRotate {
            pzLog("[pizzini] v2 chain crossing rotation threshold for \(self.short(contactId))")
        }
    }

    /// Map a sanitized filename to the best-guess MIME / UTI string.
    /// Recipient treats this as informational only; classification is
    /// re-derived from the filename extension on receive. Stays on
    /// the MainActor (no `nonisolated`) because the only call site
    /// is from `sendFile` *before* the off-main hop, and
    /// `FilenameSanitizer` is MainActor-isolated under the iOS
    /// app's default isolation rules. Internal-not-private so the
    /// group attachment sender in `ChatStoreGroups.swift` reuses
    /// the same UTType lookup rather than forking a parallel copy.
    func mimeTypeForFilename(_ name: String) -> String {
        guard let ext = FilenameSanitizer.trailingExtension(of: name)?.lowercased(),
              let type = UTType(filenameExtension: ext)
        else { return "application/octet-stream" }
        return type.preferredMIMEType ?? type.identifier
    }

    /// Pending v2 sends queued behind a chain refresh. Keyed by
    /// contact UUID. Each entry is the raw plaintext we'll re-submit
    /// to `send(_:to:)` once `handleChainSeedDelivery` installs the
    /// chain. Cap per contact + total prevents a stuck-refresh from
    /// growing unbounded if the peer never responds.
    @MainActor
    private var pendingV2Sends: [UUID: [String]] = [:]
    private static let maxPendingV2SendsPerContact = 16

    /// v2 cutover recovery: trigger a peer-bundle refresh (which the
    /// recipient answers with a sealed `chainSeedDelivery`), and
    /// queue the user's text so we re-issue the send once the chain
    /// lands. No parallel v1 fallback — this is the only path back
    /// to working sends when a chain is missing.
    @MainActor
    private func refreshChainAndQueue(text: String, forContactAt idx: Int) {
        let contact = state.contacts[idx]
        let queue = pendingV2Sends[contact.id] ?? []
        if queue.count >= Self.maxPendingV2SendsPerContact {
            appendSystem(
                "Too many messages queued while reconnecting. Try again later.",
                to: idx,
            )
            return
        }
        pendingV2Sends[contact.id, default: []].append(text)
        appendSystem("Refreshing connection — your message will go out shortly.", to: idx)
        requestBundleWithHashcash(fromPeer: contact.identityPub)
    }

    /// Drain queued sends after a chain arrives. Called from
    /// `handleChainSeedDelivery`. Re-submits each pending message via
    /// `send(_:to:)`, which now finds a chain installed and takes
    /// the v2 path.
    @MainActor
    private func drainPendingV2Sends(forContactAt idx: Int) {
        let contact = state.contacts[idx]
        guard let pending = pendingV2Sends.removeValue(forKey: contact.id), !pending.isEmpty
        else { return }
        for text in pending {
            send(text, to: contact)
        }
    }

    /// v2 token mint: pop the next token off the contact's outbound
    /// hash chain, advance the cursor, persist. Returns nil when no
    /// chain is installed or the chain is exhausted — caller calls
    /// `refreshChainAndQueue` to recover. Encoding to wire bytes is
    /// the caller's job (`HashChainToken.encode`).
    ///
    /// Internal-not-private so the group fan-out path in
    /// `ChatStoreGroups.swift` can mint one v2 token per recipient
    /// without duplicating the persist logic.
    @MainActor
    func v2TokenWire(forContactAt idx: Int) -> Data? {
        mintV2DeliveryToken(forContactAt: idx).map { HashChainToken.encode($0) }
    }

    @MainActor
    func mintV2DeliveryToken(forContactAt idx: Int) -> HashChainToken.Token? {
        guard var chain = state.contacts[idx].outboundTokenChain else { return nil }
        guard let token = HashChainToken.nextToken(in: &chain) else { return nil }
        state.contacts[idx].outboundTokenChain = chain
        Storage.upsertContact(state.contacts[idx])
        return token
    }

    /// Handle a sealed `chainSeedDelivery` payload. The peer (who minted
    /// the chain and registered the root with the relay) has shipped us
    /// the seed for our outbound v2 token chain to them. Install or
    /// replace `Contact.outboundTokenChain`; the next SEND will derive
    /// tokens from this chain instead of popping from the v1 stash.
    @MainActor
    private func handleChainSeedDelivery(payload: Data, contactIdx idx: Int) {
        guard let chain = HashChainToken.decodeSeedDelivery(payload) else {
            pzLog("[pizzini] chainSeedDelivery: malformed payload from \(self.short(state.contacts[idx].identityPub))")
            return
        }
        // Replacing an existing chain is legitimate (rotation); the old
        // chain's unused indices are simply discarded — the relay's
        // `(recipient, chainID)` state for the old chain ages out via
        // the relay's GC. Logging makes the rotation auditable in
        // sysdiagnose without revealing chain bytes.
        let priorChainID = state.contacts[idx].outboundTokenChain?.chainID
        state.contacts[idx].outboundTokenChain = chain
        Storage.upsertContact(state.contacts[idx])
        pzLog("[pizzini] chainSeedDelivery installed for \(self.short(state.contacts[idx].identityPub)) (rotation=\(priorChainID != nil))")
        // Drain any sends that were waiting on this chain. Each one
        // re-enters `send(_:to:)`, which now finds the chain and
        // takes the v2 path.
        drainPendingV2Sends(forContactAt: idx)
    }

    /// Mint a fresh outbound chain for the named peer and ship the seed
    /// via the sealed Double Ratchet. Called when (a) we're answering a
    /// peer's bootstrap (post-bundle) — the v2 replacement for
    /// `issueTokens` — and (b) the peer's outbound chain is approaching
    /// exhaustion (`shouldRotate`) so we mint a successor before the
    /// current one dries up. No-op if we have no session yet.
    ///
    /// Order is load-bearing: REGISTER_CHAIN must reach EVERY relay
    /// before the peer presents a token, otherwise the relay returns
    /// "unknown chain". Broadcasting both on the same relay set in
    /// this order means the registration is queued before the
    /// recipient's first v2 SEND can possibly land back.
    @MainActor
    private func sendChainSeedDelivery(toPeer peer: Data, via client: RelayClient, session: Session) {
        let chain = HashChainToken.mintChain()
        // 1. Register the chain root with every connected relay so v2
        //    SENDs from this peer can validate.
        broadcastToRelays {
            $0.sendRegisterChain(
                chainID: chain.chainID,
                root: chain.root,
                length: UInt32(chain.length),
            )
        }
        // 2. Ship the seed to the peer via sealed Double Ratchet —
        //    the relay sees only opaque sealed bytes; metadata
        //    posture matches today's chat traffic.
        var inner = Data([RelayClient.InnerEnvelopeKind.chainSeedDelivery.rawValue])
        inner.append(HashChainToken.encodeSeedDelivery(chain))
        do {
            let sealed = try session.encryptSealed(
                peer: peer,
                messageId: Self.makeMessageId(),
                plaintext: inner,
            )
            persistSession()
            broadcastToRelays {
                $0.sendSealed(
                    toPeer: peer,
                    sealedCiphertext: sealed,
                    ttlSeconds: 24 * 60 * 60,
                    token: Data(),
                )
            }
        } catch {
            pzLog("[pizzini] chainSeedDelivery encrypt failed: \(error)")
        }
        _ = client
    }

    /// Mint a fresh outbound chain for `peer` and ship the seed over
    /// the sealed Double Ratchet. Called right after we serve their
    /// bundle. Rate-limited per `Contact.chainServeCooldown` so a
    /// peer cycling BUNDLE_REQUEST can't drive us into a tight
    /// mint-ship loop.
    private func serveChain(forPeer peer: Data, via relay: RelayClient, session: Session) {
        guard let idx = contactIndex(forIdentity: peer) else { return }
        if let last = state.contacts[idx].lastChainServedAt,
           Date().timeIntervalSince(last) < Contact.chainServeCooldown {
            pzLog("[pizzini] chain serve rate-limited for \(self.short(peer))")
            return
        }
        state.contacts[idx].lastChainServedAt = Date()
        Storage.upsertContact(state.contacts[idx])
        sendChainSeedDelivery(toPeer: peer, via: relay, session: session)
    }

    /// Default per-message TTL until Phase 4's per-message picker lands.
    /// Matches the brief's "1 day (recommended)" default.
    private static let defaultTTLSeconds: UInt32 = 24 * 60 * 60

    /// 16 random bytes — Phase 4 plumbs this into the outbox so the
    /// sender can match acks against in-flight entries.
    private static func makeMessageId() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        let rc = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(rc == errSecSuccess, "SecRandom must succeed")
        return Data(bytes)
    }

    func deleteChat(_ contact: Contact) {
        guard let idx = contactIndex(forIdentity: contact.identityPub) else { return }
        state.contacts[idx].log.removeAll()
        state.contacts[idx].lastMessageAt = nil
        state.contacts[idx].lastSeenAt = Date()
        Storage.deleteAllContactMessages(contactId: state.contacts[idx].id)
        Storage.upsertContact(state.contacts[idx])
        refreshAppBadge()
    }

    func deleteContact(_ contact: Contact) {
        guard let idx = contactIndex(forIdentity: contact.identityPub) else { return }
        state.contacts.remove(at: idx)
        try? session?.forgetPeer(peerIdentity: contact.identityPub)
        Storage.deleteContact(id: contact.id)
        persistSession()
        refreshAppBadge()
    }

    func deleteAllChats() {
        let now = Date()
        for i in state.contacts.indices {
            state.contacts[i].log.removeAll()
            state.contacts[i].lastMessageAt = nil
            state.contacts[i].lastSeenAt = now
            Storage.deleteAllContactMessages(contactId: state.contacts[i].id)
            Storage.upsertContact(state.contacts[i])
        }
        refreshAppBadge()
    }

    /// Called when the user enters a chat — clears its unread count
    /// and, if read receipts are enabled for this contact, emits a
    /// single sealed `read` envelope covering the highest message_id
    /// seen so the peer can show "Read" in their UI.
    func markRead(contactID: UUID) {
        guard let idx = state.contacts.firstIndex(where: { $0.id == contactID }) else { return }
        state.contacts[idx].lastSeenAt = Date()
        Storage.upsertContact(state.contacts[idx])
        refreshAppBadge()
        emitReadReceiptIfEnabled(forContactAt: idx)
    }

    func setContactTTL(_ contact: Contact, seconds: UInt32) {
        guard let idx = contactIndex(forIdentity: contact.identityPub) else { return }
        state.contacts[idx].ttlSeconds = seconds
        Storage.upsertContact(state.contacts[idx])
    }

    /// Set the per-chat read-receipts override. Three modes:
    ///   - `.followDefault` — inherits `state.defaultReadReceiptsEnabled`.
    ///   - `.alwaysOn`      — opt in for this contact regardless.
    ///   - `.alwaysOff`     — opt out for this contact regardless.
    func setReadReceiptsMode(_ contact: Contact, mode: ReadReceiptsMode) {
        guard let idx = contactIndex(forIdentity: contact.identityPub) else { return }
        state.contacts[idx].readReceiptsMode = mode
        Storage.upsertContact(state.contacts[idx])
    }

    /// App-wide default for read receipts. Flips immediately apply to
    /// every contact whose `readReceiptsMode == .followDefault`; the
    /// `.alwaysOn` / `.alwaysOff` per-chat overrides are unaffected.
    func setDefaultReadReceipts(_ enabled: Bool) {
        guard state.defaultReadReceiptsEnabled != enabled else { return }
        state.defaultReadReceiptsEnabled = enabled
        Storage.upsertSettings(state)
    }

    /// Toggle per-contact mute. When muted, inbound messages from this
    /// peer don't fire haptics or bump the NSE badge floor; delivery
    /// and persistence are unchanged.
    func setContactMuted(_ contact: Contact, muted: Bool) {
        guard let idx = contactIndex(forIdentity: contact.identityPub) else { return }
        state.contacts[idx].mutedAt = muted ? Date() : nil
        Storage.upsertContact(state.contacts[idx])
        refreshAppBadge()
    }

    /// App-wide notifications mute. Suppresses the NSE badge bump and
    /// in-app haptic without affecting message delivery.
    func setNotificationsMuted(_ muted: Bool) {
        guard state.notificationsMuted != muted else { return }
        state.notificationsMuted = muted
        Storage.upsertSettings(state)
        refreshAppBadge()
    }

    /// Block a peer by identityPub. Stronger than `deleteContact`:
    /// survives re-pair, dropped at every receive-side gate.
    /// Idempotent.
    func blockIdentity(_ identityPub: Data) {
        if !state.blockedIdentities.contains(identityPub) {
            state.blockedIdentities.append(identityPub)
        }
        Storage.blockIdentity(identityPub)
        // Hard-tear the in-memory contact row if present so the chat
        // stops surfacing in the list immediately. We KEEP delivery
        // tokens minted to this peer in case the user unblocks
        // later — but a fresh BUNDLE_RESPONSE is still required, so
        // the unblock flow is "scan them again". Tokens we hold for
        // sending TO them stay; tokens they hold for sending to US
        // stop working at the relay because we never serve them
        // another bundle.
        if let idx = contactIndex(forIdentity: identityPub) {
            let contactId = state.contacts[idx].id
            state.contacts.remove(at: idx)
            Storage.deleteContact(id: contactId)
        }
    }

    /// Lift a block. The peer remains unknown until they re-pair —
    /// blocking removes the contact row, so an unblock is "stop
    /// dropping at the gate" not "restore the relationship".
    func unblockIdentity(_ identityPub: Data) {
        state.blockedIdentities.removeAll { $0 == identityPub }
        Storage.unblockIdentity(identityPub)
    }

    /// True iff this peer's identityPub is on the block list. Hot
    /// path — every inbound BUNDLE_RESPONSE / TOKEN_ISSUE / SEND
    /// passes through this gate.
    func isIdentityBlocked(_ identityPub: Data) -> Bool {
        state.blockedIdentities.contains(identityPub)
    }

    @MainActor
    private func emitReadReceiptIfEnabled(forContactAt idx: Int) {
        let contact = state.contacts[idx]
        guard let last = contact.log.last(where: { $0.side == .peer && $0.messageId != nil }),
              let highest = last.messageId
        else { return }
        emitReadReceipt(forContactAt: idx, highestMessageId: highest)
    }

    /// Encrypt + ship one 0x04 readReceipt to the contact at `idx`
    /// covering `highestMessageId`. Internal-not-private so the group
    /// read path in `ChatStoreGroups.swift` can drive per-sender
    /// receipts without re-implementing the seal-and-send shell.
    /// Honours the same `readReceiptsEnabled` toggle: if the local
    /// user hasn't opted in to telling THIS contact when they read,
    /// the helper returns silently (the F-405 symmetric-drop guard
    /// on the receive side is the matching half).
    @MainActor
    func emitReadReceipt(forContactAt idx: Int, highestMessageId: Data) {
        let contact = state.contacts[idx]
        let effective = contact.effectiveReadReceiptsEnabled(
            globalDefault: state.defaultReadReceiptsEnabled
        )
        guard effective,
              let session,
              !readyRelays.isEmpty
        else { return }
        // Read receipts are NOT in the outbox retry walk — if we
        // pop a token + encrypt + hand to a disconnected
        // NWConnection, the bytes are silently dropped and the
        // sender's eye glyph never fires. Skip the emit when we
        // know the relay won't accept it; the next mark-read on
        // re-connect / chat re-open will retry with a fresh
        // receipt covering the same (or newer) highest messageId.
        guard relayState == .connected else {
            pzLog("[pizzini] deferring read receipt — relay not connected (state=\(relayState))")
            return
        }
        guard let v2 = mintV2DeliveryToken(forContactAt: idx) else {
            pzLog("[pizzini] cannot emit read receipt: chain missing or exhausted")
            return
        }
        let token = HashChainToken.encode(v2)
        var inner = Data([RelayClient.InnerEnvelopeKind.readReceipt.rawValue])
        inner.append(highestMessageId)
        do {
            let sealed = try session.encryptSealed(
                peer: contact.identityPub,
                messageId: Self.makeMessageId(),
                plaintext: inner,
            )
            // Same root-cause guard as `emitAck`: persist before the
            // socket write so a force-quit between encrypt and the
            // next chat send can't roll the ratchet back.
            persistSession()
            broadcastToRelays {
                $0.sendSealed(
                    toPeer: contact.identityPub,
                    sealedCiphertext: sealed,
                    ttlSeconds: contact.ttlSeconds,
                    token: token,
                )
            }
        } catch {
            pzLog("[pizzini] read-receipt encrypt failed: \(error)")
        }
    }

    func rename(_ contact: Contact, to newName: String) {
        let trimmed = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let idx = contactIndex(forIdentity: contact.identityPub)
        else { return }
        state.contacts[idx].displayName = trimmed
        Storage.upsertContact(state.contacts[idx])
    }

    // MARK: - Onboarding + security settings

    func completeOnboarding(enableBiometric: Bool) {
        state.onboardingCompleted = true
        state.biometricLockEnabled = enableBiometric
        Storage.upsertSettings(state)
    }

    func setBiometricLockEnabled(_ enabled: Bool) {
        guard state.biometricLockEnabled != enabled else { return }
        state.biometricLockEnabled = enabled
        Storage.upsertSettings(state)
        // If the user just disabled the lock, lift any active gate so
        // we don't strand them on an overlay they can no longer dismiss.
        if !enabled {
            LockManager.shared.unlockBecauseDisabled()
        }
    }

    func setAutoLockTimeout(_ value: AutoLockTimeout) {
        guard state.autoLockTimeout != value else { return }
        state.autoLockTimeout = value
        Storage.upsertSettings(state)
    }

    /// Switch the attachment-preview tier. Default `.off` — strict
    /// mode, no bytes parsed. `.quickLook` adds Apple's sandboxed
    /// QuickLook XPC; `.inlineThumbnail` parses incoming bytes
    /// in-process behind the `AttachmentThumbnail` guard set.
    func setAttachmentPreviewMode(_ mode: AttachmentPreviewMode) {
        guard state.attachmentPreviewMode != mode else { return }
        state.attachmentPreviewMode = mode
        Storage.upsertSettings(state)
    }

    /// Toggle the per-chat triple-tap panic gesture. Default OFF.
    /// When ON, three fast taps on the chat-content area inside an
    /// open chat instantly delete that chat (the per-contact log;
    /// the contact + the encryption session stay).
    func setPanicModeEnabled(_ enabled: Bool) {
        guard state.panicModeEnabled != enabled else { return }
        state.panicModeEnabled = enabled
        Storage.upsertSettings(state)
    }

    /// Toggle the contacts-list ordering: contacts above groups vs.
    /// groups above contacts. Default true (contacts above) because
    /// 1:1 chats are the more frequently-opened surface for the
    /// activist threat model and a long groups section pushed them
    /// off the first viewport.
    func setContactsBeforeGroups(_ enabled: Bool) {
        guard state.contactsBeforeGroups != enabled else { return }
        state.contactsBeforeGroups = enabled
        Storage.upsertSettings(state)
    }

    /// Toggle the in-app haptic for messages landing in a chat OTHER
    /// than the active one. Default OFF — silent reliance on the
    /// badge + chat list updates is the privacy-first default; the
    /// haptic is opt-in for users who want a felt cue without the
    /// content leak of a banner.
    func setInAppHapticsEnabled(_ enabled: Bool) {
        guard state.inAppHapticsEnabled != enabled else { return }
        state.inAppHapticsEnabled = enabled
        Storage.upsertSettings(state)
    }

    /// True when the app-wide screenshot mask should be applied — i.e.
    /// the runtime self-test for the underlying `isSecureTextEntry`
    /// technique passed on this iOS version. The mask is unconditional
    /// when the technique works; there is no user-facing toggle. Read
    /// by `WindowSecureMask` before reparenting a scene's window.
    ///
    /// When the self-test fails (Apple has narrowed the technique on
    /// this iOS) `WindowSecureMask` skips the reparent rather than
    /// falsely advertise protection. The degraded state is surfaced
    /// to the user via the "Screenshot protection — degraded" Settings
    /// notice and documented in the FAQ.
    var shouldMaskAppContents: Bool {
        state.qrBlockEffective != false
    }

    /// Persist the runtime-self-test result for the QR-block trick.
    /// Called by `SecureScreenshotSelfTest.runIfNeeded` once on first
    /// launch and again after every iOS major-version change.
    func setQRBlockEffective(_ effective: Bool, osVersion: String) {
        state.qrBlockEffective = effective
        state.qrBlockTestedOSVersion = osVersion
        Storage.upsertSettings(state)
    }

    func resetIdentity() {
        // F-704: full teardown — null self.relay, invalidate retry
        // timer, clear delegate. Mirrors disconnectForBackground so
        // any queued retry tick that fires before connectRelay runs
        // again can't observe a half-reset state.
        teardownRelay()
        // Preserve non-identity configuration across the wipe. The relay
        // host is a network endpoint (typically a LAN IP for a physical
        // iPhone, loopback for the sim); resetting it to the
        // 127.0.0.1 default would leave a real device unable to find
        // the relay until the user re-edited it. Same reasoning for
        // the UX prefs (auto-lock, biometric, onboarding-seen):
        // they're not identity-derived.
        let preservedHost = state.relayHost
        let preservedAutoLock = state.autoLockTimeout
        let preservedBiometric = state.biometricLockEnabled
        let preservedOnboarding = state.onboardingCompleted
        let preservedPreviewMode = state.attachmentPreviewMode
        let preservedPanicMode = state.panicModeEnabled
        let preservedContactsBeforeGroups = state.contactsBeforeGroups
        let preservedInAppHaptics = state.inAppHapticsEnabled
        // Privacy-oriented preference: surviving the identity wipe so
        // a user who set "default read receipts off" doesn't have
        // them silently turn back on after a duress-style reset.
        let preservedDefaultReadReceipts = state.defaultReadReceiptsEnabled
        let preservedNotificationsMuted = state.notificationsMuted
        // The block list is by identityPub, not contact id. Its
        // purpose is to outlive the contact row, so a peer the user
        // blocked then "removed" can't simply re-pair around the
        // block. Preserve across identity reset.
        let preservedBlocked = state.blockedIdentities
        let resetState = AppState(
            relayHost: preservedHost,
            onboardingCompleted: preservedOnboarding,
            biometricLockEnabled: preservedBiometric,
            autoLockTimeout: preservedAutoLock,
            attachmentPreviewMode: preservedPreviewMode,
            panicModeEnabled: preservedPanicMode,
            contactsBeforeGroups: preservedContactsBeforeGroups,
            inAppHapticsEnabled: preservedInAppHaptics,
            defaultReadReceiptsEnabled: preservedDefaultReadReceipts,
            notificationsMuted: preservedNotificationsMuted,
            blockedIdentities: preservedBlocked,
        )
        // F-703: write the post-reset AppState to Keychain BEFORE wiping
        // the device-store / outbox / legacy slots. The previous order
        // (wipe, then re-create-and-persist) had a process-kill window
        // between the two where on next launch `loadAppState()` returned
        // `AppState()` defaults — silently dropping the user's biometric
        // lock posture among the preserved fields. Now the new value is
        // durable across the wipe call's sequence of Keychain ops.
        Storage.upsertSettings(resetState)
        Storage.resetEverything(preserveAppState: true)
        state = resetState
        outbox = .empty
        do {
            let s = try Storage.loadOrCreateSession()
            session = s
            myIdentityPublicCached = try s.identityPublic()
            connectRelay()
            initError = nil
        } catch {
            initError = String(describing: error)
        }
        refreshAppBadge()
    }

    // MARK: - Duress wipe

    /// Trigger the cryptographic-erasure path. Called when the user
    /// enters the duress passcode at the lock screen.
    ///
    /// Steps, in order:
    ///   1. Snapshot the UX settings (relay host, Face ID, panic
    ///      mode, etc.) so the post-wipe app looks lived-in rather
    ///      than freshly installed (design Q2 → option b).
    ///   2. Tear down the relay socket + retry timer so no in-
    ///      flight encrypt can reach the network with the soon-to-
    ///      be-orphaned session.
    ///   3. `Storage.eraseAndReinitialize` — deletes the SQLCipher
    ///      file, the Secure-Enclave key, the Argon2id salt + params
    ///      + wrapped seed, and the AppPasscode slots; re-opens a
    ///      fresh empty DB.
    ///   4. Reset every in-memory ChatStore field to its cold-launch
    ///      defaults: load AppState + outbox from the fresh DB, mint
    ///      a brand-new libsignal identity, reconnect the relay
    ///      under the new identity.
    ///
    /// Returns synchronously — the caller (LockManager) drops the
    /// lock + the UI shows the now-empty chat list. From a
    /// coercer's perspective the timing is indistinguishable from a
    /// real unlock (Argon2id verify dominates wall-clock either way).
    func duressWipe() {
        let snapshot = state
        teardownRelay()
        session = nil
        myIdentityPublicCached = nil
        // Drop the APNs device token under the OLD identity. iOS mints
        // a fresh device token on the next registerForRemoteNotifications
        // call — so a relay-adjacent adversary who recorded the
        // pre-duress (peer-id, APNs token) tuple cannot correlate it
        // with a post-duress (fresh peer-id, fresh APNs token) tuple.
        // The next onboarding pass (which the duress wipe routes the
        // user through, by clearing `onboardingCompleted`) re-registers.
        UIApplication.shared.unregisterForRemoteNotifications()
        Storage.eraseAndReinitialize(preserving: snapshot, clearPasscodes: true)
        state = Storage.loadAppState()
        outbox = Storage.loadOutbox()
        diagEvents.removeAll()
        keychainWriteFailing = false
        initError = nil
        do {
            let s = try Storage.loadOrCreateSession()
            session = s
            myIdentityPublicCached = try s.identityPublic()
            // Deliberately do NOT auto-reconnect to the relay here.
            // The post-wipe state has `onboardingCompleted == false`,
            // so the user is routed through onboarding on next
            // foreground; the relay registration happens there with
            // the fresh APNs token. Reconnecting here under the new
            // identity but the same APNs registration would let a
            // relay operator correlate (old peer-id, push-token) →
            // (new peer-id, same push-token) and infer duress.
        } catch {
            initError = String(describing: error)
        }
        refreshAppBadge()
    }

    // MARK: - Helpers

    /// **Wholesale fallback** used by paths that mutate multiple
    /// contacts / groups in one pass. The schema is normalised so
    /// this is still correct on-disk — just bigger than the
    /// per-row mutators below. Prefer `persistContactSlice` /
    /// `persistContactSliceAndAppended` at any site that only
    /// touched one contact + the libsignal session.
    private func persistAll() {
        Storage.persist(appState: state)
        persistSession()
        refreshAppBadge()
    }

    /// Per-row counterpart to `persistAll()` when the caller mutated
    /// exactly one contact's row. Writes that row + the libsignal
    /// session blob (any send/receive advanced the ratchet) + the
    /// app-icon badge. Avoids the O(contact-count × message-count)
    /// sweep that `persistAll` does.
    private func persistContactSlice(at idx: Int) {
        Storage.upsertContact(state.contacts[idx])
        persistSession()
        refreshAppBadge()
    }

    /// Per-row counterpart to `persistAll()` for the message-append
    /// hot path. Writes the new message row, the contact row (which
    /// the caller typically bumped — lastMessageAt, sessionEstablished,
    /// etc.), the libsignal blob, and the badge.
    private func persistContactSliceAndAppended(_ msg: PersistedMessage, at idx: Int) {
        Storage.appendContactMessage(contactId: state.contacts[idx].id, msg)
        Storage.upsertContact(state.contacts[idx])
        persistSession()
        refreshAppBadge()
    }

    /// Persist *only* the libsignal session blob — used after every
    /// `Session.encryptSealed` / `decryptSealed` whose call-site doesn't
    /// already trigger a `persistAll()` for unrelated reasons. The
    /// libsignal ratchet advances on every encrypt and on every decrypt;
    /// dropping that state on the floor (e.g. after `emitAck` followed
    /// by a force-quit) rolls the on-disk session back, so the NEXT
    /// outbound message reuses an already-consumed counter and the peer
    /// rejects with `DuplicatedMessage`. Cheap to call — the blob is
    /// kilobytes and Keychain writes are async.
    /// Flush the libsignal session state to Keychain. Internal so the
    /// group surface can flush after every group_encrypt /
    /// senderKeyDistributionCreate / group_decrypt — those advance
    /// libsignal's internal stores the same way 1:1 ratchet
    /// operations do.
    func persistSession() {
        persistSessionImpl()
    }

    private func persistSessionImpl() {
        guard let session else { return }
        do {
            try Storage.persist(session: session)
            // Clear the warning the moment a write succeeds. Chronic
            // failure stays surfaced; transient hiccups self-resolve
            // on the next persistSession call.
            if keychainWriteFailing {
                keychainWriteFailing = false
            }
        } catch {
            // F-602: surface to UI via the published flag. Storage layer
            // already NSLog'd the underlying errSec status — the banner
            // tells the user to investigate before they trust further
            // ✓✓ indicators (which would otherwise be lying about
            // delivery in the worst case).
            keychainWriteFailing = true
        }
    }

    /// Total unread → app icon. Uses the modern API (the
    /// `UIApplication.shared.applicationIconBadgeNumber` setter is
    /// deprecated in iOS 17 and we target ≥ 17).
    ///
    /// Also publishes the count into the shared App Group container so
    /// the Notification Service Extension can pick up an authoritative
    /// baseline whenever a push arrives while the app is dead. The
    /// extension reads, increments, writes back; the main app then
    /// re-syncs from `state.totalUnread` on next launch.
    /// Fire the soft "new message somewhere else" haptic if the
    /// user opted in AND the incoming message landed in a chat the
    /// user is NOT currently looking at. Privacy-first messengers
    /// (Signal / WhatsApp / Threema / iMessage) skip in-app banners
    /// entirely because a "Alice: meet at 4pm" toast leaks content
    /// to anyone glancing at the screen — exactly the threat model
    /// Pizzini's screenshot-shield + no-thumbnails posture is built
    /// against. We match that posture: no banner, no sound, no
    /// preview, just a single soft haptic. Default off; toggle in
    /// Settings → "Haptic on new messages".
    func maybeFireBackgroundHaptic(forIncoming incoming: ActiveSurface) {
        guard state.inAppHapticsEnabled else { return }
        // Suppress when the user has paused notifications app-wide —
        // the haptic IS a notification, and silencing it here is the
        // counterpart to the NSE badge-suppress bit we publish via
        // SharedAppGroup.
        if state.notificationsMuted { return }
        // Per-contact / per-group mute: a haptic for a muted peer is
        // the attention-grab surface the user said they don't want.
        // Group surfaces don't have their own mute today (ChatGroup
        // doesn't carry mutedAt) — only the 1:1 branch checks.
        if case .oneOnOne(let peerIdentity) = incoming,
           let idx = contactIndex(forIdentity: peerIdentity),
           state.contacts[idx].mutedAt != nil {
            return
        }
        // Suppress when the message arrived in the chat the user is
        // already in — those rows render right under their thumb;
        // an extra haptic is redundant noise.
        if activeSurface == incoming { return }
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
    }

    func refreshAppBadge() {
        let count = state.totalUnread
        UNUserNotificationCenter.current().setBadgeCount(count) { _ in }
        // The NSE caps its bumps at `nseBadgeFloor + nseBadgeCap` so a
        // flood of pushes while the app is dead can't inflate the
        // badge into an oracle. Updating the floor on every refresh
        // collapses the cap back to the truth value the moment the
        // main app touches state.
        if let defaults = SharedAppGroup.defaults {
            defaults.set(count, forKey: SharedAppGroup.unreadCountKey)
            defaults.set(count, forKey: SharedAppGroup.nseBadgeFloorKey)
            // The user can pause NSE bumps entirely with the
            // global-mute toggle (Settings → Notifications); writing
            // the bit on every refresh keeps the NSE's view in sync
            // even if the user toggled it while the app was active.
            defaults.set(
                state.notificationsMuted,
                forKey: SharedAppGroup.suppressBadgeKey,
            )
        }
    }

    private func appendSystem(_ text: String, to idx: Int) {
        let row = PersistedMessage(side: .me, text: text, kind: .system, bytes: 0)
        state.contacts[idx].log.append(row)
        Storage.appendContactMessage(contactId: state.contacts[idx].id, row)
    }
}

extension ChatStore: RelayClientDelegate {
    nonisolated func relayClient(_ client: RelayClient, didChange state: RelayClient.State) {
        Task { @MainActor in
            // Drop callbacks from clients that are no longer in the
            // active fleet. `teardownRelay` clears the delegate
            // before disconnecting, but a `didChange` callback may
            // have ALREADY been enqueued on MainActor before that
            // delegate-nil ran; by the time the Task body executes,
            // `self.relays` no longer contains the sender. Acting
            // on the stale event would:
            //   * stamp the dead host's failure into `perRelayState`
            //     (UI flicker on the row we just rebuilt for that
            //     host),
            //   * recompute `aggregateRelayState` against a fleet
            //     that includes the now-detached client (it does
            //     not — the dead client isn't in `self.relays`
            //     anymore, so aggregateRelayState is fine in
            //     isolation), AND
            //   * call `electPushPrimary`, which would set
            //     `pushPrimary` to a freshly-built client that may
            //     still be `.connecting` (the old `firstReady`
            //     could now be one whose `.connected` event hadn't
            //     fired yet — but `readyRelays.first` skips it,
            //     so the primary candidate is consistent). The
            //     real risk is the late event masquerading as a
            //     real state change: `pushPrimary` could legitimately
            //     change on every late event, burning N
            //     `registerPush` round-trips.
            // Mirror the per-client state into the observable
            // `perRelayState` dict so Settings → Relays gets a live
            // redraw without the user having to expand/collapse the
            // row. `relays` and `relayDescriptors` are kept in
            // lockstep by `connectRelay` / `teardownRelay`, so
            // position-by-index lookup is sound.
            guard let idx = self.relays.firstIndex(where: { $0 === client }),
                  idx < self.relayDescriptors.count
            else {
                return
            }
            self.perRelayState[self.relayDescriptors[idx].host] = state
            let prevAggregate = self.relayState
            self.relayState = self.aggregateRelayState()
            self.electPushPrimary()
            // Self-healing reconnect: when the aggregate state
            // transitions to `.failed` we schedule an automatic
            // retry with exponential backoff. Without this the user
            // sees the "tap to reconnect" pill on EVERY cold launch
            // where the first Tor bootstrap times out — a real
            // problem on cellular / DPI networks where the first
            // circuit takes 60-120s but tor keeps the daemon
            // running in the background. The auto-retry reuses the
            // already-bootstrapping TORThread, so by the time the
            // backoff fires the daemon is usually ready and the
            // user never sees a red badge.
            //
            // On `.connected` we reset the backoff and cancel any
            // pending auto-reconnect.
            self.handleAggregateRelayStateTransition(
                from: prevAggregate,
                to: self.relayState,
            )
            // STATUS_REQUEST is per-relay — each one attests
            // separately. The cached `relayStatus` will be
            // overwritten by whichever response arrives last, but
            // since every relay should run the same audited binary
            // the value converges. A future UI surface that lists
            // per-relay attestation can use the per-client identity.
            // STATUS_REQUEST per relay — each one attests separately.
            // The response lands at `didReceiveStatus` and overwrites
            // the cached `relayStatus`. With a homogeneous fleet
            // (every relay runs the audited binary) the value
            // converges; a future UI surface can key per-relay
            // identity to show divergence.
            if state == .connected {
                client.requestStatus()
            }
            // Fleet-level one-shots: bundle requests, the retry
            // walk, transparency-log refresh, deferred read
            // receipts. We only fire these on the transition from
            // "no relays ready" to "at least one ready" — each
            // additional relay joining after that shouldn't
            // re-trigger them (would re-walk the outbox N times,
            // re-fetch the transparency log over HTTPS N times).
            let isNewlyReady = (self.relayState == .connected && prevAggregate != .connected)
            guard isNewlyReady else { return }
            // Retry bundle requests for any contact that hasn't yet
            // completed the handshake — the typical reason is "the
            // other side hadn't scanned us when we last asked".
            //
            // Also re-request for paired contacts whose `peerVerifyKey`
            // is nil OR whose v2 chain hasn't been delivered. The
            // BUNDLE_RESPONSE handler installs the verify_key; the
            // serveChain handler installs the chain — together they
            // bring a half-paired contact back online.
            for c in self.state.contacts
                where !c.sessionEstablished
                    || c.peerVerifyKey == nil
                    || c.outboundTokenChain == nil
            {
                self.requestBundleWithHashcash(fromPeer: c.identityPub)
            }
            // F-502: also kick the outbox retry walk immediately on
            // reconnect rather than waiting up to 30s for the next
            // timer tick. `runRetryWalk` is idempotent — if no
            // entries are due, it's a no-op.
            self.runRetryWalk()
            // USP #1 second half: refresh the transparency log
            // from the operator's pinned URL alongside the
            // relay-attestation refresh. The UI's match badge
            // depends on both — pulling them together keeps
            // the rendered state internally consistent.
            self.refreshTransparencyLog()
            // Drain any read receipts deferred while the relay
            // was offline. `emitReadReceipt` skips when
            // `relayState != .connected` so a missed receive
            // from a flapping socket doesn't burn a token into
            // a dead channel; re-firing mark-read here ships a
            // fresh receipt covering the current latest.
            switch self.activeSurface {
            case .oneOnOne(let peerIdentity):
                if let cIdx = self.contactIndex(forIdentity: peerIdentity) {
                    self.emitReadReceiptIfEnabled(forContactAt: cIdx)
                }
            case .group(let groupId):
                self.markGroupRead(groupID: groupId)
            case .none:
                break
            }
        }
    }

    nonisolated func relayClient(
        _ client: RelayClient,
        didReceiveSealedSend sealedCiphertext: Data
    ) {
        Task { @MainActor in
            self.handleSealedFrame(sealedCiphertext, isAckFrame: false, via: client)
        }
    }

    nonisolated func relayClient(_ client: RelayClient, didReceiveAck sealedCiphertext: Data) {
        Task { @MainActor in
            self.handleSealedFrame(sealedCiphertext, isAckFrame: true, via: client)
        }
    }

    nonisolated func relayClient(_ client: RelayClient, didReceiveStatus status: RelayStatus) {
        // USP #1: cache the latest relay attestation so the
        // Settings panel can read it synchronously when the user
        // opens the relay-info row. Also a useful diagnostic line
        // in NSLog — the operator's published transparency-log
        // SHA must match `binarySha256` for the running relay
        // to be considered the audited build.
        Task { @MainActor in
            self.relayStatus = status
            pzLog(
                "[pizzini] relay attest: v\(status.crateVersion) commit=\(status.gitSha)"
                    + " dirty=\(status.gitDirty) sha256=\(self.hex(status.binarySha256))",
            )
        }
    }


    @MainActor
    private func handleSealedFrame(_ sealedCiphertext: Data, isAckFrame: Bool, via client: RelayClient) {
        guard let session = self.session else { return }
        let received: Session.SealedReceived
        do {
            received = try session.decryptSealed(sealedCiphertext)
        } catch {
            pzLog("[pizzini] sealed decrypt failed: \(error) (sealed=\(sealedCiphertext.count) bytes, isAckFrame=\(isAckFrame))")
            return
        }
        // Persist BEFORE dispatching to per-kind handlers. The libsignal
        // ratchet has already advanced (decrypt is destructive); if we
        // crash mid-handler the on-disk session must reflect that step
        // or the peer's NEXT inbound to us reuses a chain key we've
        // already consumed and the whole conversation desyncs.
        persistSession()
        // Block-list gate: a sealed SEND from a blocked peer is
        // dropped after the ratchet step (so the libsignal session
        // for THIS peer stays consistent even though we no longer
        // surface their traffic). We do NOT emit an ACK — the
        // sender's outbox eventually marks the leg failed, which
        // is the intended "they no longer hear from me" signal.
        if self.isIdentityBlocked(received.peer) {
            return
        }
        guard let idx = self.contactIndex(forIdentity: received.peer) else {
            self.diagLog("relay", "DROPPED sealed frame from UNKNOWN PEER \(self.short(received.peer))"
                + " — they are not in this device's contacts (you must QR-pair before they can"
                + " send anything to you)")
            return
        }
        if received.isDuplicate {
            // Sender retried a SEND we already processed (their first
            // ACK from us probably got lost). Re-emit a fresh ACK
            // pointing at the same message_id so their outbox can flip
            // ✓→✓✓; do NOT re-append to the chat log or advance any
            // app-level state. The ratchet already returned us to
            // a quiescent state in this case (libsignal's
            // DuplicatedMessage path doesn't mutate the session).
            pzLog(
                "[pizzini] duplicate sealed frame from \(self.short(received.peer)) — re-emitting ACK"
            )
            self.emitAck(for: received.messageId, toPeer: received.peer, via: client)
            return
        }
        guard let kindByte = received.plaintext.first,
              let kind = RelayClient.InnerEnvelopeKind(rawValue: kindByte) else {
            // F-403: surface as a visible system row so a malicious paired
            // peer can't silently advance our chain key (the ratchet step
            // already happened above; we keep the persisted advance) — the
            // user sees something arrived from this contact and can act
            // (e.g. re-pair) even though we couldn't decode the envelope.
            let kindHex = received.plaintext.first.map { String(format: "0x%02x", $0) } ?? "(empty)"
            self.appendSystem(
                "Received an unknown envelope (\(kindHex)) — possible client mismatch.",
                to: idx,
            )
            return
        }
        let payload = received.plaintext.dropFirst()
        switch kind {
        case .chat:
            self.handleChatPayload(payload, sealedSize: sealedCiphertext.count, contactIdx: idx, ackId: received.messageId, via: client)
        case .ack:
            self.handleAckPayload(payload, contactIdx: idx)
        case .readReceipt:
            self.handleReadReceiptPayload(payload, contactIdx: idx)
        case .fileChunk:
            self.handleFileChunkPayload(
                payload,
                contactIdx: idx,
                fromPeer: received.peer,
                ackId: received.messageId,
                via: client,
            )
        case .groupChat:
            self.handleGroupChat(
                payload: Data(payload),
                fromPeer: received.peer,
                pairwiseMessageId: received.messageId,
            )
        case .groupKeyDistribution:
            self.handleGroupKeyDistribution(payload: Data(payload), fromPeer: received.peer)
        case .groupOp:
            self.handleGroupOp(payload: Data(payload), fromPeer: received.peer)
        case .groupBootstrap:
            self.handleGroupBootstrap(payload: Data(payload), fromPeer: received.peer)
        case .groupFileChunk:
            self.handleGroupFileChunk(payload: Data(payload), fromPeer: received.peer)
        case .chainSeedDelivery:
            self.handleChainSeedDelivery(payload: Data(payload), contactIdx: idx)
        }
        // Defensive: an ACK arriving on the SEND channel would have
        // landed in the chat path above unless its inner-kind byte is
        // 0x02. The wire-frame `isAckFrame` distinguishes the relay's
        // routing decision but the inner kind is authoritative.
        let _ = isAckFrame
    }

    @MainActor
    private func handleChatPayload(_ payload: Data, sealedSize: Int, contactIdx idx: Int, ackId: Data, via client: RelayClient) {
        let text = String(data: payload, encoding: .utf8) ?? "<\(payload.count) non-utf8 bytes>"
        // Stamp `messageId` on the inbound row so a later
        // `emitReadReceiptIfEnabled` can find the highest-read-msg
        // to confirm. Without this the receipt path was a silent
        // no-op (the helper filters on `messageId != nil`).
        let entry = PersistedMessage(
            side: .peer,
            text: text,
            kind: .whisper,
            bytes: sealedSize,
            messageId: ackId,
        )
        self.state.contacts[idx].log.append(entry)
        self.state.contacts[idx].lastMessageAt = entry.timestamp
        self.state.contacts[idx].sessionEstablished = true
        // When the receive lands in the chat the user is provably
        // in (`activeSurface` matches), fire the read-receipt emit
        // synchronously instead of waiting for SwiftUI's
        // `.onChange(of: log.count)` roundtrip in `ChatView`. The
        // SwiftUI path is a fallback for the "chat re-opened later"
        // case; the synchronous path here is the deterministic one
        // and removes the race where a brief relay-state flap
        // around the same moment as a new message would silently
        // drop the receipt (read receipts aren't in the outbox
        // retry walk).
        if activeSurface == .oneOnOne(peerIdentity: state.contacts[idx].identityPub) {
            state.contacts[idx].lastSeenAt = Date()
            emitReadReceiptIfEnabled(forContactAt: idx)
            refreshAppBadge()
        }
        maybeFireBackgroundHaptic(
            forIncoming: .oneOnOne(peerIdentity: state.contacts[idx].identityPub),
        )
        self.persistContactSliceAndAppended(entry, at: idx)
        // Emit an ACK so the sender's outbox (Phase 4) can flip ✓→✓✓.
        self.emitAck(for: ackId, toPeer: state.contacts[idx].identityPub, via: client)
    }

    @MainActor
    private func handleFileChunkPayload(
        _ payload: Data,
        contactIdx idx: Int,
        fromPeer peer: Data,
        ackId: Data,
        via client: RelayClient,
    ) {
        let envelope: FileChunkEnvelope
        do {
            envelope = try FileChunkEnvelope.decode(Data(payload))
        } catch {
            // Malformed chunk — paired peer, malicious or buggy.
            // Surface as a system row so the user knows something
            // tried but couldn't be parsed; the ratchet step has
            // already happened upstream so drop further work.
            appendSystem(
                "Got a malformed file chunk from \(state.contacts[idx].displayName). Dropped.",
                to: idx,
            )
            // Still ACK so the sender's outbox doesn't retry forever.
            emitAck(for: ackId, toPeer: peer, via: client)
            return
        }
        let outcome = reassembler.feed(envelope: envelope, fromPeer: peer)
        switch outcome {
        case .progress:
            // Mid-attachment — quiet. Sender will see ✓✓ for each
            // chunk landing as the ACKs flow back; we don't surface
            // intermediate progress to avoid log noise.
            break
        case .complete(let completion):
            let safeName = completion.sanitizedFilename
            let relPath = sandboxRelativePath(forURL: completion.url)
            let info = AttachmentInfo(
                attachmentId: completion.attachmentId,
                filename: safeName,
                byteSize: completion.totalSize,
                mime: completion.mime,
                tier: completion.tier,
                sandboxRelativePath: relPath,
                isInbound: true,
            )
            let row = PersistedMessage(
                side: .peer,
                text: "",   // captions are sender's chat-message; receiver sees attachment row only.
                kind: .attachment,
                bytes: Int(completion.totalSize),
                attachment: info,
            )
            state.contacts[idx].log.append(row)
            state.contacts[idx].lastMessageAt = row.timestamp
            state.contacts[idx].sessionEstablished = true
            persistContactSliceAndAppended(row, at: idx)
            maybeFireBackgroundHaptic(
                forIncoming: .oneOnOne(peerIdentity: state.contacts[idx].identityPub),
            )
            pzLog(
                "[pizzini] received attachment \(safeName) (\(completion.totalSize) bytes, tier=\(completion.tier.rawValue))"
            )
        case .rejected(let reason):
            pzLog("[pizzini] reassembler rejected chunk: \(reason)")
        }
        // Always ACK — the sender needs to flip ✓→✓✓ on every chunk
        // it submitted, regardless of reassembler outcome. Duplicates
        // are handled by libsignal's seal_receive (this handler isn't
        // even called for ratchet-level dups; the upstream
        // `received.isDuplicate` branch re-emits the ACK there).
        emitAck(for: ackId, toPeer: peer, via: client)
    }

    /// Convert a sandbox-rooted URL to its relative path under
    /// `attachments/`. Stored on `AttachmentInfo` so a future SQLCipher
    /// migration that relocates the sandbox doesn't strand existing
    /// rows. Returns nil for URLs outside the sandbox (treat as a
    /// programmer bug — log + nil rather than persist a brittle path).
    /// Internal-not-private so the group receive path in
    /// `ChatStoreGroups.swift` resolves completion URLs through the
    /// same logic as the 1:1 receive path.
    func sandboxRelativePath(forURL url: URL) -> String? {
        guard let root = try? AttachmentSandbox.root() else { return nil }
        let rootPath = root.path.hasSuffix("/") ? root.path : root.path + "/"
        let p = url.path
        guard p.hasPrefix(rootPath) else {
            pzLog("[pizzini] attachment URL not under sandbox: \(p)")
            return nil
        }
        return String(p.dropFirst(rootPath.count))
    }

    /// Resolve an `AttachmentInfo.sandboxRelativePath` back to an
    /// absolute URL. Used by the receive UI to present
    /// `UIDocumentInteractionController`.
    func attachmentURL(for info: AttachmentInfo) -> URL? {
        guard let rel = info.sandboxRelativePath,
              let root = try? AttachmentSandbox.root()
        else { return nil }
        return root.appending(path: rel, directoryHint: .notDirectory)
    }

    @MainActor
    private func handleReadReceiptPayload(_ payload: Data, contactIdx idx: Int) {
        guard payload.count == 16 else { return }
        // F-405: honour the effective read-receipts setting symmetrically.
        // If the user disabled emission of their own read receipts to
        // this contact (via per-chat override OR via the global default),
        // also drop incoming claims that we read — otherwise a paired
        // peer could spoof "Read" stamps onto our own messages
        // unilaterally regardless of our setting.
        let effective = state.contacts[idx].effectiveReadReceiptsEnabled(
            globalDefault: state.defaultReadReceiptsEnabled
        )
        guard effective else {
            return
        }
        let highest = Data(payload)
        let now = Date()
        // Resolve the cutoff via the shared helper which prefers the
        // log row's timestamp over the outbox entry's sentAt — the
        // log timestamp is created strictly after sentAt in
        // `send(_:to:)`, so using sentAt as the cutoff would
        // silently skip the row the receipt explicitly cites (the
        // "eye only lights on the previous message" regression).
        guard let cutoff = OutboxStore.readReceiptCutoff(
            highest: highest, log: state.contacts[idx].log, outbox: outbox,
        ) else { return }
        for i in state.contacts[idx].log.indices {
            let m = state.contacts[idx].log[i]
            guard m.side == .me, m.timestamp <= cutoff else { continue }
            if state.contacts[idx].log[i].readAt == nil {
                state.contacts[idx].log[i].readAt = now
                Storage.updateContactMessage(
                    contactId: state.contacts[idx].id,
                    state.contacts[idx].log[i],
                )
            }
        }
        // Phase 7 group-read aggregation. The same incoming receipt
        // ALSO covers every group fan-out leg we shipped to this peer
        // up to the cutoff. Stamp `readAt` on those outbox entries so
        // `OutboxStore.groupMessageReadByAll(forId:)` returns true
        // once every member has confirmed — `GroupChatBubble` then
        // flips ✓✓ → 👁 on the rolled-up row indicator. Honours the
        // same `readReceiptsEnabled`-off symmetric drop as the 1:1
        // path above (the early-return already guarded it).
        let peerId = state.contacts[idx].identityPub
        for (id, entry) in outbox.entries
            where entry.recipientPeerId == peerId
                && entry.groupMessageId != nil
                && entry.sentAt <= cutoff
                && entry.readAt == nil {
            var updated = entry
            updated.readAt = now
            outbox.entries[id] = updated
            Storage.upsertOutboxEntry(updated)
        }
    }

    @MainActor
    private func handleAckPayload(_ payload: Data, contactIdx idx: Int) {
        guard payload.count == 16 else {
            pzLog("[pizzini] malformed ACK from \(self.short(state.contacts[idx].identityPub))")
            return
        }
        let messageId = Data(payload)
        guard var entry = outbox.entries[messageId] else {
            pzLog("[pizzini] ACK for unknown messageId \(messageId.map { String(format: "%02x", $0) }.joined())")
            return
        }
        entry.deliveredAt = Date()
        outbox.entries[messageId] = entry
        Storage.upsertOutboxEntry(entry)
    }

    /// Periodic walk: re-send unacked entries that satisfy
    /// `OutboxEntry.shouldRetry`, mark expired entries failed, drop
    /// terminal entries older than 24h to keep the outbox bounded.
    /// Every mutation persists per-row to SQLCipher.
    @MainActor
    private func runRetryWalk() {
        guard let session, !relays.isEmpty else { return }
        let now = Date()

        // 1. TTL expiry → mark failed.
        for (id, entry) in outbox.entries where entry.hasExpired(now: now) {
            var e = entry
            e.failedAt = now
            outbox.entries[id] = e
            Storage.upsertOutboxEntry(e)
        }

        // 2. Retry walk — only if connected. NWConnection.send while
        // disconnected silently drops; we'd burn tokens.
        if relayState == .connected {
            for entry in outbox.retryableEntries(now: now) {
                guard let idx = contactIndex(forIdentity: entry.recipientPeerId) else {
                    continue
                }
                guard let v2 = mintV2DeliveryToken(forContactAt: idx) else {
                    pzLog("[pizzini] cannot retry \(short(entry.recipientPeerId)): chain missing or exhausted")
                    continue
                }
                let wire = HashChainToken.encode(v2)
                broadcastToRelays {
                    $0.sendSealed(
                        toPeer: entry.recipientPeerId,
                        sealedCiphertext: entry.sealedCiphertext,
                        ttlSeconds: UInt32(entry.ttl),
                        token: wire,
                    )
                }
                var e = entry
                e.retries += 1
                // `relayedAt` records the FIRST time bytes left our
                // socket — bumping it on retry would lie to the UI
                // about how long this message has been waiting. The
                // status icon reads from `relayedAt`/`deliveredAt`/
                // `failedAt`; only the new retry count is interesting.
                outbox.entries[entry.messageId] = e
                Storage.upsertOutboxEntry(e)
                _ = session  // silence unused-let in current scope
            }
        }

        // 3. Garbage-collect terminal entries past their post-mortem
        // window. 24h after delivered or failed is plenty for the UI
        // to read; the user can still see the message in the chat
        // log, just without a status icon.
        let postMortem: TimeInterval = 24 * 60 * 60
        for (id, entry) in outbox.entries {
            if let t = entry.deliveredAt ?? entry.failedAt,
               now.timeIntervalSince(t) > postMortem {
                outbox.entries.removeValue(forKey: id)
                Storage.deleteOutboxEntry(messageId: id)
            }
        }

        // 4. Reassembler stale cleanup. A malicious sender shipping
        // chunk_count=1024 then 1 chunk would otherwise pin a partial
        // dir until the user resets the app. The reassembler stamps
        // each pending entry with `expiresAt = now + partialTTL` (24h);
        // we reap here on the same 30s tick so the leak is bounded.
        let staleAttachments = reassembler.staleEntries(now: now)
        for stale in staleAttachments {
            pzLog(
                "[pizzini] discarding stale partial attachment from \(short(stale.peer)): \(stale.claimedFilename)"
            )
            reassembler.discard(peer: stale.peer, attachmentId: stale.attachmentId)
        }
        // Same walk for the group reassembler — a partial group
        // transfer is just as exploitable and shares the same disk-
        // pinning surface. We also drop the routing map entry so a
        // re-send under the same (peer, aid) is treated as a fresh
        // attachment rather than colliding with the GC'd chain.
        let staleGroupAttachments = groupReassembler.staleEntries(now: now)
        for stale in staleGroupAttachments {
            pzLog(
                "[pizzini] discarding stale partial group attachment from \(short(stale.peer)): \(stale.claimedFilename)"
            )
            groupReassembler.discard(peer: stale.peer, attachmentId: stale.attachmentId)
            groupAttachmentRouting.removeValue(forKey: stale.peer + stale.attachmentId)
        }

        // 5. Sandbox cleanup: drop assembled attachment files older
        // than the per-chat TTL (the chat row stays as a record but
        // the bytes are gone). 7d hard cap matches the relay's per-
        // message TTL ceiling; longer would let an attacker who
        // compromises the device read material that should have
        // already been cryptographically erased.
        let sandboxCutoff = now.addingTimeInterval(-7 * 24 * 60 * 60)
        _ = AttachmentSandbox.cleanup(olderThan: sandboxCutoff)
    }

    @MainActor
    private func emitAck(for messageId: Data, toPeer: Data, via client: RelayClient) {
        guard let session = self.session,
              let idx = contactIndex(forIdentity: toPeer)
        else { return }
        guard let v2 = mintV2DeliveryToken(forContactAt: idx) else {
            pzLog("[pizzini] cannot emit ACK to \(self.short(toPeer)): chain missing or exhausted")
            return
        }
        let token = HashChainToken.encode(v2)
        var inner = Data([RelayClient.InnerEnvelopeKind.ack.rawValue])
        inner.append(messageId)
        do {
            let sealed = try session.encryptSealed(
                peer: toPeer,
                messageId: Self.makeMessageId(),
                plaintext: inner,
            )
            // CRITICAL: persist immediately. encryptSealed advanced the
            // ratchet; if the app is killed before the next persistAll,
            // the on-disk session rolls back one step and our NEXT
            // outbound encrypt reuses an already-consumed counter that
            // the peer will reject as DuplicatedMessage.
            persistSession()
            // D3 fanout: the sender of the SEND we're acking may be
            // connected to any subset of the fleet. Fan the ACK out
            // so they get ✓✓ via whichever relay's queue holds their
            // session.
            broadcastToRelays {
                $0.sendAck(
                    toPeer: toPeer,
                    sealedCiphertext: sealed,
                    ttlSeconds: Self.defaultTTLSeconds,
                    token: token,
                )
            }
        } catch {
            pzLog("[pizzini] failed to emit ACK to \(self.short(toPeer)): \(error)")
        }
    }

    nonisolated func relayClient(_ client: RelayClient, didReceiveBundleRequestFrom fromPeer: Data) {
        Task { @MainActor in
            // Block-list gate: a BUNDLE_REQUEST from a blocked peer
            // is dropped without a decoy emission. The decoy is the
            // anti-probe defense for *unknown* requesters; for a
            // blocked one, the user has explicitly opted out of
            // ever pairing with them again, and silence is the
            // intended posture. Emitting a decoy here would also
            // mint a TOKEN_ISSUE batch into the blocked peer's
            // contact-graph view.
            if self.isIdentityBlocked(fromPeer) {
                return
            }
            guard let idx = self.contactIndex(forIdentity: fromPeer),
                  let session = self.session
            else {
                // F-402: a malicious relay can fabricate BUNDLE_REQUEST
                // frames with arbitrary `from_id` to probe our contact
                // set — silence-vs-(BUNDLE_RESPONSE+TOKEN_ISSUE) on the
                // wire is the oracle. Mask by emitting a same-shape,
                // same-timing decoy when the requester isn't in our
                // contacts, so the relay sees identical outbound
                // bandwidth + latency for known-vs-unknown.
                pzLog("[pizzini] BUNDLE_REQUEST from unknown peer \(self.short(fromPeer)) — emitting decoy")
                self.emitBundleResponseDecoy(toFakePeer: fromPeer, via: client)
                return
            }
            // F-404: cooldown publishBundle the same way we cooldown
            // issueTokens. A paired peer can otherwise loop BUNDLE_REQUEST
            // (the per-recipient hashcash bound is per-hour and they have
            // our peer_id, so they can grind one proof per hour) and
            // burn one one-time prekey + one kyber1024 keygen per
            // request — a CPU/battery DoS amplified by the existing
            // F-402 ability for a malicious relay to inject requests.
            if let last = self.state.contacts[idx].lastBundleServedAt,
               Date().timeIntervalSince(last) < Contact.chainServeCooldown
            {
                pzLog(
                    "[pizzini] BUNDLE_REQUEST from \(self.short(fromPeer)) rate-limited; last served \(last)"
                )
                return
            }
            do {
                let bundle = try session.publishBundle()
                // D3 fanout: requester may be connected to a different
                // subset of the fleet than we are. Fan the response
                // out so the bundle reaches them via at least one
                // shared relay.
                self.broadcastToRelays { $0.sendBundle(toPeer: fromPeer, bundle: bundle) }
                self.state.contacts[idx].lastBundleServedAt = Date()
                // Right after the bundle, mint and ship a fresh v2
                // hash chain. The peer derives every future delivery
                // token from this one seed; the chain root is
                // registered with our connected relays as part of
                // `serveChain` so v2 SENDs from the peer validate.
                self.serveChain(forPeer: fromPeer, via: client, session: session)
                self.persistContactSlice(at: idx)
                // The peer just proved they have us in their contacts (we
                // only get here if our own contact-gate let them through).
                // If we haven't yet got a session ourselves — typical when
                // we were the second of the two to add the other — ask
                // for their bundle now too. Closes the asymmetric pairing.
                if !self.state.contacts[idx].sessionEstablished {
                    self.requestBundleWithHashcash(fromPeer: fromPeer)
                }
            } catch {
                pzLog("[pizzini] publishBundle failed: \(error)")
            }
        }
    }

    nonisolated func relayClient(
        _ client: RelayClient,
        didReceiveBundleFrom fromPeer: Data,
        bundle: Data
    ) {
        Task { @MainActor in
            // Block-list gate: BUNDLE_RESPONSE from a blocked peer is
            // dropped before initiateSession does any work. The
            // libsignal session state for this peer is untouched.
            if self.isIdentityBlocked(fromPeer) {
                return
            }
            guard let session = self.session,
                  let idx = self.contactIndex(forIdentity: fromPeer)
            else {
                pzLog("[pizzini] dropped BUNDLE_RESPONSE from unknown peer \(self.short(fromPeer))")
                return
            }
            do {
                // F-202/F-401: stash the peer's verify_key. With v2
                // hash-chain tokens this key isn't used for token
                // authentication at the relay (the chain root is the
                // capability), but it's still the libsignal verify
                // key for sealed-sender certificates — keep it in
                // step with the bundle.
                let verifyKey = try Session.extractBundleVerifyKey(bundle)
                try session.initiateSession(peerIdentity: fromPeer, bundle: bundle)
                // A bundle from a peer who's rotated their identity
                // invalidates our outbound chain to them: its root is
                // registered with the relay under the peer's prior
                // (peer_id, chain_id) state, and after the peer
                // re-pairs they'll register a new one. Drop the chain
                // here so the next send hits `refreshChainAndQueue`.
                let priorVerifyKey = self.state.contacts[idx].peerVerifyKey
                if priorVerifyKey != nil, priorVerifyKey != verifyKey {
                    self.state.contacts[idx].outboundTokenChain = nil
                }
                self.state.contacts[idx].peerVerifyKey = verifyKey
                self.state.contacts[idx].sessionEstablished = true
                self.persistContactSlice(at: idx)
            } catch {
                pzLog("[pizzini] initiateSession failed: \(error)")
            }
        }
    }

    /// 4-byte hex fingerprint shorthand for log lines and system rows.
    /// Internal-not-private so the group surface in
    /// `ChatStoreGroups.swift` can render the same shorthand without
    /// duplicating the formatter. `nonisolated` so detached tasks
    /// (e.g. the off-actor TOKEN_ISSUE verify loop) can format peer
    /// ids without hopping back through MainActor.
    nonisolated func short(_ data: Data) -> String {
        let head = data.prefix(4).map { String(format: "%02x", $0) }.joined()
        return head + "…"
    }

    /// Full lowercase hex. Used by the USP #1 relay-info logging /
    /// Settings row to render binary SHA-256s the operator can
    /// match against a transparency-log entry.
    nonisolated func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
