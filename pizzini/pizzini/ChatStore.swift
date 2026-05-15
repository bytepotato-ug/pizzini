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
    /// Most-recent self-attestation snapshot from the relay
    /// (binary SHA-256, git commit, dirty bit, crate version).
    /// Refreshed on every successful (re)connect; rendered in
    /// Settings → Relay info so users can compare the running
    /// binary against the operator-published transparency-log
    /// entry. `nil` until the first STATUS_RESPONSE lands.
    var relayStatus: RelayStatus?

    /// Verdict of comparing the running relay's reported
    /// `binarySha256` against the verified transparency log. Computed
    /// in `relayClient(_:didReceiveStatus:)` on every reconnect — NOT
    /// merely on demand in the Settings view — so it is an
    /// enforceable signal, not just badge state. The actual
    /// enforcement ACTION (disconnect / block sends / signed grace
    /// window) is decision-gated on policy; see the
    /// `AUDIT-DECISION-NEEDED` marker in `didReceiveStatus`.
    enum RelayAttestationVerdict: Sendable, Equatable {
        /// No STATUS_RESPONSE yet, or no operator verify key is
        /// configured in this build — verification has not run.
        case notEvaluated
        /// The reported binary SHA appears in a verified, signed
        /// transparency-log entry. The relay is running an audited
        /// build.
        case verified
        /// A non-empty verified log was available and the reported
        /// binary SHA does NOT appear in it. Either a tampered
        /// binary or a deploy the operator has not yet signed into
        /// the log.
        case mismatch
        /// The transparency log could not be verified at all — empty
        /// cache, blocked/failed fetch, no signed entries. The client
        /// cannot tell whether this relay is audited. This is NOT
        /// equivalent to `verified` — an adversary who simply blocks
        /// the log fetch must not silently downgrade the client to
        /// "looks fine."
        case unverifiable
    }

    /// Latest per-reconnect attestation verdict. Drives both the
    /// Settings badge and (once the enforcement policy is decided)
    /// the interruption path. `.notEvaluated` until the first
    /// STATUS_RESPONSE is compared against the log.
    private(set) var relayAttestationVerdict: RelayAttestationVerdict = .notEvaluated

    /// Re-pair UX: set true after the user explicitly resets their
    /// identity via Settings → Reset everything. Drives a one-shot
    /// alert in `ContactsListView` that tells them anyone who had
    /// them in their contacts must delete + re-scan their new QR.
    ///
    /// **NOT** set after `duressWipe()` — the duress path's design
    /// (Q2b in the README session log) explicitly requires the
    /// post-wipe state to be indistinguishable from a normal
    /// freshly-installed app, so a coercer watching the screen sees
    /// no telltale "identity was reset" affordance. Persisted via
    /// `UserDefaults` (a single boolean, set on reset, cleared on
    /// the user's "Got it" tap) so a crash between reset and
    /// dismiss doesn't lose the prompt.
    var identityResetBannerPending: Bool = false {
        didSet {
            UserDefaults.standard.set(
                identityResetBannerPending,
                forKey: Self.identityResetBannerPendingDefaultsKey,
            )
        }
    }
    private static let identityResetBannerPendingDefaultsKey = "pizzini.identityResetBannerPending"

    /// User dismissed the identity-reset banner. Idempotent; safe to
    /// call from any caller (a duplicate tap on "Got it" is a no-op).
    func dismissIdentityResetBanner() {
        identityResetBannerPending = false
    }
    /// Cached transparency-log entries loaded
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

    /// True when `Storage.bootstrap()` failed because no derivable key
    /// can decrypt the on-disk database, OR a cold-load query against
    /// an opened store threw. In either case the app must NOT present
    /// a running chat surface against `AppState()` defaults — the
    /// in-memory security posture would be weaker than what is
    /// persisted on disk, and an empty chat list would be
    /// indistinguishable from a fresh install while the user's real
    /// (encrypted, intact) state sits on disk. `ContentView` keys its
    /// recoverable-error banner off `initError`; this flag additionally
    /// gates `ChatStore.init` from installing observers / connecting
    /// the relay against the half-initialised defaults. A benign
    /// schema-downgrade self-heals inside `SQLiteStorage.bootstrap`
    /// and never sets this.
    private(set) var unrecoverableStorageState: Bool = false

    /// True when the most recent `duressWipe()` could NOT confirm
    /// every key-material delete (e.g. a Keychain delete returned a
    /// non-success `OSStatus` because the device was in a
    /// locked-after-first-unlock state). The duress flow's contract
    /// is cryptographic erasure; it must not silently report a
    /// completed wipe while a usable decryption path may survive.
    /// `ContentView` can surface this so the user knows to retry the
    /// wipe rather than trusting it landed.
    private(set) var duressWipeIncomplete: Bool = false

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
    /// policy at ). Trims the buffer to `diagBufferCap`
    /// from the front. Always called from `@MainActor`-bound code
    /// so the array mutation is race-free.
    ///
    /// NSLog had been the historical choice, but NSLog lines from
    /// release builds remain in `sysdiagnose` archives a coercer
    /// can exfiltrate over Lightning. os_log .debug is dropped at
    /// the kernel level on release devices.
    func diagLog(_ category: String, _ message: String) {
        os_log(.debug, "[pizzini.%{public}@] %{public}@", category, message)
        // QA-debug persistent log (DEBUG only — release builds compile
        // the recording path out so a deployed app never carries the
        // forensic-attack surface). See `QALog.swift` for the file
        // layout and the rotation policy.
        QALog.record(category: category, message: message)
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
        // user on a community relay pairing with a stranger, that
        // narrows the stranger's anonymity set to "uses the same
        // relay as this user." Always emit the bundled-fleet
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
    nonisolated static let autoReconnectBackoffFloor: TimeInterval = 5
    nonisolated static let autoReconnectBackoffCeiling: TimeInterval = 60

    /// Hard cap on consecutive auto-reconnect attempts before we stop
    /// retrying silently and surface the Reconnect button via the
    /// `manualReconnectRequired` flag. Five attempts at 5-10-20-40-60 s
    /// spread is about 2 minutes of background spinning, which is
    /// enough rope for any transient outage to recover but short
    /// enough that a user who comes back to the app after a real
    /// outage sees an actionable affordance instead of a spinner
    /// that's been spinning since they last looked.
    nonisolated static let autoReconnectMaxConsecutiveFailures: Int = 5

    /// Pure decision for the auto-reconnect state machine. Given the
    /// pre-failure streak and current backoff, returns what action
    /// the host should take: schedule another retry (with the
    /// `delaySeconds` to wait and the `nextBackoff` to remember for
    /// the FOLLOWING failure), or stop silently retrying and require
    /// a user tap. Public so `AutoReconnectDecisionTests` in the iOS
    /// app test target pins the contract — every backoff doubles,
    /// every doubling is capped at the ceiling, and the streak cap
    /// switches modes exactly once.
    public enum AutoReconnectAction: Equatable, Sendable {
        case scheduleRetry(delaySeconds: TimeInterval, nextBackoff: TimeInterval)
        case requireManual
    }
    public struct AutoReconnectDecision: Equatable, Sendable {
        public let action: AutoReconnectAction
        public let newStreak: Int
    }
    public nonisolated static func computeAutoReconnectDecision(
        previousStreak: Int,
        currentBackoff: TimeInterval,
    ) -> AutoReconnectDecision {
        let newStreak = previousStreak + 1
        if newStreak >= autoReconnectMaxConsecutiveFailures {
            return AutoReconnectDecision(action: .requireManual, newStreak: newStreak)
        }
        let nextBackoff = min(currentBackoff * 2, autoReconnectBackoffCeiling)
        return AutoReconnectDecision(
            action: .scheduleRetry(delaySeconds: currentBackoff, nextBackoff: nextBackoff),
            newStreak: newStreak,
        )
    }
    /// Consecutive auto-reconnect failures since the last successful
    /// HELLO. Reset to 0 on `.connected` (which only fires after the
    /// HELLO is ack'd — i.e. a relay actually accepted us), NOT on
    /// every intermediate state transition. A flaky relay that
    /// bounces us back to `.failed` shouldn't drain the budget.
    private var autoReconnectFailureStreak: Int = 0

    /// Per-relay exponential-backoff floor and ceiling. Drives the
    /// silent background retry of a single `.failed` relay while the
    /// aggregate fleet stays `.connected` (D3 fanout means N-1 of N
    /// healthy is still a usable send/receive path — the user must
    /// not see a banner blip for one degraded route, but the dead
    /// route must rejoin on its own so the fleet doesn't quietly
    /// erode to a single point of failure). Values are deliberately
    /// tighter than the aggregate-`failed` backoff: a single-relay
    /// blip on a healthy network usually clears in seconds (one Tor
    /// circuit reselect), so the floor is 2 s.
    nonisolated static let perRelayBackoffFloor: TimeInterval = 2
    nonisolated static let perRelayBackoffCeiling: TimeInterval = 60

    /// Pure decision for the per-relay retry. Given the current
    /// backoff for one relay, returns the delay to wait before the
    /// next attempt and the backoff to remember for the FOLLOWING
    /// failure. Doubles on each call, capped at the ceiling. There
    /// is no streak cap — the per-relay retry is silent and the
    /// fleet keeps serving traffic via the other N-1 routes for as
    /// long as it takes the dead relay to recover.
    public struct PerRelayRetryDecision: Equatable, Sendable {
        public let delaySeconds: TimeInterval
        public let nextBackoff: TimeInterval
    }
    public nonisolated static func computePerRelayRetryDecision(
        currentBackoff: TimeInterval,
    ) -> PerRelayRetryDecision {
        let delay = max(perRelayBackoffFloor, min(currentBackoff, perRelayBackoffCeiling))
        let next = min(delay * 2, perRelayBackoffCeiling)
        return PerRelayRetryDecision(delaySeconds: delay, nextBackoff: next)
    }

    /// Per-relay backoff state, keyed by `RelayDescriptor.host`.
    /// Cleared when the relay (re)connects; cleared in bulk by
    /// `teardownRelay` so a fresh fleet always starts at the floor.
    private var perRelayBackoff: [String: TimeInterval] = [:]
    /// Per-relay retry tasks. One pending Task per host while that
    /// host is in `.failed`; cancelled on connect / teardown / new
    /// scheduling. Keyed by host the same way as `perRelayBackoff`.
    private var perRelayRetryTasks: [String: Task<Void, Never>] = [:]
    /// True once `autoReconnectFailureStreak` has hit the cap and we
    /// stopped scheduling new auto-reconnect tasks. The UI surfaces
    /// a tappable "Reconnect" button (forceReconnectRelays clears
    /// the flag + restarts the auto-loop). Reset to false on the
    /// next `.connected` so the next outage starts a fresh budget.
    var manualReconnectRequired: Bool = false
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
        // Pre-load any previously-cached
        // transparency-log entries so the Settings panel can
        // render an immediate answer without waiting for the
        // first reconnect to repopulate.
        self.transparencyLog = TransparencyLog.loadCachedLog()
        // Re-pair UX: restore the post-reset banner flag from
        // UserDefaults so a crash between reset and the user's
        // "Got it" tap doesn't lose the prompt. Default false
        // (no banner pending) is the right value for a fresh
        // install and also for any unset key.
        self.identityResetBannerPending = UserDefaults.standard.bool(
            forKey: Self.identityResetBannerPendingDefaultsKey,
        )
        super.init()
        // Unrecoverable storage state — refuse to come up against
        // half-initialised defaults. Two causes, both meaning the
        // in-memory graph is NOT a faithful picture of what is on
        // disk:
        //   1. `Storage.bootstrap()` failed because no derivable key
        //      opens the on-disk DB (SE key handle gone, tampered
        //      material) — `SQLiteStorage.shared` is nil, every
        //      Storage accessor degrades to `AppState()` defaults.
        //   2. A cold-load query against an opened store threw (torn
        //      WAL, `SQLITE_CORRUPT`) — `loadAppState`/`loadOutbox`
        //      returned defaults but the real data is intact on disk.
        // In either case constructing a live ChatStore — connecting
        // the relay under a defaults posture, installing scene
        // observers, registering a push token — would present a
        // running surface weaker than what is persisted. Set
        // `initError` (so ContentView's existing recoverable-error
        // banner shows, which already suppresses onboarding) and the
        // `unrecoverableStorageState` flag, then stop: no relay, no
        // observers, no badge write. A benign schema-downgrade
        // self-heals inside `SQLiteStorage.bootstrap` and never
        // reaches here.
        if Storage.unrecoverableKeyMaterialFailure {
            self.unrecoverableStorageState = true
            self.initError = "Pizzini can't unlock its database on this device."
            return
        }
        if let coldLoadError = Storage.lastColdLoadError {
            self.unrecoverableStorageState = true
            self.initError = "Pizzini couldn't read its saved data: \(coldLoadError)"
            return
        }
        // Migration: pre-fleet installs persisted dev hosts like
        // `127.0.0.1`. Per the relay architecture doc (D1), every
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
        // QA-DIAG (2026-05-14): drain the launch-time storage diagnostics
        // (StorageMigration branch + device_store load verdict) into the
        // in-app Diagnostics view, so the cross-launch persistence
        // question is answerable from a screenshot — no Console.app
        // capture needed. Remove once the persistence bug is closed.
        for line in Storage.qaDiag {
            diagLog("qa-diag", line)
        }
        Storage.qaDiag.removeAll()
        refreshAppBadge()
        // Wifi↔cellular handoffs, captive-portal flips, and
        // constrained-mode changes invalidate tor's circuits. The
        // observer in TorController issues SIGNAL NEWNYM on its own;
        // we just need to drop + redial our RelayClient sockets so
        // the next outgoing frame uses a fresh circuit.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleTorNetworkPathChanged),
            name: .pizziniTorNetworkPathChanged,
            object: nil,
        )
        // Mirror TorController.requiresAppRestart onto our @Observable
        // state so ContentView's banner can re-render. tor_run_main()
        // is single-shot per process; once tor exits in-process, the
        // only safe path is a user-driven app restart.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleTorRequiresAppRestart),
            name: .pizziniTorRequiresAppRestart,
            object: nil,
        )
        // Mirror TorController.bootstrapPhaseLabel for the
        // connection-status indicator in ContactsListView.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleTorBootstrapPhaseChanged(_:)),
            name: .pizziniTorBootstrapPhaseChanged,
            object: nil,
        )
    }

    @objc
    private func handleTorNetworkPathChanged() {
        // Notification arrives from TorController on MainActor.
        guard !relays.isEmpty else { return }
        pzLog("[pizzini] network path changed — redialing relays")
        teardownRelay(keepRetryTimer: true)
        connectRelay()
    }

    /// Sticky flag mirroring `TorController.requiresAppRestart`. Set
    /// to true once the embedded tor's NSThread reports finished —
    /// after that, no amount of reconnect is going to recover, the
    /// user has to restart. ContentView surfaces a non-dismissable
    /// banner whose "Restart Pizzini" button calls `exit(0)` (iOS
    /// auto-relaunches because the trigger was a direct user tap).
    var torRequiresAppRestart: Bool = false

    /// Mirror of `TorController.bootstrapPhaseLabel` — short
    /// user-facing string for the current bootstrap phase ("Loading
    /// directory", "Building circuit", "Connecting to relay", …).
    /// Empty until the first STATUS_CLIENT event arrives.
    /// ContactsListView renders it next to the connection spinner
    /// so the user can see the app is making progress.
    var torBootstrapPhase: String = ""

    /// Live mirror of `TorController.shared.bootstrapProgress`.
    /// Updated by the captive-portal stall watcher (which already
    /// polls progress every second) so the pill state machine can
    /// read it without a separate polling Task. Range 0-100;
    /// 100 means Tor is bootstrapped and the SOCKS port is ready.
    /// Drives the `.bootstrappingTor` branch of `pillState`.
    var torBootstrapProgress: Int = 0

    /// Latest captive-portal probe verdict. `nil` until a stalled
    /// bootstrap triggers the probe (Tor progress <50% for >30 s).
    /// Set to `.none` if the probe came back clean (Tor is just slow
    /// on this network — no banner), `.portal` to drive the "this
    /// WiFi needs a sign-in page" banner, `.networkDown` to drive
    /// the "no internet connection" banner. Reset to `nil` on every
    /// reconnect / teardown so a fresh attempt isn't gated by a
    /// stale verdict from the previous network.
    var captivePortalVerdict: CaptivePortalVerdict?

    /// Threshold for the captive-portal stall heuristic. Below this
    /// percent, Tor's bootstrap is doing essentially nothing — either
    /// the network is blocking the directory fetch (portal) or
    /// there's no connectivity at all. Above this, Tor has already
    /// completed the consensus + descriptor fetch and the slow path
    /// is somewhere we can't help with from clearnet.
    nonisolated static let captivePortalStallProgress: Int = 50
    /// How long Tor's bootstrap must stay below
    /// `captivePortalStallProgress` before the clearnet probe fires.
    /// 30 s is long enough that a normal slow cellular start finishes
    /// without ever triggering it, short enough that a user on a
    /// captive-portal WiFi sees the actionable banner quickly.
    nonisolated static let captivePortalStallSeconds: TimeInterval = 30

    /// First moment we saw Tor bootstrap progress below the stall
    /// threshold. Cleared whenever progress crosses ≥ threshold (so
    /// a normal climb past 50% never accumulates stall time) and on
    /// every relay teardown / fresh connect.
    private var captivePortalLowSince: Date?
    /// Background polling task that watches Tor bootstrap progress
    /// and fires the captive-portal probe on stall. Cancelled in
    /// `teardownRelay` and re-armed in `connectRelay`.
    private var captivePortalStallTask: Task<Void, Never>?
    /// True once the current connect cycle has fired its one probe.
    /// Sticky for the cycle so a long stall doesn't repeatedly hit
    /// `captive.apple.com` — one probe per connect attempt is
    /// enough to drive the banner, and the user's next action will
    /// reset us via teardown/reconnect.
    private var captivePortalProbeFired: Bool = false

    @objc
    private func handleTorRequiresAppRestart() {
        pzLog("[pizzini] tor daemon exited — surfacing restart CTA")
        torRequiresAppRestart = true
        // Cancel any pending auto-reconnect — it will just spin
        // forever against a dead daemon. The user has to act.
        autoReconnectTask?.cancel()
        autoReconnectTask = nil
    }

    @objc
    private func handleTorBootstrapPhaseChanged(_ notification: Notification) {
        guard let label = notification.userInfo?["label"] as? String else { return }
        torBootstrapPhase = label
    }

    /// Start watching Tor bootstrap progress for the captive-portal
    /// stall heuristic. Called from `connectRelay`; tears down its
    /// own previous task on each (re)start so a rapid reconnect
    /// cycle doesn't accumulate watchers.
    ///
    /// The watcher polls `TorController.shared.bootstrapProgress`
    /// every second. The math is intentionally simple — a Combine
    /// pipeline would let us subscribe to @Published changes but
    /// the polling cost is one Int read per second and the polling
    /// loop is easier to reason about when the relevant property
    /// already lives on an actor we have to hop to anyway.
    private func startCaptivePortalStallWatcher() {
        captivePortalStallTask?.cancel()
        captivePortalLowSince = nil
        captivePortalProbeFired = false
        captivePortalVerdict = nil
        captivePortalStallTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard let self else { return }
                if Task.isCancelled { return }
                let pct = TorController.shared.bootstrapProgress
                // Mirror the live progress onto the observable
                // `torBootstrapProgress` so the multi-state pill in
                // ContactsListView redraws as bootstrap climbs. The
                // watcher is the only periodic Tor-progress reader
                // in ChatStore — running a second polling Task just
                // for the pill would be wasteful when this one is
                // already on a 1 s tick.
                self.torBootstrapProgress = pct
                // Already fired this cycle — keep the task alive in
                // case the watcher is cancelled but skip the work.
                if self.captivePortalProbeFired { continue }
                if pct >= Self.captivePortalStallProgress {
                    // Progress climbed past the threshold — clear
                    // any accumulated stall window. A subsequent
                    // regression below the threshold restarts the
                    // clock cleanly.
                    self.captivePortalLowSince = nil
                    continue
                }
                let now = Date()
                guard let since = self.captivePortalLowSince else {
                    self.captivePortalLowSince = now
                    continue
                }
                if now.timeIntervalSince(since) >= Self.captivePortalStallSeconds {
                    self.captivePortalProbeFired = true
                    pzLog("[pizzini] tor bootstrap stalled at <\(Self.captivePortalStallProgress)% for >\(Int(Self.captivePortalStallSeconds)) s — probing captive.apple.com")
                    Task { @MainActor [weak self] in
                        let verdict = await CaptivePortalProbe.run()
                        guard let self else { return }
                        self.captivePortalVerdict = verdict
                        pzLog("[pizzini] captive portal verdict: \(verdict)")
                    }
                }
            }
        }
    }

    /// Cancel the captive-portal watcher and clear its state. Called
    /// from `teardownRelay`; the next `connectRelay` starts a fresh
    /// watcher. The verdict itself is cleared too so the UI doesn't
    /// keep showing "captive portal" after the user has switched
    /// networks and reconnected.
    private func stopCaptivePortalStallWatcher() {
        captivePortalStallTask?.cancel()
        captivePortalStallTask = nil
        captivePortalLowSince = nil
        captivePortalProbeFired = false
        captivePortalVerdict = nil
    }

    /// Refresh the transparency log from the
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
                // The log just changed — re-evaluate the attestation
                // verdict against the cached relay status. The
                // STATUS_RESPONSE and the log fetch race on reconnect;
                // whichever lands second must recompute so the stored
                // enforceable signal reflects both inputs.
                if let status = self.relayStatus {
                    self.relayAttestationVerdict = self.computeAttestationVerdict(for: status)
                    pzLog("[pizzini] relay attestation verdict (post-log-refresh): \(self.relayAttestationVerdict)")
                }
            } catch let err as TransparencyLog.FetchError {
                self.transparencyLogError = err
                pzLog("[pizzini.translog] fetch failed: \(err)")
                // A failed fetch means we still cannot verify — if a
                // status is cached, downgrade the verdict accordingly
                // rather than leaving a stale `.verified` standing on
                // a log we can no longer confirm.
                if let status = self.relayStatus {
                    self.relayAttestationVerdict = self.computeAttestationVerdict(for: status)
                }
            } catch {
                self.transparencyLogError = .http(error.localizedDescription)
                pzLog("[pizzini.translog] fetch failed (unexpected): \(error)")
                if let status = self.relayStatus {
                    self.relayAttestationVerdict = self.computeAttestationVerdict(for: status)
                }
            }
        }
    }

    /// Outbox entry for `messageId`, if any. Used by the chat row to
    /// pick its status icon.
    func outboxEntry(forMessageId id: Data) -> OutboxEntry? {
        outbox.entries[id]
    }

    /// User-initiated retry of a stuck pending entry. The auto-retry
    /// walk already re-broadcasts on a `max(30, retries*60)` baseline;
    /// this entry-point exists so a user staring at a row that's been
    /// pending past `OutboxEntry.userRetryThreshold` can kick the
    /// re-broadcast without waiting for the next walker tick. Hits the
    /// same `broadcastToRelays` path as a fresh send and re-mints the
    /// v2 delivery token (the previous one is single-use and the
    /// chain has very likely advanced behind it).
    ///
    /// Plain-message path. Attachments use
    /// `userRetryAttachment(attachmentId:)` which re-emits only the
    /// chunks that never reached a relay (S2).
    @MainActor
    func userRetry(messageId: Data) {
        guard let entry = outbox.entries[messageId] else { return }
        // Already relayed / delivered / failed — nothing to retry.
        // The UI's `rowStatus` mapping won't expose a Retry button for
        // these states, but the entry-point stays defensive against a
        // race where the user tapped just as an ACK landed.
        guard entry.deliveredAt == nil,
              entry.failedAt == nil,
              entry.relayedAt == nil
        else { return }
        guard let idx = contactIndex(forIdentity: entry.recipientPeerId) else { return }
        guard relayState == .connected else { return }
        guard let v2 = mintV2DeliveryToken(forContactAt: idx) else {
            pzLog("[pizzini] user retry: chain missing / exhausted for \(short(entry.recipientPeerId))")
            return
        }
        let wire = HashChainToken.encode(v2)
        let count = broadcastToRelays {
            $0.sendSealed(
                toPeer: entry.recipientPeerId,
                sealedCiphertext: entry.sealedCiphertext,
                ttlSeconds: UInt32(entry.ttl),
                token: wire,
            )
        }
        var e = entry
        e.retries += 1
        if count > 0 {
            // Same gate as the original send path: only flip to
            // `.relayed` when bytes actually left ≥1 socket. A
            // user-initiated retry while every relay happens to be
            // mid-rotation should NOT advance the row to ✓.
            e.relayedAt = Date()
            e.token = Data() // F-505: scrub once relayed.
        }
        outbox.entries[messageId] = e
        Storage.upsertOutboxEntry(e)
    }

    /// User-initiated re-send of a TTL-expired message. A queued
    /// message that aged out behind an offline peer must NOT
    /// disappear silently — the row sits at `.expired` until the
    /// user taps Try Again. This entry-point:
    ///
    ///   1. Resolves the original chat-row text via the log lookup.
    ///   2. Drops the failed outbox entry + tombstones it from
    ///      persistent storage.
    ///   3. Calls `send(_:to:)` which mints a fresh sentAt + token
    ///      and re-encrypts under the current ratchet step.
    ///
    /// Plain text messages only — chunked attachments aren't
    /// covered (an attachment that ages out is a rare case and the
    /// user can re-attach the file from disk).
    @MainActor
    func userTryAgainExpired(messageId: Data) {
        guard let entry = outbox.entries[messageId] else { return }
        guard entry.failedAt != nil || entry.hasExpired(now: Date()) else { return }
        guard let idx = contactIndex(forIdentity: entry.recipientPeerId) else { return }
        // Recover original text from the log row. Only plain text rows
        // carry the cleartext on disk; attachment rows have `text`
        // populated with the caption only, not the file bytes.
        guard let logRow = state.contacts[idx].log.last(where: {
            $0.side == .me && $0.messageId == messageId
        }) else { return }
        guard logRow.kind != .attachment, !logRow.text.isEmpty else { return }
        let text = logRow.text
        // Drop the failed entry so the user doesn't see two indicators
        // for the same logical message. The log row stays — sending
        // re-pushes a fresh row under a fresh TTL clock.
        outbox.entries.removeValue(forKey: messageId)
        Storage.deleteOutboxEntry(messageId: messageId)
        send(text, to: state.contacts[idx])
    }

    /// User-initiated per-chunk retry for a stuck attachment. Each
    /// chunk of a chunked attachment is already its own
    /// `OutboxEntry` — the auto-retry walker covers them
    /// individually via `shouldRetry`. This entry-point exists for
    /// the user-initiated kick that bypasses the
    /// `max(30, retries*60)` baseline.
    ///
    /// Crucially: re-emits ONLY chunks where `relayedAt` is still
    /// nil — chunks that already left the socket sit in the relay's
    /// offline queue under the existing ratchet step and re-sending
    /// them would duplicate frames at the receiver + burn extra
    /// chain tokens (audit S2: per-chunk granularity, not
    /// per-message restart).
    @MainActor
    func userRetryAttachment(attachmentId: Data) {
        guard relayState == .connected else { return }
        let stuck = outbox.entries.values.filter {
            $0.attachmentId == attachmentId
                && $0.deliveredAt == nil
                && $0.failedAt == nil
                && $0.relayedAt == nil
        }
        for entry in stuck {
            userRetry(messageId: entry.messageId)
        }
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
        // Speculative HSFETCH: tell TorController about every onion
        // we're about to dial so it can fetch HS descriptors in
        // parallel with bootstrap. Each RelayClient still calls
        // `prepareHiddenService` on its own; those calls short-
        // circuit through TorController.preparedOnions once these
        // speculative fetches complete.
        TorController.shared.primeOnions(targets.map { $0.host })
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
                    // HELLO signatures are domain-separated
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
        // Re-arm the captive-portal stall watcher for this connect
        // cycle. The watcher clears any stale verdict from the
        // previous network so a portal banner left behind by an old
        // WiFi can't outlive the reconnect.
        startCaptivePortalStallWatcher()
    }

    /// Elect the push-token primary. Called whenever a relay
    /// transitions in or out of `.connected`. Picks the first ready
    /// relay (deterministic per session, since `relays` retains the
    /// `relayTargets()` order) and registers our cached APNs token
    /// against it.
    ///
    /// Every connected relay independently evaluates `maybe_send_push`
    /// on every inbound SEND for us, so the invariant is hard: at most
    /// ONE relay may ever hold our push token, or the recipient gets a
    /// duplicate APNs wake-up — and a duplicate NSE badge bump — per
    /// stale-token relay per message. The hazard case: a relay that
    /// was primary loses its connection (the DEREGISTER_PUSH cannot be
    /// sent), then later reconnects while a *different* relay is now
    /// primary. The old "DEREGISTER only the immediately-previous
    /// primary, only when the primary changes" rule never cleaned that
    /// relay up — its reconnect does not change `pushPrimary` — so its
    /// stale token lingered until the relay-side 30-day TTL purge: N
    /// duplicate pushes per message for up to a month.
    ///
    /// So this runs unconditionally on every call, *before* the
    /// early-return, and DEREGISTERs every relay that is not the
    /// elected primary — connected or not. `deregisterPush` clears the
    /// per-client cached intent (`pushToken`) even while offline, so a
    /// reconnecting ex-primary does not re-register itself, and sends
    /// the wire DEREGISTER to any relay that is connected. It is
    /// idempotent and a no-op on a relay that holds nothing.
    private func electPushPrimary() {
        let firstReady = readyRelays.first
        // Enforce "at most one relay holds our token" on every call.
        // A non-primary relay reconnecting does not change
        // `pushPrimary`, so this must run before the early-return
        // below or a reconnected ex-primary is never cleaned up.
        for relay in relays where relay !== firstReady {
            relay.deregisterPush()
        }
        guard firstReady !== pushPrimary else { return }
        pushPrimary = firstReady
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
    /// are alive. The actual aggregation lives in
    /// `Self.aggregateRelayState(states:)` so tests can pin the
    /// "N-1 of N healthy stays .connected" invariant without spinning
    /// up a ChatStore + RelayClient fleet.
    private func aggregateRelayState() -> RelayClient.State {
        Self.aggregateRelayState(states: relays.map { $0.state })
    }

    /// Pure aggregation: same rules as `aggregateRelayState()` but
    /// operates on a plain `[RelayClient.State]` snapshot so it can
    /// be exercised in unit tests. `public nonisolated` so the iOS
    /// app's test target can pin the N-1-of-N invariant — this is
    /// the only load-bearing behaviour of multi-relay fanout from
    /// the user's perspective.
    public nonisolated static func aggregateRelayState(
        states: [RelayClient.State],
    ) -> RelayClient.State {
        guard !states.isEmpty else { return .idle }
        if states.contains(where: { $0 == .connected }) {
            return .connected
        }
        let torProgresses: [Int] = states.compactMap { s in
            if case let .connectingToTor(p) = s { return p }
            return nil
        }
        if let p = torProgresses.max() {
            return .connectingToTor(progress: p)
        }
        if states.contains(where: { $0 == .connecting }) {
            return .connecting
        }
        let failures: [String] = states.compactMap { s in
            if case let .failed(msg) = s { return msg }
            return nil
        }
        if failures.count == states.count, let first = failures.first {
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

    /// Schedule the next silent retry of a single failed relay.
    /// Called from the per-relay state-change handler when a relay
    /// hits `.failed` and the aggregate fleet is still serving
    /// traffic. The task re-dials the same descriptor after the
    /// computed backoff; on success the relay's `.connected` event
    /// clears the per-relay backoff and the dead route is silently
    /// back in the fanout set. Aggregate-`.failed` retries are
    /// handled separately by `handleAggregateRelayStateTransition`
    /// and use the louder, user-visible reconnect-or-give-up loop.
    private func scheduleSilentPerRelayRetry(host: String) {
        // Cancel any in-flight retry task for this host — a new
        // `.failed` event supersedes the previous one's pending tick.
        perRelayRetryTasks[host]?.cancel()
        let current = perRelayBackoff[host] ?? Self.perRelayBackoffFloor
        let decision = Self.computePerRelayRetryDecision(currentBackoff: current)
        perRelayBackoff[host] = decision.nextBackoff
        pzLog("[pizzini] silent per-relay retry for \(host.prefix(8))… in \(Int(decision.delaySeconds)) s (next backoff \(Int(decision.nextBackoff)) s)")
        perRelayRetryTasks[host] = Task { @MainActor [weak self] in
            let nanos = UInt64(decision.delaySeconds * 1_000_000_000)
            try? await Task.sleep(nanoseconds: nanos)
            guard let self else { return }
            if Task.isCancelled { return }
            // Recheck — the relay or the whole fleet may have been
            // torn down or already reconnected between schedule and
            // fire. Look up the live RelayClient + descriptor by
            // host so a fleet rebuild between schedule and fire
            // doesn't hit a stale pointer.
            guard let idx = self.relayDescriptors.firstIndex(where: { $0.host == host }),
                  idx < self.relays.count
            else { return }
            let client = self.relays[idx]
            // If this client is already connected (or actively
            // re-dialing), don't punch it back into a fresh dial
            // and reset its in-progress connect.
            if case .connected = client.state { return }
            if case .connecting = client.state { return }
            if case .connectingToTor = client.state { return }
            let descriptor = self.relayDescriptors[idx]
            pzLog("[pizzini] silent retry firing for \(host.prefix(8))…")
            client.connect(to: descriptor.host, port: descriptor.port)
        }
    }

    /// Cancel and clear a single host's pending retry. Called when
    /// the host crosses back into `.connected` (the dead route is
    /// alive again — drop the backoff state so the NEXT outage starts
    /// fresh from the floor) and from `teardownRelay`.
    private func clearPerRelayRetry(host: String) {
        perRelayRetryTasks[host]?.cancel()
        perRelayRetryTasks.removeValue(forKey: host)
        perRelayBackoff.removeValue(forKey: host)
    }

    /// Hard cap on the user-visible aggregated failure string. See
    /// `aggregateRelayState`. Public-on-the-class for tests.
    nonisolated static let maxAggregatedFailureLength: Int = 240
    nonisolated static func boundedFailureString(_ s: String) -> String {
        if s.count <= maxAggregatedFailureLength { return s }
        let head = s.prefix(maxAggregatedFailureLength - 1)
        return "\(head)…"
    }

    /// Coarse health snapshot of a single relay, as seen by the
    /// pill state machine. Strips the failure-string detail so the
    /// pill function stays pure-data and Equatable for tests.
    public nonisolated enum RelayHealth: Equatable, Sendable {
        case bootstrapping(progress: Int)
        case connecting
        case connected
        case failed
        case idle

        /// Project a full `RelayClient.State` down to the coarse
        /// pill input. The failure-message string is dropped — the
        /// pill renders one fleet-level label, not per-relay error
        /// detail.
        public init(_ state: RelayClient.State) {
            switch state {
            case .connectingToTor(let p): self = .bootstrapping(progress: p)
            case .connecting:             self = .connecting
            case .connected:              self = .connected
            case .failed:                 self = .failed
            case .idle:                   self = .idle
            }
        }
    }

    /// Multi-state connection pill. Driven by a pure derivation
    /// function so every branch can be unit-pinned without spinning
    /// up a ChatStore + a Tor instance. The pill is the user's only
    /// continuous signal of whether Pizzini can send and receive,
    /// and the load-bearing copy bug (`version = "0.0.0"`) escaped
    /// for months because nothing pinned the rendered string. Each
    /// case maps 1:1 to a tint colour and a piece of copy; the
    /// derivation is pure on top of two inputs (Tor bootstrap
    /// percent + the coarse relay-health array).
    public enum PillState: Equatable, Sendable {
        /// Tor's bootstrap is still in flight. `progress` is the
        /// latest BOOTSTRAP STATUS_CLIENT integer, 0–100.
        case bootstrappingTor(progress: Int)
        /// Tor is up. SOCKS dials to the .onion fleet are in flight
        /// and zero relays have reached `.connected` yet.
        case connectingRelays(connected: Int, total: Int)
        /// Every relay in the fleet is `.connected`. Auto-hides
        /// after a 2-second grace so the pill confirms "we made it"
        /// before disappearing.
        case connected
        /// At least one relay is `.connected` and at least one is
        /// NOT — the fleet has degraded redundancy but the user
        /// has working send/receive. Surface so the user knows
        /// retries are happening; the silent per-relay retry will
        /// flip back to `.connected` on its own once the dead route
        /// recovers.
        case partial(connected: Int, total: Int)
        /// Every relay failed. The user can tap to re-dial; auto-
        /// reconnect is also in flight in the background, but the
        /// pill becomes a tap target so the user isn't stuck
        /// waiting if they want to retry now.
        case failed
        /// Pre-connection: fleet built, no relay has started
        /// dialing yet. Brief — the next state transition is
        /// usually `.bootstrappingTor` within a frame or two.
        case idle

        /// Visual tint bucket. The capsule background renders one
        /// of three colours so the user can read the pill at a
        /// glance even without parsing the label. Grey = working
        /// on it (pre-network); amber = working on it (network
        /// reachable, dialing); green = healthy; red = the user
        /// needs to act.
        public enum Tint: Equatable, Sendable {
            case grey
            case amber
            case green
            case red
        }

        public var tint: Tint {
            switch self {
            case .bootstrappingTor, .idle:        return .grey
            case .connectingRelays, .partial:     return .amber
            case .connected:                      return .green
            case .failed:                         return .red
            }
        }

        /// User-facing label for this state. Strings are pinned in
        /// `PillStateLabelTests`; a copy edit must update the test
        /// at the same time.
        public var label: String {
            switch self {
            case .bootstrappingTor(let p):
                return p > 0 ? "Connecting to Tor \(p)%" : "Connecting to Tor"
            case .connectingRelays(_, let total):
                // Mid-dial: `connected` is always 0 here (the
                // derivation guarantees it — once any relay is
                // `.connected`, the state is `.connected` or
                // `.partial`, never `.connectingRelays`). Parens
                // disambiguate the count from a generic mid-loading
                // "0 of N" string.
                return "Connecting to relays (0/\(total))"
            case .connected:
                return "Connected"
            case .partial(let connected, let total):
                return "\(connected)/\(total) relays online"
            case .failed:
                return "Couldn't connect — tap to retry"
            case .idle:
                return "Starting"
            }
        }

        /// True when tapping the pill should kick a manual
        /// reconnect. Only `.failed` is tap-actionable — the other
        /// states are self-resolving and a tap would just thrash
        /// the in-flight dial.
        public var isTappable: Bool {
            if case .failed = self { return true }
            return false
        }
    }

    /// Pure derivation of the pill state from the two raw inputs:
    /// Tor's bootstrap percent and the coarse per-relay health
    /// array. The relay-state aggregation is part of this function
    /// so the pill never disagrees with the underlying fleet (a
    /// subtle bug class: aggregator says `.connected` but pill
    /// says `.partial` because they were computed from different
    /// snapshots).
    ///
    /// Order of evaluation:
    ///   1. If bootstrap < 100 AND no relay has yet reached
    ///      `.connected`, we're in the bootstrap phase.
    ///      `.bootstrappingTor`.
    ///   2. Otherwise, count connected vs total:
    ///      • 0 / N with N > 0 and any non-failed → connectingRelays
    ///      • all N failed → failed
    ///      • all N connected → connected
    ///      • 1..<N connected → partial
    ///   3. Empty fleet → idle (the brief teardown→connectRelay
    ///      window has zero relays).
    public nonisolated static func pillState(
        bootstrap: Int,
        relays: [RelayHealth],
    ) -> PillState {
        let total = relays.count
        let connected = relays.filter { $0 == .connected }.count
        let failed = relays.filter { $0 == .failed }.count
        // Bootstrap phase: tor isn't ready yet AND nothing is up.
        // Once at least one relay reaches `.connected`, we leave
        // the bootstrap branch even if the percent is still <100
        // (which can happen briefly on a warm reconnect).
        if bootstrap < 100, connected == 0 {
            // Only show the bootstrap pill while at least one
            // relay is actively in the bootstrap phase (or we
            // haven't started dialing yet). If the fleet is
            // entirely `.failed` we want the failed pill, not
            // a stuck-at-N% bootstrap label.
            if total == 0 || failed < total {
                return .bootstrappingTor(progress: bootstrap)
            }
        }
        if total == 0 {
            return .idle
        }
        if failed == total {
            return .failed
        }
        if connected == 0 {
            // Tor is up (or close to it) but no SOCKS handshake
            // has completed yet.
            return .connectingRelays(connected: 0, total: total)
        }
        if connected == total {
            return .connected
        }
        return .partial(connected: connected, total: total)
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
            // A `.connected` aggregate means at least one relay
            // ack'd our HELLO. This is the only place where the
            // backoff + streak should reset — a flaky relay
            // bouncing us through `.failed → .connecting → .failed`
            // without ever reaching `.connected` should keep
            // draining the streak so the user eventually sees the
            // Reconnect button.
            autoReconnectTask?.cancel()
            autoReconnectTask = nil
            autoReconnectBackoff = Self.autoReconnectBackoffFloor
            autoReconnectFailureStreak = 0
            manualReconnectRequired = false
        case .failed:
            // Already failed previously? Don't double-arm — there's
            // already a task in flight. (The existing task will
            // re-fire connectRelay on its own deadline.)
            if case .failed = prev { return }
            let decision = Self.computeAutoReconnectDecision(
                previousStreak: autoReconnectFailureStreak,
                currentBackoff: autoReconnectBackoff,
            )
            autoReconnectFailureStreak = decision.newStreak
            switch decision.action {
            case .requireManual:
                pzLog("[pizzini] aggregate state .failed; auto-reconnect cap reached (\(self.autoReconnectFailureStreak)/\(Self.autoReconnectMaxConsecutiveFailures)) — surfacing Reconnect button")
                manualReconnectRequired = true
                autoReconnectTask?.cancel()
                autoReconnectTask = nil
            case let .scheduleRetry(delay, nextBackoff):
                pzLog("[pizzini] aggregate state .failed; auto-reconnecting in \(Int(delay)) s (attempt \(self.autoReconnectFailureStreak)/\(Self.autoReconnectMaxConsecutiveFailures))")
                autoReconnectBackoff = nextBackoff
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
    /// Acts on every state EXCEPT `.connected` (where there's
    /// nothing to retry). A user tapping "Reconnect now" while
    /// the state is `.connecting` / `.connectingToTor` / `.idle`
    /// means an in-flight bootstrap is taking too long — the
    /// user explicitly asked for a fresh attempt; dropping it
    /// and redialing is exactly what they want. Prior version
    /// silently no-op'd on those states, surfacing as "I tap the
    /// button and nothing happens" (real-device report
    /// 2026-05-14: connecting hung ~2 min, tapping Reconnect did
    /// nothing).
    func forceReconnectRelays() {
        switch relayState {
        case .connected:
            pzLog("[pizzini] reconnect requested but already connected; ignoring")
        case .failed, .connecting, .connectingToTor, .idle:
            pzLog("[pizzini] manual reconnect requested (was \(relayState))")
            // Reset auto-reconnect backoff AND the consecutive-
            // failure streak: the user's explicit intervention is a
            // fresh slate. Without resetting the streak, hitting
            // Reconnect when `manualReconnectRequired == true`
            // would just spin once and re-surface the button.
            autoReconnectBackoff = Self.autoReconnectBackoffFloor
            autoReconnectFailureStreak = 0
            manualReconnectRequired = false
            connectRelay()
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
        // Cancel every pending per-relay silent retry; the fresh
        // fleet about to be built (or the identity wipe) makes
        // their captured host references stale.
        for task in perRelayRetryTasks.values {
            task.cancel()
        }
        perRelayRetryTasks.removeAll()
        perRelayBackoff.removeAll()
        // Tear down the captive-portal watcher and clear any stale
        // verdict — a banner from the previous network must not
        // outlive the reconnect.
        stopCaptivePortalStallWatcher()
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
        // Reconcile the app-icon badge with the authoritative
        // `state.totalUnread` on every foreground. While we were
        // backgrounded the NSE may have inflated the badge (every
        // push it processes is a +1), but the main app's stored
        // state is the truth — re-asserting it here means a fresh
        // glance at the home screen + the in-app contact rows show
        // the same number.
        refreshAppBadge()
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
        // Probe the embedded tor for hung-libevent / stale-circuit
        // state BEFORE redialing. If iOS suspended us for more than
        // a few minutes, tor's runloop is alive but its socket
        // handles return stale errors; probeAndRecover surfaces
        // that by `GETINFO status/bootstrap-phase` with a 2 s
        // deadline and forces SIGNAL RELOAD if the daemon is slow
        // or degraded. Async-fire-and-redial: the connectRelay
        // call inside the Task fires AFTER probeAndRecover settles,
        // so the redial picks up freshly-rotated guards.
        pzLog("[pizzini] relay reconnect on foreground")
        Task { @MainActor [weak self] in
            await TorController.shared.probeAndRecover()
            self?.connectRelay()
        }
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
    ///: even if every iteration uses a fresh peer-id,
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
    /// Pacing budget for the real BUNDLE_RESPONSE + chainSeedDelivery
    /// path on a modern phone — kyber1024 keygen + one sealed-sender
    /// envelope encrypt runs ~1s in steady state. Decoy waits within
    /// this window before emitting so the relay can't time-distinguish
    /// "Y is in Alice's contacts" from "Y is not". 50ms jitter prevents
    /// a learned-fixed-1s signature.
    private static let decoyEmitDelay: ClosedRange<Duration> = .milliseconds(900) ... .milliseconds(1100)

    @MainActor
    private func emitBundleResponseDecoy(toFakePeer fromPeer: Data, via client: RelayClient) {
        // Cooldown — TWO gates, both required to ship a decoy:
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
            // `mintV2DeliveryToken` already advanced + persisted the
            // chain cursor before this call. The encrypt failed, so
            // no frame carrying `v2Token.index` will reach the relay
            // layer — roll the cursor back so a transient failure
            // doesn't permanently burn a chain index and pull
            // rotation / exhaustion forward.
            rollbackV2DeliveryToken(forContactAt: idx, mintedIndex: v2Token.index)
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
        // Fail-closed: `encryptSealed` advanced the ratchet. If that
        // advance is not durably committed, the sealed bytes must NOT
        // reach the wire — a later cold launch would rehydrate from a
        // stale snapshot behind the wire state. Abort the broadcast
        // and mark the row failed (a terminal state — `shouldRetry`
        // returns false for it): the ciphertext was produced from
        // ratchet state that will not survive a relaunch, so it can
        // never be safely re-broadcast. Recovery is a fresh user-
        // initiated send, which re-encrypts from scratch once the
        // session persists cleanly again.
        guard persistSession() else {
            entry.failedAt = now
            outbox.entries[messageId] = entry
            Storage.upsertOutboxEntry(entry)
            appendSystem(
                "Couldn't save secure state — message not sent. Send it again.",
                to: idx,
            )
            diagLog(
                "send",
                "v2 SEND → \(short(contact.identityPub)) ABORTED — session persist failed; "
                + "msgid=\(hex(messageId)) queued failed (no ciphertext on wire)"
            )
            return
        }
        let readyCount = readyRelays.count
        // AUDIT-DECISION-NEEDED: the SAME `wireToken` (chain_id, index,
        // value) is broadcast to every relay in the fanout. A v2
        // delivery token is a pure bearer credential — the relay's
        // `check_delivery_token` authenticates it against the
        // recipient's chain state with no binding to the submitting
        // connection. So a malicious relay in the fleet can replay an
        // observed token to the sibling relays: the first acceptance
        // advances `last_index`, and the sender's genuine fan-out copy
        // then loses to `OutOfRange` on those siblings — a silent
        // message-suppression / censorship primitive against the
        // exact adversary the multi-relay fanout exists to neutralise.
        // The fix is a wire-protocol change (per-relay token minting,
        // or binding token presentation to the HELLO-authenticated
        // connection, or a per-relay chain namespace) and needs
        // design sign-off before it can land — `from_id` binding is
        // not available because SEND is sealed-sender. Left as the
        // current broadcast pending that decision.
        broadcastToRelays {
            $0.sendSealed(
                toPeer: contact.identityPub,
                sealedCiphertext: sealed,
                ttlSeconds: ttl,
                token: wireToken,
            )
        }
        diagLog(
            "send",
            "v2 SEND → \(short(contact.identityPub)) "
            + "msgid=\(hex(messageId)) sealed=\(sealed.count)B ttl=\(ttl)s "
            + "fanout=\(readyCount)"
        )
        // `relayedAt` must mean "handed to at least one connected
        // relay," not merely "a send was attempted" — `broadcastToRelays`
        // is fire-and-forget and returns the count it actually reached.
        // With zero ready relays the SEND went nowhere: leaving
        // `relayedAt` nil keeps the UI honest (no false ✓ for bytes that
        // never left the device) and the entry on the "never relayed"
        // retry path. The token blob is scrubbed (F-505) only in the
        // same branch — an un-relayed entry keeps its un-relayed shape.
        if readyCount > 0 {
            entry.relayedAt = now
            // F-505 parity with v1: scrub the token blob once relayed.
            entry.token = Data()
        }
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
        // Audit M1: if the chain just crossed the rotation threshold,
        // ask the peer (chain owner) to mint a fresh one over the
        // sealed `chainRefreshRequest` channel. Debounced per-contact
        // so a burst of sends at the threshold doesn't fan into a
        // burst of requests; recipient's 30 min cooldown is the
        // hard rate limit on the receive side.
        maybeRequestProactiveChainRotation(forContactAt: idx)
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
                    self?.appendSystem("Couldn't read \(safeName). Try sending it again.", to: idx)
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
                    self?.appendSystem("Couldn't process \(safeName) before sending. Try a different file.", to: idx)
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
                // Fail-closed: encryptSealed advanced the ratchet. If
                // the advance is not durably committed, this chunk's
                // ciphertext must not reach the wire. Mark the chunk's
                // outbox row failed (terminal) and abort the rest of
                // the attachment — ciphertext produced from ratchet
                // state that will not survive a relaunch can never be
                // safely re-broadcast, so recovery is a fresh user-
                // initiated re-send of the attachment, which
                // re-encrypts every chunk afresh.
                guard persistSession() else {
                    entry.failedAt = now
                    outbox.entries[messageId] = entry
                    Storage.upsertOutboxEntry(entry)
                    appendSystem(
                        "Couldn't save secure state at chunk \(i)/\(chunks.count) — "
                        + "attachment not sent. Send it again.",
                        to: idx,
                    )
                    return
                }
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
        // Audit M1: attachments burn chain tokens fast (one per
        // chunk; a 10 MB file is ~160 chunks). Same proactive trigger
        // as the text-send path, same per-contact debounce.
        maybeRequestProactiveChainRotation(forContactAt: idx)
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

    /// Audit M1: sender-side debounce for proactive chain rotation.
    /// Last time we asked a given peer to mint a fresh chain. Reset
    /// across process restarts — a duplicate request after a relaunch
    /// is harmless because the recipient's `chainRefreshCooldown`
    /// (30 min) collapses it.
    @MainActor
    private var chainRotationLastRequestedAt: [UUID: Date] = [:]

    /// Sender-side cooldown between proactive chain-rotation requests
    /// for the same contact. 1 h is much shorter than the natural
    /// rotation cadence (~13 000 tokens / direction = months at
    /// typical volume) so a legit rotation never hits this cap, and
    /// comfortably longer than any reconnect storm.
    private static let chainRotationRequestCooldown: TimeInterval = 60 * 60

    /// Audit M1: fire a sealed `chainRefreshRequest` envelope iff the
    /// contact's outbound chain has crossed the rotation threshold
    /// AND we haven't requested a rotation for them in the last hour.
    /// Replaces the prior log-only handling at the two `shouldRotate`
    /// observation sites; closes the audit M1 follow-up properly
    /// without the cooldown-deadlock the reverted commit 62dcc54
    /// introduced — that one fired BUNDLE_REQUEST and tripped the
    /// recipient's 6 h `chainServeCooldown`. The chain-refresh path
    /// uses a separate 30 min cooldown on the recipient side.
    @MainActor
    private func maybeRequestProactiveChainRotation(forContactAt idx: Int) {
        guard let chain = state.contacts[idx].outboundTokenChain,
              chain.shouldRotate else { return }
        let contact = state.contacts[idx]
        let now = Date()
        if let last = chainRotationLastRequestedAt[contact.id],
           now.timeIntervalSince(last) < Self.chainRotationRequestCooldown {
            return
        }
        guard let session,
              let client = readyRelays.first else { return }
        let sent = sendChainRefreshRequest(toPeer: contact.identityPub, via: client, session: session)
        guard sent else { return }
        chainRotationLastRequestedAt[contact.id] = now
        pzLog(
            "[pizzini] v2 chain at rotation threshold (\(chain.nextIndex - 1)/\(chain.length)) — "
            + "sent chainRefreshRequest to \(self.short(contact.identityPub))"
        )
    }

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
            diagLog(
                "send",
                "refresh-queue FULL for \(short(contact.identityPub)) — dropping send "
                + "(queue=\(queue.count)/\(Self.maxPendingV2SendsPerContact))"
            )
            appendSystem(
                "Too many messages queued while reconnecting. Try again later.",
                to: idx,
            )
            return
        }
        pendingV2Sends[contact.id, default: []].append(text)
        diagLog(
            "send",
            "send for \(short(contact.identityPub)) queued behind chain refresh "
            + "(queue depth now \(queue.count + 1)); firing BUNDLE_REQUEST"
        )
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
        let peer = state.contacts[idx].identityPub
        guard var chain = state.contacts[idx].outboundTokenChain else {
            diagLog("send", "NO CHAIN for \(short(peer)) — mintV2DeliveryToken returns nil; refreshChainAndQueue will fire")
            return nil
        }
        guard let token = HashChainToken.nextToken(in: &chain) else {
            diagLog("send", "CHAIN EXHAUSTED for \(short(peer)) (length=\(chain.length), nextIndex=\(chain.nextIndex)) — refreshChainAndQueue will fire")
            return nil
        }
        let remaining = chain.length - (chain.nextIndex - 1)
        state.contacts[idx].outboundTokenChain = chain
        Storage.upsertContact(state.contacts[idx])
        diagLog(
            "send",
            "minted v2 token idx=\(token.index) for \(short(peer)) "
            + "(chain remaining \(remaining)/\(chain.length))"
        )
        return token
    }

    /// Roll the contact's outbound-chain cursor back by one and
    /// re-persist. Called on the encrypt-failure path AFTER a
    /// `mintV2DeliveryToken` advanced the cursor but the frame that
    /// would have carried that index was never handed to the relay
    /// layer. Without this, every transient `encryptSealed` failure
    /// permanently shortens the chain by one and brings `shouldRotate`
    /// / exhaustion forward. Invariant: a chain index is consumed iff
    /// a frame carrying it actually reached the wire path.
    ///
    /// Only rolls back if the chain still looks exactly like the one
    /// the token was minted from (`nextIndex == mintedIndex + 1`, i.e.
    /// no other mint advanced the cursor in between) — a defensive
    /// no-op otherwise.
    @MainActor
    private func rollbackV2DeliveryToken(forContactAt idx: Int, mintedIndex: Int) {
        guard idx >= 0, idx < state.contacts.count,
              var chain = state.contacts[idx].outboundTokenChain,
              chain.nextIndex == mintedIndex + 1 else {
            return
        }
        chain.nextIndex = mintedIndex
        state.contacts[idx].outboundTokenChain = chain
        Storage.upsertContact(state.contacts[idx])
        diagLog(
            "send",
            "rolled back v2 token idx=\(mintedIndex) for "
            + "\(short(state.contacts[idx].identityPub)) — encrypt failed, index not consumed"
        )
    }

    /// Audit M1: recipient side. Sender's outbound chain to us hit
    /// the 80 % `shouldRotate` threshold and they've asked us to
    /// mint + ship a fresh one. Identical to the
    /// `BUNDLE_REQUEST → publishBundle + serveChain` path but
    /// shorter cooldown (30 min) because we skip the kyber1024
    /// prekey burn entirely — this path mints a chain only.
    @MainActor
    private func handleChainRefreshRequest(
        fromPeer peer: Data,
        contactIdx idx: Int,
        via client: RelayClient,
        session: Session
    ) {
        diagLog(
            "chain",
            "chainRefreshRequest from \(short(peer)) — "
            + "serveChain(cooldown=\(Int(Contact.chainRefreshCooldown))s)"
        )
        serveChain(
            forPeer: peer,
            via: client,
            session: session,
            cooldown: Contact.chainRefreshCooldown,
        )
        _ = idx
    }

    /// Handle a sealed `chainSeedDelivery` payload. The peer (who minted
    /// the chain and registered the root with the relay) has shipped us
    /// the seed for our outbound v2 token chain to them. Install or
    /// replace `Contact.outboundTokenChain`; the next SEND will derive
    /// tokens from this chain instead of popping from the v1 stash.
    @MainActor
    private func handleChainSeedDelivery(payload: Data, contactIdx idx: Int) {
        let peer = state.contacts[idx].identityPub
        guard let chain = HashChainToken.decodeSeedDelivery(payload) else {
            diagLog("chain", "chainSeedDelivery MALFORMED payload from \(short(peer)) (payload=\(payload.count)B)")
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
        let pendingCount = pendingV2Sends[state.contacts[idx].id]?.count ?? 0
        diagLog(
            "chain",
            "chainSeedDelivery INSTALLED for \(short(peer)) "
            + "chainID=\(hex(chain.chainID)) length=\(chain.length) "
            + "rotation=\(priorChainID != nil) drain=\(pendingCount)"
        )
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
    /// Returns true iff the seed was successfully encrypted and shipped.
    /// Caller uses the boolean to drive `lastChainServedAt` so a
    /// failed serve does not engage the chain-serve cooldown — without
    /// that, the very first attempt (typically before a libsignal
    /// session to the peer exists) would burn the cooldown window and
    /// every later retry would silently rate-limit.
    /// Audit M1: sender side. Encrypt + ship a sealed
    /// `chainRefreshRequest` envelope to the peer who owns (minted)
    /// our outbound chain. Burns ONE token from the chain we're
    /// asking to rotate — we have ~20 % of the chain left at the
    /// `shouldRotate` threshold, so plenty of headroom for the
    /// request itself plus normal sends while waiting for the
    /// reply.
    ///
    /// Returns true if the request was encrypted and queued for
    /// broadcast. False if there's no chain to derive a token from
    /// (already exhausted — fall back to the heavier reactive path
    /// in `refreshChainAndQueue`) or if encryption failed (no
    /// session yet, etc.).
    @discardableResult
    private func sendChainRefreshRequest(toPeer peer: Data, via client: RelayClient, session: Session) -> Bool {
        guard let idx = contactIndex(forIdentity: peer) else { return false }
        guard let v2Token = mintV2DeliveryToken(forContactAt: idx) else {
            // No chain → no token. The reactive
            // `refreshChainAndQueue` path covers exhaustion; we
            // don't double-fire here.
            return false
        }
        let messageId = Self.makeMessageId()
        let inner = Data([RelayClient.InnerEnvelopeKind.chainRefreshRequest.rawValue])
        let sealed: Data
        do {
            sealed = try session.encryptSealed(
                peer: peer,
                messageId: messageId,
                plaintext: inner,
            )
        } catch {
            pzLog("[pizzini] chainRefreshRequest encrypt failed: \(error)")
            return false
        }
        // Fail-closed: the ratchet advanced in `encryptSealed`; if the
        // advance is not durably committed, the sealed bytes must not
        // reach the wire. Return false (no broadcast) — the caller
        // treats that the same as an encrypt failure and the reactive
        // refresh path retries later.
        guard persistSession() else {
            pzLog("[pizzini] chainRefreshRequest ABORTED — session persist failed; no ciphertext on wire")
            return false
        }
        let wireToken = HashChainToken.encode(v2Token)
        broadcastToRelays {
            $0.sendSealed(
                toPeer: peer,
                sealedCiphertext: sealed,
                ttlSeconds: UInt32(Contact.chainRefreshCooldown),
                token: wireToken,
            )
        }
        _ = client
        return true
    }

    @discardableResult
    private func sendChainSeedDelivery(toPeer peer: Data, via client: RelayClient, session: Session) -> Bool {
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
        // 2. Ship the seed via the dedicated `FRAME_TYPE_CHAIN_SEED_DELIVERY`
        //    wire frame — NOT a sealed SEND. The first chain seed in a
        //    pair predates any chain on the wire, so there's no v2
        //    delivery token to derive; a SEND with empty token is
        //    correctly rejected by the relay's `check_delivery_token`.
        //    The chain-seed frame skips the token gate and is rate-
        //    limited per-(sender, recipient) at the relay instead.
        //    The inner sealed envelope still carries the
        //    `chainSeedDelivery` inner kind; the recipient verifies
        //    this and the contact-gate before installing the chain.
        var inner = Data([RelayClient.InnerEnvelopeKind.chainSeedDelivery.rawValue])
        inner.append(HashChainToken.encodeSeedDelivery(chain))
        do {
            let sealed = try session.encryptSealed(
                peer: peer,
                messageId: Self.makeMessageId(),
                plaintext: inner,
            )
            // Fail-closed: the ratchet advanced in `encryptSealed`. If
            // the advance is not durably committed, the sealed frame
            // must not reach the wire — return false so the caller
            // treats it like an encrypt failure and the retry path
            // re-serves the chain once Keychain writes recover. The
            // `sendRegisterChain` broadcast above is harmless to leave
            // standing (it carries no ratchet state — it just
            // registers a root the relay will accept later).
            guard persistSession() else {
                diagLog(
                    "chain",
                    "chainSeedDelivery → \(short(peer)) ABORTED — session persist failed; "
                    + "no ciphertext on wire"
                )
                _ = client
                return false
            }
            let fanout = readyRelays.count
            broadcastToRelays {
                $0.sendChainSeedFrame(toPeer: peer, sealedCiphertext: sealed)
            }
            diagLog(
                "chain",
                "shipped chainSeedDelivery → \(short(peer)) "
                + "chainID=\(hex(chain.chainID)) length=\(chain.length) "
                + "sealed=\(sealed.count)B fanout=\(fanout)"
            )
            _ = client
            return true
        } catch {
            // Almost always "no session yet" — happens when peer asked
            // for our bundle before we'd processed theirs. Don't burn
            // the cooldown; the retry in `maybeServePendingChain` will
            // fire as soon as session establishes.
            pzLog("[pizzini] chainSeedDelivery encrypt failed: \(error) — will retry when session lands")
            _ = client
            return false
        }
    }

    /// Mint a fresh outbound chain for `peer` and ship the seed over
    /// the sealed Double Ratchet. Called right after we serve their
    /// bundle (the bundle-coupled path passes `cooldown:
    /// Contact.chainServeCooldown` = 6 h) and from the audit-M1
    /// proactive-refresh path (which passes `cooldown:
    /// Contact.chainRefreshCooldown` = 30 min). The two paths share
    /// the same `lastChainServedAt` stamp but enforce different
    /// cooldown windows, so a paired peer can request proactive
    /// rotation roughly every 30 min while bundle-coupled
    /// re-publishes remain capped at every 6 h.
    private func serveChain(
        forPeer peer: Data,
        via relay: RelayClient,
        session: Session,
        cooldown: TimeInterval = Contact.chainServeCooldown,
    ) {
        guard let idx = contactIndex(forIdentity: peer) else { return }
        if let last = state.contacts[idx].lastChainServedAt,
           Date().timeIntervalSince(last) < cooldown {
            pzLog(
                "[pizzini] chain serve rate-limited for \(self.short(peer)) "
                + "(cooldown=\(Int(cooldown))s)"
            )
            return
        }
        // sealed_sender encryptSealed needs a libsignal session with the
        // peer — i.e. we must have processed their bundle. The typical
        // asymmetric pairing has peer's BUNDLE_REQUEST arriving BEFORE
        // we've fetched their bundle, so the first call here finds
        // sessionEstablished=false and must defer. The bundle-response
        // handler (and any other path that flips sessionEstablished)
        // calls `maybeServePendingChain` to drain.
        guard state.contacts[idx].sessionEstablished else {
            pzLog("[pizzini] chain serve deferred for \(self.short(peer)) — no session yet")
            return
        }
        let ok = sendChainSeedDelivery(toPeer: peer, via: relay, session: session)
        guard ok else {
            diagLog("chain", "serveChain failed (sendChainSeedDelivery returned false) for \(short(peer))")
            return
        }
        diagLog(
            "chain",
            "serveChain shipped for \(short(peer)) "
            + "(cooldown=\(Int(cooldown))s)"
        )
        // Only stamp on success so a failed serve doesn't engage the
        // cooldown — otherwise the very first deferred attempt would
        // win the cooldown window even though no chain was shipped.
        state.contacts[idx].lastChainServedAt = Date()
        Storage.upsertContact(state.contacts[idx])
    }

    /// Drain the "owe peer a chain seed but couldn't ship yet" state.
    /// Called from every path that flips `sessionEstablished` to true.
    /// The signal that peer is owed a chain is "we served them a
    /// bundle but never successfully shipped a chain after it" —
    /// `lastBundleServedAt != nil && lastChainServedAt == nil`.
    @MainActor
    private func maybeServePendingChain(forContactAt idx: Int) {
        guard let session else { return }
        guard idx >= 0, idx < state.contacts.count else { return }
        let contact = state.contacts[idx]
        guard contact.sessionEstablished else { return }
        guard contact.lastBundleServedAt != nil, contact.lastChainServedAt == nil else { return }
        // Pick any connected relay for the `via` parameter; serveChain's
        // sealed envelope fans out via `broadcastToRelays` so the
        // specific client passed in is informational only.
        guard let anyRelay = readyRelays.first else { return }
        pzLog("[pizzini] retrying deferred chain serve for \(self.short(contact.identityPub))")
        serveChain(forPeer: contact.identityPub, via: anyRelay, session: session)
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
    /// path — every inbound BUNDLE_RESPONSE / chainSeedDelivery /
    /// SEND passes through this gate.
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
            // Fail-closed: the ratchet advanced in `encryptSealed`. If
            // the advance is not durably committed, do NOT put the
            // receipt on the wire — a cold launch would rehydrate
            // behind the wire state. Read receipts are not in the
            // retry walk, so the recovery is the next mark-read after
            // Keychain writes recover (it ships a fresh receipt
            // covering the same-or-newer highestMessageId).
            guard persistSession() else {
                pzLog("[pizzini] read-receipt ABORTED — session persist failed; no ciphertext on wire")
                return
            }
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
    /// 1:1 chats are the more frequently-opened surface and a long
    /// groups section pushed them off the first viewport.
    func setContactsBeforeGroups(_ enabled: Bool) {
        guard state.contactsBeforeGroups != enabled else { return }
        state.contactsBeforeGroups = enabled
        Storage.upsertSettings(state)
    }

    /// Override the app's light/dark appearance. `.system` follows the
    /// OS toggle; `.light` / `.dark` pin the appearance regardless.
    /// Persisted under `AppState.appearanceMode` and applied by
    /// `ContentView` via `.preferredColorScheme(_:)`.
    func setAppearanceMode(_ mode: AppearanceMode) {
        guard state.appearanceMode != mode else { return }
        state.appearanceMode = mode
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
        // Appearance is a pure UX choice with no identity correlation,
        // so the explicit-reset path preserves it. The duress path
        // (Storage.eraseAndReinitialize, clearPasscodes branch) does
        // NOT preserve it — a freshly-installed app is light/system
        // by default, and a dark-mode-pinned post-wipe surface would
        // signal "this device has been used before" to a coercer.
        let preservedAppearance = state.appearanceMode
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
            appearanceMode: preservedAppearance,
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
        // Re-pair UX: explicit reset → surface the one-shot
        // banner that tells the user their identity changed and
        // anyone who had them as a contact must delete + re-scan
        // their new QR. NOT fired on `duressWipe()` (see that
        // method's design — coercer-watching invariant).
        identityResetBannerPending = true
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
    ///   1. Snapshot `state` so `Storage.eraseAndReinitialize` can
    ///      carry a narrow allowlist of UX prefs into the post-wipe
    ///      `AppState`. **What actually survives the duress path is
    ///      only `relayHost` plus the screenshot-self-test cache
    ///      (`qrBlockEffective` / `qrBlockTestedOSVersion`).** Face ID,
    ///      auto-lock, panic mode, and `onboardingCompleted` are
    ///      DELIBERATELY reset to fresh-install defaults — preserving
    ///      a Face-ID-on or onboarded posture would make the device
    ///      show a lock screen / skip onboarding, which a genuinely
    ///      fresh install does not, breaking the "indistinguishable
    ///      from a clean install" goal. (The brief and README still
    ///      describe a larger preserved set; the code here is
    ///      authoritative — see `Storage.eraseAndReinitialize`.)
    ///   2. Tear down the relay socket + retry timer so no in-
    ///      flight encrypt can reach the network with the soon-to-
    ///      be-orphaned session.
    ///   3. `Storage.eraseAndReinitialize` — erases the key material
    ///      FIRST (the single irreversible step), then the AppPasscode
    ///      slots, the attachment tree, the SQLCipher file, and the
    ///      `UserDefaults.standard` + App Group persistence surfaces;
    ///      re-opens a fresh empty DB.
    ///   4. Reset every in-memory ChatStore field to its cold-launch
    ///      defaults: load AppState + outbox from the fresh DB, mint
    ///      a brand-new libsignal identity.
    ///
    /// Returns synchronously. The caller (`LockOverlayView`) pads the
    /// passcode-submit → lock-drop latency to a fixed ceiling so the
    /// duress unlock is not wall-clock-distinguishable from a real
    /// one — the wipe below is fast but NOT constant-time, so the
    /// padding lives in the caller, not here.
    func duressWipe() {
        let snapshot = state
        teardownRelay()
        session = nil
        myIdentityPublicCached = nil
        // Reset the identity-reset banner flag BEFORE the wipe. The
        // setter's `didSet` writes the value to `UserDefaults.standard`;
        // doing it here means that write lands first and is then
        // dropped along with the rest of the standard persistent
        // domain by `eraseAndReinitialize` step 5. Net result: the
        // in-memory mirror is `false` AND the standard defaults plist
        // is absent — byte-identical to a never-launched fresh
        // install. (Setting it AFTER the wipe would re-create the
        // plist with a single key, a telltale a fresh install lacks.)
        identityResetBannerPending = false
        // Drop the APNs device token under the OLD identity. iOS mints
        // a fresh device token on the next registerForRemoteNotifications
        // call — so a relay-adjacent adversary who recorded the
        // pre-duress (peer-id, APNs token) tuple cannot correlate it
        // with a post-duress (fresh peer-id, fresh APNs token) tuple.
        // The next onboarding pass (which the duress wipe routes the
        // user through, by clearing `onboardingCompleted`) re-registers.
        UIApplication.shared.unregisterForRemoteNotifications()
        let wipeComplete = Storage.eraseAndReinitialize(preserving: snapshot, clearPasscodes: true)
        // Cryptographic erasure must not be silently reported as done
        // when a key-material delete could not be confirmed.
        // `eraseAndReinitialize` already retried the erase a bounded
        // number of times (see its step 1); this records whether it
        // still came up short. Deliberately NOT surfaced as a visible
        // banner: the duress path routes the user straight into the
        // fresh-install onboarding surface, and a "wipe incomplete"
        // banner there would itself be a duress tell a coercer could
        // read. Kept as queryable state for diagnostics / a future
        // safe-context recovery prompt.
        duressWipeIncomplete = !wipeComplete
        state = Storage.loadAppState()
        outbox = Storage.loadOutbox()
        diagEvents.removeAll()
        keychainWriteFailing = false
        unrecoverableStorageState = false
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
        // Deliberately do NOT call `refreshAppBadge()` here. That
        // method rewrites every App Group key — including a
        // `mainAppActiveEpoch` wall-clock timestamp — which would
        // immediately repopulate the App Group plist that step 5 of
        // `eraseAndReinitialize` just dropped, leaving a "something
        // happened on this device at time T" residue. The post-wipe
        // App Group plist must stay absent (matching a never-launched
        // fresh install) until the user re-onboards. We still clear
        // the visible app-icon badge directly — a stale pre-wipe
        // count on the home screen would itself be a telltale — but
        // via `setBadgeCount` only, touching no App Group key.
        UNUserNotificationCenter.current().setBadgeCount(0) { _ in }
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
    ///
    /// **Returns `true` only if the blob was durably committed.** The
    /// send pipeline is fail-closed on this: a call site that has just
    /// `encryptSealed`'d (advancing the ratchet) MUST check the return
    /// value and abort the wire send on `false` — emitting ciphertext
    /// from ratchet state that is not yet on disk means a later cold
    /// launch rehydrates from a stale snapshot behind the wire state.
    /// Non-send call sites (post-decrypt flushes, per-row persists)
    /// may ignore the result; the `keychainWriteFailing` banner still
    /// warns the user about chronic failure either way.
    @discardableResult
    func persistSession() -> Bool {
        persistSessionImpl()
    }

    @discardableResult
    private func persistSessionImpl() -> Bool {
        guard let session else { return false }
        do {
            try Storage.persist(session: session)
            // Clear the warning the moment a write succeeds. Chronic
            // failure stays surfaced; transient hiccups self-resolve
            // on the next persistSession call.
            if keychainWriteFailing {
                keychainWriteFailing = false
            }
            return true
        } catch {
            // F-602: surface to UI via the published flag. Storage layer
            // already NSLog'd the underlying errSec status — the banner
            // tells the user to investigate before they trust further
            // ✓✓ indicators (which would otherwise be lying about
            // delivery in the worst case). The `false` return is the
            // fail-closed signal: send call sites abort the wire send
            // so no ciphertext from un-committed ratchet state leaves
            // the device.
            keychainWriteFailing = true
            return false
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
            // Activity heartbeat: tells the NSE "the main app is alive
            // and has just written the authoritative badge value." For
            // the next `mainAppActiveWindow` seconds the NSE will
            // suppress its own bump on incoming pushes, because the
            // relay is delivering the same payload to us and the
            // existing handlers will call `refreshAppBadge` again with
            // the correct count. Closes the foreground-race that
            // produced the "badge=5 when only 1 unread" bug.
            defaults.set(
                Date().timeIntervalSince1970,
                forKey: SharedAppGroup.mainAppActiveEpochKey,
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
            let host = self.relayDescriptors[idx].host
            self.perRelayState[host] = state
            let prevAggregate = self.relayState
            self.relayState = self.aggregateRelayState()
            // Silent per-relay retry. The contract: a single relay
            // failing while the fleet still has at least one healthy
            // route does NOT surface as a banner blip — the user
            // already has working send/receive via the other routes.
            // But the dead route is silently re-dialed on a tight
            // exponential backoff so the fleet recovers full
            // redundancy without manual intervention. The aggregate-
            // `.failed` retry below handles the case where every
            // route is down; this handles the case where one is.
            switch state {
            case .connected:
                self.clearPerRelayRetry(host: host)
            case .failed:
                // Only run the silent retry when the AGGREGATE is
                // still serving traffic (i.e. at least one other
                // relay is up). When the aggregate is itself
                // `.failed`, the louder reconnect loop in
                // `handleAggregateRelayStateTransition` rebuilds
                // the whole fleet — running both would double-dial
                // the dead route.
                if case .connected = self.relayState {
                    self.scheduleSilentPerRelayRetry(host: host)
                }
            case .idle, .connecting, .connectingToTor:
                break
            }
            // Parseable marker so `scripts/tor-foreground-stress.sh`
            // can tail QALog and count reconnect cycles without
            // having to scrape free-form prose. DEBUG-only via
            // pzLog; release builds compile this out.
            if prevAggregate != self.relayState {
                pzLog("[reconnect-cycle] state=\(self.relayState)")
            }
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
            // Refresh the transparency log
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

    /// `FRAME_TYPE_CHAIN_SEED_DELIVERY` receive hook. The wire frame
    /// carries a sealed envelope, just like a SEND, but is a separate
    /// pipe with its own relay-side rate limit and no delivery-token
    /// gate. Decryption happens here; the inner-kind restriction
    /// enforces that this pipe carries ONLY chain seeds (a paired
    /// peer must not be able to slip chat/ack/etc through the
    /// no-token wire path).
    nonisolated func relayClient(
        _ client: RelayClient,
        didReceiveChainSeedFrom fromPeer: Data,
        sealedCiphertext: Data
    ) {
        // `fromPeer` is the relay-spoof-checked wire-level sender; the
        // sealed cert is the authoritative identity for the receive
        // handler (matches the SEND path's contact-gate).
        _ = fromPeer
        Task { @MainActor in
            self.handleChainSeedFrame(sealedCiphertext, via: client)
        }
    }

    /// Decrypt + dispatch a sealed envelope that arrived via the
    /// dedicated chain-seed wire frame. Strict: any inner kind other
    /// than `chainSeedDelivery` is dropped as a protocol violation
    /// (the no-token pipe must not become an abuse vector for chat
    /// or other envelope kinds).
    @MainActor
    private func handleChainSeedFrame(_ sealedCiphertext: Data, via client: RelayClient) {
        diagLog(
            "chain",
            "FRAME_TYPE_CHAIN_SEED_DELIVERY received sealed=\(sealedCiphertext.count)B"
        )
        guard let session = self.session else {
            diagLog("chain", "chain-seed-frame: dropping — no session")
            return
        }
        let received: Session.SealedReceived
        do {
            received = try session.decryptSealed(sealedCiphertext)
        } catch {
            diagLog("chain", "chain-seed-frame decrypt FAILED: \(error)")
            return
        }
        // libsignal's ratchet step happens during decrypt; persist
        // before any further work so a crash here doesn't desync.
        persistSession()
        // A relay-queue redelivery of a chainSeedDelivery we've
        // already consumed surfaces here as `isDuplicate=true` with
        // an empty plaintext (the ratchet swallowed the duplicate
        // ciphertext and returned the metadata-only frame). The
        // prior code fell through to the inner-kind check and
        // logged a misleading "REJECTED non-chainSeedDelivery
        // inner kind (empty)" — the operator reading the QA log
        // would chase a non-existent protocol bug. Short-circuit
        // here with the correct diagnostic.
        if received.isDuplicate {
            diagLog(
                "chain",
                "chain-seed-frame ratchet-duplicate from \(short(received.peer)) — drop (chain already installed)",
            )
            return
        }
        if self.isIdentityBlocked(received.peer) {
            diagLog("chain", "chain-seed-frame from BLOCKED peer \(short(received.peer)) — drop")
            return
        }
        guard let idx = self.contactIndex(forIdentity: received.peer) else {
            diagLog(
                "chain",
                "chain-seed-frame from UNKNOWN peer \(short(received.peer)) — drop (not in contacts)"
            )
            return
        }
        guard let kindByte = received.plaintext.first,
              let kind = RelayClient.InnerEnvelopeKind(rawValue: kindByte),
              kind == .chainSeedDelivery else {
            let kindHex = received.plaintext.first.map { String(format: "0x%02x", $0) } ?? "(empty)"
            diagLog(
                "chain",
                "chain-seed-frame REJECTED non-chainSeedDelivery inner kind \(kindHex) "
                + "from \(short(received.peer))"
            )
            return
        }
        let payload = received.plaintext.dropFirst()
        self.handleChainSeedDelivery(payload: Data(payload), contactIdx: idx)
        _ = client
    }

    nonisolated func relayClient(_ client: RelayClient, didReceiveStatus status: RelayStatus) {
        // Cache the latest relay attestation so the
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
            // Actually COMPUTE the transparency-log comparison here,
            // on every STATUS_RESPONSE — not lazily inside the
            // Settings view body. The result is stored in
            // `relayAttestationVerdict` as an enforceable signal so a
            // future enforcement gate has a verdict to read without
            // re-deriving it. This closes the "verification is real
            // but advisory-only / discoverable only via Settings"
            // gap: the verdict now exists at the connection layer.
            let verdict = self.computeAttestationVerdict(for: status)
            self.relayAttestationVerdict = verdict
            pzLog("[pizzini] relay attestation verdict: \(verdict)")

            // AUDIT-DECISION-NEEDED: enforcement action on a non-clean
            // verdict. The verdict above is now computed and stored,
            // but the protective ACTION is gated on a policy decision
            // that is not ours to make unilaterally:
            //   - `.mismatch`  — hard-disconnect this relay? block
            //     only sends (let receives drain)? or allow a signed,
            //     time-bounded grace window so a legitimately-new
            //     deploy that is not yet in the log isn't a
            //     bootstrapping deadlock?
            //   - `.unverifiable` — should an un-checkable relay feed
            //     the SAME interruption path as a mismatched one
            //     (fail-closed), or only a louder warning?
            // Both options change user-visible behaviour and the BYO /
            // new-deploy story, so the enforcement is left as this
            // marked stub. When the policy lands, the action hooks in
            // here, keyed off `verdict`; `RelayAttestationView` and
            // `FAQView` copy must be reconciled with whatever is
            // chosen (the FAQ currently claims the app "refuses to
            // talk to" an unattested relay, which is not yet true).
            switch verdict {
            case .mismatch, .unverifiable:
                pzLog("[pizzini] relay attestation \(verdict) — enforcement policy pending (AUDIT-DECISION-NEEDED)")
            case .verified, .notEvaluated:
                break
            }
        }
    }

    /// Compare a relay's reported `binarySha256` against the verified
    /// transparency log and return an enforceable verdict. Fail-closed
    /// on the "could not verify" case: an empty or unfetchable log is
    /// `.unverifiable`, never silently treated as `.verified` — an
    /// adversary who merely blocks the log fetch must not be able to
    /// downgrade the client to "looks fine."
    @MainActor
    private func computeAttestationVerdict(for status: RelayStatus) -> RelayAttestationVerdict {
        // No operator verify key in this build → verification can't
        // run at all. `.notEvaluated` (the Settings view already
        // renders an explicit "not configured" state for this).
        guard TransparencyLogConfig.operatorVerifyKey != nil else {
            return .notEvaluated
        }
        // An empty / no-valid-entries log means we have nothing to
        // check against — the fetch was blocked, the cache is empty,
        // or every entry failed signature verification. Cannot
        // conclude "verified"; this is the fail-open hole the audit
        // flagged, so it is its own verdict.
        guard TransparencyLog.verifiedCount(in: transparencyLog) > 0 else {
            return .unverifiable
        }
        let reportedSha = hex(status.binarySha256)
        return TransparencyLog.contains(binarySha256Hex: reportedSha, in: transparencyLog)
            ? .verified
            : .mismatch
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
            // Relay-queue redelivery of a sealed frame we already
            // processed. NEVER re-emit an ACK here — every emitAck
            // call mints a v2 delivery token off our outbound chain,
            // and a long relay-queue backlog of distinct messageIds
            // can drain the entire 16,384-entry chain in minutes.
            // (QA log 2026-05-13: 12,492 first-time duplicates from
            // one peer over an hour, each minting a fresh token,
            // the prior per-(peer, messageId) suppressor caught only
            // *subsequent* redeliveries of the same messageId, not
            // the first.)
            //
            // Why always-suppress is safe: when the peer's outbox
            // retries because our original ACK didn't reach them,
            // they re-encrypt the plaintext with a FRESH ratchet
            // number. That arrives here as `isDuplicate=false` and
            // gets a normal ACK via the regular fresh-receive path.
            // `isDuplicate=true` only ever means "the relay's
            // at-least-once queue redelivered the same sealed bytes",
            // and our original ACK for those bytes is already queued
            // at every connected relay — the peer sees ✓✓ from
            // whichever relay's queue drains first.
            pzLog(
                "[pizzini] duplicate sealed frame from \(self.short(received.peer)) — drop (relay-queue redelivery)"
            )
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
        case .chainRefreshRequest:
            // Audit M1. Sender's outbound chain to us hit the
            // rotation threshold; mint + ship a fresh chain via the
            // dedicated FRAME_TYPE_CHAIN_SEED_DELIVERY pipe. The
            // 30-min cooldown bounds buggy-client retry storms; the
            // bundle-coupled 6 h cap is NOT consulted on this path,
            // by design (different cost profile).
            self.handleChainRefreshRequest(
                fromPeer: received.peer,
                contactIdx: idx,
                via: client,
                session: session,
            )
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
        // Drain a deferred chain serve if peer asked for our bundle
        // before our libsignal session to them existed.
        self.maybeServePendingChain(forContactAt: idx)
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
            maybeServePendingChain(forContactAt: idx)
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
            // Chain is dead and we can't ACK. The peer will retry
            // forever. Trigger a debounced bundle refresh so the
            // peer mints + ships a fresh chainSeedDelivery; once
            // that lands, future ACKs work again. Without this
            // recovery the captured 2026-05-13 log shows the loop
            // ran for thousands of frames with `refreshChainAndQueue
            // will fire` logged on every attempt but no BUNDLE_REQUEST
            // actually going out, because that text was just the
            // mint-failure log line and the only path that actually
            // refreshes was on the user-text send route — not the
            // ACK path.
            recoverChainAfterExhaustion(forContactAt: idx)
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
            // Fail-closed: encryptSealed advanced the ratchet. If that
            // advance is not durably committed, the ACK must NOT reach
            // the wire — emitting it would mean a later cold launch
            // rehydrates a session behind the wire state, and the
            // NEXT outbound encrypt reuses an already-consumed
            // counter. Aborting just means no ✓✓ this round; the
            // peer's retry re-triggers an ACK once Keychain writes
            // recover, with the ratchet state consistent again.
            guard persistSession() else {
                pzLog("[pizzini] ACK to \(self.short(toPeer)) ABORTED — session persist failed; no ciphertext on wire")
                return
            }
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

    /// Recover after `emitAck` finds the outbound chain to this
    /// contact missing or exhausted. Fires a `BUNDLE_REQUEST` —
    /// the peer responds with a fresh `chainSeedDelivery` which
    /// `handleChainSeedDelivery` installs as our new outbound
    /// chain. Debounced via the existing `chainRotationLastRequestedAt`
    /// per-contact cooldown (1 h) so a duplicate flood can't
    /// hammer the network. Idempotent: if a refresh request is
    /// already in flight from the proactive 80%-threshold path,
    /// the cooldown short-circuits us.
    @MainActor
    private func recoverChainAfterExhaustion(forContactAt idx: Int) {
        let contact = state.contacts[idx]
        let now = Date()
        if let last = chainRotationLastRequestedAt[contact.id],
           now.timeIntervalSince(last) < Self.chainRotationRequestCooldown {
            return
        }
        chainRotationLastRequestedAt[contact.id] = now
        diagLog(
            "chain",
            "ACK chain missing/exhausted for \(short(contact.identityPub)) — firing BUNDLE_REQUEST recovery",
        )
        requestBundleWithHashcash(fromPeer: contact.identityPub)
    }

    nonisolated func relayClient(_ client: RelayClient, didReceiveBundleRequestFrom fromPeer: Data) {
        Task { @MainActor in
            // Block-list gate: a BUNDLE_REQUEST from a blocked peer
            // is dropped without a decoy emission. The decoy is the
            // anti-probe defense for *unknown* requesters; for a
            // blocked one, the user has explicitly opted out of
            // ever pairing with them again, and silence is the
            // intended posture.
            if self.isIdentityBlocked(fromPeer) {
                return
            }
            guard let idx = self.contactIndex(forIdentity: fromPeer),
                  let session = self.session
            else {
                // F-402: a malicious relay can fabricate BUNDLE_REQUEST
                // frames with arbitrary `from_id` to probe our contact
                // set — silence-vs-(BUNDLE_RESPONSE+chainSeedDelivery)
                // on the wire is the oracle. Mask by emitting a same-shape,
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
                let priorVerifyKey = self.state.contacts[idx].peerVerifyKey

                // Idempotency gate against relay-queue redelivery.
                // `BUNDLE_RESPONSE` is at-least-once: a single peer-
                // side reply surfaces N times (once per ready relay
                // whose queue still holds our session). libsignal's
                // `initiateSession` consumes the bundle's one-time-
                // prekey on the FIRST call; re-running on the same
                // bytes throws `internalError` because the prekey is
                // gone, and serves no purpose either way because we
                // already have a working session. Skip when we have
                // a session AND the bundle's verify_key matches what
                // we stashed last time (peer has NOT rotated). If
                // priorVerifyKey is nil (legacy pair predating the
                // F-401 stash) we still call initiateSession; the
                // verify_key compare below this site then catches
                // any actual rotation. Same root-cause class as the
                // duplicate-ACK runaway: relay's at-least-once
                // redelivery hitting an idempotency boundary the
                // earlier code didn't gate.
                if self.state.contacts[idx].sessionEstablished,
                   priorVerifyKey != nil,
                   priorVerifyKey == verifyKey {
                    pzLog(
                        "[pizzini] BUNDLE_RESPONSE from \(self.short(fromPeer))"
                        + " — session already established with matching"
                        + " verify_key, skipping initiateSession"
                        + " (queue-redelivery idempotency)"
                    )
                    // Still drain any deferred chain serve — the peer
                    // may have just asked for our bundle in parallel
                    // and `maybeServePendingChain` is the gate on that
                    // queue. Skipping it here would strand a chain.
                    self.maybeServePendingChain(forContactAt: idx)
                    return
                }

                try session.initiateSession(peerIdentity: fromPeer, bundle: bundle)
                // A bundle from a peer who's rotated their identity
                // invalidates our outbound chain to them: its root is
                // registered with the relay under the peer's prior
                // (peer_id, chain_id) state, and after the peer
                // re-pairs they'll register a new one. Drop the chain
                // here so the next send hits `refreshChainAndQueue`.
                if priorVerifyKey != nil, priorVerifyKey != verifyKey {
                    self.state.contacts[idx].outboundTokenChain = nil
                }
                self.state.contacts[idx].peerVerifyKey = verifyKey
                self.state.contacts[idx].sessionEstablished = true
                self.persistContactSlice(at: idx)
                // Now that we have an outbound session, drain any
                // chain serve that was deferred because the peer
                // asked for our bundle before we had their bundle.
                self.maybeServePendingChain(forContactAt: idx)
            } catch {
                // Include the peer's short id so a future QA capture
                // pinpoints which contact's session init failed.
                // Previous error line was "initiateSession failed:
                // internalError" with no peer context — useless for
                // multi-contact diagnosis.
                pzLog("[pizzini] initiateSession failed for \(self.short(fromPeer)): \(error)")
            }
        }
    }

    /// 4-byte hex fingerprint shorthand for log lines and system rows.
    /// Internal-not-private so the group surface in
    /// `ChatStoreGroups.swift` can render the same shorthand without
    /// duplicating the formatter. `nonisolated` so detached tasks
    /// can format peer ids without hopping back through MainActor.
    nonisolated func short(_ data: Data) -> String {
        let head = data.prefix(4).map { String(format: "%02x", $0) }.joined()
        return head + "…"
    }

    /// Full lowercase hex. Used by the relay-info logging /
    /// Settings row to render binary SHA-256s the operator can
    /// match against a transparency-log entry.
    nonisolated func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
