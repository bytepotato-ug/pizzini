// Embedded Tor controller. Spins up a tor thread on first use, watches
// its bootstrap-progress events, and surfaces a local SOCKS5 port that
// the rest of the app dials when the relay address is a .onion.
//
// Architecture:
//
//   TorController.shared
//       │  bootstrap() async throws -> UInt16
//       │  prepareHiddenService(_:) async throws
//       │  bootstrapProgress: Int           (0-100, observable)
//       │  isReady: Bool
//       │  stop()
//       ▼
//   TORThread (PizziniTorObjC) ── runs the C-tor event loop on a
//   detached NSThread (TORThread.start uses tor_run_main() under
//   the hood). The thread lives until `stop()` issues SIGNAL
//   SHUTDOWN via the control port.
//
//   TORController (PizziniTorObjC) ── speaks the tor control
//   protocol over a unix socket whose path lives in the data
//   directory. Authentication is via the cookie file tor writes
//   on startup (cookieAuthentication = YES).
//
// ─── What "ready" means in this codebase ────────────────────────────
//
// `bootstrap()` returns when tor emits CIRCUIT_ESTABLISHED — i.e. the
// FIRST general-purpose circuit is open. That is enough to dial a
// public-internet target but NOT enough to dial a hidden service:
// the first .onion CONNECT additionally needs (1) an HS-descriptor
// fetched off the HSDirs, (2) an introduction circuit, and (3) a
// rendezvous circuit. Cold launch, even with a warm consensus cache,
// fails the first SOCKS5 CONNECT until those three exist. The next
// attempt 5-15 s later finds the descriptor cached and succeeds —
// which is the "the app only connects after I tap Reconnect" symptom
// we shipped against.
//
// The fix is two halves:
//   - `bootstrap()` still resolves on CIRCUIT_ESTABLISHED, since that
//     is the well-defined "tor is functioning" milestone.
//   - `prepareHiddenService(_:)` is the missing step on the relay
//     dial path. RelayClient calls it between bootstrap() and the
//     SOCKS handshake; it issues a `HSFETCH` over the control port,
//     waits for the matching `HS_DESC RECEIVED` event, and only
//     then returns. The SOCKS5 CONNECT that follows skips the
//     descriptor-lookup phase entirely; the intro/rendezvous
//     handshake still takes a few seconds but is well inside the
//     time tor's SocksTimeout (2 min) and our own retry window
//     allow. Cold-launch first-attempt success is the observable
//     property.
//
// Future readers: do NOT collapse `prepareHiddenService` back into
// `bootstrap()`. The daemon is a fleet-wide singleton; the HS step
// is per-onion. Two relays in the trusted fleet need two HSFETCHes.
//
// Concurrency:
//   - All public methods are safe to call from any task. The first
//     concurrent caller wins the bootstrap; subsequent callers
//     await the same task.
//   - Bootstrap progress updates land on `@MainActor` so SwiftUI
//     views observing this object don't need additional bridging.
//
// Data directory:
//   `Library/Caches/tor/`. iOS may evict caches under storage
//   pressure — that's acceptable here. A wiped consensus cache
//   forces a fresh bootstrap on next start (a few extra seconds
//   on the cold path), but no app data is lost.

import Foundation
import Network
import os
import PizziniTorObjC

public extension Notification.Name {
    /// Posted on the MainActor when the system's network path
    /// changes in a way that may have invalidated tor's circuits
    /// (interface flip, captive portal rotation, airplane-mode
    /// toggle, constrained-mode change). The host listens to drop
    /// + redial its RelayClients without tearing tor itself down.
    /// `object` is the `TorController.shared` singleton; userInfo
    /// is currently empty (reserved for a future change-cause
    /// tag).
    static let pizziniTorNetworkPathChanged = Notification.Name("app.pizzini.tor.network-path-changed")
}

/// Debug logger for the embedded tor lifecycle. Subsystem +
/// category match `app.pizzini.tor` so Console.app can filter to
/// just our tor activity (`subsystem:app.pizzini.tor`). All
/// significant phase transitions log here with wall-clock-style
/// elapsed-since-bootstrap-start markers so the gap between "tor
/// printed BOOTSTRAP 0%" and "we gave up" stops being invisible.
private let torLog = Logger(subsystem: "app.pizzini.tor", category: "lifecycle")

/// Errors surfaced from `TorController.bootstrap()`.
public enum TorControllerError: Error, LocalizedError, Sendable {
    /// Tor's bootstrap stalled past the deadline. The most common cause
    /// is the device having no working network at all; a slow first
    /// circuit (15-25s on cellular) is still inside the deadline.
    case bootstrapTimedOut(after: TimeInterval)
    /// The cookie file tor writes to the data directory at startup was
    /// missing when we tried to authenticate against the control port.
    /// Indicates a tor startup failure (disk full, permissions, etc.).
    case missingCookie
    /// The control-port socket couldn't be reached. Either tor never
    /// started or the control socket file was evicted before we could
    /// connect.
    case controllerConnectFailed(underlying: Error)
    /// Tor's control-port authentication rejected our cookie. Should
    /// not happen in practice; indicates a corrupt cookie file.
    case authenticationFailed
    /// Caller cancelled the bootstrap via task cancellation.
    case cancelled
    /// `prepareHiddenService(_:)` could not get tor to cache an HS
    /// descriptor for the target onion. `reason` is the HS_DESC FAILED
    /// `REASON=` field (e.g. `NOT_FOUND`, `QUERY_NO_HSDIR`) or
    /// `hsDescTimedOut`. Distinguished from `bootstrapTimedOut` because
    /// the daemon itself is up — the HS endpoint is what's unreachable.
    case hsDescriptorUnavailable(onion: String, reason: String)
    /// Caller invoked `prepareHiddenService(_:)` before `bootstrap()`
    /// returned. Programmer error in the relay-client flow.
    case notBootstrapped
}

/// What `TorController.purgeStaleControlFiles(in:)` removed before
/// starting a fresh TORThread. `anyRemoved` is set when at least
/// one leftover control file from a previous app process was found
/// and unlinked.
///
/// Public so the iOS app test target can assert against the
/// cleanup outcome — see `StaleControlFilesPurgeTests` in
/// `pizziniTests`. The fields are stable contract.
public struct StaleControlFilesPurge: Equatable, Sendable {
    public let cookieRemoved: Bool
    public let portRemoved: Bool
    public var anyRemoved: Bool { cookieRemoved || portRemoved }

    public init(cookieRemoved: Bool, portRemoved: Bool) {
        self.cookieRemoved = cookieRemoved
        self.portRemoved = portRemoved
    }
}

@MainActor
public final class TorController: ObservableObject {
    /// Process-wide singleton. Tor is a global resource — a second
    /// daemon in the same process would fight for the same ports and
    /// data directory.
    public static let shared = TorController()

    /// 0–100. Reflects the latest `BOOTSTRAP` status event published
    /// by tor over the control port. Observable from SwiftUI; the
    /// `ChatStore.relayState` projection drives the
    /// "Connecting to Tor… N%" UI.
    @Published public private(set) var bootstrapProgress: Int = 0

    /// True once tor has reported `BOOTSTRAP PROGRESS=100`. Stays true
    /// until `stop()` tears the daemon down. RelayClient gates SOCKS
    /// dialing on this; before it flips, dialing would just stall on
    /// the SOCKS handshake while tor is still wiring its directory.
    @Published public private(set) var isReady: Bool = false

    /// SOCKS5 port tor is bound to on `127.0.0.1`. Picked at startup by
    /// `TorConfiguration.socksPort` below (we pin to a fixed port so
    /// background-foreground cycles dial the same place). Returned by
    /// `bootstrap()`.
    public var socksPort: UInt16 { Self.fixedSocksPort }

    // ─── Internal state ───────────────────────────────────────────────

    /// We pin to 39150 rather than `0` (let-tor-pick). The port is
    /// loopback-only and process-internal; conflict risk is bounded
    /// to "another tor in the same app", which the singleton already
    /// prevents. Pinning means RelayClient can construct the SOCKS
    /// endpoint without first round-tripping a `getInfo` to the
    /// control port. (39150 was chosen as Tor Browser's traditional
    /// 9150 + 30000 to avoid clashing with anyone testing locally
    /// against an Onion Browser instance on 9050/9150.)
    // `nonisolated` because these are read from detached Tasks
    // (specifically the deadline-timer child task inside
    // `runBootstrap`). They're immutable constants, so escaping
    // them from the MainActor is trivially safe.
    nonisolated private static let fixedSocksPort: UInt16 = 39_150

    /// Stall window — if tor's bootstrap progress hasn't advanced in
    /// this many seconds, we conclude the network is broken and
    /// surface the failure. A FIRST cold-launch on cellular with DPI
    /// can take 60-120s end-to-end while still making steady
    /// progress every few seconds; the previous hard 90s deadline
    /// killed those bootstraps mid-flight even though tor would have
    /// succeeded a few seconds later. Switching to a stall check
    /// removes the spurious-failure UX (user opens app → "failed"
    /// pill → user taps → works) without giving up the bound.
    nonisolated private static let bootstrapStallTimeout: TimeInterval = 60

    /// Hard ceiling on total bootstrap time. Even if tor is reporting
    /// steady progress, we give up after this long — protects against
    /// a hostile network that slow-drips progress events without ever
    /// completing. 4 minutes is enough for a worst-case cellular cold
    /// start with consensus fetch, well short of "user thinks the app
    /// is broken" patience.
    nonisolated private static let bootstrapHardDeadline: TimeInterval = 4 * 60

    /// How long we wait for tor to create its `control_auth_cookie`
    /// and `controlport` files in the data directory after
    /// `TORThread.start()` returns. iOS Simulator cold-start with no
    /// cached consensus can stall tor's main loop for 10-20 s while
    /// libevent finishes setting up — *before* it writes either file.
    /// Empirical: 30 s covers a worst-case sim cold-start, and the
    /// poll itself is cheap (100 ms cadence, two `FileManager`
    /// lookups). The previous 15 s here was the silent culprit in
    /// many "first launch never connects" reports.
    nonisolated private static let startupFilePollDeadline: TimeInterval = 30

    /// How long we keep retrying the control-port TCP connect after
    /// tor's control listener writes its `controlport` file.
    /// **This is the most load-bearing single timeout in the cold-
    /// start path.** Even after tor logs "Control listener listening
    /// on port N", its libevent loop is busy setting up directory
    /// fetches, guard contexts, etc. and doesn't actually drain the
    /// accept queue for another 10-15 s on iOS Simulator. The
    /// previous 10 s here gave up while tor was still warming up,
    /// flipped RelayClient to `.failed`, and the user saw the
    /// "tap to reconnect" pill before the auto-reconnect timer
    /// fired — even though tor would have accepted us if we'd
    /// waited a few more seconds. 60 s gives a 4× margin over the
    /// empirical worst case, and we still bail fast (sub-second
    /// retry cadence) once tor's control listener wakes up. If we
    /// ever wait the full 60 s, tor has genuinely failed to start —
    /// at which point a user-visible failure is the correct UX.
    nonisolated private static let controllerConnectDeadline: TimeInterval = 60

    /// Tor's C runtime (`tor_run_main`) can only be invoked once per
    /// process — TORThread enforces this via an `abort()` in its
    /// initialiser (release-safe; the upstream NSAssert is compiled
    /// out in App Store builds). We mirror the lifecycle in Swift:
    /// the first successful `bootstrap()` creates the thread and we
    /// keep it for the duration of the process. Subsequent
    /// `stop()` / re-`bootstrap()` cycles only re-create the
    /// CONTROLLER (a TCP socket to tor's control port) — the daemon
    /// itself stays running. The cost is ~25 MB resident and a
    /// background CPU hum while idle; the alternative is a hard
    /// crash on every reconnect.
    ///
    /// Stored in a STATIC slot rather than an instance ivar so a
    /// hypothetical future `TorController` re-instantiation (or a
    /// regression that resets `shared`) cannot lose the reference
    /// and let ARC deallocate the daemon. `tor_run_main` is a
    /// process-global resource — its owner has to outlive every
    /// stop / reconnect cycle, not the controller object that
    /// happened to spawn it.
    nonisolated(unsafe) private static var processSingletonThread: TORThread?

    /// Mirror of `processSingletonThread` for the MainActor-isolated
    /// read paths in `runBootstrap()`. Reads/writes go through the
    /// static singleton so MainActor isolation is sufficient.
    private var torThread: TORThread? {
        get { Self.processSingletonThread }
        set { Self.processSingletonThread = newValue }
    }
    private var torController: TORController?
    /// Cached data directory for the bootstrapped tor. Used to
    /// re-read the cookie on a reconnect without re-running the
    /// full `runBootstrap()` from scratch. Set on first bootstrap;
    /// never cleared.
    private var bootstrappedDataDir: URL?
    /// Coalesces concurrent callers. The first call kicks off the
    /// bootstrap task; subsequent calls before completion await the
    /// same one. Cleared on `stop()` so the next foreground-cycle
    /// `bootstrap()` starts a fresh task.
    private var pendingBootstrap: Task<UInt16, Error>?

    /// Per-onion HSFETCH coalescing. Keyed by the bare v3 onion
    /// label (no `.onion` suffix, lowercase). Concurrent callers
    /// of `prepareHiddenService(_:)` for the same target share one
    /// in-flight fetch instead of stacking HSFETCHes on top of each
    /// other. Cleared on `stop()`.
    private var hsFetchTasks: [String: Task<Void, Error>] = [:]

    /// Onions we've already primed in the current tor session. tor
    /// caches HS descriptors locally for hours, so re-issuing
    /// HSFETCH on every warm reconnect (background → foreground,
    /// relay drop + recover, manual Reconnect) adds ~0.7 s of
    /// "Connecting…" with zero functional benefit. We track which
    /// addresses have already been prepared and short-circuit on
    /// the fast path. Invalidated when tor itself restarts via
    /// `stop()`; tor's own cache eviction handles descriptor TTL
    /// transparently (a SOCKS5 CONNECT against an evicted cache
    /// makes tor re-fetch on demand, slowing that one connect
    /// but not breaking it).
    private var preparedOnions: Set<String> = []

    /// Onions the host has asked us to proactively HSFETCH in parallel
    /// with tor's bootstrap, populated via `primeOnions(_:)`. Set
    /// before the first `bootstrap()` call so `runBootstrap` can read
    /// it once the control channel authenticates. Subsequent
    /// `primeOnions` calls overwrite the list (relay-host flip,
    /// fleet membership change).
    private var onionsToPrime: [String] = []

    /// NWPathMonitor watching the system network path. Started once
    /// on first `bootstrap()` and never stopped — the daemon is
    /// pinned for the process lifetime and so is this observer.
    /// Updates dispatch onto `pathMonitorQueue`, then re-hop to
    /// MainActor for `handlePathChange`.
    nonisolated(unsafe) private static var pathMonitor: NWPathMonitor?
    nonisolated private static let pathMonitorQueue = DispatchQueue(label: "app.pizzini.tor.path")
    /// Fingerprint of the most recently observed path, set on the
    /// MainActor inside `handlePathChange`. The first sample
    /// (initial value) is recorded but produces no signal — there's
    /// nothing to invalidate yet. Subsequent changes that differ
    /// from this trigger a NEWNYM + relay-redial flow.
    private var lastPathFingerprint: String?

    /// Hard deadline for a single HSFETCH. **The first HSFETCH after
    /// a fresh bootstrap is the load-bearing one** — tor's HSDir
    /// circuit pool is empty, so the descriptor lookup pays for the
    /// 3-hop circuit build (~5 s) plus the HSDir round-trip
    /// (variable, 5-25 s depending on which HSDir tor picks first).
    /// Empirically on an iOS device cold launch we've seen the
    /// full path complete in ~28-30 s; the previous 25 s budget
    /// fired *just* before tor would have emitted HS_DESC RECEIVED,
    /// stranded the observer, and the descriptor landed in cache
    /// silently — letting the next attempt (auto-reconnect 5 s
    /// later) succeed in <1 s. 90 s gives a 3× margin over the
    /// observed worst case so the first attempt actually catches
    /// the event instead of timing out 5 s short. UI stays at
    /// `.connecting` during the wait, no `.failed` flash.
    nonisolated private static let hsFetchDeadline: TimeInterval = 90

    private init() {}

    // ─── Public surface ───────────────────────────────────────────────

    /// Starts tor (if not already running) and waits for the first
    /// successful bootstrap. Returns the local SOCKS5 port.
    ///
    /// Idempotent. If tor is already bootstrapped, returns immediately
    /// with the cached port. If a bootstrap is in progress, awaits it.
    public func bootstrap() async throws -> UInt16 {
        if isReady {
            return Self.fixedSocksPort
        }
        if let pending = pendingBootstrap {
            return try await pending.value
        }
        let task = Task<UInt16, Error> { [weak self] in
            guard let self else { throw TorControllerError.cancelled }
            return try await self.runBootstrap()
        }
        pendingBootstrap = task
        do {
            let port = try await task.value
            pendingBootstrap = nil
            return port
        } catch {
            pendingBootstrap = nil
            // On failure, tear down so the next bootstrap() starts
            // clean. Otherwise a half-started TORThread sits around
            // holding the data directory lock and the retry would
            // hit "address in use" on the SOCKS bind.
            stopInternal()
            throw error
        }
    }

    /// Register onion hosts to proactively HSFETCH in parallel with
    /// the rest of the bootstrap. Call from the host as early as the
    /// relay target list is known — typically `ChatStore.connectRelay`
    /// right before building RelayClients. Fire-and-forget; the
    /// speculative fetches run on tor's own schedule the moment the
    /// control channel authenticates, well before `bootstrap()`
    /// returns. By the time RelayClient calls `prepareHiddenService`,
    /// the descriptor is usually already cached and the call
    /// short-circuits through `preparedOnions`.
    ///
    /// Idempotent. Repeated calls overwrite the prime list — the
    /// host may shrink it when a BYO override is flipped on, or grow
    /// it when the fleet expands. Onions already in `preparedOnions`
    /// are skipped; in-flight fetches via `hsFetchTasks` are reused.
    public func primeOnions(_ hosts: [String]) {
        let normalized = hosts.map { Self.stripOnionSuffix($0).lowercased() }
        onionsToPrime = normalized
        // If we already have an authenticated controller (e.g. the
        // host is changing the prime list mid-session), dispatch
        // immediately. On the cold-launch path the controller is nil
        // here and the dispatch happens inside `runBootstrap` right
        // after authenticate succeeds.
        if torController != nil {
            dispatchSpeculativeHsFetches()
        }
    }

    /// Probe tor for hung-libevent / stale-circuit state and force a
    /// guard rotation if it looks degraded. Call from the foreground
    /// path BEFORE the host redials its RelayClients.
    ///
    /// **Why this exists.** When iOS suspends the app for more than a
    /// few minutes, the embedded tor's libevent runloop is still
    /// alive but its epoll/kevent handles return stale errors against
    /// connections the OS evicted while we slept. The control socket
    /// usually survives (it's loopback), so the obvious "is tor up"
    /// signal — `controller.isConnected` — lies. We probe with
    /// `GETINFO status/bootstrap-phase`: a healthy tor replies in
    /// well under 100 ms with a `PROGRESS=100` line, a hung one
    /// either takes seconds or reports a non-100 state. Either case
    /// triggers `SIGNAL RELOAD` (refreshes guard set + reloads
    /// config — does NOT kill tor) before the host's
    /// `connectRelay()` opens a fresh SOCKS5 socket.
    ///
    /// 2 s deadline matches the user-perceptible "did the app
    /// freeze on resume" threshold — anything longer and we'd
    /// rather spend the budget on RELOAD + reconnect.
    public func probeAndRecover() async {
        guard let controller = torController, controller.isConnected else {
            torLog.debug("probe: skipped — no controller")
            return
        }
        let probeStart = Date()
        let deadline: TimeInterval = 2
        // Race GETINFO completion against the deadline. `single`
        // guarantees the continuation resumes exactly once; the
        // controller callback fires on tor's control queue (off
        // MainActor) and Task.sleep below fires on a background
        // task.
        let result: Bool? = await withCheckedContinuation { (cont: CheckedContinuation<Bool?, Never>) in
            let single = SingleFire()
            controller.getInfoForKeys(["status/bootstrap-phase"]) { values in
                guard single.claim() else { return }
                let raw = values.first ?? ""
                // A healthy tor reports e.g.
                //   `NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"`
                // A daemon that's still warming up or in a degraded
                // state reports `PROGRESS=<n>` where n < 100.
                let ok = raw.contains("PROGRESS=100")
                cont.resume(returning: ok)
            }
            Task {
                try? await Task.sleep(nanoseconds: UInt64(deadline * 1_000_000_000))
                guard single.claim() else { return }
                cont.resume(returning: nil)
            }
        }
        let elapsed = Date().timeIntervalSince(probeStart)
        let elapsedFmt = String(format: "%.2fs", elapsed)
        switch result {
        case .some(true):
            torLog.debug("probe: bootstrap-phase OK after \(elapsedFmt)")
        case .some(false):
            torLog.notice("probe: bootstrap-phase reports degraded after \(elapsedFmt) — issuing SIGNAL RELOAD")
            sendReloadSignal()
        case .none:
            torLog.notice("probe: GETINFO timed out after \(elapsedFmt) — issuing SIGNAL RELOAD")
            sendReloadSignal()
        }
    }

    /// Single-fire atomic claim, used by `probeBootstrapPhase` to keep
    /// the GETINFO completion + timeout task from both resuming the
    /// same continuation. The first `claim()` returns true; everyone
    /// else returns false.
    final class SingleFire: @unchecked Sendable {
        private let lock = OSAllocatedUnfairLock<Bool>(initialState: false)
        func claim() -> Bool {
            lock.withLock { fired in
                if fired { return false }
                fired = true
                return true
            }
        }
    }

    /// SIGNAL RELOAD — tells tor to re-read torrc and refresh guard
    /// selection logic. Heavier than NEWNYM, lighter than SHUTDOWN.
    /// Safe to call mid-session; tor will keep serving streams while
    /// it reloads.
    private func sendReloadSignal() {
        guard let controller = torController, controller.isConnected else { return }
        controller.sendCommand("SIGNAL", arguments: ["RELOAD"], data: nil) { @Sendable codes, _, stop in
            let ok = codes.first?.intValue == 250
            torLog.debug("probe: SIGNAL RELOAD \(ok ? "OK" : "rejected")")
            stop.pointee = true
            return true
        }
    }

    /// Tears down the running tor daemon. Used by the app-background
    /// flow after the relay drain window. Idempotent.
    public func stop() {
        pendingBootstrap?.cancel()
        pendingBootstrap = nil
        hsFetchTasks.values.forEach { $0.cancel() }
        hsFetchTasks.removeAll()
        // Tor itself is shut down — its descriptor cache goes with
        // it. The "prepared" set must clear so the next bootstrap
        // re-primes from scratch.
        preparedOnions.removeAll()
        stopInternal()
    }

    /// Prime tor's hidden-service descriptor cache for `onionHost`.
    /// Call after `bootstrap()` returned and before opening a SOCKS5
    /// CONNECT against the same onion.
    ///
    /// **Why this exists.** Tor's `BOOTSTRAP=100` / `CIRCUIT_ESTABLISHED`
    /// event means tor can build circuits — it does NOT mean tor can
    /// satisfy a `.onion` connect. The hidden-service dial path
    /// additionally needs:
    ///   * an HS descriptor fetched off the HSDirs (5–10 s cold),
    ///   * an introduction circuit to one of the descriptor's intro
    ///     points (3–5 s),
    ///   * a rendezvous circuit (3–5 s, parallel to the previous).
    /// A SOCKS5 CONNECT issued before the descriptor is cached either
    /// blocks for ~30 s (best case) or returns `REP=0x06 TTL expired`
    /// once tor's `MaxClientCircuitsPending` watchdog fires. Either
    /// way, the first cold-launch attempt fails. This call kicks off
    /// step 1 explicitly (`HSFETCH`) and only resumes once the matching
    /// `HS_DESC RECEIVED` event arrives. The follow-up SOCKS5 CONNECT
    /// goes straight into intro/rendezvous and completes inside the
    /// retry window already built into RelayClient.
    ///
    /// Concurrent callers for the same onion share one in-flight
    /// fetch (we coalesce on `hsFetchTasks`). Cancelling the awaiting
    /// task does NOT cancel the underlying HSFETCH — tor caches the
    /// descriptor either way, and the next caller will see RECEIVED
    /// from the cache.
    public func prepareHiddenService(_ onionHost: String) async throws {
        let address = Self.stripOnionSuffix(onionHost).lowercased()
        guard isReady, let controller = torController else {
            throw TorControllerError.notBootstrapped
        }

        // Fast path: tor's local cache holds the descriptor from an
        // earlier prime in this tor session. Skip the round-trip.
        if preparedOnions.contains(address) {
            torLog.debug("hsfetch: skip (descriptor already primed this tor session) addr=\(address.prefix(8), privacy: .public)…")
            return
        }

        // Coalesce. The hsFetchTasks map is keyed by onion address;
        // two concurrent RelayClient connects against the same relay
        // share a single in-flight fetch. Two different onions get
        // two parallel HSFETCHes — tor handles them independently.
        if let inflight = hsFetchTasks[address] {
            try await inflight.value
            return
        }
        let task = Task<Void, Error> { [weak self] in
            guard let self else { throw TorControllerError.cancelled }
            try await self.runHsFetch(address: address, on: controller)
            // Mark prepared only on success — failed fetches must
            // retry on the next call.
            self.preparedOnions.insert(address)
        }
        hsFetchTasks[address] = task
        do {
            try await task.value
            hsFetchTasks[address] = nil
        } catch {
            hsFetchTasks[address] = nil
            throw error
        }
    }

    // ─── Internals ────────────────────────────────────────────────────

    private func stopInternal() {
        // CRITICAL: use `closeControlChannel` (Pizzini-only), NOT
        // `disconnect`. The latter issues `SIGNAL SHUTDOWN` to tor,
        // which makes the embedded daemon exit cleanly
        // ("Interrupt: exiting cleanly" in tor's log) and orphans
        // `TORThread.active` — the next `bootstrap()` reuses a
        // dead-tor thread, polls 30 s for cookie/controlport files
        // that will never appear, throws `missingCookie`, and
        // retries forever. `closeControlChannel` shuts down the
        // socket only, leaving tor running so reconnection is a
        // re-auth round-trip rather than a full bootstrap.
        torController?.closeControlChannel()
        torController = nil
        // We do NOT release `torThread`. TORThread upstream enforces
        // a one-thread-per-process invariant via abort(), and
        // `tor_run_main()` is single-shot anyway. Leave the daemon
        // alive in the background; the next `bootstrap()` re-reads
        // the still-valid cookie + re-opens the control socket
        // against the still-listening tor.
        isReady = false
        bootstrapProgress = 0
    }

    private func runBootstrap() async throws -> UInt16 {
        let bootstrapStart = Date()
        torLog.info("bootstrap: begin")
        // First bootstrap also installs the NWPathMonitor. We pin it
        // for the process lifetime — there's no use case for stopping
        // it (tor itself is process-singleton; the path observer
        // mirrors that lifetime).
        Self.ensurePathMonitorStarted()
        // Reuse the existing tor thread if one is already running.
        // TORThread enforces one-per-process; `TORThread.active`
        // returns the live instance (or nil before the first start).
        // On a reconnect after `stop()`, this skips re-creating tor
        // and goes straight to controller re-auth.
        let dataDir: URL
        let reusedThread: Bool
        if let existing = torThread ?? TORThread.active {
            torThread = existing
            reusedThread = true
            if let cached = bootstrappedDataDir {
                dataDir = cached
            } else {
                dataDir = try resolveDataDirectory()
            }
        } else {
            reusedThread = false
            // Double-check that no TORThread is alive in the process
            // before we ask C-tor to allocate a fresh one. The
            // composite `torThread ?? TORThread.active` test above
            // covers the happy path; this guard is belt-and-braces
            // against a future refactor that splits the check from
            // the construction. `precondition` (NOT `assert`) so the
            // guard survives -O builds — the only safe action if
            // both checks somehow disagreed is to refuse the second
            // tor; everything else is undefined behaviour.
            precondition(
                TORThread.active == nil,
                "TORThread.active != nil but torThread is nil — TORThread retain dropped while tor is still running. tor_run_main() is single-shot per process."
            )
            dataDir = try resolveDataDirectory()
            // Delete the cookie + controlport files left behind by a
            // previous app-process launch. See `purgeStaleControlFiles`
            // below for why this is load-bearing.
            let purge = Self.purgeStaleControlFiles(in: dataDir)
            if purge.anyRemoved {
                torLog.info("bootstrap: removed stale control files (cookie=\(purge.cookieRemoved) port=\(purge.portRemoved)) from previous session")
            }
            let config = makeConfiguration(dataDir: dataDir)
            let thread = TORThread(configuration: config)
            torThread = thread
            thread.start()
        }
        bootstrappedDataDir = dataDir
        torLog.info("bootstrap: thread \(reusedThread ? "reused" : "started") dataDir=\(dataDir.lastPathComponent, privacy: .public)")
        let config = makeConfiguration(dataDir: dataDir)

        // tor writes the cookie + control-port file lazily during
        // early startup. Poll for BOTH before constructing the
        // controller — the cookie alone isn't sufficient because
        // `TORController.initWithControlPortFile:` parses
        // `<dataDir>/controlport` *synchronously* during init, and a
        // file that's missing or still empty produces a controller
        // with nil host / port=0 whose subsequent `connect()` falls
        // through and returns NO with `*error == nil`, surfacing as
        // a useless `GenericObjCError.nilError` to Swift.
        let cookieURL = dataDir.appendingPathComponent("control_auth_cookie")
        guard let controlPortFile = config.controlPortFile else {
            // `autoControlPort = YES` always sets this; the guard is
            // belt-and-braces for a future TORConfiguration change.
            torLog.error("bootstrap: controlPortFile is nil — TORConfiguration misconfigured")
            throw TorControllerError.missingCookie
        }
        do {
            let phaseStart = Date()
            try await waitForFile(at: cookieURL, deadline: Self.startupFilePollDeadline)
            torLog.info("bootstrap: cookie file appeared after \(Self.fmtElapsed(from: phaseStart)) (total \(Self.fmtElapsed(from: bootstrapStart)))")
            let phase2Start = Date()
            try await waitForControlPortFile(at: controlPortFile, deadline: Self.startupFilePollDeadline)
            torLog.info("bootstrap: controlport file appeared after \(Self.fmtElapsed(from: phase2Start)) (total \(Self.fmtElapsed(from: bootstrapStart)))")
        } catch {
            torLog.error("bootstrap: startup files did not appear within \(Int(Self.startupFilePollDeadline)) s — tor likely crashed. cookie=\(cookieURL.path, privacy: .public) controlport=\(controlPortFile.path, privacy: .public)")
            throw TorControllerError.missingCookie
        }
        guard let cookie = try? Data(contentsOf: cookieURL), !cookie.isEmpty else {
            torLog.error("bootstrap: cookie file present but unreadable / empty")
            throw TorControllerError.missingCookie
        }
        torLog.debug("bootstrap: cookie loaded (\(cookie.count) bytes)")

        let controller = TORController(controlPortFile: controlPortFile)
        torController = controller

        // TORController's init also calls `[self connect:nil]`
        // synchronously, but at that point tor has only written the
        // controlport file — its `listen()` on the control socket is
        // bound but tor's libevent main loop on iOS Simulator
        // cold-start can take 10-15 s to actually drain the accept
        // queue (it's busy fetching consensus, picking guards,
        // etc.). Each attempt either returns immediately (success)
        // or fails with ECONNREFUSED in microseconds; we retry on a
        // 200 ms cadence so we land within a tick of tor's listener
        // waking up.
        let connectPhaseStart = Date()
        do {
            try await retryControllerConnect(controller, deadline: Self.controllerConnectDeadline)
            torLog.info("bootstrap: control-port TCP connect ready after \(Self.fmtElapsed(from: connectPhaseStart)) (total \(Self.fmtElapsed(from: bootstrapStart)))")
        } catch {
            torLog.error("bootstrap: control-port TCP connect failed after \(Int(Self.controllerConnectDeadline)) s — tor's libevent loop never accepted. error=\(String(describing: error), privacy: .public)")
            throw error
        }

        let authStart = Date()
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            controller.authenticate(with: cookie) { success, error in
                if success {
                    cont.resume()
                } else if let error {
                    cont.resume(throwing: error)
                } else {
                    cont.resume(throwing: TorControllerError.authenticationFailed)
                }
            }
        }
        torLog.info("bootstrap: authenticate OK after \(Self.fmtElapsed(from: authStart)) (total \(Self.fmtElapsed(from: bootstrapStart)))")

        // Speculative HSFETCH: kick off descriptor lookups for the
        // host-primed onions BEFORE waiting for CIRCUIT_ESTABLISHED.
        // Tor accepts the HSFETCH command at the control port even
        // mid-bootstrap; the descriptor circuit races the
        // general-purpose circuit instead of being serialised behind
        // it. By the time RelayClient calls `prepareHiddenService`
        // the descriptor is usually already cached and we short-
        // circuit on `preparedOnions`, shaving ~2-3 s off cold-launch
        // dial latency. Failures are swallowed — the regular
        // prepareHiddenService path retries on demand.
        dispatchSpeculativeHsFetches()

        // Subscribe to STATUS_CLIENT events to drive bootstrapProgress.
        // The observer must capture self weakly — TORController retains
        // the block, and we don't want a retain cycle keeping the
        // controller (and its socket) alive past stop().
        // Both observer closures MUST be `@Sendable`. They're invoked
        // on TORController's serial control queue (a background
        // GCD queue), not on the MainActor. Swift 6 infers
        // enclosing-class isolation onto plain `@escaping` closures
        // that don't carry an explicit `@Sendable` marker, which
        // would mean Swift's runtime traps with EXC_BREAKPOINT the
        // moment TORController calls them off the MainActor. The
        // explicit `@Sendable` opts out of that inference. Captured
        // state (self via weak ref, the BootstrapResumer class) is
        // already Sendable-safe.
        let progressObserver = controller.addObserver(forStatusEvents: { @Sendable [weak self] type, _, action, arguments in
            // Tor emits `STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=N TAG=...
            // SUMMARY="..."`. We only care about progress integers.
            guard type == "STATUS_CLIENT", action == "BOOTSTRAP" else { return false }
            guard let raw = arguments?["PROGRESS"], let pct = Int(raw) else { return false }
            let tag = arguments?["TAG"] ?? ""
            torLog.debug("bootstrap: progress=\(pct)% tag=\(tag, privacy: .public)")
            Task { @MainActor [weak self] in
                self?.bootstrapProgress = pct
            }
            // Don't claim the event — other observers (e.g. tests) may
            // also want to see it.
            return false
        })
        // Sanity guard against ARC eating the observer (TORController
        // stores blocks in an NSArray; the return value is the block
        // itself). Holding a reference at function scope keeps it
        // alive past the suspension below. The actual long-term
        // ownership lives inside TORController's internal observer
        // array, so we can drop the variable on the way out.
        _ = progressObserver

        // Wait for circuit-established (the definitive ready signal —
        // tor emits CIRCUIT_ESTABLISHED the first time it has a
        // usable first-hop). The deadline lives inside the same
        // continuation as a sibling timer task so we don't have to
        // hand the non-Sendable TORController to a task group.
        let circuitStart = Date()
        do {
            try await awaitCircuitEstablished(on: controller)
            torLog.info("bootstrap: CIRCUIT_ESTABLISHED after \(Self.fmtElapsed(from: circuitStart)) (total \(Self.fmtElapsed(from: bootstrapStart)))")
        } catch {
            torLog.error("bootstrap: CIRCUIT_ESTABLISHED wait failed after \(Self.fmtElapsed(from: circuitStart)) — error=\(String(describing: error), privacy: .public)")
            throw error
        }

        // Drive progress to 100 even if the BOOTSTRAP event arrived
        // out of order with respect to CIRCUIT_ESTABLISHED. The UI
        // shouldn't ever see "ready" while still showing 87%.
        bootstrapProgress = 100
        isReady = true
        torLog.info("bootstrap: ready (total \(Self.fmtElapsed(from: bootstrapStart)))")
        return Self.fixedSocksPort
    }

    private func awaitCircuitEstablished(on controller: TORController) async throws {
        // The continuation has three competing resume paths:
        //   1. The TORController observer fires asynchronously.
        //   2. The TORController observer fires SYNCHRONOUSLY from
        //      inside `addObserver(...)` (warm-cache reconnect: tor
        //      already has an established circuit when we subscribe).
        //   3. The stall watchdog fires (no progress for stallTimeout
        //      seconds, OR total elapsed past hardDeadline).
        // Whichever resolves first wins; `BootstrapResumer` keeps
        // both `done` and `observerToken` under a single unfair lock
        // so a synchronous observer callback fired before `bind`
        // recorded the token cannot leak the observer.
        let stallTimeout = Self.bootstrapStallTimeout
        let hardDeadline = Self.bootstrapHardDeadline
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let resumer = BootstrapResumer(controller: controller, continuation: cont)
            let token = controller.addObserver(forCircuitEstablished: { @Sendable established in
                guard established else { return }
                resumer.resolveSuccess()
            })
            // The observer above may have already fired and
            // resumed the continuation (warm cache); `bind` then
            // detects `done == true` and removes the token
            // inline to prevent the observer leaking on
            // TORController.
            resumer.bind(observerToken: token)

            // Stall watchdog: poll bootstrapProgress every second
            // and only declare failure if (a) progress has been
            // unchanged for `stallTimeout` seconds OR (b) total
            // elapsed has reached `hardDeadline`. The previous
            // single-shot deadline killed slow-but-progressing
            // cold-launch bootstraps the moment the clock hit 90s,
            // even though tor would have completed in another few
            // seconds. With the stall check, only genuinely-broken
            // networks (no progress in a full minute) fail; the
            // common-case cold launch on cellular completes
            // without ever surfacing a `.failed` state.
            // Bootstrap watchdog. `Task { ... }` (NOT `.detached`)
            // because:
            //   * The enclosing method is on `@MainActor TorController`,
            //     so a child task inherits MainActor isolation —
            //     `self.bootstrapProgress` reads are in-isolation, no
            //     `MainActor.run` hop needed.
            //   * Under Swift 6 strict concurrency, the prior shape
            //     (`Task.detached { @MainActor [..., weak/strong self]
            //     in ... }`) tripped a region-isolation-checker bug
            //     ("pattern that the region-based isolation checker
            //     does not understand how to check"). The plain
            //     `Task` form sidesteps the bug.
            //   * Cancellation: the watchdog's only job is to resolve
            //     the `resumer` on stall/deadline. If the caller of
            //     `awaitCircuitEstablished` cancels, no one is
            //     awaiting the resumer — letting the child task
            //     cancel too is the correct behaviour (the prior
            //     `.detached` was over-cautious here; tor's own
            //     bootstrap state continues regardless of whether
            //     this Swift-side watchdog is alive).
            //   * `self` captured strongly: TorController is a
            //     process-wide singleton (`public static let shared`),
            //     so there's no leak surface — the instance lives
            //     for the app's lifetime regardless.
            Task { [resumer, self] in
                let start = Date()
                var lastProgress = self.bootstrapProgress
                var lastChange = Date()
                while !Task.isCancelled {
                    try? await Task.sleep(nanoseconds: 1_000_000_000) // 1 s
                    let now = Date()
                    let current = self.bootstrapProgress
                    if current != lastProgress {
                        lastProgress = current
                        lastChange = now
                    }
                    // Hard ceiling.
                    if now.timeIntervalSince(start) >= hardDeadline {
                        resumer.resolveTimeout(after: hardDeadline)
                        return
                    }
                    // Stall — no progress in stallTimeout. Two
                    // sub-cases:
                    //   • we never moved off 0 ⇒ tor never started
                    //     making progress (network broken, or tor
                    //     crashed). Surface failure so the host's
                    //     auto-reconnect path retries.
                    //   • we plateaued mid-bootstrap (e.g. 75% for
                    //     60s). Also a network-broken signal.
                    if now.timeIntervalSince(lastChange) >= stallTimeout {
                        resumer.resolveTimeout(after: stallTimeout)
                        return
                    }
                }
            }
        }
    }

    /// Single-fire bridge between the circuit-established observer,
    /// the deadline timer, and the CheckedContinuation in
    /// `awaitCircuitEstablished`. Encapsulating it as a class lets us
    /// mark the whole thing `@unchecked Sendable` and keeps the
    /// non-Sendable TORController + observer-token references out of
    /// the surrounding @Sendable closures.
    final class BootstrapResumer: @unchecked Sendable {
        private let controller: TORController
        private let continuation: CheckedContinuation<Void, Error>
        // Combined state under one lock: `done` (single-fire guard)
        // and `observerToken` (set during bind, read during detach).
        // Single-lock ordering closes the warm-cache race where a
        // synchronous observer callback fires from inside
        // `addObserver` before bind has recorded the token —
        // resolveSuccess sees `observerToken == nil`, sets `done`,
        // then bind() runs, sees `done == true`, and removes the
        // token inline.
        // `Any?` is not Sendable; OSAllocatedUnfairLock<State> requires
        // State: Sendable. The observer token TORController hands back
        // is opaque (an NSArray-of-blocks index in iCepa's API) and
        // safe to pass across threads, but the type system can't
        // verify that. Wrap it in `@unchecked Sendable` to assert the
        // claim and keep the lock generic-bound on a Sendable type.
        private struct State: @unchecked Sendable {
            var done: Bool = false
            var observerToken: Any? = nil
        }
        private let lock = OSAllocatedUnfairLock<State>(initialState: State())

        init(controller: TORController, continuation: CheckedContinuation<Void, Error>) {
            self.controller = controller
            self.continuation = continuation
        }

        /// Record the observer token. If `resolveSuccess` or
        /// `resolveTimeout` already won (warm-cache: the
        /// circuit-established observer fired synchronously inside
        /// `addObserver` before this function was reached), detach
        /// the token immediately so it doesn't leak on
        /// TORController's internal observer array.
        func bind(observerToken token: Any) {
            // The observer token TORController hands us is opaque
            // `Any`; iCepa's API doesn't expose a richer type. It's
            // safe to move across threads because TORController
            // owns its own serialisation, but Swift 6 doesn't
            // know that. Box the token through a struct that
            // explicitly opts into `@unchecked Sendable` so we can
            // both store it inside the lock-guarded State and pass
            // it back to `removeObserver` on the cleanup path.
            let boxed = TokenBox(token)
            let alreadyResolved: Bool = lock.withLock { state in
                if state.done {
                    return true
                }
                state.observerToken = boxed.unwrap()
                return false
            }
            if alreadyResolved {
                Self.removeObserverUnsafe(controller, boxed.unwrap())
            }
        }

        /// `@unchecked Sendable` box over the opaque observer token.
        /// The token is internally an NSArray index TORController
        /// owns; passing it across threads is safe in practice.
        private struct TokenBox: @unchecked Sendable {
            private let value: Any
            init(_ value: Any) { self.value = value }
            func unwrap() -> Any { value }
        }

        func resolveSuccess() {
            let outcome = claim()
            guard outcome.winner else { return }
            if let t = outcome.token {
                Self.removeObserverUnsafe(controller, t)
            }
            continuation.resume()
        }

        func resolveTimeout(after seconds: TimeInterval) {
            let outcome = claim()
            guard outcome.winner else { return }
            if let t = outcome.token {
                Self.removeObserverUnsafe(controller, t)
            }
            continuation.resume(throwing: TorControllerError.bootstrapTimedOut(after: seconds))
        }

        /// Atomically flip `done` to true and extract whatever
        /// `observerToken` was recorded so far. `winner == false`
        /// means another caller already claimed (loser path);
        /// `winner == true` with `token == nil` means we won but
        /// bind() hasn't run yet (subscribe still in flight — bind
        /// will see `done == true` and clean up itself).
        private struct ClaimOutcome: @unchecked Sendable {
            let winner: Bool
            let token: Any?
        }
        private func claim() -> ClaimOutcome {
            lock.withLock { state in
                if state.done {
                    return ClaimOutcome(winner: false, token: nil)
                }
                state.done = true
                let t = state.observerToken
                state.observerToken = nil
                return ClaimOutcome(winner: true, token: t)
            }
        }

        /// Static-dispatch wrapper so we can call `removeObserver`
        /// from a `@Sendable` context without Swift complaining
        /// that `Any` isn't Sendable. The observer-token shape is
        /// genuinely thread-safe (TORController serialises its
        /// observer-array writes), so the unchecked move is sound.
        nonisolated(unsafe) private static func removeObserverUnsafe(_ c: TORController, _ token: Any) {
            c.removeObserver(token)
        }

        /// Wrapper that lets `claim()` distinguish "already
        /// claimed" (nil ClaimedToken) from "claimed but no token
        /// recorded yet" (ClaimedToken with nil token).
        private struct ClaimedToken: @unchecked Sendable {
            let token: Any?
            func unwrap() -> Any? { token }
        }
    }

    /// Single-fire bridge between the HS_DESC observer, the HSFETCH
    /// command-failure path, and the deadline timer in `runHsFetch`.
    /// Shares its locking shape with `BootstrapResumer` so the
    /// warm-cache observer-fires-synchronously race is closed the
    /// same way.
    final class HsFetchResumer: @unchecked Sendable {
        private let controller: TORController
        private let continuation: CheckedContinuation<Void, Error>
        private let address: String
        private struct State: @unchecked Sendable {
            var done: Bool = false
            var observerToken: Any? = nil
        }
        private let lock = OSAllocatedUnfairLock<State>(initialState: State())

        init(
            controller: TORController,
            continuation: CheckedContinuation<Void, Error>,
            address: String,
        ) {
            self.controller = controller
            self.continuation = continuation
            self.address = address
        }

        func bind(observerToken token: Any) {
            let boxed = TokenBox(token)
            let alreadyResolved: Bool = lock.withLock { state in
                if state.done { return true }
                state.observerToken = boxed.unwrap()
                return false
            }
            if alreadyResolved {
                Self.removeObserverUnsafe(controller, boxed.unwrap())
            }
        }

        func resolveSuccess() {
            let outcome = claim()
            guard outcome.winner else { return }
            if let t = outcome.token {
                Self.removeObserverUnsafe(controller, t)
            }
            torLog.info("hsfetch: RECEIVED address=\(self.address.prefix(8), privacy: .public)…")
            continuation.resume()
        }

        func resolveFailure(reason: String) {
            let outcome = claim()
            guard outcome.winner else { return }
            if let t = outcome.token {
                Self.removeObserverUnsafe(controller, t)
            }
            torLog.error("hsfetch: FAILED address=\(self.address.prefix(8), privacy: .public)… reason=\(reason, privacy: .public)")
            continuation.resume(
                throwing: TorControllerError.hsDescriptorUnavailable(
                    onion: address,
                    reason: reason,
                ),
            )
        }

        func resolveTimeout(after seconds: TimeInterval) {
            let outcome = claim()
            guard outcome.winner else { return }
            if let t = outcome.token {
                Self.removeObserverUnsafe(controller, t)
            }
            torLog.error("hsfetch: TIMEOUT address=\(self.address.prefix(8), privacy: .public)… after \(Int(seconds))s")
            continuation.resume(
                throwing: TorControllerError.hsDescriptorUnavailable(
                    onion: address,
                    reason: "hsDescTimedOut after \(Int(seconds))s",
                ),
            )
        }

        /// Parse one `650 HS_DESC ...` event line and, if it matches
        /// the awaited address, resume the continuation. Returns
        /// false unconditionally (we never want to monopolise the
        /// reply line — other observers, e.g. the bootstrap-progress
        /// STATUS_CLIENT watcher, may share the dispatch).
        @discardableResult
        static func consume(
            eventLine: String,
            address: String,
            resumer: HsFetchResumer,
        ) -> Bool {
            // Format: "HS_DESC <ACTION> <HSAddress> <AuthType> [<HsDir>] [REASON=... ...]"
            // We need ACTION (1), HSAddress (2), and any REASON token
            // that follows. `split(separator:maxSplits:)` keeps the
            // remainder intact for cheap REASON scanning.
            guard eventLine.hasPrefix("HS_DESC ") else { return false }
            let parts = eventLine.split(separator: " ", omittingEmptySubsequences: true)
            guard parts.count >= 3 else { return false }
            let action = String(parts[1])
            let hsAddress = String(parts[2]).lowercased()
            // Log EVERY HS_DESC event we see — including ones for
            // other onions, or actions we don't act on. Without this,
            // a tor that's emitting REQUESTED but never RECEIVED
            // looks identical from outside to a tor that's silent;
            // we want to be able to tell those two cases apart in
            // the next log dump.
            let matches = (hsAddress == address)
            torLog.debug("hsfetch: observed HS_DESC \(action, privacy: .public) addr=\(hsAddress.prefix(8), privacy: .public)… match=\(matches)")
            guard matches else { return false }
            switch action {
            case "RECEIVED":
                resumer.resolveSuccess()
            case "FAILED":
                let reason: String = {
                    for tok in parts.dropFirst(3) where tok.hasPrefix("REASON=") {
                        return String(tok.dropFirst("REASON=".count))
                    }
                    return "unknown"
                }()
                resumer.resolveFailure(reason: reason)
            default:
                // REQUESTED / IGNORE / UPLOAD / UPLOADED / CREATED:
                // intermediate or unrelated to our wait condition.
                break
            }
            return false
        }

        private struct TokenBox: @unchecked Sendable {
            private let value: Any
            init(_ value: Any) { self.value = value }
            func unwrap() -> Any { value }
        }
        private struct ClaimOutcome: @unchecked Sendable {
            let winner: Bool
            let token: Any?
        }
        private func claim() -> ClaimOutcome {
            lock.withLock { state in
                if state.done {
                    return ClaimOutcome(winner: false, token: nil)
                }
                state.done = true
                let t = state.observerToken
                state.observerToken = nil
                return ClaimOutcome(winner: true, token: t)
            }
        }

        nonisolated(unsafe) private static func removeObserverUnsafe(
            _ c: TORController,
            _ token: Any,
        ) {
            c.removeObserver(token)
        }
    }


    /// Start the shared NWPathMonitor if it isn't already running.
    /// The first MainActor hop seeds `lastPathFingerprint` without
    /// signalling — there's no "previous" state to compare against
    /// on the first sample.
    nonisolated static func ensurePathMonitorStarted() {
        if pathMonitor != nil { return }
        let monitor = NWPathMonitor()
        pathMonitor = monitor
        monitor.pathUpdateHandler = { path in
            let fp = computePathFingerprint(path)
            Task { @MainActor in
                TorController.shared.handlePathChange(fingerprint: fp)
            }
        }
        monitor.start(queue: pathMonitorQueue)
    }

    /// Stable string fingerprint of an NWPath. Covers everything
    /// the user instructions called out: `status`, `isConstrained`,
    /// and the set of interface types the path uses. A change in
    /// any of those rotates the fingerprint so the MainActor
    /// handler fires NEWNYM + redial.
    nonisolated static func computePathFingerprint(_ path: NWPath) -> String {
        let types = path.availableInterfaces
            .map { "\($0.type)" }
            .sorted()
            .joined(separator: ",")
        return "\(path.status):\(path.isConstrained):\(types)"
    }

    /// MainActor-side path-change handler. First sample seeds the
    /// fingerprint and exits; subsequent samples that differ from
    /// the recorded one rotate tor's stream-isolation pool via
    /// SIGNAL NEWNYM and post a notification so the host drops +
    /// redials its RelayClient sockets. Never issues SIGNAL
    /// SHUTDOWN — that would kill the daemon (see commit 44eaec7).
    func handlePathChange(fingerprint fp: String) {
        let previous = lastPathFingerprint
        lastPathFingerprint = fp
        guard Self.shouldRotateCircuits(previous: previous, current: fp) else {
            if previous == nil {
                torLog.debug("path: initial fingerprint=\(fp, privacy: .public)")
            }
            return
        }
        torLog.notice("path: changed \(previous ?? "<nil>", privacy: .public) → \(fp, privacy: .public) — rotating circuits")
        sendNewnymSignal()
        NotificationCenter.default.post(
            name: .pizziniTorNetworkPathChanged,
            object: self,
        )
    }

    /// Pure decision: should a fingerprint transition fire a
    /// circuit-rotation? First sample (previous == nil) always
    /// returns false — there's no prior state to invalidate.
    /// Same-fingerprint repeats return false. Anything else
    /// returns true. Public so the iOS app test target can pin
    /// the contract — see `NetworkPathRotationTests` in
    /// `pizziniTests`.
    public nonisolated static func shouldRotateCircuits(
        previous: String?,
        current: String
    ) -> Bool {
        guard let previous else { return false }
        return previous != current
    }

    /// SIGNAL NEWNYM — tells tor to start using fresh circuits for
    /// future streams. Existing circuits are not torn down (a
    /// streamcount=0 circuit will idle out on its own); the host's
    /// relay-redial drops the SOCKS5 TCP socket which forces a new
    /// circuit on reconnect. NEWNYM is the right primitive here:
    /// SIGNAL RELOAD would also rotate guard-set selection logic
    /// which is overkill for a wifi→cellular handoff. No-op if the
    /// control channel isn't currently authenticated.
    private func sendNewnymSignal() {
        guard let controller = torController, controller.isConnected else {
            torLog.debug("path: NEWNYM skipped — controller not connected")
            return
        }
        controller.sendCommand("SIGNAL", arguments: ["NEWNYM"], data: nil) { @Sendable codes, _, stop in
            let ok = codes.first?.intValue == 250
            torLog.debug("path: NEWNYM \(ok ? "OK" : "rejected")")
            stop.pointee = true
            return true
        }
    }

    /// Fire HSFETCH for each onion in `onionsToPrime` that we haven't
    /// already cached and don't already have an in-flight fetch for.
    /// The tasks live in `hsFetchTasks` so a concurrent
    /// `prepareHiddenService(_:)` from RelayClient coalesces onto
    /// the same in-flight fetch instead of stacking a second one.
    private func dispatchSpeculativeHsFetches() {
        guard let controller = torController, !onionsToPrime.isEmpty else { return }
        var dispatched = 0
        for address in onionsToPrime {
            if preparedOnions.contains(address) { continue }
            if hsFetchTasks[address] != nil { continue }
            let task = Task<Void, Error> { [weak self] in
                guard let self else { throw TorControllerError.cancelled }
                try await self.runHsFetch(address: address, on: controller)
                self.preparedOnions.insert(address)
            }
            hsFetchTasks[address] = task
            // Drain on completion so a subsequent prime-list update
            // can re-dispatch this onion if needed.
            Task { [weak self, address] in
                _ = try? await task.value
                self?.hsFetchTasks[address] = nil
            }
            dispatched += 1
        }
        if dispatched > 0 {
            torLog.info("hsfetch: speculative dispatch (\(dispatched) onions)")
        }
    }

    private func resolveDataDirectory() throws -> URL {
        let fm = FileManager.default
        // Library/Caches/tor — eviction-safe. Tor's consensus cache
        // can be rebuilt from the network if iOS purges it; nothing
        // here is user data.
        let caches = try fm.url(
            for: .cachesDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let dir = caches.appendingPathComponent("tor", isDirectory: true)
        if !fm.fileExists(atPath: dir.path) {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        return dir
    }

    private func makeConfiguration(dataDir: URL) -> TORConfiguration {
        let config = TORConfiguration()
        config.ignoreMissingTorrc = true
        // F-NEW: we deliberately skip writing geoip/geoip6 — the
        // tor circuit selection logic for client-only doesn't need
        // them, and shipping the ~3MB pair would bloat the app
        // without buying us anything.
        config.cookieAuthentication = true
        config.autoControlPort = true
        // `avoidDiskWrites` was on historically as a flash-longevity
        // gesture. Cost: every cold launch re-downloads the
        // ~2.5 MB consensus + microdescriptor set AND re-picks fresh
        // guards from scratch — ~6-8 s on real-device cellular.
        // Leaving it off lets tor persist `cached-microdesc-consensus`,
        // `cached-microdescs`, `cached-certs`, and `state` (the guard
        // set) under `Library/Caches/tor/`, so the next cold launch
        // loads them off disk, validates against the cached directory
        // authority certs, and is ready in 1-2 s. iOS may evict the
        // cache under storage pressure; the fallback is the old
        // re-download path, so no correctness regression.
        config.avoidDiskWrites = false
        config.clientOnly = true
        config.dataDirectory = dataDir
        // IMPORTANT: do NOT set `config.socksPort` AND a SocksPort
        // entry in `options`. TORConfiguration.compile() emits both
        // verbatim (the typed property as `--SocksPort N`, the
        // options entry as `--SocksPort 127.0.0.1:N OnionTrafficOnly`),
        // and tor reads two SocksPort directives as "bind a second
        // listener too" — the second bind fails with EADDRINUSE
        // because the first one already grabbed the port, tor exits
        // before writing the cookie, and our `bootstrap()` returns
        // `missingCookie` after the 5 s poll. The options-only form
        // is the one we want because it carries the
        // `OnionTrafficOnly` flag (restricts the SOCKS proxy to
        // .onion targets — defence-in-depth in case RelayClient
        // ever forgets to honour `.hasSuffix(".onion")`).
        config.options = [
            // Loopback-only. No external interface should ever bind
            // tor's SOCKS port — RelayClient dials 127.0.0.1.
            "SocksPort": "127.0.0.1:\(Self.fixedSocksPort) OnionTrafficOnly",
            // Suppress tor's stderr log spam in Release builds.
            // `Log notice` keeps startup signal without dumping
            // per-circuit debug noise into the system console.
            "Log": "notice stdout",
            // Disable IPv6-only bridges and similar features that
            // would slow first-hop selection on iOS-typical networks.
            "ClientUseIPv6": "1",
            "ClientPreferIPv6ORPort": "0",
        ]
        return config
    }

    private func waitForFile(at url: URL, deadline: TimeInterval) async throws {
        let fm = FileManager.default
        let start = Date()
        while Date().timeIntervalSince(start) < deadline {
            if fm.fileExists(atPath: url.path) {
                return
            }
            try Task.checkCancellation()
            try await Task.sleep(nanoseconds: 100_000_000) // 100ms
        }
        throw TorControllerError.missingCookie
    }

    /// Poll-retry the control-port TCP connect until tor's listener
    /// actually accepts. Tor writes the controlport file *before* it
    /// completes `listen()` on the control socket, so the first
    /// connect attempt typically fails with ECONNREFUSED (POSIX 61);
    /// the second or third (a few hundred ms later) succeeds. 10 s
    /// is generous — happy-path is ~300 ms; sim cold-launch can
    /// stretch to a few seconds; anything longer is a real failure.
    private func retryControllerConnect(_ controller: TORController, deadline: TimeInterval) async throws {
        if controller.isConnected { return }
        let start = Date()
        var lastError: Error?
        while Date().timeIntervalSince(start) < deadline {
            do {
                try controller.connect()
                return
            } catch {
                lastError = error
                try Task.checkCancellation()
                try await Task.sleep(nanoseconds: 200_000_000) // 200 ms
            }
        }
        throw TorControllerError.controllerConnectFailed(
            underlying: lastError ?? TorControllerError.authenticationFailed
        )
    }

    /// Format an elapsed duration since `start` as `"%.2f s"`. Used
    /// throughout the bootstrap path's `torLog` lines so a future
    /// reader can spot which phase ate the budget on a slow cold
    /// start without needing to subtract timestamps by hand.
    nonisolated static func fmtElapsed(from start: Date) -> String {
        let s = Date().timeIntervalSince(start)
        return String(format: "%.2fs", s)
    }

    /// Remove tor's `control_auth_cookie` and `controlport` files
    /// from `dataDir` if they exist. Called by `runBootstrap` BEFORE
    /// starting a fresh `TORThread`.
    ///
    /// **Why this exists.** On real devices the data directory
    /// (`Library/Caches/tor/`) persists across app launches, but
    /// `ControlPort auto` makes tor pick a random control-port
    /// number every startup. A leftover `controlport` file from
    /// the previous session points at a port no one is listening
    /// on; `waitForControlPortFile` finds it instantly; the
    /// controller is built with the dead port; the subsequent
    /// connect spends its full deadline dialing nothing while the
    /// live tor sits on a different port we never learn about.
    /// Deleting both files first forces tor to rewrite them with
    /// the live port + a fresh cookie.
    ///
    /// This is the load-bearing fix for the "first launch shows
    /// 'connecting to Tor… 0%' for 60 seconds then flashes the
    /// reconnect pill" symptom.
    ///
    /// Public (not private) so the cleanup contract — exactly
    /// which filenames, exactly which directory, only these two —
    /// is pinned by `StaleControlFilesPurgeTests` in the iOS app
    /// test target. The `fileManager` parameter is for tests to
    /// stay scoped to a tmp dir; production callers take the
    /// default.
    public nonisolated static func purgeStaleControlFiles(
        in dataDir: URL,
        fileManager: FileManager = .default
    ) -> StaleControlFilesPurge {
        let cookieURL = dataDir.appendingPathComponent("control_auth_cookie")
        let portURL = dataDir.appendingPathComponent("controlport")
        let cookieExists = fileManager.fileExists(atPath: cookieURL.path)
        let portExists = fileManager.fileExists(atPath: portURL.path)
        if cookieExists {
            try? fileManager.removeItem(at: cookieURL)
        }
        if portExists {
            try? fileManager.removeItem(at: portURL)
        }
        return StaleControlFilesPurge(
            cookieRemoved: cookieExists,
            portRemoved: portExists,
        )
    }

    /// Drop a trailing `.onion` suffix if present (case-insensitive)
    /// so the bare 56-char base32 label can be compared against the
    /// `HSAddress` field tor reports in `HS_DESC` events.
    nonisolated static func stripOnionSuffix(_ host: String) -> String {
        let lower = host.lowercased()
        if lower.hasSuffix(".onion") {
            return String(lower.dropLast(6))
        }
        return lower
    }

    /// Issue an HSFETCH and wait for the matching HS_DESC RECEIVED
    /// (success) or HS_DESC FAILED (throws). Implementation note:
    /// we subscribe to the `HS_DESC` event *first*, then send
    /// `HSFETCH` — the reverse order has a race where tor could
    /// emit the RECEIVED event before our observer is registered,
    /// stranding the caller until the deadline.
    private func runHsFetch(address: String, on controller: TORController) async throws {
        let fetchStart = Date()
        torLog.info("hsfetch: begin address=\(address.prefix(8), privacy: .public)…")
        // Extend the active event subscription to include HS_DESC.
        // listenForEvents() REPLACES the active set, so we have to
        // re-issue every currently-subscribed event (STATUS_CLIENT
        // for bootstrap progress) plus the new HS_DESC.
        let current = controller.events.array.compactMap { $0 as? String }
        if !current.contains("HS_DESC") {
            let merged = current + ["HS_DESC"]
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                controller.listen(forEvents: merged) { success, error in
                    if success {
                        cont.resume()
                    } else if let error {
                        cont.resume(throwing: error)
                    } else {
                        cont.resume(throwing: TorControllerError.authenticationFailed)
                    }
                }
            }
            torLog.debug("hsfetch: subscribed to HS_DESC events")
        }

        let deadline = Self.hsFetchDeadline
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let resumer = HsFetchResumer(
                controller: controller,
                continuation: cont,
                address: address,
            )

            // Generic event observer. Matches "HS_DESC ACTION
            // <address> ..." lines. Stays on the controller's
            // observer list until resolver fires (which detaches
            // the token). Block runs on TORController's serial
            // control queue, off the MainActor — explicit
            // `@Sendable` opts out of Swift 6's automatic
            // enclosing-actor inference.
            let token = controller.addObserver { @Sendable codes, lines, _ in
                guard codes.first?.intValue == 650 else { return false }
                guard let lineData = lines.first as? Data,
                      let line = String(data: lineData, encoding: .utf8)
                else { return false }
                return HsFetchResumer.consume(eventLine: line, address: address, resumer: resumer)
            }
            resumer.bind(observerToken: token)

            // Fire HSFETCH. The sync `250 OK` ack is fire-and-forget;
            // the real signal is the async `650 HS_DESC RECEIVED`
            // (or `FAILED`) the generic observer above picks up.
            // tor accepts both `.onion` and bare-label arguments;
            // we send the bare label for symmetry with the HS_DESC
            // event format.
            torLog.debug("hsfetch: dispatching HSFETCH \(address.prefix(8), privacy: .public)…")
            controller.sendCommand(
                "HSFETCH",
                arguments: [address],
                data: nil,
            ) { @Sendable codes, lines, stop in
                guard let firstCode = codes.first?.intValue else { return false }
                // iCepa's `sendCommand:` registers a single observer in
                // the same `_blocks` array that dispatches ALL incoming
                // control-port frames — sync replies (2xx/5xx) AND
                // async event frames (6xx). The first frame to arrive
                // after we register can therefore be an unrelated 650
                // HS_DESC event for ANOTHER concurrent HSFETCH (or for
                // our own, mid-flight). Treat 6xx as "not our reply,
                // keep waiting" and let the dedicated HS_DESC observer
                // above handle the actual descriptor signal. Without
                // this skip, the very first HSFETCH dispatched after a
                // cold tor start gets falsely resolved as "HSFETCH
                // rejected — HS_DESC REQUESTED …" — the event body
                // gets mis-read as a sync error reason and the in-
                // flight task tears down before the real HS_DESC
                // RECEIVED arrives. Symptom: with a 3-relay fleet, the
                // first onion to be HSFETCH'd never resolves, only the
                // 2nd + 3rd connect.
                if (600...699).contains(firstCode) {
                    return false
                }
                if firstCode == 250 {
                    // Fetch initiated. The async HS_DESC event
                    // will resolve via the observer above.
                    torLog.debug("hsfetch: 250 OK ack received")
                    stop.pointee = true
                    return true
                }
                if (400...599).contains(firstCode) {
                    // tor rejected the command (unknown HS, malformed
                    // address, control port misconfigured, …). Surface
                    // as a failure so the caller doesn't sit on the
                    // deadline.
                    stop.pointee = true
                    let msg = (lines.first as? Data).flatMap {
                        String(data: $0, encoding: .utf8)
                    } ?? "HSFETCH rejected (\(firstCode))"
                    torLog.error("hsfetch: tor rejected HSFETCH — \(msg, privacy: .public)")
                    resumer.resolveFailure(reason: msg)
                    return true
                }
                return false
            }

            // Hard deadline. Detached so it survives if the calling
            // task is cancelled — tor will still cache whatever it
            // ends up fetching, and the next prepareHiddenService
            // call against the same address sees the cache hit.
            Task.detached { [resumer] in
                try? await Task.sleep(nanoseconds: UInt64(deadline * 1_000_000_000))
                resumer.resolveTimeout(after: deadline)
            }
        }
    }

    /// Like `waitForFile`, but tor's controlport file is written in
    /// two steps (touch then write the `PORT=host:port` line). A
    /// file that's present but still empty would let
    /// `TORController.initWithControlPortFile:` succeed but parse
    /// out nil host / port=0, then `connect()` returns NO with
    /// `*error == nil`. Wait until the file has the expected
    /// `PORT=...:NNN` shape before constructing the controller.
    private func waitForControlPortFile(at url: URL, deadline: TimeInterval) async throws {
        let start = Date()
        while Date().timeIntervalSince(start) < deadline {
            if let content = try? String(contentsOf: url, encoding: .utf8),
               let eq = content.range(of: "="),
               let colon = content.range(of: ":", range: eq.upperBound..<content.endIndex),
               let portInt = Int(
                   content[colon.upperBound..<content.endIndex]
                       .trimmingCharacters(in: .whitespacesAndNewlines)),
               portInt > 0
            {
                return
            }
            try Task.checkCancellation()
            try await Task.sleep(nanoseconds: 100_000_000) // 100ms
        }
        throw TorControllerError.missingCookie
    }
}
