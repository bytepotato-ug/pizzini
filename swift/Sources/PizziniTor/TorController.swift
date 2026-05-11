// Embedded Tor controller. Spins up a tor thread on first use, watches
// its bootstrap-progress events, and surfaces a local SOCKS5 port that
// the rest of the app dials when the relay address is a .onion.
//
// Architecture:
//
//   TorController.shared
//       │  bootstrap() async throws -> UInt16
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
import os
import PizziniTorObjC

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

    /// Deadline for the initial bootstrap. Cold start is 5-30s on
    /// good networks; tail can stretch to 60-90s on hostile ones
    /// (DPI, captive portals). 90s avoids spuriously failing on a
    /// flaky-but-recoverable network while still bounded enough
    /// that the UI doesn't lie about progress forever.
    nonisolated private static let bootstrapDeadline: TimeInterval = 90

    /// Tor's C runtime (`tor_run_main`) can only be invoked once per
    /// process — TORThread upstream enforces this via an NSAssert on
    /// a static `_thread` ivar. We mirror the lifecycle in Swift:
    /// the first successful `bootstrap()` creates the thread and we
    /// keep it for the duration of the process. Subsequent
    /// `stop()` / re-`bootstrap()` cycles only re-create the
    /// CONTROLLER (a TCP socket to tor's control port) — the daemon
    /// itself stays running. The cost is ~25 MB resident and a
    /// background CPU hum while idle; the alternative is a hard
    /// crash on every reconnect.
    private var torThread: TORThread?
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

    /// Tears down the running tor daemon. Used by the app-background
    /// flow after the relay drain window. Idempotent.
    public func stop() {
        pendingBootstrap?.cancel()
        pendingBootstrap = nil
        stopInternal()
    }

    // ─── Internals ────────────────────────────────────────────────────

    private func stopInternal() {
        torController?.disconnect()
        torController = nil
        // CRITICAL: we do NOT release `torThread`. TORThread
        // upstream enforces a one-thread-per-process invariant via
        // NSAssert, and `tor_run_main()` is single-shot anyway —
        // even if we cleared our reference, the static `_thread`
        // ivar in TORThread.m stays set, and any subsequent
        // `TORThread.init` would trip the assert and crash the
        // process. Leave the daemon alive in the background. The
        // next `bootstrap()` re-reads the still-valid cookie and
        // re-opens the control socket against the still-listening
        // tor, then re-subscribes to STATUS_CLIENT events —
        // typically completing in a few hundred ms because tor's
        // first circuit is already up.
        isReady = false
        bootstrapProgress = 0
    }

    private func runBootstrap() async throws -> UInt16 {
        // Reuse the existing tor thread if one is already running.
        // TORThread enforces one-per-process; `TORThread.active`
        // returns the live instance (or nil before the first start).
        // On a reconnect after `stop()`, this skips re-creating tor
        // and goes straight to controller re-auth.
        let dataDir: URL
        if let existing = torThread ?? TORThread.active {
            torThread = existing
            if let cached = bootstrappedDataDir {
                dataDir = cached
            } else {
                dataDir = try resolveDataDirectory()
            }
        } else {
            dataDir = try resolveDataDirectory()
            let config = makeConfiguration(dataDir: dataDir)
            let thread = TORThread(configuration: config)
            torThread = thread
            thread.start()
        }
        bootstrappedDataDir = dataDir
        let config = makeConfiguration(dataDir: dataDir)

        // tor writes the cookie + control-port file lazily during
        // early startup. Poll for BOTH before constructing the
        // controller — the cookie alone isn't sufficient because
        // `TORController.initWithControlPortFile:` parses
        // `<dataDir>/controlport` *synchronously* during init, and a
        // file that's missing or still empty produces a controller
        // with nil host / port=0 whose subsequent `connect()` falls
        // through and returns NO with `*error == nil`, surfacing as
        // a useless `GenericObjCError.nilError` to Swift. 15 s is
        // generous — happy-path tor writes both files within ~50 ms
        // of TORThread.start(), but iOS Simulator cold launches can
        // stall for several seconds before tor's first I/O lands.
        let cookieURL = dataDir.appendingPathComponent("control_auth_cookie")
        guard let controlPortFile = config.controlPortFile else {
            // `autoControlPort = YES` always sets this; the guard is
            // belt-and-braces for a future TORConfiguration change.
            throw TorControllerError.missingCookie
        }
        do {
            try await waitForFile(at: cookieURL, deadline: 15.0)
            try await waitForControlPortFile(at: controlPortFile, deadline: 15.0)
        } catch {
            NSLog("[pizzini-tor] startup files did not appear within 15 s — tor likely crashed. cookie=\(cookieURL.path) controlport=\(controlPortFile.path). Check iOS console for tor's stderr.")
            throw TorControllerError.missingCookie
        }
        guard let cookie = try? Data(contentsOf: cookieURL), !cookie.isEmpty else {
            throw TorControllerError.missingCookie
        }

        let controller = TORController(controlPortFile: controlPortFile)
        torController = controller

        // TORController's init also calls `[self connect:nil]`
        // synchronously, but at that point tor has only written the
        // controlport file — its `listen()` on the control socket
        // typically lags a few hundred ms behind, so that first
        // attempt fails with ECONNREFUSED (code 61) and the error
        // is swallowed by the `nil` error pointer. Retry with a
        // 200 ms cadence up to 10 s. Calling `connect()` on an
        // already-connected controller is a no-op (it short-
        // circuits on `_channel != nil`).
        try await retryControllerConnect(controller, deadline: 10.0)

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
        try await awaitCircuitEstablished(on: controller)

        // Drive progress to 100 even if the BOOTSTRAP event arrived
        // out of order with respect to CIRCUIT_ESTABLISHED. The UI
        // shouldn't ever see "ready" while still showing 87%.
        bootstrapProgress = 100
        isReady = true
        return Self.fixedSocksPort
    }

    private func awaitCircuitEstablished(on controller: TORController) async throws {
        // The continuation has two competing resume paths:
        //   1. The TORController observer fires with `established=true`.
        //   2. The deadline timer expires.
        // Whichever runs first wins. `BootstrapResumer` serialises
        // both paths behind an unfair lock so the underlying
        // CheckedContinuation is resumed exactly once. It also owns
        // the observer token + TORController reference so neither has
        // to leak across the @Sendable closure boundary in this
        // function.
        let deadline = Self.bootstrapDeadline
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            let resumer = BootstrapResumer(controller: controller, continuation: cont)
            let token = controller.addObserver(forCircuitEstablished: { @Sendable established in
                guard established else { return }
                resumer.resolveSuccess()
            })
            resumer.bind(observerToken: token)

            Task.detached { [resumer] in
                try? await Task.sleep(nanoseconds: UInt64(deadline * 1_000_000_000))
                resumer.resolveTimeout(after: deadline)
            }
        }
    }

    /// Single-fire bridge between the circuit-established observer,
    /// the deadline timer, and the CheckedContinuation in
    /// `awaitCircuitEstablished`. Encapsulating it as a class lets us
    /// mark the whole thing `@unchecked Sendable` and keeps the
    /// non-Sendable TORController + observer-token references out of
    /// the surrounding @Sendable closures.
    private final class BootstrapResumer: @unchecked Sendable {
        private let controller: TORController
        private let continuation: CheckedContinuation<Void, Error>
        private let lock = OSAllocatedUnfairLock<Bool>(initialState: false)
        private var observerToken: Any?

        init(controller: TORController, continuation: CheckedContinuation<Void, Error>) {
            self.controller = controller
            self.continuation = continuation
        }

        func bind(observerToken: Any) {
            // Stored without locking — `bind` is called synchronously
            // from `withCheckedThrowingContinuation`'s body, before
            // any observer callback can fire and before the deadline
            // timer has had a chance to wake.
            self.observerToken = observerToken
        }

        func resolveSuccess() {
            guard claim() else { return }
            detachObserver()
            continuation.resume()
        }

        func resolveTimeout(after seconds: TimeInterval) {
            guard claim() else { return }
            detachObserver()
            continuation.resume(throwing: TorControllerError.bootstrapTimedOut(after: seconds))
        }

        private func claim() -> Bool {
            lock.withLock { done in
                if done { return false }
                done = true
                return true
            }
        }

        private func detachObserver() {
            if let token = observerToken {
                controller.removeObserver(token)
                observerToken = nil
            }
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
        config.avoidDiskWrites = true
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
