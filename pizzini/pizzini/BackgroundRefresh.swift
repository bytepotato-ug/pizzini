import BackgroundTasks
import Foundation
import os
import UIKit

/// Secondary wake-up for APNs silent-push degradation. Belt-and-
/// braces — APNs is the primary path, but Apple's push delivery is
/// best-effort: throttled in low-power mode, paused on cellular DPI,
/// dropped during system updates, and **never delivered for
/// force-quit apps**. `BGAppRefreshTask` is iOS's official
/// "you may not have heard from us in a while, here's a few seconds
/// of CPU" hook, scheduled at the OS's discretion (typically
/// hourly-ish for an authorized app the user has used recently).
/// When it fires we open the relay socket long enough to drain any
/// queued backlog, then complete the task. iOS does the rest of
/// the wake-up budget accounting; we treat it as opportunistic.
///
/// **iOS configuration required.** The task identifier below must
/// be present in the main app's Info.plist under
/// `BGTaskSchedulerPermittedIdentifiers`, and `UIBackgroundModes`
/// must include `fetch`. Both are wired through the xcodeproj's
/// `INFOPLIST_KEY_*` build settings — see
/// `pizzini/pizzini.xcodeproj/project.pbxproj`. Without those keys
/// the `register` call below silently fails at runtime, the OS
/// refuses to schedule the task, and we fall back to "push or
/// foreground only" — same posture as before this file existed,
/// no regression.
enum BackgroundRefresh {

    /// Reverse-DNS task identifier. Must match the Info.plist
    /// entry exactly or `BGTaskScheduler.register` returns false.
    static let identifier = "app.pizzini.bgrefresh"

    /// Minimum delay between OS-scheduled fires. iOS treats this as
    /// a hint, not a contract — the actual cadence is dominated by
    /// the system's energy-and-usage budget. 1 h is the canonical
    /// "messenger-style background refresh" value; lower numbers
    /// don't make the OS fire sooner, they just look greedier in
    /// the budget accounting.
    static let earliestRefreshInterval: TimeInterval = 60 * 60

    /// Time budget we give the handler before voluntarily yielding.
    /// iOS itself enforces a ~30 s hard cap, but we want the relay
    /// reconnect + first frame drain to complete well inside that
    /// — 20 s leaves headroom for SOCKS5 retries on a slow
    /// network. If we time out internally, the handler completes
    /// with `success: false` so iOS lowers our scheduling
    /// priority instead of force-killing us.
    static let handlerBudgetSeconds: TimeInterval = 20

    private static let log = Logger(subsystem: "app.pizzini", category: "bgrefresh")

    /// Compute the BGAppRefreshTaskRequest earliest-begin date for
    /// the next submit, given the moment of submit and the
    /// minimum-cadence floor. Pure: no `Date()`, no `Calendar`
    /// other than what's passed in. Lets `BackgroundRefreshTests`
    /// pin the math without spinning up a real BGTaskScheduler.
    static func nextEarliestBeginDate(
        submittedAt: Date,
        cadenceFloor: TimeInterval = earliestRefreshInterval
    ) -> Date {
        submittedAt.addingTimeInterval(cadenceFloor)
    }

    /// Decide whether to submit a fresh request. The OS clears any
    /// pending request when it fires; if a previous handler is
    /// still running we want to leave that one to complete rather
    /// than queuing a second.
    static func shouldSubmit(
        appState: UIApplication.State,
        handlerInFlight: Bool
    ) -> Bool {
        // Active apps never need a BG refresh — they're already
        // foregrounded and `reconnectAfterBackground` will fire
        // soon. Only schedule from `.background` or `.inactive`.
        guard appState != .active else { return false }
        // A second submit while the handler is in flight would be
        // queued behind it; the OS may drop it as spam. Better to
        // submit fresh at the END of the in-flight handler.
        return !handlerInFlight
    }

    /// Call once at `didFinishLaunchingWithOptions`. Wires the
    /// handler closure to the BGTaskScheduler. Idempotent — Apple's
    /// `register` returns false on a re-register, which we ignore.
    /// Returns true if registration succeeded, false if the
    /// Info.plist permission is missing.
    @discardableResult
    static func register(
        handler: @escaping @MainActor (BGAppRefreshTask) -> Void
    ) -> Bool {
        let ok = BGTaskScheduler.shared.register(
            forTaskWithIdentifier: identifier,
            using: nil
        ) { task in
            guard let refresh = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            Task { @MainActor in
                handler(refresh)
            }
        }
        if !ok {
            log.notice("register failed — Info.plist BGTaskSchedulerPermittedIdentifiers missing '\(identifier, privacy: .public)' or UIBackgroundModes lacks 'fetch'; background refresh disabled")
        }
        return ok
    }

    /// Submit a refresh request. Call from
    /// `didEnterBackgroundNotification`. Safe to call when iOS has
    /// not granted the entitlement — `submit` throws and we log +
    /// swallow; no crash.
    static func submit() {
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = nextEarliestBeginDate(submittedAt: Date())
        do {
            try BGTaskScheduler.shared.submit(request)
            log.debug("submitted; earliest=\(request.earliestBeginDate?.description ?? "nil", privacy: .public)")
        } catch BGTaskScheduler.Error.unavailable {
            // Simulator (always) and devices without the
            // entitlement (Info.plist gap). Documented Apple
            // behaviour, not an error.
            log.debug("submit unavailable — likely simulator or missing entitlement")
        } catch {
            log.notice("submit failed: \(String(describing: error), privacy: .public)")
        }
    }

    /// Handle a fired refresh task. Drives the relay to drain its
    /// pending backlog, then completes. iOS hard-caps the handler
    /// at ~30 s; we self-cap at `handlerBudgetSeconds` so the OS
    /// sees a graceful completion rather than a forced kill.
    ///
    /// Caller must invoke `BackgroundRefresh.submit()` again from
    /// inside the completion to chain the next fire — iOS clears
    /// the request when the task starts.
    @MainActor
    static func handle(task: BGAppRefreshTask) {
        let store = ChatStore.shared
        log.debug("handler fired")
        // Single-fire completion guard. The expiration handler and
        // the budget timer might both want to complete the task;
        // only one of them must, or BGTaskScheduler logs a fault
        // and lowers our scheduling priority.
        let completion = BgRefreshCompletion()
        task.expirationHandler = {
            // OS told us we're out of time. Tear down whatever the
            // store has open and complete with success=false so the
            // OS knows the work was cut short.
            Task { @MainActor in
                if completion.claim() {
                    store.disconnectForBackground()
                    task.setTaskCompleted(success: false)
                    // Try again later regardless.
                    BackgroundRefresh.submit()
                }
            }
        }
        // Kick the relay so it dials, HELLOs, drains backlog. The
        // relay's HELLO triggers the pending-store fanout on the
        // server side — that's where any push that didn't arrive
        // actually catches up. We're not parsing messages here;
        // ChatStore's existing wiring delivers them to storage as
        // they come in.
        store.reconnectAfterBackground()
        // Self-impose the budget. When it fires (or when the
        // socket settles, whichever first), close out gracefully.
        let deadline = DispatchTime.now() + handlerBudgetSeconds
        DispatchQueue.main.asyncAfter(deadline: deadline) {
            guard completion.claim() else { return }
            store.disconnectForBackground()
            task.setTaskCompleted(success: true)
            BackgroundRefresh.submit()
        }
    }

    /// Single-fire claim — same pattern as
    /// `TorController.SingleFire`. Internal to this file so the
    /// public surface stays one identifier + four entry points.
    private final class BgRefreshCompletion: @unchecked Sendable {
        private let lock = OSAllocatedUnfairLock<Bool>(initialState: false)
        func claim() -> Bool {
            lock.withLock { fired in
                if fired { return false }
                fired = true
                return true
            }
        }
    }
}
