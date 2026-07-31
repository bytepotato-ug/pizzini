import Foundation
import LocalAuthentication
import SwiftUI

/// App-level biometric lock. One layer in Pizzini's protection model
/// (the others — at-rest DB encryption, duress passphrase, Lockdown
/// Mode, App Attest — are tracked in the README's Status checklist).
///
/// ## Why this is wired to `UIScene.*Notification` instead of SwiftUI's
/// `@Environment(\.scenePhase)` — read this before changing it.
///
/// SwiftUI updates `scenePhase` to `.active` *before* it runs the
/// `.onChange(of: scenePhase)` callback. If we keyed the privacy
/// shield to `scenePhase != .active`, the body would re-render with
/// the shield gone in the same frame the scene became active, and
/// the lock overlay would appear only on the *next* frame after
/// our callback set `isLocked = true`. The user sees one frame of
/// chat content. Bug.
///
/// The fix: don't ever let the privacy shield be tied to scenePhase.
/// `isShielded` is set explicitly on `UIScene.willDeactivateNotification`
/// and cleared explicitly on `UIScene.didActivateNotification`. The
/// lock decision happens on `UIScene.willEnterForegroundNotification`,
/// which fires *before* the scene becomes active — so by the time the
/// scene is `.foregroundActive`, both `isLocked` and `isShielded` are
/// already at their correct values and one render shows the right thing.
///
/// ## Behaviour
///
/// - When `state.biometricLockEnabled == false`, lock state is
///   permanently `.unlocked` and the foreground hooks short-circuit.
/// - When enabled, the app starts every cold launch in `.locked`.
///   Backgrounding records the time; `willEnterForeground` re-locks
///   if `(now - backgrounded) >= state.autoLockTimeout.seconds`.
/// - `LockOverlayView` calls `attemptUnlock()` on appear, which runs
///   `LAPolicy.deviceOwnerAuthentication` (biometrics with passcode
///   fallback — same as Signal).
///
/// Why a singleton: same reason as ChatStore — SwiftUI's @State
/// initialisers can fire more than once before the framework settles
/// which instance to keep, and we don't want concurrent `LAContext`
/// evaluations stepping on each other.
@MainActor
@Observable
final class LockManager {
    static let shared = LockManager()

    /// True when the lock overlay should be shown. Read by `ContentView`.
    private(set) var isLocked: Bool = false
    /// True when the in-body `PrivacyShieldView` overlay should mount.
    /// Covers the gap between `didActivate` (when `PrivacyShieldWindow`
    /// hides) and the lock overlay's first paint — a brief window
    /// where chat content would otherwise render in-tree.
    ///
    /// **NOTE on multitasking snapshot defense.** The MULTITASKING
    /// SNAPSHOT defense is `PrivacyShieldWindow`, NOT this flag.
    /// SwiftUI re-renders are async (next runloop tick), so flipping
    /// `isShielded` inside `willDeactivate` cannot guarantee an
    /// overlay frame paints before iOS captures the snapshot. The
    /// `PrivacyShieldWindow` is a separate UIWindow shown
    /// synchronously inside the willDeactivate handler — that's what
    /// the snapshot sees. The in-body `isShielded` overlay is a
    /// belt-and-suspenders cover for the activate→render gap.
    private(set) var isShielded: Bool = false
    /// True while a `LAContext.evaluatePolicy` call is in flight, so the
    /// UI can disable the "Unlock" button.
    private(set) var authInFlight: Bool = false
    /// Last user-visible auth error, surfaced on the lock overlay so the
    /// user knows whether to retry, use the passcode, or check Settings.
    private(set) var lastError: String?

    /// True when the user has summoned the passcode entry sheet from
    /// the lock overlay (via long-press, or directly when Face ID is
    /// disabled). Drives the LockOverlayView's `.sheet` presentation
    /// of `PasscodeEntryView`. Cleared when the sheet is dismissed
    /// or when a passcode entry succeeds.
    var isPasscodeSheetPresented: Bool = false

    /// True between a duress passcode being recognised and the wipe +
    /// re-bootstrap completing. While set, `submitPasscode` rejects
    /// re-entries with `.wrong` so a panicked second tap can't race
    /// the in-flight wipe and submit against the freshly-emptied
    /// Keychain (which would otherwise expose the fresh-install
    /// gate-less UI). Set by the lock-overlay coordinator; cleared
    /// by `unlockAfterDuress`.
    private(set) var wipeInFlight: Bool = false

    // MARK: - Brute-force throttle (S7-03)
    //
    // App-level rate limit on passcode entry. The persistent
    // failed-attempt COUNTER lives in `AppPasscode` (a ThisDeviceOnly
    // Keychain row that survives an app kill — an attacker cannot reset
    // it by force-quitting between guesses). This LockManager layer
    // turns that count into an escalating BACKOFF WINDOW: after enough
    // consecutive wrong guesses, additional WRONG guesses are bounced
    // for a growing delay, so a scripted attacker grinding the gate is
    // slowed far below the raw 2×Argon2id (~500 ms) per-guess cost.
    //
    // Two hard invariants:
    //   1. The duress (and real) passcode is ALWAYS evaluated and
    //      honored, even mid-backoff — a coerced user must never be
    //      blocked from entering the duress passcode. The throttle only
    //      ever delays/no-ops a `.neither` (wrong) result.
    //   2. No auto-wipe-on-N. Wiping after N failures would be a denial
    //      of service for a fat-fingered legitimate user (S7-03 calls
    //      this out explicitly); any wipe-on-N would have to be an
    //      opt-in setting. We add the throttle + delay only.

    /// Number of consecutive failures tolerated before the backoff
    /// curve begins to bite. Below this, wrong guesses are accepted at
    /// full speed (the Argon2id cost is the only limiter) so an
    /// occasional fat-finger has no friction.
    private static let backoffFreeAttempts = 4

    /// Monotonic (`CLOCK_UPTIME_RAW`) deadline before which a WRONG
    /// guess is bounced without consuming a new attempt. Uptime-based
    /// for the same reason as `backgroundedAtUptime`: a coercer winding
    /// the wall clock cannot shorten the backoff. `nil` when no backoff
    /// is active. Not persisted (the persistent signal is the counter
    /// in `AppPasscode`); on relaunch the counter re-establishes the
    /// curve from the first post-relaunch wrong guess.
    private var backoffUntilUptime: TimeInterval?

    /// Escalating backoff duration for a given consecutive-failure
    /// count. Zero for the first few failures, then grows in steps. The
    /// curve is bounded (saturates at a ceiling) so a legitimate user
    /// who eventually remembers the passcode is never locked out for an
    /// unbounded time — the duress passcode also remains enterable
    /// throughout regardless of this value.
    static func backoffDuration(forFailures failures: Int) -> TimeInterval {
        switch failures {
        case ..<backoffFreeAttempts: return 0      // 0–3 failures: no delay
        case backoffFreeAttempts..<7: return 5      // 4–6: 5 s
        case 7..<10: return 30                       // 7–9: 30 s
        default: return 60                           // 10+: 60 s (ceiling)
        }
    }

    /// Seconds remaining in the current backoff window, or 0 if none.
    /// Exposed so a UI could surface "try again in N s" (the lock
    /// overlay does not currently, but the value is available).
    var backoffRemaining: TimeInterval {
        guard let backoffUntilUptime else { return 0 }
        return max(0, backoffUntilUptime - Self.uptimeSeconds())
    }

    /// CLOCK_UPTIME_RAW seconds since boot at the moment the scene
    /// went to background. Monotonic — a user who manually winds the
    /// device clock backward in Settings.app cannot extend the unlock
    /// window. Wall-clock `Date()` would be coercer-tamperable.
    private var backgroundedAtUptime: TimeInterval?

    private static func uptimeSeconds() -> TimeInterval {
        // CLOCK_UPTIME_RAW counts seconds since boot, excludes sleep,
        // and is not affected by wall-clock adjustments.
        TimeInterval(clock_gettime_nsec_np(CLOCK_UPTIME_RAW)) / 1_000_000_000.0
    }

    private init() {
        // Cold launch: lock if EITHER Face ID is enabled OR an app
        // passcode has been set. Face ID's role is unchanged from
        // the pre-duress design — `biometricLockEnabled` drives the
        // existing Face ID prompt. The passcode path is independent:
        // even with Face ID off, setting a passcode (real or duress)
        // gates the app behind the passcode entry sheet on cold
        // launch.
        if ChatStore.shared.state.biometricLockEnabled
            || AppPasscode.isPasscodeSet
            || AppPasscode.isDuressPasscodeSet
        {
            isLocked = true
        }
    }

    /// True iff the lock UI should require ANY form of unlock — i.e.
    /// Face ID is on, OR the user has set an app passcode (real or
    /// duress). Used by ContentView + SecuritySettingsView so the
    /// lock-related UI mirrors the same gate `isLocked` reacts to.
    var isLockGateActive: Bool {
        ChatStore.shared.state.biometricLockEnabled
            || AppPasscode.isPasscodeSet
            || AppPasscode.isDuressPasscodeSet
    }

    // MARK: - Scene lifecycle hooks
    //
    // Wired up by ContentView via four `.onReceive(NotificationCenter…)`
    // modifiers. Order on a real foreground transition is:
    //
    //   willDeactivateNotification  (scene about to leave .active)
    //   didEnterBackgroundNotification
    //   …time passes…
    //   willEnterForegroundNotification  (scene about to become .active)
    //   didActivateNotification
    //
    // `isShielded` goes up at willDeactivate, the lock decision lands
    // at willEnterForeground, and the shield comes down at didActivate
    // — by which point `isLocked` is already correct, so the render
    // that lifts the shield shows the lock overlay (if locked) or the
    // chat (if unlocked) with no in-between frame.

    func handleWillDeactivate() {
        // Engage shield BEFORE the scene snapshot iOS captures for the
        // multitasking thumbnail, system alerts, control-centre pulls.
        isShielded = true
    }

    func handleDidEnterBackground() {
        backgroundedAtUptime = Self.uptimeSeconds()
    }

    func handleWillEnterForeground() {
        // Decide the lock state before the scene becomes active. The
        // shield stays up until handleDidActivate clears it, so any
        // re-render in this window is still safe.
        guard isLockGateActive else {
            backgroundedAtUptime = nil
            return
        }
        // **Fail closed.** If `backgroundedAtUptime` is nil — which can
        // happen on a scene reattach without an intervening
        // didEnterBackground (Stage Manager bring-back, watchdog
        // termination + scene-restoration path, etc.) — default to
        // locking. A security tool must not silently skip the lock
        // because the bookkeeping flag wasn't set. The user pays one
        // unnecessary biometric prompt in that edge case; the
        // alternative is exposing chat content to whoever picked up
        // the device.
        guard let backgroundedAtUptime else {
            isLocked = true
            dismissPresentedModals()
            return
        }
        let elapsed = Self.uptimeSeconds() - backgroundedAtUptime
        let timeout = ChatStore.shared.state.autoLockTimeout.seconds
        if elapsed >= timeout {
            isLocked = true
            dismissPresentedModals()
        }
        self.backgroundedAtUptime = nil
    }

    /// **Route-guard for sheets and full-screen covers.** The in-body
    /// `LockOverlayView` lives inside ContentView's ZStack, but
    /// SwiftUI sheets/covers present at the *window* level — above
    /// the ZStack root. So a `MyQRSheet` or attachment-picker that
    /// was on screen when the user backgrounded the phone stays
    /// visible *above* the lock overlay on return. Without this
    /// dismissal the lock screen is decorative for those surfaces.
    ///
    /// Reaches into UIKit because there is no SwiftUI primitive for
    /// "dismiss whatever modal happens to be presented." Calling
    /// `dismiss(animated:)` on the root view controller cascades
    /// through every layer of presentation in one shot. Animated
    /// false so the user never sees the dismissal half-frame —
    /// the lock overlay should be in place before any glimpse of
    /// the freed view tree.
    private func dismissPresentedModals() {
        let scenes = UIApplication.shared.connectedScenes
        for scene in scenes {
            guard let windowScene = scene as? UIWindowScene else { continue }
            for window in windowScene.windows {
                guard let root = window.rootViewController else { continue }
                root.dismiss(animated: false)
            }
        }
    }

    func handleDidActivate() {
        // Lock decision is in place. Safe to lift the shield now —
        // whatever's underneath (chat or lock overlay) is correct.
        isShielded = false
    }

    // MARK: - Auth

    enum AuthError: Error {
        case unavailable(String)
        case cancelled
        case failed(String)
    }

    /// Run the biometric prompt. `reason` is the line iOS shows in the
    /// Face ID / passcode sheet. Throws `.cancelled` for user/system
    /// cancels (caller usually ignores those silently), `.unavailable`
    /// when biometrics + passcode aren't usable at all, and `.failed`
    /// for everything else (with the iOS-localised reason inside).
    /// `lastError` is updated on `.failed` so the lock overlay can
    /// surface it without the caller threading an extra value.
    func authenticate(reason: String) async throws {
        guard !authInFlight else { throw AuthError.cancelled }
        let context = LAContext()
        context.localizedFallbackTitle = "Use Passcode"
        var policyError: NSError?
        // `.deviceOwnerAuthentication` = biometrics with passcode
        // fallback. If biometrics are unenrolled / disabled / locked
        // out (5 failed attempts), iOS falls through to the device
        // passcode rather than refusing. That's what we want — Pizzini
        // shouldn't be unrecoverable on a lockout.
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &policyError) else {
            let msg = policyError?.localizedDescription
                ?? "Biometric authentication unavailable on this device."
            lastError = msg
            throw AuthError.unavailable(msg)
        }
        authInFlight = true
        lastError = nil
        defer { authInFlight = false }
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch let nsError as NSError {
            if nsError.code == LAError.userCancel.rawValue
                || nsError.code == LAError.appCancel.rawValue
                || nsError.code == LAError.systemCancel.rawValue {
                throw AuthError.cancelled
            }
            lastError = nsError.localizedDescription
            throw AuthError.failed(nsError.localizedDescription)
        }
    }

    /// Attempt to lift the lock screen. Cancels are silent; other
    /// failures stay surfaced in `lastError` for `LockOverlayView`.
    func attemptUnlock() {
        Task { @MainActor in
            do {
                try await authenticate(reason: "Unlock Pizzini")
                isLocked = false
                // A successful biometric unlock is also a "the owner is
                // here" signal — clear any accrued passcode-failure
                // backoff (S7-03) so a few mistyped passcodes before a
                // Face ID success don't leave a stale lockout window.
                AppPasscode.resetFailedAttempts()
                backoffUntilUptime = nil
            } catch {
                // `lastError` already populated on non-cancel failures.
            }
        }
    }

    /// Explicit lock (called when user toggles biometric lock on, or
    /// could be wired to a future "Lock now" button).
    func lockNow() {
        guard isLockGateActive else { return }
        isLocked = true
    }

    /// Called by ChatStore when the user disables biometric lock — drop
    /// any active gate so they aren't stranded on an overlay they can
    /// no longer authenticate against. Also applies when the user
    /// removes their passcode and has no other gate left.
    func unlockBecauseDisabled() {
        isLocked = false
        lastError = nil
    }

    /// Mark a duress wipe as in flight. The lock overlay's duress
    /// handler MUST call this BEFORE invoking
    /// `ChatStore.shared.duressWipe()` so any racing passcode entry
    /// (e.g. a panicked double-tap) gets `.wrong` instead of
    /// re-triggering on the freshly-emptied state.
    func beginDuressWipe() {
        wipeInFlight = true
    }

    /// Drop the lock after a duress wipe. The caller (the lock
    /// overlay's duress handler) MUST have already invoked
    /// `ChatStore.shared.duressWipe()` so the UI underneath
    /// observes the post-wipe state on the next frame.
    func unlockAfterDuress() {
        isLocked = false
        isPasscodeSheetPresented = false
        lastError = nil
        wipeInFlight = false
    }

    // MARK: - Passcode entry

    /// Result of submitting a passcode at the lock overlay.
    enum PasscodeOutcome: Sendable, Equatable {
        /// The real unlock passcode — drop the lock and continue.
        case unlocked
        /// The duress passcode — caller MUST trigger the wipe
        /// (`ChatStore.shared.duressWipe()`) BEFORE dropping the
        /// lock so the UI underneath observes the wiped state.
        case duress
        /// Neither matched — UI shows "Incorrect passcode" and the
        /// user can retry.
        case wrong
    }

    /// Submit a passcode string. Returns synchronously — Argon2id
    /// verification is ~250 ms on iPhone 12, well under the user's
    /// perceptible-latency budget for a one-time entry.
    ///
    /// On `.unlocked`, this method drops the lock + clears the
    /// sheet flag. On `.duress`, the caller is responsible for
    /// invoking `ChatStore.shared.duressWipe()` and only then
    /// clearing the lock — the order matters because the lock
    /// drop reveals whatever UI is mounted underneath, and we
    /// want that UI to render against the post-wipe state. On
    /// `.wrong`, the lock stays up; the caller surfaces an error
    /// to the user.
    func submitPasscode(_ entry: String) -> PasscodeOutcome {
        // If a duress wipe is already in flight (set by the lock
        // overlay before it calls duressWipe), every subsequent
        // submission is bounced as `.wrong` until the wipe completes
        // and `unlockAfterDuress` clears the flag. Defends against
        // the rapid-double-tap race where the second tap could land
        // after the first has cleared the Keychain.
        if wipeInFlight {
            return .wrong
        }
        // **S7-03 invariant: evaluate the passcode FIRST, unconditionally.**
        // The brute-force throttle below must never block a real or
        // duress passcode — a coerced user has to be able to enter the
        // duress passcode even mid-backoff. So we always run the full
        // (constant-cost) check; the throttle only ever affects the
        // handling of a `.neither` (wrong) result.
        let match = AppPasscode.check(entry)
        switch match {
        case .real:
            // Successful unlock — clear the brute-force state so a
            // legitimate user never carries backoff into the next
            // session.
            AppPasscode.resetFailedAttempts()
            backoffUntilUptime = nil
            isLocked = false
            isPasscodeSheetPresented = false
            lastError = nil
            return .unlocked
        case .duress:
            // Duress is a "successful" entry from the throttle's point
            // of view: reset the counter so the post-wipe fresh-install
            // state carries no failure residue, and never let the
            // backoff have interfered with reaching this branch.
            AppPasscode.resetFailedAttempts()
            backoffUntilUptime = nil
            return .duress
        case .neither:
            // Wrong guess. If we're inside an active backoff window,
            // bounce WITHOUT consuming a new attempt or extending the
            // window — this is what rate-limits a scripted attacker:
            // their wrong guesses during the window are no-ops. (Real /
            // duress already returned above, so this never blocks a
            // legitimate or coerced unlock.)
            if backoffRemaining > 0 {
                return .wrong
            }
            // Outside any window: record the failure persistently and,
            // if we've crossed the free-attempt threshold, open an
            // escalating backoff window before the next wrong guess is
            // honored.
            let failures = AppPasscode.recordFailedAttempt()
            let delay = Self.backoffDuration(forFailures: failures)
            if delay > 0 {
                backoffUntilUptime = Self.uptimeSeconds() + delay
            }
            return .wrong
        }
    }
}
