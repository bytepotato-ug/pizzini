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
    /// True when the privacy shield should cover everything — i.e. the
    /// scene is not currently active *or* we're in the middle of the
    /// foreground transition and haven't decided whether to show the
    /// lock overlay yet. Cleared only by `handleDidActivate`, which
    /// runs after `handleWillEnterForeground` has set `isLocked`.
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

    private var backgroundedAt: Date?

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
        backgroundedAt = Date()
    }

    func handleWillEnterForeground() {
        // Decide the lock state before the scene becomes active. The
        // shield stays up until handleDidActivate clears it, so any
        // re-render in this window is still safe.
        guard isLockGateActive else {
            backgroundedAt = nil
            return
        }
        guard let backgroundedAt else { return }
        let elapsed = Date().timeIntervalSince(backgroundedAt)
        let timeout = ChatStore.shared.state.autoLockTimeout.seconds
        if elapsed >= timeout {
            isLocked = true
        }
        self.backgroundedAt = nil
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

    /// Drop the lock after a duress wipe. The caller (the lock
    /// overlay's duress handler) MUST have already invoked
    /// `ChatStore.shared.duressWipe()` so the UI underneath
    /// observes the post-wipe state on the next frame.
    func unlockAfterDuress() {
        isLocked = false
        isPasscodeSheetPresented = false
        lastError = nil
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
        switch AppPasscode.check(entry) {
        case .real:
            isLocked = false
            isPasscodeSheetPresented = false
            lastError = nil
            return .unlocked
        case .duress:
            return .duress
        case .neither:
            return .wrong
        }
    }
}
