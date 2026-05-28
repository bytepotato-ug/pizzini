import Foundation

/// PZ-C7: passcode-lockout state machine.
///
/// Goal: after enough failed app-passcode attempts, refuse further
/// attempts with exponential backoff and a hard ceiling, so an attacker
/// with the device can't brute-force the PIN at Argon2id speed (~4
/// guesses/sec on an iPhone 12). Persisted across app kill and reboot
/// via the Keychain (see `PasscodeLockoutStore`).
///
/// CRITICAL invariant (the duress feature depends on it): the lockout
/// must not let an attacker distinguish "I entered the duress PIN" from
/// "I entered the real PIN" from "I entered a wrong PIN" via observable
/// side effects. Two pieces:
///   1. `AppPasscode.check(_:)` is already constant-time across the
///      three outcomes (always two Argon2id derivations + masked
///      selection — see its comment).
///   2. The lockout update after every attempt must take the same code
///      path in all three branches, with the same operation count and
///      payload size. `nextState(after:prior:now:)` encodes that: both
///      `.real` and `.duress` reset the counter to zero (an attacker
///      cannot tell from the post-attempt lockout state which one
///      matched), and `.neither` increments — but every branch performs
///      exactly one Keychain write of a fixed-size state blob.

/// Persisted lockout state. `attempts` is the count of failed unlock
/// attempts since the last successful unlock (real or duress);
/// `lastFailedAt` is the wall-clock instant of the most recent failure
/// (used to compute when the user may try again).
struct LockoutState: Sendable, Equatable, Codable {
    var attempts: Int
    /// Wall-clock instant of the most recent failure. `nil` when there
    /// are no failures on record (fresh install, or just after a
    /// successful unlock that reset the counter).
    var lastFailedAt: Date?

    static let empty = LockoutState(attempts: 0, lastFailedAt: nil)
}

/// Result of consulting the lockout policy BEFORE running the (slow)
/// passcode verify.
enum LockoutDecision: Equatable, Sendable {
    /// Attempt allowed — caller proceeds to `AppPasscode.check`.
    case allow
    /// Temporarily blocked. UI shows "try again at <retryAt>"; the
    /// caller does NOT run the verify (refusing also stops a CPU-DoS
    /// via repeated Argon2id derivations).
    case blocked(retryAt: Date)
    /// Hard ceiling tripped — too many failed attempts ever. We do
    /// NOT silently wipe the device here, even though the duress
    /// passcode does so deliberately: a brute-force attacker could
    /// otherwise destroy the user's data just by guessing wrong N
    /// times. Recovery is a full reinstall by the legitimate user.
    case permanentlyLocked
}

/// The policy itself. Pure value type — `decision` and `nextState` are
/// pure functions, so the whole state machine can be exhaustively unit-
/// tested without touching the Keychain or the system clock.
struct PasscodeLockoutPolicy: Sendable, Equatable {
    /// Number of failures tolerated with no backoff. Argon2id at the
    /// production cost is ~250 ms; the first few failures are typically
    /// honest typos and we don't want to punish them with friction.
    let graceAttempts: Int
    /// Backoff base. Delay after attempt `N` (where `N > graceAttempts`)
    /// is `min(base * 2^(N - graceAttempts - 1), cap)`.
    let backoffBaseSeconds: TimeInterval
    /// Upper bound on the backoff delay between attempts.
    let backoffCapSeconds: TimeInterval
    /// Hard ceiling — strictly above this count, attempts are
    /// permanently blocked.
    let hardCeiling: Int

    /// Production policy: 5 free typo allowance, then 1, 2, 4, 8, …
    /// seconds capped at one minute, with a permanent block at 50 total
    /// failures. At ~250 ms/Argon2id-attempt the brute-force rate
    /// before lockout caps at 5 guesses; after the cap is hit the
    /// expected throughput is 1 guess/minute; 50 failures total tops
    /// out before any meaningful share of a 6-digit PIN space.
    static let production = PasscodeLockoutPolicy(
        graceAttempts: 5,
        backoffBaseSeconds: 1,
        backoffCapSeconds: 60,
        hardCeiling: 50
    )

    /// Pure decision: should this attempt proceed? Called BEFORE the
    /// Argon2id verify so a brute-force attacker can't burn the relay
    /// of one attempt per backoff cycle on CPU work either.
    func decision(attempts: Int, lastFailedAt: Date?, now: Date) -> LockoutDecision {
        if attempts > hardCeiling { return .permanentlyLocked }
        if attempts <= graceAttempts { return .allow }
        // Above grace: must wait until lastFailedAt + delay.
        guard let lastFailedAt else { return .allow }
        let exponent = attempts - graceAttempts - 1
        // Cap the exponent before pow() so 2^N stays in a sane range
        // even at the hard ceiling.
        let safeExponent = min(exponent, 40)
        let raw = backoffBaseSeconds * pow(2.0, Double(safeExponent))
        let delay = min(raw, backoffCapSeconds)
        let retryAt = lastFailedAt.addingTimeInterval(delay)
        if now < retryAt { return .blocked(retryAt: retryAt) }
        return .allow
    }

    /// Pure update: compute the new lockout state from the verify
    /// outcome. The caller MUST persist whatever this returns in
    /// EVERY branch (no early-return on `.real`/`.duress`) so the
    /// wall-clock cost of the post-verify Keychain write is identical
    /// across the three outcomes. The invariant — `.real` and
    /// `.duress` produce the same value (zeroed state) — is what
    /// stops an attacker from inferring the duress hit from the
    /// post-attempt persisted state.
    static func nextState(
        after match: AppPasscode.Match,
        prior: LockoutState,
        now: Date
    ) -> LockoutState {
        switch match {
        case .real, .duress:
            // Both successful unlocks reset the counter. Treating
            // `.duress` identically to `.real` is the load-bearing
            // anti-leak property — see the file-level comment.
            return LockoutState.empty
        case .neither:
            return LockoutState(attempts: prior.attempts + 1, lastFailedAt: now)
        }
    }
}
