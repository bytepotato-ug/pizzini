import Foundation
import PizziniCryptoCore

/// PZ-C7: Keychain-backed persistence for `LockoutState`.
///
/// Stored as a JSON blob in a single Keychain row under
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (same accessibility
/// as the passcode slots themselves), so the counter survives an app
/// kill, a force-quit, and a reboot — an attacker can't reset the
/// lockout by closing the app.
///
/// The blob is small and fixed-shape, so a write is constant-time at
/// the Keychain layer across all three verify outcomes (`LockManager`
/// always calls `save(...)` exactly once after a verify regardless of
/// match; see `PasscodeLockoutPolicy.nextState` for the value rule).
enum PasscodeLockoutStore {
    /// Account label for the Keychain row. Distinct from the passcode
    /// slot accounts (`AppPasscode.realSlotAccount`/`duressSlotAccount`)
    /// so a corrupt lockout blob can't be misread as passcode material
    /// or vice versa.
    static let account = "app-passcode-lockout-v1"

    /// Load the persisted state. Returns `LockoutState.empty` on a
    /// fresh install, a missing row, or a malformed blob — failing
    /// OPEN here is correct (the user gets a fresh start rather than
    /// being permanently locked out by a corrupt row), and the row
    /// is rewritten cleanly on the next save.
    static func load() -> LockoutState {
        guard let data = Keychain.read(account: account) else {
            return .empty
        }
        guard let decoded = try? JSONDecoder().decode(LockoutState.self, from: data) else {
            return .empty
        }
        return decoded
    }

    /// Persist `state`. Returns `false` on a Keychain write failure —
    /// the caller logs and proceeds (the lockout becomes session-local
    /// for this one rare failure window, which is no worse than the
    /// pre-PZ-C7 baseline of no lockout at all).
    @discardableResult
    static func save(_ state: LockoutState) -> Bool {
        guard let data = try? JSONEncoder().encode(state) else {
            return false
        }
        return Keychain.write(data, account: account)
    }

    /// Clear the persisted state. Used by the wipe path
    /// (`Storage.eraseAndReinitialize`) so a post-wipe install starts
    /// at zero attempts (per the "post-wipe surface = fresh install"
    /// principle that the duress feature depends on).
    static func reset() {
        _ = Keychain.delete(account: account)
    }
}
