import Foundation
import PizziniCryptoCore
import Testing
@testable import pizzini

/// Round-trip + duress-flow tests for `AppPasscode`. The tests
/// share Keychain with the host app — each test wipes both
/// passcode slots up front so a previous test's residue doesn't
/// leak between runs.
@MainActor
@Suite("AppPasscode + duress flow")
struct AppPasscodeTests {
    private func freshKeychain() {
        AppPasscode.eraseAll()
        #expect(!AppPasscode.isPasscodeSet)
        #expect(!AppPasscode.isDuressPasscodeSet)
    }

    @Test("setPasscode + verifyPasscode round-trips a fixed string")
    func realPasscodeRoundTrip() throws {
        freshKeychain()
        try AppPasscode.setPasscode("correct horse battery")
        #expect(AppPasscode.isPasscodeSet)
        #expect(AppPasscode.verifyPasscode("correct horse battery"))
        #expect(!AppPasscode.verifyPasscode("wrong"))
        #expect(!AppPasscode.verifyPasscode("correct horse battery!"))
    }

    @Test("duress passcode round-trips and is verified independently")
    func duressPasscodeRoundTrip() throws {
        freshKeychain()
        try AppPasscode.setPasscode("realRealReal")
        try AppPasscode.setDuressPasscode("duressDuress")
        #expect(AppPasscode.isDuressPasscodeSet)
        #expect(AppPasscode.verifyDuressPasscode("duressDuress"))
        #expect(!AppPasscode.verifyDuressPasscode("realRealReal"))
        #expect(AppPasscode.verifyPasscode("realRealReal"))
        #expect(!AppPasscode.verifyPasscode("duressDuress"))
    }

    @Test("check(_:) classifies real, duress, and neither")
    func checkClassifier() throws {
        freshKeychain()
        try AppPasscode.setPasscode("realreal")
        try AppPasscode.setDuressPasscode("duressed")
        #expect(AppPasscode.check("realreal") == .real)
        #expect(AppPasscode.check("duressed") == .duress)
        #expect(AppPasscode.check("nope!nope") == .neither)
        #expect(AppPasscode.check("") == .neither)
    }

    @Test("setDuressPasscode rejects values that match the real passcode")
    func duressCannotMatchReal() throws {
        freshKeychain()
        try AppPasscode.setPasscode("shared12")
        #expect(throws: AppPasscode.PasscodeError.self) {
            try AppPasscode.setDuressPasscode("shared12")
        }
        #expect(!AppPasscode.isDuressPasscodeSet)
    }

    @Test("setPasscode rejects below-minimum-length strings")
    func minLengthEnforced() {
        freshKeychain()
        #expect(throws: AppPasscode.PasscodeError.self) {
            try AppPasscode.setPasscode("12345")  // 5 chars, below 6-min floor
        }
        #expect(!AppPasscode.isPasscodeSet)
    }

    @Test("clearPasscode removes hash + salt and disables verify")
    func clearRemovesSlots() throws {
        freshKeychain()
        try AppPasscode.setPasscode("abcdef")
        #expect(AppPasscode.isPasscodeSet)
        AppPasscode.clearPasscode()
        #expect(!AppPasscode.isPasscodeSet)
        #expect(!AppPasscode.verifyPasscode("abcdef"))
    }

    @Test("two passcodes with same input but different salts produce distinct hashes")
    func saltsDifferPerSlot() throws {
        freshKeychain()
        try AppPasscode.setPasscode("samesamesame")
        // The slot collision check in setDuressPasscode prevents us
        // from re-using the SAME passcode under duress — that's the
        // user-facing invariant. Verify it's distinct passcodes that
        // get distinct hashes by setting a DIFFERENT duress value.
        try AppPasscode.setDuressPasscode("differentValue")
        // Atomic slot layout: `salt(32) || hash(32) || role(1)` = 65 B
        // (S7-08 added the trailing in-blob role discriminator).
        let realBlob = Keychain.read(account: AppPasscode.realSlotAccount)
        let duressBlob = Keychain.read(account: AppPasscode.duressSlotAccount)
        #expect(realBlob?.count == 65)
        #expect(duressBlob?.count == 65)
        let realSalt = realBlob?.prefix(32)
        let duressSalt = duressBlob?.prefix(32)
        #expect(realSalt != duressSalt, "real and duress must use distinct salts")
    }

    /// S7-08 / S3-03: the real and duress slots must be stored under
    /// account names that are name-INDISTINGUISHABLE, so a Keychain
    /// account-name enumeration (the only thing an AFU dump can do
    /// without decrypting blob ciphertext) cannot derive which slot is
    /// the duress slot — or even that a duress passcode is configured.
    @Test("real and duress slot account names are name-indistinguishable")
    func slotNamesAreIndistinguishable() throws {
        freshKeychain()
        let real = AppPasscode.realSlotAccount
        let duress = AppPasscode.duressSlotAccount
        // Neither name may be self-describing.
        #expect(!real.lowercased().contains("duress"))
        #expect(!duress.lowercased().contains("duress"))
        #expect(!real.lowercased().contains("real"))
        #expect(!duress.lowercased().contains("real"))
        // The two names must be structurally identical: same length and
        // differing only by a trailing slot index, so the duress slot is
        // not distinguishable from the real slot by its name alone.
        #expect(real.count == duress.count)
        #expect(real != duress)
        let commonPrefix = String(zip(real, duress).prefix { $0 == $1 }.map(\.0))
        // The names must share everything except a final disambiguator
        // (e.g. "passcode-slot-" + "0"/"1").
        #expect(real.count - commonPrefix.count <= 1)
        #expect(duress.count - commonPrefix.count <= 1)
        // And the in-blob role discriminator — not the account name —
        // is what actually classifies a matched slot: setting only the
        // duress passcode must still classify correctly via `check`.
        try AppPasscode.setDuressPasscode("duressOnlyValue")
        #expect(AppPasscode.check("duressOnlyValue") == .duress)
        AppPasscode.eraseAll()
    }

    @Test("legacy two-row layout is migrated to the atomic slot on first read")
    func legacyLayoutMigrates() throws {
        freshKeychain()
        // Simulate a pre-upgrade install: write the legacy slot
        // pair directly, then assert the atomic slot doesn't exist
        // yet — the public API hasn't been touched.
        let salt = Data(repeating: 0xAB, count: 32)
        let hash = Data(repeating: 0xCD, count: 32)
        _ = Keychain.write(hash, account: AppPasscode.legacyRealHashAccount)
        _ = Keychain.write(salt, account: AppPasscode.legacyRealSaltAccount)
        // Reading `isPasscodeSet` triggers the migration internally.
        #expect(AppPasscode.isPasscodeSet)
        // Atomic slot now populated; legacy slots wiped.
        // F-S7-08: the atomic slot is salt(32) || hash(32) || role(1) =
        // 65 bytes — the trailing role discriminator carries app-vs-duress
        // INSIDE the AFU-protected blob so the Keychain account name no
        // longer reveals which slot is the duress slot.
        let atomic = Keychain.read(account: AppPasscode.realSlotAccount)
        #expect(atomic?.count == 65)
        #expect(atomic?.prefix(32) == salt)
        #expect(atomic?.dropFirst(32).prefix(32) == hash)
        #expect(Keychain.read(account: AppPasscode.legacyRealHashAccount) == nil)
        #expect(Keychain.read(account: AppPasscode.legacyRealSaltAccount) == nil)
        AppPasscode.eraseAll()
    }

    @Test("eraseAll wipes both slots in one call")
    func eraseAllClearsEverything() throws {
        freshKeychain()
        try AppPasscode.setPasscode("realreal")
        try AppPasscode.setDuressPasscode("duressed")
        AppPasscode.eraseAll()
        #expect(!AppPasscode.isPasscodeSet)
        #expect(!AppPasscode.isDuressPasscodeSet)
    }

    @Test("LockManager.submitPasscode flips lock state on real, signals duress on duress")
    func lockManagerFlow() throws {
        freshKeychain()
        try AppPasscode.setPasscode("realreal")
        try AppPasscode.setDuressPasscode("duressed")
        let lm = LockManager.shared
        // Real → unlock; LockManager keeps `isLocked` in sync with
        // the duress-aware gate. Force-set the locked state for the
        // test so we can observe the transition.
        let realResult = lm.submitPasscode("realreal")
        #expect(realResult == .unlocked)
        // Duress doesn't auto-unlock — the caller is responsible
        // for invoking duressWipe() then unlockAfterDuress().
        let duressResult = lm.submitPasscode("duressed")
        #expect(duressResult == .duress)
        let wrongResult = lm.submitPasscode("nope!nope")
        #expect(wrongResult == .wrong)
        // Cleanup so subsequent tests see a clean Keychain.
        AppPasscode.eraseAll()
    }

    // MARK: - S7-03 brute-force throttle

    @Test("failed-attempt counter persists, increments, and resets")
    func failedAttemptCounter() {
        freshKeychain()
        #expect(AppPasscode.failedAttempts == 0)
        #expect(AppPasscode.recordFailedAttempt() == 1)
        #expect(AppPasscode.recordFailedAttempt() == 2)
        // The counter is read back from Keychain, not memory — it
        // survives a (simulated) relaunch because nothing in-process
        // caches it.
        #expect(AppPasscode.failedAttempts == 2)
        AppPasscode.resetFailedAttempts()
        #expect(AppPasscode.failedAttempts == 0)
    }

    @Test("backoff duration escalates with failure count and is bounded")
    func backoffEscalates() {
        // No delay while under the free-attempt floor.
        #expect(LockManager.backoffDuration(forFailures: 0) == 0)
        #expect(LockManager.backoffDuration(forFailures: 3) == 0)
        // Escalating steps.
        #expect(LockManager.backoffDuration(forFailures: 5) > 0)
        #expect(
            LockManager.backoffDuration(forFailures: 8)
                > LockManager.backoffDuration(forFailures: 5)
        )
        // Bounded: the curve saturates and never grows without limit.
        let ceiling = LockManager.backoffDuration(forFailures: 10)
        #expect(LockManager.backoffDuration(forFailures: 100) == ceiling)
        #expect(LockManager.backoffDuration(forFailures: 1_000_000) == ceiling)
    }

    @Test("a successful unlock resets the brute-force counter")
    func successResetsThrottle() throws {
        freshKeychain()
        try AppPasscode.setPasscode("realreal")
        let lm = LockManager.shared
        // `LockManager` is a singleton shared across tests; clear any
        // in-memory backoff window a prior test left open by doing one
        // clean unlock (also zeroes the counter).
        _ = lm.submitPasscode("realreal")
        // Accrue some wrong guesses.
        _ = lm.submitPasscode("nope!nope")
        _ = lm.submitPasscode("nope!nope")
        #expect(AppPasscode.failedAttempts > 0)
        // A correct entry clears the counter.
        #expect(lm.submitPasscode("realreal") == .unlocked)
        #expect(AppPasscode.failedAttempts == 0)
        AppPasscode.eraseAll()
    }

    @Test("duress passcode is accepted even after many failed attempts")
    func duressNeverThrottled() throws {
        freshKeychain()
        try AppPasscode.setPasscode("realreal")
        try AppPasscode.setDuressPasscode("duressed")
        let lm = LockManager.shared
        // Clear any backoff window a prior test left open on the shared
        // singleton, then drive the failure count well past the backoff
        // threshold so a fresh backoff window is certainly open.
        _ = lm.submitPasscode("realreal")
        for _ in 0..<12 {
            _ = lm.submitPasscode("nope!nope")
        }
        #expect(AppPasscode.failedAttempts > 0)
        #expect(lm.backoffRemaining > 0, "a backoff window must be active")
        // The hard S7-03 invariant: the duress passcode is STILL
        // accepted mid-backoff — a coerced user must never be blocked
        // from entering it.
        #expect(lm.submitPasscode("duressed") == .duress)
        AppPasscode.eraseAll()
    }
}
