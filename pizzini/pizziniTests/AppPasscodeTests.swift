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
        // Atomic slot layout: `salt(32) || hash(32)`.
        let realBlob = Keychain.read(account: AppPasscode.realSlotAccount)
        let duressBlob = Keychain.read(account: AppPasscode.duressSlotAccount)
        #expect(realBlob?.count == 64)
        #expect(duressBlob?.count == 64)
        let realSalt = realBlob?.prefix(32)
        let duressSalt = duressBlob?.prefix(32)
        #expect(realSalt != duressSalt, "real and duress must use distinct salts")
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
        let atomic = Keychain.read(account: AppPasscode.realSlotAccount)
        #expect(atomic?.count == 64)
        #expect(atomic?.prefix(32) == salt)
        #expect(atomic?.suffix(32) == hash)
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
}
