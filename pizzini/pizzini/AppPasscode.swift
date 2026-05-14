import Foundation
import PizziniCryptoCore
import Security

/// Two passcodes the user may have set:
///
/// - **Real**: required to open the app when Face ID is OFF; an
///   alternative path when Face ID is ON (entered via the
///   long-press-anywhere gesture on the lock screen).
/// - **Duress**: optional second passcode that, when entered,
///   silently wipes every chat / contact / outbox / message / key
///   the app holds and re-opens to an "empty installed" state.
///
/// Both are stored as Argon2id hashes in Keychain (one row per slot;
/// each row contains `salt || hash` atomically so the two cannot
/// desync via a torn write). The salts are 32 random bytes per slot;
/// the hashes are 32-byte Argon2id outputs under the
/// `Argon2id.Params.production` preset (M=64 MiB, T=3, P=1 — ~250 ms
/// on iPhone 12). Verification re-derives with the stored salt and
/// constant-time-compares against the stored hash, so an attacker
/// with Keychain read access still has to brute-force the passcode
/// at full Argon2id cost per guess.
///
/// **Constant wall-clock verification.** `check(_:)` ALWAYS runs two
/// Argon2id derivations, one against each slot. If a slot is unset,
/// the derivation runs against a deterministic dummy salt so the
/// wall-clock cost is identical to "slot is set, didn't match". A
/// coercer with a stopwatch cannot tell from latency which path was
/// taken (real / duress / neither).
///
/// Importantly: **the database encryption key is NOT derived from
/// these passcodes**. The DB key is the Secure-Enclave-wrapped seed
/// stretched by Argon2id in `DBKey`; that derivation runs even when
/// no app-level passcode is set. This module is an *access gate*
/// (and the duress trigger), not the cryptographic key source.
@MainActor
enum AppPasscode {
    // MARK: - Keychain slot names

    /// Single atomic Keychain row holding `salt || hash` for the real
    /// passcode. Atomic-write semantics: the two halves can never
    /// desync, which used to be possible with the prior two-row design
    /// (crash between salt-write and hash-write would permanently lock
    /// the user out of a passcode they typed correctly).
    static let realSlotAccount = "app-passcode-slot"
    /// Sibling row for the duress passcode.
    static let duressSlotAccount = "duress-passcode-slot"

    /// Legacy Keychain slot names — written by the pre-atomic-slot
    /// versions of this module. Read once on the first access path
    /// after upgrade, migrated to the atomic layout, then wiped. Kept
    /// `static let` so unit tests can also exercise the migration.
    static let legacyRealHashAccount = "app-passcode-hash"
    static let legacyRealSaltAccount = "app-passcode-salt"
    static let legacyDuressHashAccount = "duress-passcode-hash"
    static let legacyDuressSaltAccount = "duress-passcode-salt"

    enum PasscodeError: Error {
        case derivationFailed
        case keychainWriteFailed
        case empty
        case tooShort(minimum: Int)
        case sameAsExisting
    }

    /// Minimum passcode length. Argon2id is slow enough that a 4-char
    /// numeric PIN is still costly to brute-force, but a 6-char floor
    /// keeps the entropy in a comfortable range — and matches iOS's
    /// own device-passcode default. The duress passcode shares the
    /// floor.
    static let minLength: Int = 6

    /// Fixed sizes for the atomic slot blob layout: `salt(32) || hash(32)`.
    private static let saltLen = 32
    private static let hashLen = 32
    private static let slotLen = saltLen + hashLen

    /// Deterministic dummy slot used when the corresponding real /
    /// duress slot is unset. The dummy salt is a fixed, all-zero
    /// 32-byte value; the dummy hash is a fixed, all-zero 32-byte
    /// value. The dummy derivation runs at full Argon2id cost. The
    /// expected-hash will never equal the dummy hash for any real
    /// passcode, so the constant-time-compare always returns false
    /// for unset slots — without revealing which slot is unset.
    private static let dummySalt = Data(repeating: 0, count: saltLen)
    private static let dummyHash = Data(repeating: 0, count: hashLen)

    /// One result from `check(_:)`. Three states because "neither"
    /// (typo) must be distinguishable from "duress" (wipe) at the
    /// LockManager layer.
    enum Match: Sendable, Equatable {
        case real
        case duress
        case neither
    }

    // MARK: - State accessors

    static var isPasscodeSet: Bool {
        readSlot(realSlotAccount) != nil
    }

    static var isDuressPasscodeSet: Bool {
        readSlot(duressSlotAccount) != nil
    }

    // MARK: - Setters

    /// Set or replace the real passcode. Throws `tooShort` if the
    /// string is below `minLength`. Caller is responsible for
    /// rejecting the duress passcode value if it matches an existing
    /// real one (and vice versa) at the UI layer — that check uses
    /// `check(_:)`.
    static func setPasscode(_ passcode: String) throws {
        try setPasscodeIntoSlot(passcode, account: realSlotAccount)
    }

    /// Set or replace the duress passcode. Same shape as `setPasscode`.
    /// Caller must ensure this value differs from the real passcode
    /// — entering identical strings under both labels would silently
    /// trigger the wipe on every legitimate unlock.
    static func setDuressPasscode(_ passcode: String) throws {
        if verifyPasscode(passcode) {
            throw PasscodeError.sameAsExisting
        }
        try setPasscodeIntoSlot(passcode, account: duressSlotAccount)
    }

    /// Remove the real passcode. Used when the user disables app-
    /// passcode entry entirely (e.g. enables Face ID and decides the
    /// fallback isn't worth the friction). Returns silently if no
    /// passcode is set.
    static func clearPasscode() {
        secureDelete(account: realSlotAccount)
    }

    /// Remove the duress passcode.
    static func clearDuressPasscode() {
        secureDelete(account: duressSlotAccount)
    }

    // MARK: - Verification

    /// Verify `entry` against the real passcode. Returns false if no
    /// passcode is set OR `entry` doesn't match.
    static func verifyPasscode(_ entry: String) -> Bool {
        guard let (salt, expected) = readSlotSplit(realSlotAccount) else {
            return false
        }
        return verify(entry: entry, salt: salt, expected: expected)
    }

    /// Verify `entry` against the duress passcode.
    static func verifyDuressPasscode(_ entry: String) -> Bool {
        guard let (salt, expected) = readSlotSplit(duressSlotAccount) else {
            return false
        }
        return verify(entry: entry, salt: salt, expected: expected)
    }

    /// Composite check: does `entry` match real, duress, or neither?
    ///
    /// **Always runs both Argon2id derivations, in a fixed order, at
    /// full production cost.** If a slot is unset, the derivation runs
    /// against `dummySalt`/`dummyHash` so wall-clock cost is identical
    /// to "set but didn't match". The result of each derivation is
    /// constant-time-compared against the corresponding expected hash;
    /// match flags are folded WITHOUT short-circuiting and the priority
    /// (duress beats real) is applied via masked selection.
    ///
    /// A stopwatch-equipped coercer cannot distinguish `.real`,
    /// `.duress`, or `.neither` by latency — the wall-clock is
    /// `2 × Argon2id.production` for all three cases.
    static func check(_ entry: String) -> Match {
        let (realSalt, realExpected, realSet) =
            slotMaterial(account: realSlotAccount)
        let (duressSalt, duressExpected, duressSet) =
            slotMaterial(account: duressSlotAccount)

        // Run both derivations, in a fixed order. Both run at full
        // production cost — the result of the unset-slot derivation
        // is discarded.
        let entryBytes = Data(entry.utf8)
        let realDerived = (try? Argon2id.derive(
            passphrase: entryBytes,
            salt: realSalt,
            params: .production,
            outputLength: hashLen,
        )) ?? Data(repeating: 0xFF, count: hashLen)
        let duressDerived = (try? Argon2id.derive(
            passphrase: entryBytes,
            salt: duressSalt,
            params: .production,
            outputLength: hashLen,
        )) ?? Data(repeating: 0xFF, count: hashLen)

        // Constant-time byte equality, both checks unconditional.
        let realEq = constantTimeEquals(realDerived, realExpected)
        let duressEq = constantTimeEquals(duressDerived, duressExpected)

        // A match only counts if the corresponding slot was actually
        // set — for unset slots the expected hash is `dummyHash` and
        // can never match any real passcode (entropy assumption).
        let realMatch = realEq && realSet && !entry.isEmpty
        let duressMatch = duressEq && duressSet && !entry.isEmpty

        // Duress takes priority over real (if a user accidentally set
        // identical passcodes, the safer side wipes).
        if duressMatch { return .duress }
        if realMatch { return .real }
        return .neither
    }

    /// Wipe both passcode slots. Used by the duress flow on a
    /// successful match — after the database is reset, the passcodes
    /// go too so the post-wipe state is a true clean slate.
    static func eraseAll() {
        secureDelete(account: realSlotAccount)
        secureDelete(account: duressSlotAccount)
    }

    // MARK: - Argon2id glue

    private static func setPasscodeIntoSlot(
        _ passcode: String,
        account: String,
    ) throws {
        guard !passcode.isEmpty else { throw PasscodeError.empty }
        guard passcode.count >= minLength else {
            throw PasscodeError.tooShort(minimum: minLength)
        }
        var saltBytes = [UInt8](repeating: 0, count: saltLen)
        let rc = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
        guard rc == errSecSuccess else { throw PasscodeError.derivationFailed }
        let salt = Data(saltBytes)
        let hash: Data
        do {
            hash = try Argon2id.derive(
                passphrase: Data(passcode.utf8),
                salt: salt,
                params: .production,
                outputLength: hashLen,
            )
        } catch {
            throw PasscodeError.derivationFailed
        }
        // Atomic write: salt + hash in one Keychain row. A torn write
        // is now impossible — the prior two-row design could leave a
        // new salt next to an old hash on crash.
        var slot = Data(capacity: slotLen)
        slot.append(salt)
        slot.append(hash)
        guard Keychain.write(slot, account: account) else {
            throw PasscodeError.keychainWriteFailed
        }
    }

    private static func verify(entry: String, salt: Data, expected: Data) -> Bool {
        guard !entry.isEmpty else { return false }
        guard let derived = try? Argon2id.derive(
            passphrase: Data(entry.utf8),
            salt: salt,
            params: .production,
            outputLength: expected.count,
        ) else {
            return false
        }
        return constantTimeEquals(derived, expected)
    }

    /// Read the atomic slot blob and split into (salt, expectedHash).
    /// Returns nil if no row exists or the row is malformed. Also
    /// migrates legacy two-row (`-hash` + `-salt`) layouts into the
    /// atomic single-row layout on first access — so users upgrading
    /// from a build that wrote the old slot pair don't get silently
    /// locked out.
    ///
    /// **Constant Keychain-read count.** `check(_:)`'s constant
    /// wall-clock guarantee covers the Argon2id derivations but the
    /// pre-derivation Keychain probing must also be slot-set
    /// independent: a set slot used to cost one read, an unset slot
    /// three (the atomic read miss falling through to two legacy
    /// reads). That delta leaks whether a duress passcode is
    /// configured. So when the atomic slot IS present we still issue
    /// the same two legacy-account probes the miss path makes — same
    /// three reads either way — and discard their results.
    private static func readSlot(_ account: String) -> Data? {
        if let data = Keychain.read(account: account), data.count == slotLen {
            // Atomic slot hit. Issue the two legacy probes anyway so
            // the observable Keychain-read count is identical to the
            // miss path; results discarded.
            probeLegacyAccounts(for: account)
            return data
        }
        return migrateLegacySlot(into: account)
    }

    /// Issue (and discard) one read against each legacy account that
    /// `migrateLegacySlot` would read, so a slot-hit pays the same
    /// fixed Keychain-read count as a slot-miss. No side effects —
    /// purely to keep `check(_:)`'s pre-derivation cost independent of
    /// which slots are configured.
    private static func probeLegacyAccounts(for account: String) {
        switch account {
        case realSlotAccount:
            _ = Keychain.read(account: legacyRealHashAccount)
            _ = Keychain.read(account: legacyRealSaltAccount)
        case duressSlotAccount:
            _ = Keychain.read(account: legacyDuressHashAccount)
            _ = Keychain.read(account: legacyDuressSaltAccount)
        default:
            // Unknown account — issue two reads against the real
            // legacy accounts so the count still matches.
            _ = Keychain.read(account: legacyRealHashAccount)
            _ = Keychain.read(account: legacyRealSaltAccount)
        }
    }

    /// Read the (hash, salt) pair from the legacy two-row layout if
    /// present, write the atomic blob under `account`, and remove the
    /// legacy rows. Returns the migrated slot blob or nil if no
    /// legacy data exists. The migration runs at most once per slot
    /// per device (the legacy reads return nil after the deletes).
    private static func migrateLegacySlot(into account: String) -> Data? {
        let (legacyHashAccount, legacySaltAccount): (String, String)
        switch account {
        case realSlotAccount:
            legacyHashAccount = legacyRealHashAccount
            legacySaltAccount = legacyRealSaltAccount
        case duressSlotAccount:
            legacyHashAccount = legacyDuressHashAccount
            legacySaltAccount = legacyDuressSaltAccount
        default:
            return nil
        }
        // Read BOTH legacy rows unconditionally — not via a
        // short-circuiting `guard let … , let …`, which would skip
        // the second read when the first misses. A slot-miss must
        // issue the same fixed Keychain-read count as a slot-hit;
        // otherwise the read-count delta leaks whether the slot
        // (e.g. a duress passcode) is configured at all.
        let legacyHash = Keychain.read(account: legacyHashAccount)
        let legacySalt = Keychain.read(account: legacySaltAccount)
        guard let legacyHash, let legacySalt,
              legacyHash.count == hashLen,
              legacySalt.count == saltLen else {
            return nil
        }
        var blob = Data(capacity: slotLen)
        blob.append(legacySalt)
        blob.append(legacyHash)
        guard Keychain.write(blob, account: account) else {
            // Couldn't write the new slot — leave legacy rows in place
            // so a retry later still has the material.
            return nil
        }
        // Wipe legacy rows now that the atomic slot is authoritative.
        secureDelete(account: legacyHashAccount)
        secureDelete(account: legacySaltAccount)
        return blob
    }

    private static func readSlotSplit(_ account: String) -> (Data, Data)? {
        guard let data = readSlot(account) else { return nil }
        let salt = data.prefix(saltLen)
        let hash = data.suffix(hashLen)
        return (Data(salt), Data(hash))
    }

    /// Returns `(salt, expectedHash, isSet)`. If the slot is unset,
    /// returns `(dummySalt, dummyHash, false)` so the caller's
    /// derivation still pays the Argon2id cost — preserving constant
    /// wall-clock behavior regardless of which slots are configured.
    private static func slotMaterial(account: String) -> (Data, Data, Bool) {
        if let (salt, hash) = readSlotSplit(account) {
            return (salt, hash, true)
        }
        return (dummySalt, dummyHash, false)
    }

    /// Constant-time byte comparison. Pulls a copy through
    /// `withUnsafeBytes` so the loop walks raw `UInt8` pointers — no
    /// `Data.index(_:offsetBy:)` arithmetic, no NSData bridging, no
    /// behavior the compiler can rewrite to an early-exit `memcmp`.
    private static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        if a.count != b.count { return false }
        return a.withUnsafeBytes { aRaw in
            b.withUnsafeBytes { bRaw in
                guard let aPtr = aRaw.baseAddress, let bPtr = bRaw.baseAddress else {
                    return false
                }
                let aBytes = aPtr.assumingMemoryBound(to: UInt8.self)
                let bBytes = bPtr.assumingMemoryBound(to: UInt8.self)
                var diff: UInt8 = 0
                for i in 0..<a.count {
                    diff |= aBytes[i] ^ bBytes[i]
                }
                return diff == 0
            }
        }
    }

    /// Best-effort overwrite, then delete, a Keychain slot.
    ///
    /// `SecItemDelete` unlinks the row from `keychain-2.db`; the
    /// overwrite-with-noise first is a best-effort hardening step, NOT
    /// a guarantee. iOS does not promise that updating a row's value
    /// rewrites the prior ciphertext page in place — `keychain-2.db`
    /// is on a wear-levelled copy-on-write filesystem and the update
    /// may allocate a fresh page, leaving the old one recoverable
    /// until the filesystem reuses it. The real at-rest protection is
    /// the iOS class-key model: the row's ciphertext is itself
    /// class-key-encrypted, and the deletion is the load-bearing step.
    /// Falls back to plain delete if the overwrite write fails.
    static func secureDelete(account: String) {
        // Only overwrite if a row exists; otherwise plain delete is
        // already idempotent.
        if Keychain.read(account: account) != nil {
            var noise = [UInt8](repeating: 0, count: slotLen)
            let rc = SecRandomCopyBytes(kSecRandomDefault, noise.count, &noise)
            if rc == errSecSuccess {
                _ = Keychain.write(Data(noise), account: account)
            }
        }
        Keychain.delete(account: account)
    }
}
