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
/// Both are stored as Argon2id hashes in Keychain (separate slots,
/// distinct salts). The salts are 32 random bytes per slot; the
/// hashes are 32-byte Argon2id outputs under the
/// `Argon2id.Params.production` preset (M=64 MiB, T=3, P=1 — ~250 ms
/// on iPhone 12). Verification re-derives with the stored salt and
/// constant-time-compares against the stored hash, so an attacker
/// with Keychain read access still has to brute-force the passcode
/// at full Argon2id cost per guess.
///
/// Importantly: **the database encryption key is NOT derived from
/// these passcodes**. The DB key is the Secure-Enclave-wrapped seed
/// stretched by Argon2id in `DBKey`; that derivation runs even when
/// no app-level passcode is set. This module is an *access gate*
/// (and the duress trigger), not the cryptographic key source. A
/// future v2 could fold the passcode into the DB key derivation so
/// "forgetting the duress passcode" becomes irrecoverable on every
/// dimension — for now the SE-wrap is the primary defence against
/// off-device attacks and the passcode is the on-device coercion
/// gate.
@MainActor
enum AppPasscode {
    // MARK: - Keychain slot names

    static let realHashAccount = "app-passcode-hash"
    static let realSaltAccount = "app-passcode-salt"
    static let duressHashAccount = "duress-passcode-hash"
    static let duressSaltAccount = "duress-passcode-salt"

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
        Keychain.read(account: realHashAccount) != nil
            && Keychain.read(account: realSaltAccount) != nil
    }

    static var isDuressPasscodeSet: Bool {
        Keychain.read(account: duressHashAccount) != nil
            && Keychain.read(account: duressSaltAccount) != nil
    }

    // MARK: - Setters

    /// Set or replace the real passcode. Throws `tooShort` if the
    /// string is below `minLength`. Caller is responsible for
    /// rejecting the duress passcode value if it matches an existing
    /// real one (and vice versa) at the UI layer — that check uses
    /// `check(_:)`.
    static func setPasscode(_ passcode: String) throws {
        try setPasscodeIntoSlots(
            passcode,
            hashAccount: realHashAccount,
            saltAccount: realSaltAccount,
        )
    }

    /// Set or replace the duress passcode. Same shape as `setPasscode`.
    /// Caller must ensure this value differs from the real passcode
    /// — entering identical strings under both labels would silently
    /// trigger the wipe on every legitimate unlock.
    static func setDuressPasscode(_ passcode: String) throws {
        if verifyPasscode(passcode) {
            throw PasscodeError.sameAsExisting
        }
        try setPasscodeIntoSlots(
            passcode,
            hashAccount: duressHashAccount,
            saltAccount: duressSaltAccount,
        )
    }

    /// Remove the real passcode. Used when the user disables app-
    /// passcode entry entirely (e.g. enables Face ID and decides the
    /// fallback isn't worth the friction). Returns silently if no
    /// passcode is set.
    static func clearPasscode() {
        Keychain.delete(account: realHashAccount)
        Keychain.delete(account: realSaltAccount)
    }

    /// Remove the duress passcode. Q3 in the design discussion lands
    /// at "removable in Settings" — this is the entry point.
    static func clearDuressPasscode() {
        Keychain.delete(account: duressHashAccount)
        Keychain.delete(account: duressSaltAccount)
    }

    // MARK: - Verification

    /// Verify `entry` against the real passcode. Returns false if no
    /// passcode is set OR `entry` doesn't match.
    static func verifyPasscode(_ entry: String) -> Bool {
        guard let salt = Keychain.read(account: realSaltAccount),
              let stored = Keychain.read(account: realHashAccount)
        else {
            return false
        }
        return verify(entry: entry, salt: salt, expected: stored)
    }

    /// Verify `entry` against the duress passcode.
    static func verifyDuressPasscode(_ entry: String) -> Bool {
        guard let salt = Keychain.read(account: duressSaltAccount),
              let stored = Keychain.read(account: duressHashAccount)
        else {
            return false
        }
        return verify(entry: entry, salt: salt, expected: stored)
    }

    /// Composite check: does `entry` match real, duress, or neither?
    /// **Duress is checked first** — the constant-time compare makes
    /// both verifications take roughly the same wall-clock time, so
    /// an attacker timing the response can't tell which path was
    /// taken. (The real defence against timing is in the Argon2id
    /// cost dominating, ~250 ms; the order is belt-and-suspenders.)
    static func check(_ entry: String) -> Match {
        if isDuressPasscodeSet, verifyDuressPasscode(entry) {
            return .duress
        }
        if isPasscodeSet, verifyPasscode(entry) {
            return .real
        }
        return .neither
    }

    /// Wipe both passcode slots. Used by the duress flow on a
    /// successful match — after the database is reset, the passcodes
    /// go too so the post-wipe state is a true clean slate.
    static func eraseAll() {
        clearPasscode()
        clearDuressPasscode()
    }

    // MARK: - Argon2id glue

    private static func setPasscodeIntoSlots(
        _ passcode: String,
        hashAccount: String,
        saltAccount: String,
    ) throws {
        guard !passcode.isEmpty else { throw PasscodeError.empty }
        guard passcode.count >= minLength else {
            throw PasscodeError.tooShort(minimum: minLength)
        }
        var saltBytes = [UInt8](repeating: 0, count: 32)
        let rc = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
        guard rc == errSecSuccess else { throw PasscodeError.derivationFailed }
        let salt = Data(saltBytes)
        let hash: Data
        do {
            hash = try Argon2id.derive(
                passphrase: Data(passcode.utf8),
                salt: salt,
                params: .production,
                outputLength: 32,
            )
        } catch {
            throw PasscodeError.derivationFailed
        }
        guard Keychain.write(salt, account: saltAccount),
              Keychain.write(hash, account: hashAccount)
        else {
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

    /// Constant-time byte comparison. Standard pattern: XOR every byte
    /// pair into an accumulator and return `accumulator == 0`. Branches
    /// don't depend on the data so a timing attacker can't learn how
    /// many leading bytes matched.
    private static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[a.index(a.startIndex, offsetBy: i)]
                ^ b[b.index(b.startIndex, offsetBy: i)]
        }
        return diff == 0
    }
}
