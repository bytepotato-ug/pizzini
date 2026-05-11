import CryptoKit
import Foundation
import PizziniCryptoCore
import PizziniDB
import Security

/// Derives the SQLCipher database key.
///
/// Threefold chain, in order:
///
/// 1. **Secure Enclave wrap.** A 32-byte random `seed` is generated on
///    first launch and encrypted with a SE-resident P-256 key whose
///    private half never leaves the chip. The ciphertext lives in
///    Keychain under `Self.wrapAccount`; the SE key handle lives under
///    `Self.enclaveTag`. Both are tagged
///    `AfterFirstUnlockThisDeviceOnly` so the existing offline-push
///    pipeline (notification service extension wakes up to update the
///    badge while the app is force-quit) keeps working without
///    user biometry.
///
/// 2. **Argon2id stretch.** The unwrapped seed is mixed with a
///    Keychain-resident `salt` (32 random bytes) under Argon2id with
///    the production parameter set (M=64 MiB, T=3, P=1 — ~250 ms on
///    iPhone 12 / ~80 ms on iPhone 15 Pro). Parameters are recorded
///    in Keychain too so a future hardware-aware bump can re-derive
///    and `PRAGMA rekey` without losing what the old DB was keyed
///    with.
///
/// 3. **SQLCipher key.** The 32-byte Argon2id output is the raw
///    SQLCipher key, fed to the DB via `PRAGMA key = "x'<hex>'"`
///    inside `PizziniDB.Database`.
///
/// Erasure path (used by the future duress-passphrase task):
///   delete `wrapAccount` and `enclaveTag` from Keychain + `unlink`
///   the database file. The seed is unrecoverable without the SE
///   key; the SE key is unrecoverable without the Keychain handle.
enum DBKey {
    enum DBKeyError: Error {
        case enclaveUnavailable(OSStatus)
        case wrapFailed
        case unwrapFailed
        case keychainWriteFailed
        case missingMaterial
    }

    /// Keychain account for the SE-wrapped seed ciphertext. Distinct
    /// from the legacy `device-store` / `app-state` / `outbox` slots
    /// so a `Storage.resetEverything` doesn't blow away the wrap by
    /// accident.
    static let wrapAccount = "db-key-wrap"
    /// Keychain account for the per-install Argon2id salt.
    static let saltAccount = "db-kdf-salt"
    /// Keychain account for the JSON-encoded Argon2id parameters
    /// (memoryKiB, timeIterations, parallelism). Stored in a
    /// separate slot from the salt so a parameter rotation doesn't
    /// require a salt rotation.
    static let paramsAccount = "db-kdf-params"
    /// Application tag for the SE-resident P-256 wrapping key.
    static let enclaveTag = "app.pizzini.db-wrap-key".data(using: .utf8)!
    /// USP #8: wall-clock (epoch seconds, big-endian u64) of the
    /// last at-rest-key rotation. Read on launch to decide whether
    /// `rotationDue` should fire; written by `rotateKeyMaterial`.
    /// Missing slot is treated as "rotate immediately" — the first
    /// post-install launch performs an initial rotation so the salt
    /// that ships in the first DB write is independent of any
    /// material reachable to an attacker who exfiltrated the
    /// pre-install Keychain (e.g. a profile-installed enterprise
    /// app sharing the access group).
    static let lastRotationAccount = "db-key-last-rotation"
    /// How often the at-rest key is rotated. Default 7 days
    /// balances "wall of forgotten plaintext recovers in ~52
    /// per-year" against the ~250 ms Argon2id + a one-time VACUUM
    /// cost the user pays on the first launch each week.
    static let rotationInterval: TimeInterval = 7 * 24 * 60 * 60

    /// Codable shape persisted under `paramsAccount`.
    struct StoredParams: Codable {
        let memoryKiB: UInt32
        let timeIterations: UInt32
        let parallelism: UInt32
    }

    /// Derive the 32-byte database key. Creates the SE key + seed +
    /// salt on first call; reuses them on every subsequent call.
    /// `params` defaults to the production preset; callers that need
    /// fast tests (or run inside CI where 250 ms × every-test would
    /// be noticeable) pass a smaller preset via `Argon2id.Params`.
    static func deriveKey(
        params: Argon2id.Params = .production,
        persistParams: Bool = true,
    ) throws -> Data {
        let seed = try unwrapOrCreateSeed()
        let salt = try loadOrCreateSalt()
        let key = try Argon2id.derive(
            passphrase: seed,
            salt: salt,
            params: params,
            outputLength: 32,
        )
        if persistParams {
            try persistParamsIfMissing(params)
        }
        return key
    }

    /// Wipe the wrap + salt + params slots. Combined with `unlink` of
    /// the database file this is the cryptographic-erasure primitive
    /// for the duress-passphrase flow.
    ///
    /// Each Keychain row is OVERWRITTEN with random bytes of equal
    /// length before deletion. `SecItemDelete` only unlinks the row
    /// from `keychain-2.db`; on most modern iOS releases the underlying
    /// ciphertext block can persist in NAND. Forcing a re-encrypt
    /// under a new IV raises the bar against Cellebrite-class flash
    /// forensics. The SE key itself cannot leak its private half (the
    /// chip's attestation guarantees that), so a plain delete of its
    /// handle is sufficient.
    static func eraseKeyMaterial() {
        secureDeleteKeychainSlot(account: wrapAccount)
        secureDeleteKeychainSlot(account: saltAccount)
        secureDeleteKeychainSlot(account: paramsAccount)
        // USP #8: the rotation timestamp lives in Keychain too — if
        // we left it around, a future reinstall would inherit a
        // stale "last rotated" mark and the first-launch initial
        // rotation would be skipped. Drop the slot here so reinstall
        // = fresh rotation cycle.
        secureDeleteKeychainSlot(account: lastRotationAccount)
        deleteEnclaveKey()
    }

    /// Overwrite a Keychain row with same-sized random bytes, then
    /// delete it. Used by `eraseKeyMaterial` (duress flow) and by the
    /// AppPasscode slot teardown so the on-disk Keychain page is
    /// re-encrypted before the row entry is unlinked.
    private static func secureDeleteKeychainSlot(account: String) {
        if let existing = Keychain.read(account: account) {
            var noise = [UInt8](repeating: 0, count: max(existing.count, 16))
            let rc = SecRandomCopyBytes(kSecRandomDefault, noise.count, &noise)
            if rc == errSecSuccess {
                _ = Keychain.write(Data(noise), account: account)
            }
        }
        Keychain.delete(account: account)
    }

    /// Convenience: True iff the SE-wrap exists. Used by the
    /// migration runner to tell "first launch with SQLCipher" from
    /// "ordinary re-launch".
    static var isInitialized: Bool {
        Keychain.read(account: wrapAccount) != nil
            && Keychain.read(account: saltAccount) != nil
    }

    // MARK: - SE-backed seed wrap

    private static func unwrapOrCreateSeed() throws -> Data {
        if let wrapped = Keychain.read(account: wrapAccount) {
            return try unwrapSeed(wrapped)
        }
        // First-launch path: generate a 32-byte seed, wrap it,
        // write the ciphertext into Keychain. The seed itself is
        // discarded — it lives only inside the SE wrap from now on.
        var seedBytes = [UInt8](repeating: 0, count: 32)
        let rc = SecRandomCopyBytes(kSecRandomDefault, seedBytes.count, &seedBytes)
        guard rc == errSecSuccess else {
            throw DBKeyError.wrapFailed
        }
        let seed = Data(seedBytes)
        let wrapped = try wrapSeed(seed)
        guard Keychain.write(wrapped, account: wrapAccount) else {
            throw DBKeyError.keychainWriteFailed
        }
        return seed
    }

    private static func wrapSeed(_ seed: Data) throws -> Data {
        let pub = try enclavePublicKey()
        var cfError: Unmanaged<CFError>?
        guard let wrapped = SecKeyCreateEncryptedData(
            pub,
            // ECIES + AES-GCM. The variant baked into iOS is
            // standardized; `eciesEncryptionStandardX963SHA256AESGCM`
            // hashes the ECDH shared secret through SHA-256 (X9.63
            // KDF) and uses AES-GCM for the symmetric leg — exactly
            // the construction we want for a small fixed-size seed.
            .eciesEncryptionStandardX963SHA256AESGCM,
            seed as CFData,
            &cfError,
        ) else {
            throw DBKeyError.wrapFailed
        }
        return wrapped as Data
    }

    private static func unwrapSeed(_ wrapped: Data) throws -> Data {
        let priv = try enclavePrivateKey()
        var cfError: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(
            priv,
            .eciesEncryptionStandardX963SHA256AESGCM,
            wrapped as CFData,
            &cfError,
        ) else {
            throw DBKeyError.unwrapFailed
        }
        return plain as Data
    }

    private static func enclavePrivateKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String:                kSecClassKey,
            kSecAttrApplicationTag as String:   enclaveTag,
            kSecAttrKeyType as String:          kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:            true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let item {
            return (item as! SecKey)
        }
        if status == errSecItemNotFound {
            return try createEnclaveKey()
        }
        throw DBKeyError.enclaveUnavailable(status)
    }

    private static func enclavePublicKey() throws -> SecKey {
        let priv = try enclavePrivateKey()
        guard let pub = SecKeyCopyPublicKey(priv) else {
            throw DBKeyError.enclaveUnavailable(errSecInternalError)
        }
        return pub
    }

    private static func createEnclaveKey() throws -> SecKey {
        // Access control:
        //   - `.privateKeyUsage`     allow the SE key to participate
        //                            in `SecKeyCreateDecryptedData`.
        //   - accessibility tier matches the rest of Pizzini's
        //     Keychain posture: after first unlock, this device
        //     only. Choosing a stricter tier (e.g.
        //     `.devicePasscode`) would block the notification
        //     service extension's badge math path because it runs
        //     during APNs wake-up — pre any biometric prompt.
        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            &acError,
        ) else {
            throw DBKeyError.enclaveUnavailable(errSecInternalError)
        }

        let attrs: [String: Any] = [
            kSecAttrKeyType as String:           kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String:     256,
            // `kSecAttrTokenIDSecureEnclave` is what makes this an
            // SE-resident key. Without it we'd get a software ECC
            // key, defeating the hardware-binding goal.
            kSecAttrTokenID as String:           kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String:       true,
                kSecAttrApplicationTag as String:    enclaveTag,
                kSecAttrAccessControl as String:     access,
            ],
        ]

        var cfError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &cfError) else {
            throw DBKeyError.enclaveUnavailable(errSecInternalError)
        }
        return key
    }

    private static func deleteEnclaveKey() {
        let query: [String: Any] = [
            kSecClass as String:               kSecClassKey,
            kSecAttrApplicationTag as String:  enclaveTag,
            kSecAttrKeyType as String:         kSecAttrKeyTypeECSECPrimeRandom,
        ]
        _ = SecItemDelete(query as CFDictionary)
    }

    // MARK: - Salt + params

    private static func loadOrCreateSalt() throws -> Data {
        if let salt = Keychain.read(account: saltAccount), salt.count >= 16 {
            return salt
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        let rc = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard rc == errSecSuccess else {
            throw DBKeyError.wrapFailed
        }
        let salt = Data(bytes)
        guard Keychain.write(salt, account: saltAccount) else {
            throw DBKeyError.keychainWriteFailed
        }
        return salt
    }

    private static func persistParamsIfMissing(_ params: Argon2id.Params) throws {
        if Keychain.read(account: paramsAccount) != nil { return }
        let stored = StoredParams(
            memoryKiB: params.memoryKiB,
            timeIterations: params.timeIterations,
            parallelism: params.parallelism,
        )
        let data = try JSONEncoder().encode(stored)
        guard Keychain.write(data, account: paramsAccount) else {
            throw DBKeyError.keychainWriteFailed
        }
    }

    /// Restore the Argon2id parameters under which this database was
    /// last keyed. Returns the production preset if no params row
    /// exists (first install path) — that's also what got written.
    ///
    /// **Validation against pre-planted weak params.** A Keychain
    /// row written before first launch by another process (a profile-
    /// installed enterprise app sharing an access group, a Cellebrite
    /// staging attack) could plant `M=8 KiB, T=1, P=1`-style weak
    /// parameters. Pizzini would then mint the DB key under those
    /// parameters and an offline Argon2id grind becomes feasible
    /// against a captured extraction. The minimum-strength gate below
    /// catches that: any stored params weaker than half of production
    /// memory OR less than 2 iterations are treated as tampered and
    /// rejected, falling back to `.production`. The legitimate use
    /// case for non-production params is unit tests, which use
    /// `Argon2id.Params` directly rather than going through the
    /// Keychain round-trip.
    static func loadStoredParams() -> Argon2id.Params {
        guard
            let data = Keychain.read(account: paramsAccount),
            let stored = try? JSONDecoder().decode(StoredParams.self, from: data)
        else {
            return .production
        }
        let params = Argon2id.Params(
            memoryKiB: stored.memoryKiB,
            timeIterations: stored.timeIterations,
            parallelism: stored.parallelism,
        )
        if paramsFailMinimumStrength(params) {
            NSLog("[pizzini.dbkey] stored Argon2id params below floor — using production")
            return .production
        }
        return params
    }

    /// True if stored params look like a tamper / downgrade attempt:
    /// memory < 32 MiB (half of production) OR iterations < 2.
    /// Production is M=64 MiB, T=3, P=1. The floor leaves room for
    /// future hardware-aware lowering on truly resource-constrained
    /// devices while still refusing anything that's brute-forceable
    /// in seconds.
    private static func paramsFailMinimumStrength(_ p: Argon2id.Params) -> Bool {
        if p.memoryKiB < 32 * 1024 { return true }  // < 32 MiB
        if p.timeIterations < 2 { return true }
        return false
    }

    // MARK: - USP #8: timed at-rest key rotation

    /// True iff the at-rest key has not been rotated within
    /// `rotationInterval`. The first post-install launch always
    /// returns true (no slot present → treat as "due"), giving
    /// the user a fresh salt that's not reachable to any
    /// pre-install Keychain reader.
    static func rotationDue(now: Date = Date()) -> Bool {
        guard let bytes = Keychain.read(account: lastRotationAccount),
              bytes.count == MemoryLayout<UInt64>.size
        else {
            return true
        }
        let epoch = bytes.withUnsafeBytes { raw -> UInt64 in
            let beValue = raw.load(as: UInt64.self)
            return UInt64(bigEndian: beValue)
        }
        let last = Date(timeIntervalSince1970: TimeInterval(epoch))
        return now.timeIntervalSince(last) >= rotationInterval
    }

    /// Run a full at-rest key rotation against the already-open
    /// `db`. The caller owns the live DB connection (so we don't
    /// open + close + re-open here, which would require the host
    /// to thread a fresh handle through the entire app). Steps:
    ///
    ///   1. Derive a fresh 32-byte key from a brand-new salt
    ///      (existing SE-wrapped seed; existing Argon2id params).
    ///   2. `sqlite3_rekey_v2` to re-encrypt every page under the
    ///      new key.
    ///   3. `VACUUM` to rewrite the entire file, purging any
    ///      orphaned plaintext-shaped bytes the rekey alone left
    ///      behind (SQLite doesn't reclaim freelist pages without
    ///      vacuum; a wiped page on disk under the old key is
    ///      still recoverable forensically until those bytes are
    ///      overwritten).
    ///   4. Persist the new salt (so the next launch derives the
    ///      same key) and a fresh rotation timestamp.
    ///   5. Return the new key so the caller can keep it in
    ///      memory for the rest of the session.
    ///
    /// If any step throws, the DB is in an indeterminate state.
    /// Callers must either (a) reopen with the old key — they
    /// still have the old salt in Keychain until step 4 — or
    /// (b) report the failure and force-quit. The function is
    /// transactional only in the all-or-nothing sense of "the
    /// Keychain salt commit at step 4 is the point of no return."
    static func rotateKeyMaterial(
        liveDB db: Database,
        params: Argon2id.Params = DBKey.loadStoredParams(),
        now: Date = Date(),
    ) throws -> Data {
        let seed = try unwrapOrCreateSeed()

        // Step 1: fresh salt + fresh derivation.
        var saltBytes = [UInt8](repeating: 0, count: 32)
        let saltRC = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
        guard saltRC == errSecSuccess else { throw DBKeyError.wrapFailed }
        let newSalt = Data(saltBytes)
        let newKey = try Argon2id.derive(
            passphrase: seed,
            salt: newSalt,
            params: params,
            outputLength: 32,
        )

        // Step 2: SQLCipher rekey. Throws on failure; DB stays
        // openable under the old key in that case.
        try db.rekey(newRawKey: newKey)

        // Step 3: vacuum. Releases freelist pages back as
        // ciphertext-under-the-new-key bytes; before this call
        // the old plaintext-on-disk pattern can still be
        // reconstructed by a forensic analyst with the
        // pre-rotation key.
        try db.execute("VACUUM;")

        // Step 4: commit the new salt + rotation timestamp. The
        // order here is load-bearing — until both lines complete,
        // the on-disk salt still derives the OLD key, which is no
        // longer the DB's key. A crash between rekey and salt-write
        // is recoverable: the next launch fails the SQLCipher
        // smoke-read, the user re-runs onboarding. A crash AFTER
        // the salt write but before timestamp write means we'll
        // rotate again on the next launch — wasteful but safe.
        guard Keychain.write(newSalt, account: saltAccount) else {
            throw DBKeyError.keychainWriteFailed
        }
        var epochBE = UInt64(now.timeIntervalSince1970).bigEndian
        let stampBytes = withUnsafeBytes(of: &epochBE) { Data($0) }
        guard Keychain.write(stampBytes, account: lastRotationAccount) else {
            throw DBKeyError.keychainWriteFailed
        }

        return newKey
    }
}
