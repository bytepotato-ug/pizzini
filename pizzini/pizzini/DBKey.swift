import CryptoKit
import Foundation
import PizziniCryptoCore
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
    /// for the future duress-passphrase task.
    static func eraseKeyMaterial() {
        Keychain.delete(account: wrapAccount)
        Keychain.delete(account: saltAccount)
        Keychain.delete(account: paramsAccount)
        deleteEnclaveKey()
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
    static func loadStoredParams() -> Argon2id.Params {
        guard
            let data = Keychain.read(account: paramsAccount),
            let stored = try? JSONDecoder().decode(StoredParams.self, from: data)
        else {
            return .production
        }
        return Argon2id.Params(
            memoryKiB: stored.memoryKiB,
            timeIterations: stored.timeIterations,
            parallelism: stored.parallelism,
        )
    }
}
