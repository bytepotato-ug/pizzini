import CryptoKit
import Foundation
import os
import PizziniCryptoCore
import PizziniDB
import Security

/// At-rest key derivation log channel. Console.app filter:
/// `subsystem:app.pizzini category:dbkey`. The messages emitted
/// here are static strings (no sensitive interpolation) because
/// anything covering the actual key material or Argon2id output
/// would be a leak — we only log policy decisions ("params below
/// floor", etc.).
private let dbKeyLog = Logger(subsystem: "app.pizzini", category: "dbkey")

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
    /// Staging slot for the at-rest key rotation. `rotateKeyMaterial`
    /// writes the new salt here BEFORE `db.rekey`, so a crash between
    /// the rekey and the promotion of the new salt to `saltAccount`
    /// is recoverable: `bootstrap`'s `deriveKey` retries under the
    /// staged salt before giving up. Cleared once the salt is
    /// promoted, and on `eraseKeyMaterial`.
    static let stagedSaltAccount = "db-kdf-salt-staged"
    /// Keychain account for the JSON-encoded Argon2id parameters
    /// (memoryKiB, timeIterations, parallelism). Stored in a
    /// separate slot from the salt so a parameter rotation doesn't
    /// require a salt rotation.
    static let paramsAccount = "db-kdf-params"
    /// Application tag for the SE-resident P-256 wrapping key.
    static let enclaveTag = "app.pizzini.db-wrap-key".data(using: .utf8)!
    /// Wall-clock (epoch seconds, big-endian u64) of the
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
    /// The wrap row is plain-deleted first (a single atomic Keychain
    /// op — see the body comment); the remaining rows are deleted
    /// after a best-effort overwrite (see `secureDeleteKeychainSlot`).
    /// The SE key itself cannot leak
    /// its private half (the chip's attestation guarantees that), so a
    /// plain delete of its handle is sufficient — but the delete can
    /// still fail (`errSecInteractionNotAllowed` while the device is
    /// locked-after-first-unlock, key in use), so its status is checked.
    ///
    /// Returns `true` only if every key-material delete is confirmed.
    /// The duress path uses the return value to decide whether the
    /// wipe genuinely completed — it must not report a completed wipe
    /// while a usable decryption path survives.
    @discardableResult
    static func eraseKeyMaterial() -> Bool {
        var ok = true
        // The wrap row is what `isInitialized` (and therefore the
        // bootstrap orphan check) gates on. Delete it with a plain,
        // single Keychain op FIRST — before any overwrite-then-delete
        // on the other slots — so a force-quit can never catch the
        // wrap row present-but-overwritten-with-noise. That
        // intermediate state still reads as `isInitialized == true`,
        // which would defeat the orphan check and leave a duress-wiped
        // device showing an error banner behind a passcode gate
        // instead of a clean fresh-install surface. A plain
        // `SecItemDelete` flips `isInitialized` false atomically;
        // re-introducing that window for the sake of a best-effort
        // overwrite (see `secureDeleteKeychainSlot`) is not worth it.
        ok = Keychain.delete(account: wrapAccount) && ok
        ok = secureDeleteKeychainSlot(account: saltAccount) && ok
        ok = secureDeleteKeychainSlot(account: paramsAccount) && ok
        // The rotation timestamp lives in Keychain too — if
        // we left it around, a future reinstall would inherit a
        // stale "last rotated" mark and the first-launch initial
        // rotation would be skipped. Drop the slot here so reinstall
        // = fresh rotation cycle.
        ok = secureDeleteKeychainSlot(account: lastRotationAccount) && ok
        // Staging slot for the crash-atomic rekey (see
        // `rotateKeyMaterial`). If a rotation was interrupted before
        // the staged salt was promoted, the slot is still on disk and
        // must go too.
        ok = secureDeleteKeychainSlot(account: stagedSaltAccount) && ok
        ok = deleteEnclaveKey() && ok
        return ok
    }

    /// Best-effort overwrite of a Keychain row with same-sized random
    /// bytes, then delete it. Used by `eraseKeyMaterial` (duress flow)
    /// and by the AppPasscode slot teardown.
    ///
    /// The overwrite is a best-effort hardening step, not a guarantee:
    /// `keychain-2.db` sits on a wear-levelled copy-on-write filesystem
    /// and iOS does not promise that overwriting a row's value rewrites
    /// the prior ciphertext page rather than allocating a fresh one.
    /// The actual at-rest protection is the iOS class-key model — the
    /// row's ciphertext is itself class-key-encrypted. The unlink
    /// (`SecItemDelete`) is the load-bearing step; its status is the
    /// return value.
    @discardableResult
    private static func secureDeleteKeychainSlot(account: String) -> Bool {
        if let existing = Keychain.read(account: account) {
            var noise = [UInt8](repeating: 0, count: max(existing.count, 16))
            let rc = SecRandomCopyBytes(kSecRandomDefault, noise.count, &noise)
            if rc == errSecSuccess {
                _ = Keychain.write(Data(noise), account: account)
            }
        }
        return Keychain.delete(account: account)
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

    /// Delete the SE-resident wrapping key handle. Returns `true` only
    /// if the delete is confirmed — `errSecItemNotFound` counts as
    /// confirmed-gone. A failure here (e.g. `errSecInteractionNotAllowed`
    /// when the device is locked-after-first-unlock) leaves a usable SE
    /// key behind; the caller (`eraseKeyMaterial`) propagates that so
    /// the duress flow never reports a wipe it did not actually finish.
    @discardableResult
    private static func deleteEnclaveKey() -> Bool {
        let query: [String: Any] = [
            kSecClass as String:               kSecClassKey,
            kSecAttrApplicationTag as String:  enclaveTag,
            kSecAttrKeyType as String:         kSecAttrKeyTypeECSECPrimeRandom,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
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

    /// Every Argon2id preset a Pizzini build has ever keyed a
    /// database under. The persisted `db-kdf-params` Keychain row is
    /// attacker-reachable (a profile-installed enterprise app sharing
    /// an access group, a Cellebrite staging attack), so it is
    /// advisory, not authoritative — the set of parameters the code
    /// will actually key a DB under must be this small, code-defined,
    /// audit-visible list, not "anything above a floor."
    ///
    /// Only `.production` has ever shipped. If a future hardware-aware
    /// tuning bump lands, its preset is appended here (and `bootstrap`
    /// gains it as a `keyingFailed` fallback automatically — see
    /// `historicallyShippedParams`).
    static let acceptedParamPresets: [Argon2id.Params] = [.production]

    /// Presets a `keyingFailed` open should retry under, in order.
    /// `bootstrap` walks this list when the stored-params-derived key
    /// does not open the on-disk DB — the DB could legitimately have
    /// been keyed under any preset this code has shipped, and the
    /// (mutable, attacker-reachable) params row is not authoritative
    /// enough to brick the store over.
    static let historicallyShippedParams: [Argon2id.Params] = [.production]

    /// Restore the Argon2id parameters under which this database was
    /// last keyed. Returns the production preset if no params row
    /// exists (first install path) — that's also what got written.
    ///
    /// **Validation against tampered params.** A Keychain row written
    /// before first launch by another process could plant weakened
    /// parameters; Pizzini would then mint the DB key under them and
    /// an offline Argon2id grind becomes feasible against a captured
    /// extraction. The gate below is an exact-match allowlist: the
    /// stored params must equal one of `acceptedParamPresets` (today,
    /// only `.production`) or they are treated as tampered and
    /// `.production` is used instead. An open `>=` floor would let an
    /// attacker key the DB at any work factor above the floor — half
    /// production, say — which is still pure attack surface until a
    /// hardware-aware lowering path actually ships. The legitimate use
    /// case for non-production params is unit tests, which use
    /// `Argon2id.Params` directly rather than the Keychain round-trip.
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
            dbKeyLog.notice("stored Argon2id params not an accepted preset — using production")
            return .production
        }
        return params
    }

    /// True if stored params are NOT one of `acceptedParamPresets`.
    /// The set of KDF parameters the code will key a database under
    /// is a small, code-defined, audit-visible set — not "anything
    /// above an arbitrary floor." Internal (not private) so tests can
    /// pin the allowlist — see `DBKeyParamsFloorTests`.
    static func paramsFailMinimumStrength(_ p: Argon2id.Params) -> Bool {
        !acceptedParamPresets.contains(p)
    }

    // MARK: - Timed at-rest key rotation

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
    ///   2. Stage the new salt to `stagedSaltAccount` BEFORE the
    ///      rekey, so a crash after the rekey can still recover the
    ///      key that opens the on-disk DB.
    ///   3. `sqlite3_rekey_v2` to re-encrypt every page under the
    ///      new key.
    ///   4. `VACUUM` to rewrite the entire file, purging any
    ///      orphaned plaintext-shaped bytes the rekey alone left
    ///      behind (SQLite doesn't reclaim freelist pages without
    ///      vacuum; a wiped page on disk under the old key is
    ///      still recoverable forensically until those bytes are
    ///      overwritten).
    ///   5. Promote the staged salt to `saltAccount` and write a
    ///      fresh rotation timestamp, then clear the staging slot.
    ///   6. Return the new key so the caller can keep it in
    ///      memory for the rest of the session.
    ///
    /// **Crash-atomicity.** The staged salt is written before the
    /// rekey, so at no instant does the persisted material fail to
    /// derive a key that opens the on-disk DB:
    ///   - Crash before rekey: `saltAccount` still derives the live
    ///     key; the orphan staged salt is ignored on next launch.
    ///   - Crash between rekey and salt promotion: `saltAccount`
    ///     derives the OLD key, but `stagedSaltAccount` derives the
    ///     NEW key — `bootstrap` tries the staged salt as a fallback
    ///     (`deriveKey(useStagedSalt:)`) and recovers the DB without
    ///     data loss.
    ///   - Crash after promotion: the next launch re-rotates
    ///     (timestamp not yet written) — wasteful but safe.
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

        // Step 2: stage the new salt BEFORE the rekey. This is the
        // crash-atomicity hook — if the process dies after the rekey
        // but before the salt is promoted, `bootstrap` can still
        // recover the DB from this staged copy.
        guard Keychain.write(newSalt, account: stagedSaltAccount) else {
            throw DBKeyError.keychainWriteFailed
        }

        // Step 3: SQLCipher rekey. Throws on failure; DB stays
        // openable under the old key in that case (the staged salt
        // is then a harmless orphan the next launch ignores).
        try db.rekey(newRawKey: newKey)

        // Step 4: vacuum. Releases freelist pages back as
        // ciphertext-under-the-new-key bytes; before this call
        // the old plaintext-on-disk pattern can still be
        // reconstructed by a forensic analyst with the
        // pre-rotation key.
        try db.execute("VACUUM;")

        // Step 5: promote the staged salt to the live slot, then the
        // rotation timestamp. A crash AFTER the salt write but before
        // the timestamp write means we'll rotate again on the next
        // launch — wasteful but safe.
        guard Keychain.write(newSalt, account: saltAccount) else {
            throw DBKeyError.keychainWriteFailed
        }
        // Staging slot is now redundant — clear it so a later
        // unrelated crash-recovery doesn't find a stale staged salt.
        Keychain.delete(account: stagedSaltAccount)
        var epochBE = UInt64(now.timeIntervalSince1970).bigEndian
        let stampBytes = withUnsafeBytes(of: &epochBE) { Data($0) }
        guard Keychain.write(stampBytes, account: lastRotationAccount) else {
            throw DBKeyError.keychainWriteFailed
        }

        return newKey
    }

    /// Derive the database key using the *staged* rotation salt
    /// (`stagedSaltAccount`) rather than the live one. Used by
    /// `SQLiteStorage.bootstrap` as the recovery path when a key
    /// derived from `saltAccount` fails the SQLCipher smoke-read —
    /// the symptom of a rotation crash between `db.rekey` and the
    /// salt promotion. Returns nil if no staged salt is present.
    static func deriveKeyWithStagedSalt(params: Argon2id.Params = .production) throws -> Data? {
        guard let stagedSalt = Keychain.read(account: stagedSaltAccount),
              stagedSalt.count >= 16 else {
            return nil
        }
        let seed = try unwrapOrCreateSeed()
        return try Argon2id.derive(
            passphrase: seed,
            salt: stagedSalt,
            params: params,
            outputLength: 32,
        )
    }

    /// Promote the staged rotation salt to the live slot. Called by
    /// `bootstrap` after the staged-salt recovery path succeeds, so
    /// subsequent launches derive the correct key from `saltAccount`
    /// directly. Best-effort: a failure here just means the next
    /// launch repeats the staged-salt recovery.
    static func promoteStagedSalt() {
        guard let stagedSalt = Keychain.read(account: stagedSaltAccount) else { return }
        if Keychain.write(stagedSalt, account: saltAccount) {
            Keychain.delete(account: stagedSaltAccount)
        }
    }
}
