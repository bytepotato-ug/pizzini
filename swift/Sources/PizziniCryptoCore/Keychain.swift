// Production Keychain wrapper for Pizzini's long-term cryptographic state:
// the Secure-Enclave-wrapped DB seed, the Argon2id salt + params, the
// at-rest-key rotation stamp, the real + duress AppPasscode slots, and the
// legacy migration slots. Every item is stored with
// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (device-bound, readable
// after first unlock so the Notification Service Extension's badge path works
// while the app is force-quit) and `kSecAttrSynchronizable = false` set
// EXPLICITLY — the iCloud-mirroring posture of sensitive items is asserted in
// code, not inherited from an iOS default that a future edit to this shared
// wrapper (or an OS-version default change) could silently flip for every
// caller at once. SE-resident keys themselves are created directly in
// `DBKey` via `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`;
// this wrapper handles the generic-password rows that pair with them.

import Foundation
import Security

public enum Keychain {
    public enum KeychainError: Error, Sendable {
        case unhandled(OSStatus)
    }

    public static func read(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String:             kSecClassGenericPassword,
            kSecAttrService as String:       "app.pizzini",
            kSecAttrAccount as String:       account,
            // Match only non-synchronizable items — every item this
            // wrapper writes is `false`, and being explicit keeps a
            // read from ever picking up an iCloud-mirrored row that
            // some other code path (or a restore) introduced.
            kSecAttrSynchronizable as String: false,
            kSecReturnData as String:        true,
            kSecMatchLimit as String:        kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { return nil }
        return item as? Data
    }

    @discardableResult
    public static func write(_ data: Data, account: String) -> Bool {
        // Upsert: try update first, fall back to add.
        let query: [String: Any] = [
            kSecClass as String:             kSecClassGenericPassword,
            kSecAttrService as String:       "app.pizzini",
            kSecAttrAccount as String:       account,
            // Scope the match to non-synchronizable rows so the
            // update targets the item this wrapper owns.
            kSecAttrSynchronizable as String: false,
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String:          data,
            kSecAttrAccessible as String:     kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            // Assert "never mirrored to iCloud Keychain" in code, not
            // by relying on the default.
            kSecAttrSynchronizable as String: false,
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecSuccess { return true }

        var addAttrs = query
        addAttrs[kSecValueData as String]      = data
        addAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        // `kSecAttrSynchronizable: false` is already in `query`, which
        // `addAttrs` copies — the added item is explicitly local-only.
        let addStatus = SecItemAdd(addAttrs as CFDictionary, nil)
        return addStatus == errSecSuccess
    }

    @discardableResult
    public static func delete(account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String:             kSecClassGenericPassword,
            kSecAttrService as String:       "app.pizzini",
            kSecAttrAccount as String:       account,
            // `kSecAttrSynchronizableAny` on delete so a row written
            // under EITHER policy is still removable — a wipe must not
            // leave an orphan behind just because some prior build (or
            // a restore) marked the item synchronizable.
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
