// Minimal Keychain wrapper for persisting raw byte material between launches.
// Data is stored ThisDeviceOnly, AfterFirstUnlock — the right default for
// long-term cryptographic state on iOS.
//
// For the production identity store this will graduate to Secure Enclave-backed
// keys (kSecAttrTokenIDSecureEnclave) and a passcode-required accessibility
// (kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly). The current settings are
// fine for the loopback demo.

import Foundation
import Security

public enum Keychain {
    public enum KeychainError: Error, Sendable {
        case unhandled(OSStatus)
    }

    public static func read(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrService as String:    "app.pizzini",
            kSecAttrAccount as String:    account,
            kSecReturnData as String:     true,
            kSecMatchLimit as String:     kSecMatchLimitOne,
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
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrService as String:    "app.pizzini",
            kSecAttrAccount as String:    account,
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String:      data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecSuccess { return true }

        var addAttrs = query
        addAttrs[kSecValueData as String]      = data
        addAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(addAttrs as CFDictionary, nil)
        return addStatus == errSecSuccess
    }

    @discardableResult
    public static func delete(account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String:          kSecClassGenericPassword,
            kSecAttrService as String:    "app.pizzini",
            kSecAttrAccount as String:    account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
