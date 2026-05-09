import Foundation
import PizziniCryptoCore

/// Three Keychain slots, one role each:
///
/// - `device-store` — opaque libsignal blob from `Session.serialize()`.
///   The post-pairing-rewrite source of truth for the ratchet.
/// - `app-state` — JSON `AppState` (relay host, contacts list, message
///   logs). Re-encoded on every mutation.
/// - `long-term-identity` — legacy slot, IdentityKeyPair-only bytes from
///   pre-persistence builds. Read once to migrate, then deleted.
///
/// All slots use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. The
/// production storage layer (SQLCipher + Secure Enclave) is downstream.
enum Storage {
    static let deviceStoreAccount = "device-store"
    static let appStateAccount = "app-state"
    static let outboxAccount = "outbox"
    static let legacyIdentityAccount = "long-term-identity"

    /// Load the libsignal session, migrating an old identity-only blob if
    /// that's all that's available. Returns a fresh `Session` if neither
    /// slot is populated yet.
    static func loadOrCreateSession() throws -> Session {
        if let blob = Keychain.read(account: deviceStoreAccount) {
            return try Session(serialized: blob)
        }
        if let seed = Keychain.read(account: legacyIdentityAccount) {
            // Migrate: rehydrate from the seed, persist a full snapshot
            // under the new key, drop the legacy slot.
            let s = try Session(identitySeed: seed)
            try persist(session: s)
            Keychain.delete(account: legacyIdentityAccount)
            return s
        }
        let s = try Session()
        try persist(session: s)
        return s
    }

    static func persist(session: Session) throws {
        let blob = try session.serialize()
        _ = Keychain.write(blob, account: deviceStoreAccount)
    }

    static func loadAppState() -> AppState {
        guard
            let data = Keychain.read(account: appStateAccount),
            let decoded = try? JSONDecoder().decode(AppState.self, from: data)
        else {
            return AppState()
        }
        return decoded
    }

    static func persist(appState: AppState) {
        guard let data = try? JSONEncoder().encode(appState) else { return }
        _ = Keychain.write(data, account: appStateAccount)
    }

    static func loadOutbox() -> OutboxStore {
        guard let data = Keychain.read(account: outboxAccount),
              let store = try? JSONDecoder().decode(OutboxStore.self, from: data)
        else { return .empty }
        return store
    }

    static func persist(outbox: OutboxStore) {
        guard let data = try? JSONEncoder().encode(outbox) else { return }
        _ = Keychain.write(data, account: outboxAccount)
    }

    /// Wipes everything Pizzini owns in Keychain. Used by "Reset identity"
    /// — different from "delete all chats" (which only clears logs).
    static func resetEverything() {
        Keychain.delete(account: deviceStoreAccount)
        Keychain.delete(account: appStateAccount)
        Keychain.delete(account: outboxAccount)
        Keychain.delete(account: legacyIdentityAccount)
    }
}
