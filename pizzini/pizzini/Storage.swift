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

    /// `Storage` operations now propagate Keychain failures rather than
    /// `_ = Keychain.write(...)`-discarding them. F-602: a sustained
    /// write-fail loop would otherwise let the in-memory libsignal
    /// session keep advancing while the on-disk blob froze; on next
    /// cold launch the rolled-back blob loses session continuity and
    /// the user sees ✓✓ for messages the peer never gets.
    enum StorageError: Error {
        case keychainWriteFailed(account: String)
    }

    /// Load the libsignal session, migrating an old identity-only blob if
    /// that's all that's available. Returns a fresh `Session` if neither
    /// slot is populated yet.
    static func loadOrCreateSession() throws -> Session {
        if let blob = Keychain.read(account: deviceStoreAccount) {
            return try Session(serialized: blob)
        }
        if let seed = Keychain.read(account: legacyIdentityAccount) {
            // Migrate: rehydrate from the seed, persist a full snapshot
            // under the new key, then *verify the new slot is readable*
            // before deleting the legacy seed. F-603: a Keychain.write
            // failure between rehydrate and delete would otherwise wipe
            // both slots and force the user to re-pair from scratch.
            let s = try Session(identitySeed: seed)
            try persist(session: s)
            if Keychain.read(account: deviceStoreAccount) != nil {
                Keychain.delete(account: legacyIdentityAccount)
            } else {
                NSLog(
                    "[pizzini] migration kept legacy identity slot — new device-store slot did not read back"
                )
            }
            return s
        }
        let s = try Session()
        try persist(session: s)
        return s
    }

    @discardableResult
    static func persist(session: Session) throws -> Bool {
        let blob = try session.serialize()
        let ok = Keychain.write(blob, account: deviceStoreAccount)
        if !ok {
            // Surface to NSLog so a TestFlight tester or a developer
            // running with the device console attached sees a chronic
            // failure. Throwing also lets call sites that care propagate
            // it as a user-facing error (currently only the migration
            // path does — `persistSession()` deliberately wraps in `try?`
            // because it's invoked from non-throwing async contexts).
            NSLog("[pizzini] Keychain write FAILED for \(deviceStoreAccount)")
            throw StorageError.keychainWriteFailed(account: deviceStoreAccount)
        }
        return ok
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

    @discardableResult
    static func persist(appState: AppState) -> Bool {
        guard let data = try? JSONEncoder().encode(appState) else { return false }
        let ok = Keychain.write(data, account: appStateAccount)
        if !ok {
            NSLog("[pizzini] Keychain write FAILED for \(appStateAccount)")
        }
        return ok
    }

    static func loadOutbox() -> OutboxStore {
        guard let data = Keychain.read(account: outboxAccount),
              let store = try? JSONDecoder().decode(OutboxStore.self, from: data)
        else { return .empty }
        return store
    }

    @discardableResult
    static func persist(outbox: OutboxStore) -> Bool {
        guard let data = try? JSONEncoder().encode(outbox) else { return false }
        let ok = Keychain.write(data, account: outboxAccount)
        if !ok {
            NSLog("[pizzini] Keychain write FAILED for \(outboxAccount)")
        }
        return ok
    }

    /// Wipes everything Pizzini owns in Keychain. Used by "Reset identity"
    /// — different from "delete all chats" (which only clears logs).
    ///
    /// `preserveAppState`: F-703. When `true`, the app-state slot is left
    /// alone — `resetIdentity` writes the post-reset settings (preserved
    /// fields: `relayHost`, `autoLockTimeout`, `biometricLockEnabled`,
    /// `onboardingCompleted`) BEFORE calling resetEverything, and we
    /// must not undo that durable record. With the previous `false`-
    /// equivalent unconditional behaviour, a process kill between the
    /// wipe and the post-wipe re-persist silently downgraded the user's
    /// biometric posture on next launch.
    static func resetEverything(preserveAppState: Bool = false) {
        Keychain.delete(account: deviceStoreAccount)
        if !preserveAppState {
            Keychain.delete(account: appStateAccount)
        }
        Keychain.delete(account: outboxAccount)
        Keychain.delete(account: legacyIdentityAccount)
    }
}
