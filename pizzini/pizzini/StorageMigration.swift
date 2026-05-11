import Foundation
import PizziniCryptoCore
import PizziniDB

/// One-shot migration from the legacy Keychain slots
/// (`app-state` / `outbox` / `device-store` / `long-term-identity`)
/// into SQLCipher.
///
/// Runs at `Storage.bootstrap` time on the first launch after upgrade.
/// Follows the same verify-before-delete defensive pattern as the
/// existing Keychain `legacy-identity` → `device-store` migration:
/// write the new rows + verify readback, only then delete the
/// legacy Keychain slots. A process kill at any point leaves the
/// system in a state where the next launch either retries cleanly
/// (Keychain still has it; SQLCipher doesn't yet) or proceeds
/// normally (migration completed).
///
/// Idempotent: if neither the legacy slots nor a marker exist,
/// the migration is a no-op. If both exist (interrupted migration),
/// the writes run again under SQLCipher's UPSERT semantics and
/// the legacy slots are deleted on success.
@MainActor
enum StorageMigration {
    /// Migration marker stored in `meta` after a successful copy.
    /// Prevents re-migration if the user uninstalls and reinstalls
    /// the app without wiping the Secure Enclave key (which is
    /// rare but possible on jailbroken devices that bypass the
    /// keychain cleanup).
    static let metaKey = "keychain_migration_v1_complete"

    static func run(storage: SQLiteStorage) throws {
        // Already migrated? Nothing to do.
        if try metaFlagPresent(storage: storage) { return }
        // No legacy Keychain content? Set the marker and return —
        // fresh install needs no migration but should not re-probe
        // every launch.
        guard hasLegacyContent() else {
            try setMetaFlag(storage: storage)
            return
        }
        NSLog("[pizzini.migration] Keychain → SQLCipher migration starting")

        try storage.db.transaction { _ in
            try migrateAppState(into: storage)
            try migrateOutbox(into: storage)
            try migrateDeviceStore(into: storage)
        }

        // Verify readback BEFORE deleting the Keychain slots.
        // This is the F-603-class defense from `Storage.loadOrCreateSession`:
        // we only delete the source once the destination round-trips.
        try verifyReadback(storage: storage)
        try setMetaFlag(storage: storage)

        Keychain.delete(account: legacyAppStateAccount)
        Keychain.delete(account: legacyOutboxAccount)
        Keychain.delete(account: legacyDeviceStoreAccount)
        Keychain.delete(account: legacyIdentityAccount)
        NSLog("[pizzini.migration] Keychain → SQLCipher migration complete")
    }

    // MARK: - Legacy slot constants (frozen, never reused)

    private static let legacyAppStateAccount    = "app-state"
    private static let legacyOutboxAccount      = "outbox"
    private static let legacyDeviceStoreAccount = "device-store"
    private static let legacyIdentityAccount    = "long-term-identity"

    // MARK: - Migration steps

    private static func hasLegacyContent() -> Bool {
        Keychain.read(account: legacyAppStateAccount) != nil
            || Keychain.read(account: legacyOutboxAccount) != nil
            || Keychain.read(account: legacyDeviceStoreAccount) != nil
            || Keychain.read(account: legacyIdentityAccount) != nil
    }

    private static func migrateAppState(into storage: SQLiteStorage) throws {
        guard
            let data = Keychain.read(account: legacyAppStateAccount),
            let state = try? JSONDecoder().decode(AppState.self, from: data)
        else {
            return
        }
        try storage.upsertSettings(state)
        for contact in state.contacts {
            try storage.upsertContact(contact)
            // The Contact struct's `log` is an inline array in the
            // old JSON shape; replay it as per-message inserts so
            // each row lands in the normalized `messages` table.
            for msg in contact.log {
                try storage.appendContactMessage(contactId: contact.id, msg)
            }
            // Same for the FIFO token queue — replayed in original
            // order so MIN(position) still hands out the oldest
            // token first.
            if !contact.deliveryTokensForPeer.isEmpty {
                try storage.replaceDeliveryTokens(
                    contactId: contact.id,
                    tokens: contact.deliveryTokensForPeer,
                )
            }
        }
        for group in state.groups {
            try storage.upsertGroup(group)
            for msg in group.log {
                try storage.appendGroupMessage(groupId: group.id, msg)
            }
        }
    }

    private static func migrateOutbox(into storage: SQLiteStorage) throws {
        guard
            let data = Keychain.read(account: legacyOutboxAccount),
            let store = try? JSONDecoder().decode(OutboxStore.self, from: data)
        else {
            return
        }
        for (_, entry) in store.entries {
            try storage.upsertOutboxEntry(entry)
        }
    }

    private static func migrateDeviceStore(into storage: SQLiteStorage) throws {
        // The full `device-store` blob is the libsignal serialize()
        // output post-pairing-rewrite. The legacy `long-term-identity`
        // is the pre-persistence identity seed; if both exist the
        // device-store blob wins because it carries the active
        // ratchet state.
        if let blob = Keychain.read(account: legacyDeviceStoreAccount) {
            try storage.saveDeviceStore(blob)
            return
        }
        if let seed = Keychain.read(account: legacyIdentityAccount) {
            // Rehydrate just enough to bootstrap a fresh DeviceStore
            // from the identity seed, then persist its serialize().
            // Mirrors the F-603 defensive path in the old
            // `Storage.loadOrCreateSession`.
            let session = try Session(identitySeed: seed)
            try storage.saveDeviceStore(try session.serialize())
        }
    }

    private static func verifyReadback(storage: SQLiteStorage) throws {
        if let _ = Keychain.read(account: legacyDeviceStoreAccount) {
            guard let _ = try storage.loadDeviceStore() else {
                throw MigrationError.deviceStoreNotReadable
            }
        }
        // For app_state + outbox, an empty Keychain blob is
        // legitimate (user with no contacts / empty outbox). The
        // settings row should exist after upsertSettings.
        if Keychain.read(account: legacyAppStateAccount) != nil {
            guard try storage.loadSettings() != nil else {
                throw MigrationError.settingsNotReadable
            }
        }
    }

    // MARK: - Marker

    private static func metaFlagPresent(storage: SQLiteStorage) throws -> Bool {
        let stmt = try storage.db.prepare("SELECT value FROM meta WHERE key = ?;")
        try stmt.bindAll(metaKey)
        return try stmt.step()
    }

    private static func setMetaFlag(storage: SQLiteStorage) throws {
        let stmt = try storage.db.prepare("""
            INSERT INTO meta (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value;
        """)
        try stmt.bind(metaKey, at: 1).bind(Data([0x01]), at: 2).run()
    }

    enum MigrationError: Error {
        case deviceStoreNotReadable
        case settingsNotReadable
    }
}
