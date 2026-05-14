import Foundation
import PizziniCryptoCore
import PizziniDB
import Security

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
        // Already migrated? Re-probe the legacy slots anyway —
        // a prior run could have set the marker BEFORE the delete
        // pass completed (process kill, OOM, watchdog) and left
        // plaintext Keychain copies behind. The delete is
        // idempotent (returns success on errSecItemNotFound), so
        // running it on every bootstrap is cheap and closes the
        // post-marker-pre-delete crash window forever.
        if try metaFlagPresent(storage: storage) {
            // QA-DIAG (2026-05-14): the steady-state branch — must be
            // what every launch after the first hits. If a sysdiagnose
            // shows the `migrating` line below on a launch where the
            // user already has chat history, the migration is re-running
            // and `migrateDeviceStore` is clobbering device_store with
            // the frozen legacy Keychain blob — that rolls the libsignal
            // ratchet back on every launch.
            pzLog("[pizzini.migration] QA-DIAG run: meta flag present — steady state, device_store untouched")
            deleteAllLegacySlots()
            return
        }
        // No legacy Keychain content? Set the marker and return —
        // fresh install needs no migration but should not re-probe
        // every launch.
        guard hasLegacyContent() else {
            pzLog("[pizzini.migration] QA-DIAG run: no meta flag, no legacy content — fresh install, setting marker")
            try setMetaFlag(storage: storage)
            return
        }
        pzLog("[pizzini.migration] QA-DIAG run: no meta flag + legacy content present — RUNNING migration (migrateDeviceStore will overwrite device_store)")
        pzLog("[pizzini.migration] Keychain → SQLCipher migration starting")

        try storage.db.transaction { _ in
            try migrateAppState(into: storage)
            try migrateOutbox(into: storage)
            try migrateDeviceStore(into: storage)
        }

        // Verify readback BEFORE deleting the Keychain slots.
        // Includes app-state, outbox, AND device-store round-trips
        // so a `try?` decode failure cannot pretend to have migrated
        // an outbox we couldn't actually parse.
        try verifyReadback(storage: storage)

        // **Delete-before-flag.** Drop the legacy slots first; only
        // mark the migration complete once the source is gone. A
        // process kill between the deletes and the flag means the
        // next launch's `hasLegacyContent` check returns false (or
        // partially false) and the migration is a no-op, leaving
        // the marker unset — which is fine: the next launch sets
        // it. A process kill in the prior ordering (flag set,
        // deletes pending) left Cellebrite-extractable plaintext
        // copies permanently behind the marker's short-circuit.
        deleteAllLegacySlots()
        try setMetaFlag(storage: storage)
        pzLog("[pizzini.migration] Keychain → SQLCipher migration complete")
    }

    /// Idempotent delete of every legacy Keychain slot. Each row is
    /// overwritten with same-sized noise before delete so the on-disk
    /// `keychain-2.db` page is re-encrypted under a fresh IV before
    /// the row is unlinked — defense in depth against NAND-level
    /// recovery of the pre-deletion ciphertext (F-NEW-403 mitigation
    /// applied here too since these blobs are the same threat shape).
    private static func deleteAllLegacySlots() {
        for account in [
            legacyAppStateAccount,
            legacyOutboxAccount,
            legacyDeviceStoreAccount,
            legacyIdentityAccount,
        ] {
            secureDeleteLegacySlot(account: account)
        }
    }

    private static func secureDeleteLegacySlot(account: String) {
        if let existing = Keychain.read(account: account) {
            var noise = [UInt8](repeating: 0, count: max(existing.count, 16))
            let rc = SecRandomCopyBytes(kSecRandomDefault, noise.count, &noise)
            if rc == errSecSuccess {
                _ = Keychain.write(Data(noise), account: account)
            }
        }
        Keychain.delete(account: account)
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
        guard let data = Keychain.read(account: legacyAppStateAccount) else {
            return
        }
        // `try` (not `try?`) — a decode failure here is a hard
        // migration error, NOT a silent drop. A `try?` would let the
        // transaction commit with no settings row, the deletes would
        // wipe the legacy slot, and the user's previous AppState
        // would be permanently lost without any user-visible signal.
        // Better to throw and let the next launch retry (the legacy
        // row is still present because the deletes run AFTER verify).
        let state: AppState
        do {
            state = try JSONDecoder().decode(AppState.self, from: data)
        } catch {
            throw MigrationError.appStateDecodeFailed(detail: "\(error)")
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
        }
        for group in state.groups {
            try storage.upsertGroup(group)
            for msg in group.log {
                try storage.appendGroupMessage(groupId: group.id, msg)
            }
        }
    }

    private static func migrateOutbox(into storage: SQLiteStorage) throws {
        guard let data = Keychain.read(account: legacyOutboxAccount) else {
            return
        }
        // Same reasoning as `migrateAppState`: a decode failure must
        // throw rather than silently drop the outbox.
        let store: OutboxStore
        do {
            store = try JSONDecoder().decode(OutboxStore.self, from: data)
        } catch {
            throw MigrationError.outboxDecodeFailed(detail: "\(error)")
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
            // QA-DIAG (2026-05-14): if this fires on a launch where the
            // user already has chat history, the frozen legacy blob is
            // overwriting a live, ratchet-advanced device_store.
            let fp = Blake3.hash(blob).prefix(4).map { String(format: "%02x", $0) }.joined()
            pzLog("[pizzini.migration] QA-DIAG migrateDeviceStore: overwriting device_store with legacy Keychain blob len=\(blob.count) fp=\(fp)")
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
        // Device-store readback. The migration has TWO sources for
        // the libsignal blob — the full `device-store` slot and the
        // older `long-term-identity` seed (rehydrated into a fresh
        // `Session` then serialized). `deleteAllLegacySlots()` runs
        // unconditionally after this verify and secure-deletes BOTH,
        // and the threat model is explicit that there is no other
        // identity recovery (no mnemonic, no backup). So whenever
        // EITHER source was present going in, the SQLCipher copy must
        // be confirmed present AND non-empty before the source is
        // destroyed — a `saveDeviceStore` that returned success while
        // persisting a zero-length blob (an UPSERT no-op, a future
        // regression in the blob path) would otherwise wipe the only
        // copy of the user's identity seed with no verification gate.
        if Keychain.read(account: legacyDeviceStoreAccount) != nil
            || Keychain.read(account: legacyIdentityAccount) != nil {
            guard let blob = try storage.loadDeviceStore(), !blob.isEmpty else {
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
        // Outbox round-trip — explicitly verify that the row count
        // in SQLCipher matches the legacy entries we tried to migrate.
        // The migrate path uses `try` (not `try?`) on decode now, so
        // a decode failure would have thrown earlier; this check
        // catches any UPSERT path that silently no-ops (which would
        // also be a bug, but is worth catching at the verify step).
        if let data = Keychain.read(account: legacyOutboxAccount) {
            let legacyCount: Int
            do {
                let store = try JSONDecoder().decode(OutboxStore.self, from: data)
                legacyCount = store.entries.count
            } catch {
                // Decode failed at verify time too — let the caller
                // throw the same shape as the migrate path would.
                throw MigrationError.outboxDecodeFailed(detail: "\(error)")
            }
            let landed = try storage.loadOutbox().entries.count
            guard landed == legacyCount else {
                throw MigrationError.outboxRowCountMismatch(
                    expected: legacyCount,
                    actual: landed,
                )
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
        case appStateDecodeFailed(detail: String)
        case outboxDecodeFailed(detail: String)
        case outboxRowCountMismatch(expected: Int, actual: Int)
    }
}
