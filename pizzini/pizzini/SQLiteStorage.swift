import Foundation
import PizziniCryptoCore
import PizziniDB

/// SQLCipher-backed implementation of Pizzini's on-disk store.
///
/// Owns one open `Database` connection for the lifetime of the app,
/// keyed by `DBKey.deriveKey()` (Secure-Enclave-wrapped seed → Argon2id
/// → 32-byte SQLCipher key).
///
/// API shape: per-row mutators rather than whole-state writes. Every
/// `AppState` / `OutboxStore` mutation in `ChatStore` maps to exactly
/// one row-scoped `INSERT` / `UPDATE` / `DELETE` against the schema.
/// The whole-state `loadAppState` / `loadOutbox` paths exist only
/// for bootstrap on cold launch and for the Keychain → SQLCipher
/// migration runner.
///
/// Threading: `@MainActor`-isolated to match the existing ChatStore
/// callers. Every method on this type may only be called from the
/// main actor. The SQLite connection itself is serialized by
/// SQLCipher's full-mutex compile flag; the main-actor isolation is
/// the additional Swift-language guarantee that no other actor can
/// touch it concurrently.
@MainActor
final class SQLiteStorage {
    /// The singleton store. Initialized once via `bootstrap()`,
    /// thereafter accessible from any main-actor code via `shared`.
    /// Force-unwrapped on access — `bootstrap()` runs at app startup
    /// and must succeed before any UI code reaches a Storage call.
    private(set) static var shared: SQLiteStorage!

    let db: Database

    /// Filesystem location of the encrypted database. Returned for
    /// the future cryptographic-erasure path which `unlink`s this
    /// file alongside `DBKey.eraseKeyMaterial()`.
    let databasePath: String

    private init(db: Database, path: String) {
        self.db = db
        self.databasePath = path
    }

#if DEBUG
    /// Test-only entry point: bypass DBKey + the Keychain-bound
    /// derivation chain. Tests pass an opened `Database` (typically
    /// pointed at `NSTemporaryDirectory()`) and a fresh raw key.
    /// The migration runner is invoked here so the schema lands
    /// before the test touches the singleton.
    ///
    /// Gated on `#if DEBUG` so the symbols are absent from release
    /// builds — an in-process attacker can't pivot through them.
    @discardableResult
    static func _bootstrapForTesting(path: String, rawKey: Data) throws -> SQLiteStorage {
        let db = try Database(path: path, rawKey: rawKey)
        try Migrator.run(on: db)
        let inst = SQLiteStorage(db: db, path: path)
        shared = inst
        return inst
    }

    /// Test-only teardown — drop the singleton reference. Used by
    /// tests that want to assert "no SQLiteStorage initialised"
    /// behaviour or to reset between test cases.
    static func _resetForTesting() {
        shared = nil
    }
#endif

    /// Open (or create) the SQLCipher database. Idempotent — calling
    /// twice in a single process is a programmer bug and trips a
    /// precondition. The expected lifecycle is one call from
    /// `pizziniApp.init`-equivalent code, before any UI surface
    /// reads from `Storage`.
    ///
    /// **Orphan-wipe recovery.** If a `.sqlite` file exists on disk
    /// AND no SE-wrap row is present in Keychain, the prior duress
    /// wipe was interrupted between "unlink DB" and "erase keys" (or
    /// the user has a Keychain-restored backup pointing at a DB the
    /// keys can no longer decrypt). Either way the DB file is unusable
    /// — unlink it before deriving fresh key material so the next
    /// open produces a clean database.
    static func bootstrap() throws {
        precondition(shared == nil, "SQLiteStorage.bootstrap called twice")
        let path = try databaseURL().path
        try ensureParentDirectory()

        // Orphan check before any key derivation. If a DB file exists
        // but the SE wrap doesn't, the file is forensically useless
        // (no key can ever decrypt it) and would just produce a
        // confusing open-failure if we tried. Unlink it and the
        // next path proceeds as fresh-install.
        let fm = FileManager.default
        if fm.fileExists(atPath: path), !DBKey.isInitialized {
            unlinkDatabaseFiles()
        }

        // Run Argon2id with the same params the DB was originally
        // keyed under. On first launch `loadStoredParams()` returns
        // the production preset; on subsequent launches it returns
        // what was persisted at first keying so a future tuning
        // bump doesn't break existing installs.
        let params = DBKey.loadStoredParams()
        let key = try DBKey.deriveKey(params: params)

        let db = try Database(path: path, rawKey: key)
        try Migrator.run(on: db)
        let inst = SQLiteStorage(db: db, path: path)
        shared = inst
        // Re-assert file-protection + iCloud-backup-exclusion on the
        // database files themselves (not just the parent directory).
        // iOS inherits the directory's class for newly-created files,
        // but Apple recommends setting per-file `URLResourceValues`
        // explicitly and the cost is one no-op syscall per file.
        try? inst.reassertDatabaseFileAttributes()

        // USP #8: rotate the at-rest encryption key if it's been
        // longer than `DBKey.rotationInterval` since the last
        // rotation. Runs INLINE on bootstrap — Argon2id + rekey +
        // VACUUM total ~1–5 s on a typical DB. That's a one-time
        // cost per week (per launch frequency), paid on the first
        // unlock the rotation window opens. A failure here is
        // logged but non-fatal: the DB is still openable under the
        // current key, so the user keeps working; the next launch
        // re-evaluates `rotationDue` and tries again. Better than
        // refusing to boot the chat over a missed rotation.
        if DBKey.rotationDue() {
            do {
                _ = try DBKey.rotateKeyMaterial(liveDB: db, params: params)
                NSLog("[pizzini.dbkey] at-rest key rotated (USP #8)")
            } catch {
                NSLog("[pizzini.dbkey] at-rest key rotation FAILED: \(error)")
            }
        }
    }

    /// Unlink the SQLCipher database file + its WAL/SHM sidecars.
    /// Closes the open connection (drops `shared`) so the next
    /// `bootstrap()` call re-opens fresh. Used by the duress wipe
    /// path in `Storage.eraseAndReinitialize` and by the orphan
    /// recovery path in `bootstrap()` itself.
    static func unlinkDatabaseFiles() {
        let fm = FileManager.default
        let path: String
        if let existing = shared {
            path = existing.databasePath
            shared = nil
        } else {
            guard let url = try? databaseURL() else { return }
            path = url.path
        }
        try? fm.removeItem(atPath: path)
        // SQLCipher writes `-wal` and `-shm` siblings for WAL
        // journalling; both must go for the next open to produce a
        // clean database.
        try? fm.removeItem(atPath: path + "-wal")
        try? fm.removeItem(atPath: path + "-shm")
    }

    /// Reset path used by `Storage.resetEverything`. Closes the
    /// connection, deletes the database file, and re-opens fresh.
    /// Key material is unchanged — only the database content is
    /// wiped. Caller is responsible for re-persisting any preserved
    /// settings via the per-row mutators afterwards.
    static func wipeAndReopen() throws {
        unlinkDatabaseFiles()
        try bootstrap()
    }

    /// Set `completeUntilFirstUserAuthentication` + excluded-from-backup
    /// on the live database files. Per-file attributes layer on top of
    /// the parent directory's class — the SHM/WAL sidecars are created
    /// lazily by SQLCipher on first write, so this is called both at
    /// bootstrap (covers the main `.sqlite`) and could be re-run after
    /// the first transaction (covers the sidecars). Setting the same
    /// value is a no-op.
    private func reassertDatabaseFileAttributes() throws {
        let paths = [databasePath, databasePath + "-wal", databasePath + "-shm"]
        for p in paths {
            var url = URL(fileURLWithPath: p)
            guard FileManager.default.fileExists(atPath: p) else { continue }
            var v = URLResourceValues()
            v.isExcludedFromBackup = true
            try? url.setResourceValues(v)
            // The protection-class flag is a separate FileManager call.
            try? FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                ofItemAtPath: p,
            )
        }
    }

    // MARK: - DB location

    private static func databaseURL() throws -> URL {
        let fm = FileManager.default
        guard let appSupport = fm.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
        ).first else {
            throw DBKey.DBKeyError.missingMaterial
        }
        return appSupport
            .appending(path: "pizzini", directoryHint: .isDirectory)
            .appending(path: "pizzini.sqlite", directoryHint: .notDirectory)
    }

    private static func ensureParentDirectory() throws {
        let fm = FileManager.default
        let dir = try databaseURL().deletingLastPathComponent()
        if !fm.fileExists(atPath: dir.path) {
            try fm.createDirectory(
                at: dir,
                withIntermediateDirectories: true,
                attributes: [
                    // Match the attachments sandbox posture: bytes
                    // protected at rest until first unlock, but
                    // accessible to background tasks (NSE wake-ups,
                    // launchedByPush) afterwards. Stricter
                    // `complete` would lock the NSE out of its
                    // unread-count read.
                    .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
                ],
            )
        }
        // Re-assert the iCloud-backup-exclusion + protection class on
        // every bootstrap, not just at creation. Setting the same value
        // is a no-op, so this defends against (a) a future code path
        // that creates the directory out-of-band, and (b) any iOS
        // version that demands explicit re-assertion after restore.
        var v = URLResourceValues()
        v.isExcludedFromBackup = true
        var mutable = dir
        try? mutable.setResourceValues(v)
        try? fm.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: dir.path,
        )
    }

    // MARK: - Settings (singleton row)

    /// Read the singleton settings row. Returns nil if no row exists
    /// (first launch, pre-migration); caller substitutes
    /// `AppState()` defaults.
    func loadSettings() throws -> AppState? {
        let stmt = try db.prepare("""
            SELECT relay_host, onboarding_completed, biometric_lock_enabled,
                   auto_lock_timeout, quicklook_preview_enabled, panic_mode_enabled,
                   qr_block_effective, qr_block_tested_os_version,
                   contacts_before_groups, in_app_haptics_enabled,
                   default_read_receipts_enabled
            FROM settings WHERE id = 1;
        """)
        guard try stmt.step() else { return nil }
        let autoLock = AutoLockTimeout(rawValue: stmt.columnText(3) ?? "")
            ?? .immediately
        return AppState(
            relayHost: stmt.columnText(0) ?? AppState.defaultRelayHost,
            contacts: [],
            onboardingCompleted: stmt.columnBool(1),
            biometricLockEnabled: stmt.columnBool(2),
            autoLockTimeout: autoLock,
            quickLookPreviewEnabled: stmt.columnBool(4),
            panicModeEnabled: stmt.columnBool(5),
            qrBlockEffective: stmt.columnOptionalInt64(6).map { $0 != 0 },
            qrBlockTestedOSVersion: stmt.columnText(7),
            groups: [],
            contactsBeforeGroups: stmt.columnBool(8),
            inAppHapticsEnabled: stmt.columnBool(9),
            defaultReadReceiptsEnabled: stmt.columnBool(10),
        )
    }

    /// Upsert the singleton settings row from a complete `AppState`.
    /// Contacts + groups + outbox are persisted via their own
    /// per-row methods, not via this call.
    func upsertSettings(_ s: AppState) throws {
        let stmt = try db.prepare("""
            INSERT INTO settings (
                id, relay_host, onboarding_completed, biometric_lock_enabled,
                auto_lock_timeout, quicklook_preview_enabled, panic_mode_enabled,
                qr_block_effective, qr_block_tested_os_version,
                contacts_before_groups, in_app_haptics_enabled,
                default_read_receipts_enabled
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                relay_host = excluded.relay_host,
                onboarding_completed = excluded.onboarding_completed,
                biometric_lock_enabled = excluded.biometric_lock_enabled,
                auto_lock_timeout = excluded.auto_lock_timeout,
                quicklook_preview_enabled = excluded.quicklook_preview_enabled,
                panic_mode_enabled = excluded.panic_mode_enabled,
                qr_block_effective = excluded.qr_block_effective,
                qr_block_tested_os_version = excluded.qr_block_tested_os_version,
                contacts_before_groups = excluded.contacts_before_groups,
                in_app_haptics_enabled = excluded.in_app_haptics_enabled,
                default_read_receipts_enabled = excluded.default_read_receipts_enabled;
        """)
        try stmt
            .bind(s.relayHost, at: 1)
            .bind(s.onboardingCompleted, at: 2)
            .bind(s.biometricLockEnabled, at: 3)
            .bind(s.autoLockTimeout.rawValue, at: 4)
            .bind(s.quickLookPreviewEnabled, at: 5)
            .bind(s.panicModeEnabled, at: 6)
            .bind(s.qrBlockEffective.map { $0 ? Int(1) : Int(0) }, at: 7)
            .bind(s.qrBlockTestedOSVersion, at: 8)
            .bind(s.contactsBeforeGroups, at: 9)
            .bind(s.inAppHapticsEnabled, at: 10)
            .bind(s.defaultReadReceiptsEnabled, at: 11)
            .run()
    }

    // MARK: - Device store (libsignal blob)

    func loadDeviceStore() throws -> Data? {
        let stmt = try db.prepare("SELECT blob FROM device_store WHERE id = 1;")
        guard try stmt.step() else { return nil }
        return stmt.columnBlob(0)
    }

    func saveDeviceStore(_ blob: Data) throws {
        let stmt = try db.prepare("""
            INSERT INTO device_store (id, blob, updated_at) VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET blob = excluded.blob, updated_at = excluded.updated_at;
        """)
        try stmt.bind(blob, at: 1).bind(Date(), at: 2).run()
    }

    // MARK: - Contacts

    func loadContacts() throws -> [Contact] {
        let stmt = try db.prepare("""
            SELECT id, identity_pub, display_name, session_established,
                   last_message_at, last_seen_at, added_at,
                   last_refill_request_sent_at, last_refill_request_handled_at,
                   ttl_seconds, read_receipts_mode, peer_verify_key, last_bundle_served_at,
                   added_via, verified_at
            FROM contacts ORDER BY added_at ASC;
        """)
        var contacts: [Contact] = []
        while try stmt.step() {
            let idData = stmt.columnBlob(0) ?? Data()
            guard let uuid = idData.asUUID() else { continue }
            let rawSource = stmt.columnText(13) ?? ContactSource.unknown.rawValue
            // Schema v2 migration backfills 'qr_scan' for pre-v2 rows
            // and the column is NOT NULL — but a future schema rewrite
            // could in principle introduce a new variant. Fall back to
            // `.unknown` instead of crashing the chat list.
            let source = ContactSource(rawValue: rawSource) ?? .unknown
            let rawMode = stmt.columnText(10) ?? ReadReceiptsMode.followDefault.rawValue
            // Schema v3 backfills 'always_on' for legacy enabled=1
            // rows and 'follow_default' for everything else.
            // Defence-in-depth: an unknown variant from a future
            // downgrade falls back to `.followDefault` so the
            // chat list still renders.
            let receiptsMode = ReadReceiptsMode(rawValue: rawMode) ?? .followDefault
            var c = Contact(
                id: uuid,
                identityPub: stmt.columnBlob(1) ?? Data(),
                displayName: stmt.columnText(2) ?? "",
                sessionEstablished: stmt.columnBool(3),
                log: [],
                lastMessageAt: stmt.columnOptionalInt64(4).map { $0.dateFromEpochMs },
                lastSeenAt: stmt.columnOptionalInt64(5).map { $0.dateFromEpochMs },
                addedAt: stmt.columnInt64(6).dateFromEpochMs,
                deliveryTokensForPeer: [],
                lastRefillRequestSentAt: stmt.columnOptionalInt64(7).map { $0.dateFromEpochMs },
                lastRefillRequestHandledAt: stmt.columnOptionalInt64(8).map { $0.dateFromEpochMs },
                ttlSeconds: UInt32(stmt.columnInt64(9)),
                readReceiptsMode: receiptsMode,
                peerVerifyKey: stmt.columnBlob(11),
                lastBundleServedAt: stmt.columnOptionalInt64(12).map { $0.dateFromEpochMs },
                addedVia: source,
                verifiedAt: stmt.columnOptionalInt64(14).map { $0.dateFromEpochMs },
            )
            c.log = try loadMessages(contactId: idData)
            c.deliveryTokensForPeer = try loadDeliveryTokens(contactId: idData)
            contacts.append(c)
        }
        return contacts
    }

    /// Note: `added_via` is intentionally absent from the ON CONFLICT
    /// UPDATE list below. A contact's provenance is fixed the moment
    /// it first enters the database. Re-scanning the same QR or
    /// re-pasting the same URL doesn't change how it originally
    /// arrived, and silently upgrading a `pasted_text` row to
    /// `qr_scan` if the user later rescans would erase the warning
    /// state that previously informed the verification UI.
    func upsertContact(_ c: Contact) throws {
        // The v3 migration replaced `read_receipts_enabled` (Bool) with
        // `read_receipts_mode` (3-state enum) but had to leave the legacy
        // column in place because SQLCipher's ALTER TABLE has no
        // DROP COLUMN. The legacy column is `NOT NULL` with no default,
        // so every INSERT must still bind it; we derive a backward-
        // compatible Bool from the mode (`alwaysOff → 0`, anything else
        // → 1, mirroring how the v3 backfill mapped `1 → always_on`).
        // New code never reads this column.
        let legacyEnabled = c.readReceiptsMode == .alwaysOff ? 0 : 1
        let stmt = try db.prepare("""
            INSERT INTO contacts (
                id, identity_pub, display_name, session_established,
                last_message_at, last_seen_at, added_at,
                last_refill_request_sent_at, last_refill_request_handled_at,
                ttl_seconds, read_receipts_enabled, read_receipts_mode,
                peer_verify_key, last_bundle_served_at,
                added_via, verified_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                identity_pub = excluded.identity_pub,
                display_name = excluded.display_name,
                session_established = excluded.session_established,
                last_message_at = excluded.last_message_at,
                last_seen_at = excluded.last_seen_at,
                last_refill_request_sent_at = excluded.last_refill_request_sent_at,
                last_refill_request_handled_at = excluded.last_refill_request_handled_at,
                ttl_seconds = excluded.ttl_seconds,
                read_receipts_enabled = excluded.read_receipts_enabled,
                read_receipts_mode = excluded.read_receipts_mode,
                peer_verify_key = excluded.peer_verify_key,
                last_bundle_served_at = excluded.last_bundle_served_at,
                verified_at = excluded.verified_at;
        """)
        try stmt
            .bind(c.id.data, at: 1)
            .bind(c.identityPub, at: 2)
            .bind(c.displayName, at: 3)
            .bind(c.sessionEstablished, at: 4)
            .bind(c.lastMessageAt, at: 5)
            .bind(c.lastSeenAt, at: 6)
            .bind(c.addedAt, at: 7)
            .bind(c.lastRefillRequestSentAt, at: 8)
            .bind(c.lastRefillRequestHandledAt, at: 9)
            .bind(Int(c.ttlSeconds), at: 10)
            .bind(legacyEnabled, at: 11)
            .bind(c.readReceiptsMode.rawValue, at: 12)
            .bind(c.peerVerifyKey, at: 13)
            .bind(c.lastBundleServedAt, at: 14)
            .bind(c.addedVia.rawValue, at: 15)
            .bind(c.verifiedAt, at: 16)
            .run()
    }

    func deleteContact(id: UUID) throws {
        try db.prepare("DELETE FROM contacts WHERE id = ?;")
            .bindAll(id.data).run()
    }

    // MARK: - Delivery tokens

    private func loadDeliveryTokens(contactId: Data) throws -> [Data] {
        let stmt = try db.prepare("""
            SELECT token FROM delivery_tokens
            WHERE contact_id = ? ORDER BY position ASC;
        """)
        try stmt.bindAll(contactId)
        var tokens: [Data] = []
        while try stmt.step() {
            if let t = stmt.columnBlob(0) { tokens.append(t) }
        }
        return tokens
    }

    /// Replace this contact's entire token queue. Used after a
    /// fresh issuance (1024 tokens) or any rare path that rewrites
    /// the whole list. The common case is `popDeliveryToken` /
    /// `appendDeliveryTokens` which are O(1).
    func replaceDeliveryTokens(contactId: UUID, tokens: [Data]) throws {
        try db.transaction { tx in
            let cid = contactId.data
            try tx.prepare("DELETE FROM delivery_tokens WHERE contact_id = ?;")
                .bindAll(cid).run()
            let ins = try tx.prepare("""
                INSERT INTO delivery_tokens (contact_id, position, token)
                VALUES (?, ?, ?);
            """)
            for (i, token) in tokens.enumerated() {
                try ins.bind(cid, at: 1).bind(i, at: 2).bind(token, at: 3).run()
            }
        }
    }

    /// Pop the oldest token (MIN(position)) for `contactId`. Returns
    /// nil if the queue is empty. The brief's "tokens are popped from
    /// the front" semantics maps onto the obvious DELETE … RETURNING
    /// pattern; SQLite has supported `RETURNING` since 3.35
    /// (well below our SQLCipher 4.6.1 baseline).
    func popDeliveryToken(contactId: UUID) throws -> Data? {
        let cid = contactId.data
        let select = try db.prepare("""
            SELECT position, token FROM delivery_tokens
            WHERE contact_id = ? ORDER BY position ASC LIMIT 1;
        """)
        try select.bindAll(cid)
        guard try select.step() else { return nil }
        let position = select.columnInt64(0)
        let token = select.columnBlob(1)
        try db.prepare("""
            DELETE FROM delivery_tokens WHERE contact_id = ? AND position = ?;
        """).bindAll(cid, position).run()
        return token
    }

    /// Atomic "spend a delivery token AND record the outbox entry
    /// that consumed it" — both writes happen in a single SQLite
    /// transaction so a crash mid-flow can never leave the queue
    /// missing a token without a corresponding outbox row that
    /// records where it went. The separate-call alternative used
    /// before had a small but real window between `DELETE FROM
    /// delivery_tokens` and `INSERT INTO outbox` where a force-kill
    /// would burn the token irretrievably (the retry walk could
    /// never re-bind it to an outbox row, and the relay would
    /// reject any later replay).
    ///
    /// `entryBuilder` is invoked INSIDE the transaction with the
    /// popped token bytes; it must return the fully-formed
    /// `OutboxEntry` to persist. Returns the assembled entry on
    /// success or `nil` if the contact's queue was empty — in
    /// which case the transaction is rolled back and the caller
    /// must surface "token stash exhausted".
    func commitDeliveryTokenSpend(
        contactId: UUID,
        entryBuilder: (Data) -> OutboxEntry
    ) throws -> OutboxEntry? {
        let cid = contactId.data
        var built: OutboxEntry?
        try db.transaction { tx in
            let select = try tx.prepare("""
                SELECT position, token FROM delivery_tokens
                WHERE contact_id = ? ORDER BY position ASC LIMIT 1;
            """)
            try select.bindAll(cid)
            guard try select.step() else { return }
            let position = select.columnInt64(0)
            guard let token = select.columnBlob(1) else { return }
            let entry = entryBuilder(token)
            try tx.prepare("""
                INSERT INTO outbox (
                    message_id, recipient_peer_id, sealed_ciphertext, token,
                    ttl, sent_at, retries, delivered_at, failed_at, relayed_at,
                    attachment_id, chunk_index, chunk_count, group_message_id, read_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(message_id) DO UPDATE SET
                    recipient_peer_id = excluded.recipient_peer_id,
                    sealed_ciphertext = excluded.sealed_ciphertext,
                    token = excluded.token,
                    ttl = excluded.ttl,
                    sent_at = excluded.sent_at,
                    retries = excluded.retries,
                    delivered_at = excluded.delivered_at,
                    failed_at = excluded.failed_at,
                    relayed_at = excluded.relayed_at,
                    attachment_id = excluded.attachment_id,
                    chunk_index = excluded.chunk_index,
                    chunk_count = excluded.chunk_count,
                    group_message_id = excluded.group_message_id,
                    read_at = excluded.read_at;
            """)
                .bind(entry.messageId, at: 1)
                .bind(entry.recipientPeerId, at: 2)
                .bind(entry.sealedCiphertext, at: 3)
                .bind(entry.token, at: 4)
                .bind(Int64(entry.ttl), at: 5)
                .bind(entry.sentAt, at: 6)
                .bind(entry.retries, at: 7)
                .bind(entry.deliveredAt, at: 8)
                .bind(entry.failedAt, at: 9)
                .bind(entry.relayedAt, at: 10)
                .bind(entry.attachmentId, at: 11)
                .bind(entry.chunkIndex.map { Int($0) }, at: 12)
                .bind(entry.chunkCount.map { Int($0) }, at: 13)
                .bind(entry.groupMessageId, at: 14)
                .bind(entry.readAt, at: 15)
                .run()
            try tx.prepare("""
                DELETE FROM delivery_tokens WHERE contact_id = ? AND position = ?;
            """).bindAll(cid, position).run()
            built = entry
        }
        return built
    }

    /// Append a batch of tokens to the end of `contactId`'s queue.
    func appendDeliveryTokens(contactId: UUID, tokens: [Data]) throws {
        guard !tokens.isEmpty else { return }
        let cid = contactId.data
        try db.transaction { tx in
            // Probe the current max position so we don't collide
            // with an existing token (the table's PRIMARY KEY is
            // (contact_id, position) — a duplicate would throw).
            let maxStmt = try tx.prepare("""
                SELECT IFNULL(MAX(position), -1) FROM delivery_tokens WHERE contact_id = ?;
            """)
            try maxStmt.bindAll(cid)
            _ = try maxStmt.step()
            var nextPos = maxStmt.columnInt64(0) + 1
            let ins = try tx.prepare("""
                INSERT INTO delivery_tokens (contact_id, position, token)
                VALUES (?, ?, ?);
            """)
            for token in tokens {
                try ins.bind(cid, at: 1).bind(nextPos, at: 2).bind(token, at: 3).run()
                nextPos += 1
            }
        }
    }

    // MARK: - Messages (1:1 + group, polymorphic owner)

    private func loadMessages(contactId: Data) throws -> [PersistedMessage] {
        try loadMessagesWhere(
            sql: "WHERE contact_id = ? ORDER BY timestamp ASC, id ASC",
            bind: contactId,
        )
    }

    private func loadMessages(groupId: Data) throws -> [PersistedMessage] {
        try loadMessagesWhere(
            sql: "WHERE group_id = ? ORDER BY timestamp ASC, id ASC",
            bind: groupId,
        )
    }

    private func loadMessagesWhere(sql whereClause: String, bind: Data) throws -> [PersistedMessage] {
        let stmt = try db.prepare("""
            SELECT id, side, text, kind, bytes, timestamp, message_id, read_at,
                   sender_peer_id, group_message_id,
                   attachment_id, attachment_filename, attachment_byte_size,
                   attachment_mime, attachment_tier, attachment_sandbox_path,
                   attachment_is_inbound
            FROM messages \(whereClause);
        """)
        try stmt.bindAll(bind)
        var out: [PersistedMessage] = []
        while try stmt.step() {
            let idData = stmt.columnBlob(0) ?? Data()
            guard let uuid = idData.asUUID() else { continue }
            let side = ChatBubbleSide(rawValue: stmt.columnText(1) ?? "") ?? .me
            let kind = ChatMessageKind(rawValue: stmt.columnText(3) ?? "") ?? .whisper
            var attachment: AttachmentInfo?
            if !stmt.columnIsNull(10), let aid = stmt.columnBlob(10) {
                // `.textFamily` is the most innocuous fallback if a
                // tier round-trip ever fails (e.g. a new enum case
                // was rolled back). We log to NSLog so the
                // degradation isn't silent, but we keep the message
                // visible to the user — a missing tier is much
                // less bad than a missing chat row.
                let tierRaw = stmt.columnText(14) ?? ""
                let tier = AttachmentTier(rawValue: tierRaw) ?? {
                    NSLog("[pizzini.storage] unknown attachment tier '\(tierRaw)', falling back to textFamily")
                    return .textFamily
                }()
                attachment = AttachmentInfo(
                    attachmentId: aid,
                    filename: stmt.columnText(11) ?? "",
                    byteSize: UInt64(stmt.columnInt64(12)),
                    mime: stmt.columnText(13) ?? "",
                    tier: tier,
                    sandboxRelativePath: stmt.columnText(15),
                    isInbound: stmt.columnBool(16),
                )
            }
            out.append(PersistedMessage(
                id: uuid,
                side: side,
                text: stmt.columnText(2) ?? "",
                kind: kind,
                bytes: stmt.columnInt(4),
                timestamp: stmt.columnInt64(5).dateFromEpochMs,
                messageId: stmt.columnBlob(6),
                readAt: stmt.columnOptionalInt64(7).map { $0.dateFromEpochMs },
                attachment: attachment,
                senderPeerId: stmt.columnBlob(8),
                groupMessageId: stmt.columnBlob(9),
            ))
        }
        return out
    }

    private enum MessageOwner {
        case contact(UUID)
        case group(Data)
    }

    private func upsertMessage(_ m: PersistedMessage, owner: MessageOwner) throws {
        let stmt = try db.prepare("""
            INSERT INTO messages (
                id, contact_id, group_id, side, text, kind, bytes, timestamp,
                message_id, read_at, sender_peer_id, group_message_id,
                attachment_id, attachment_filename, attachment_byte_size,
                attachment_mime, attachment_tier, attachment_sandbox_path,
                attachment_is_inbound
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                side = excluded.side,
                text = excluded.text,
                kind = excluded.kind,
                bytes = excluded.bytes,
                timestamp = excluded.timestamp,
                message_id = excluded.message_id,
                read_at = excluded.read_at,
                sender_peer_id = excluded.sender_peer_id,
                group_message_id = excluded.group_message_id,
                attachment_id = excluded.attachment_id,
                attachment_filename = excluded.attachment_filename,
                attachment_byte_size = excluded.attachment_byte_size,
                attachment_mime = excluded.attachment_mime,
                attachment_tier = excluded.attachment_tier,
                attachment_sandbox_path = excluded.attachment_sandbox_path,
                attachment_is_inbound = excluded.attachment_is_inbound;
        """)
        let (contactId, groupId): (Data?, Data?) = {
            switch owner {
            case .contact(let uuid): return (uuid.data, nil)
            case .group(let gid):    return (nil, gid)
            }
        }()
        try stmt
            .bind(m.id.data, at: 1)
            .bind(contactId, at: 2)
            .bind(groupId, at: 3)
            .bind(m.side.rawValue, at: 4)
            .bind(m.text, at: 5)
            .bind(m.kind.rawValue, at: 6)
            .bind(m.bytes, at: 7)
            .bind(m.timestamp, at: 8)
            .bind(m.messageId, at: 9)
            .bind(m.readAt, at: 10)
            .bind(m.senderPeerId, at: 11)
            .bind(m.groupMessageId, at: 12)
            .bind(m.attachment?.attachmentId, at: 13)
            .bind(m.attachment?.filename, at: 14)
            .bind(m.attachment.map { Int64($0.byteSize) }, at: 15)
            .bind(m.attachment?.mime, at: 16)
            .bind(m.attachment?.tier.rawValue, at: 17)
            .bind(m.attachment?.sandboxRelativePath, at: 18)
            .bind(m.attachment?.isInbound, at: 19)
            .run()
    }

    func appendContactMessage(contactId: UUID, _ m: PersistedMessage) throws {
        try upsertMessage(m, owner: .contact(contactId))
    }

    func updateContactMessage(contactId: UUID, _ m: PersistedMessage) throws {
        try upsertMessage(m, owner: .contact(contactId))
    }

    func deleteAllContactMessages(contactId: UUID) throws {
        try db.prepare("DELETE FROM messages WHERE contact_id = ?;")
            .bindAll(contactId.data).run()
    }

    func appendGroupMessage(groupId: Data, _ m: PersistedMessage) throws {
        try upsertMessage(m, owner: .group(groupId))
    }

    func updateGroupMessage(groupId: Data, _ m: PersistedMessage) throws {
        try upsertMessage(m, owner: .group(groupId))
    }

    func deleteAllGroupMessages(groupId: Data) throws {
        try db.prepare("DELETE FROM messages WHERE group_id = ?;")
            .bindAll(groupId).run()
    }

    // MARK: - Groups

    func loadGroups() throws -> [ChatGroup] {
        let stmt = try db.prepare("""
            SELECT id, display_name, created_at, current_epoch, last_op_digest,
                   last_seen_at, last_message_at, my_current_distribution_id,
                   sent_since_rotation, last_rotated_at, my_skdm_recipients,
                   pending_invitation
            FROM groups ORDER BY created_at ASC;
        """)
        var groups: [ChatGroup] = []
        while try stmt.step() {
            let gid = stmt.columnBlob(0) ?? Data()
            let members = try loadGroupMembers(groupId: gid)
            let pending = try loadGroupPendingOps(groupId: gid)
            let digests = try loadGroupOpDigests(groupId: gid)
            let log = try loadMessages(groupId: gid)
            let myDist = stmt.columnBlob(7).flatMap { $0.asUUID() }
            let memberDistMap = Dictionary(uniqueKeysWithValues: members.compactMap {
                (loaded) -> (Data, UUID)? in
                guard let d = loaded.distributionId else { return nil }
                return (loaded.peerId.peerId, d)
            })
            let skdmRecips = unpack33ByteSet(stmt.columnBlob(10) ?? Data())

            groups.append(ChatGroup(
                id: gid,
                displayName: stmt.columnText(1) ?? "",
                members: members.map { $0.member },
                createdAt: stmt.columnInt64(2).dateFromEpochMs,
                currentEpoch: UInt64(bitPattern: stmt.columnInt64(3)),
                lastOpDigest: stmt.columnBlob(4) ?? Data(),
                pendingOps: pending,
                log: log,
                lastSeenAt: stmt.columnOptionalInt64(5).map { $0.dateFromEpochMs },
                lastMessageAt: stmt.columnOptionalInt64(6).map { $0.dateFromEpochMs },
                myCurrentDistributionId: myDist,
                memberDistributionIds: memberDistMap,
                sentSinceRotation: UInt32(stmt.columnInt64(8)),
                lastRotatedAt: stmt.columnInt64(9).dateFromEpochMs,
                mySkdmRecipients: skdmRecips,
                recentOpDigests: digests,
                pendingInvitation: stmt.columnBool(11),
            ))
        }
        return groups
    }

    func upsertGroup(_ g: ChatGroup) throws {
        try db.transaction { tx in
            try Self.upsertGroupRow(g, on: tx)
            try Self.replaceGroupMembers(g, on: tx)
        }
    }

    private static func upsertGroupRow(_ g: ChatGroup, on tx: Database) throws {
        let stmt = try tx.prepare("""
            INSERT INTO groups (
                id, display_name, created_at, current_epoch, last_op_digest,
                last_seen_at, last_message_at, my_current_distribution_id,
                sent_since_rotation, last_rotated_at, my_skdm_recipients,
                pending_invitation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                display_name = excluded.display_name,
                current_epoch = excluded.current_epoch,
                last_op_digest = excluded.last_op_digest,
                last_seen_at = excluded.last_seen_at,
                last_message_at = excluded.last_message_at,
                my_current_distribution_id = excluded.my_current_distribution_id,
                sent_since_rotation = excluded.sent_since_rotation,
                last_rotated_at = excluded.last_rotated_at,
                my_skdm_recipients = excluded.my_skdm_recipients,
                pending_invitation = excluded.pending_invitation;
        """)
        try stmt
            .bind(g.id, at: 1)
            .bind(g.displayName, at: 2)
            .bind(g.createdAt, at: 3)
            .bind(Int64(bitPattern: g.currentEpoch), at: 4)
            .bind(g.lastOpDigest, at: 5)
            .bind(g.lastSeenAt, at: 6)
            .bind(g.lastMessageAt, at: 7)
            .bind(g.myCurrentDistributionId.map { $0.data }, at: 8)
            .bind(Int(g.sentSinceRotation), at: 9)
            .bind(g.lastRotatedAt, at: 10)
            .bind(pack33ByteSet(g.mySkdmRecipients), at: 11)
            .bind(g.pendingInvitation, at: 12)
            .run()
    }

    func deleteGroup(id: Data) throws {
        try db.prepare("DELETE FROM groups WHERE id = ?;").bindAll(id).run()
    }

    // MARK: - Group members

    private struct LoadedMember {
        let peerId: PeerIdBox
        let member: GroupMember
        let distributionId: UUID?
    }
    private struct PeerIdBox: Hashable {
        let peerId: Data
    }

    private func loadGroupMembers(groupId: Data) throws -> [LoadedMember] {
        let stmt = try db.prepare("""
            SELECT peer_id, display_name, role, joined_at_epoch, status,
                   added_by, current_distribution_id
            FROM group_members WHERE group_id = ?
            ORDER BY joined_at_epoch ASC, peer_id ASC;
        """)
        try stmt.bindAll(groupId)
        var out: [LoadedMember] = []
        while try stmt.step() {
            let peer = stmt.columnBlob(0) ?? Data()
            let role = GroupRole(rawValue: stmt.columnText(2) ?? "") ?? .member
            let status = MemberStatus(rawValue: stmt.columnText(4) ?? "") ?? .active
            let member = GroupMember(
                peerId: peer,
                displayName: stmt.columnText(1) ?? "",
                role: role,
                joinedAtEpoch: UInt64(bitPattern: stmt.columnInt64(3)),
                status: status,
                addedBy: stmt.columnBlob(5),
            )
            let dist = stmt.columnBlob(6).flatMap { $0.asUUID() }
            out.append(LoadedMember(peerId: PeerIdBox(peerId: peer), member: member, distributionId: dist))
        }
        return out
    }

    private static func replaceGroupMembers(_ g: ChatGroup, on tx: Database) throws {
        // Membership churn is rare relative to message volume — a
        // whole-list rewrite is correct and simpler than per-member
        // diff. Wrapped in the caller's transaction.
        try tx.prepare("DELETE FROM group_members WHERE group_id = ?;")
            .bindAll(g.id).run()
        let ins = try tx.prepare("""
            INSERT INTO group_members (
                group_id, peer_id, display_name, role, joined_at_epoch,
                status, added_by, current_distribution_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """)
        for member in g.members {
            try ins
                .bind(g.id, at: 1)
                .bind(member.peerId, at: 2)
                .bind(member.displayName, at: 3)
                .bind(member.role.rawValue, at: 4)
                .bind(Int64(bitPattern: member.joinedAtEpoch), at: 5)
                .bind(member.status.rawValue, at: 6)
                .bind(member.addedBy, at: 7)
                .bind(g.memberDistributionIds[member.peerId].map { $0.data }, at: 8)
                .run()
        }
    }

    // MARK: - Group pending ops

    private func loadGroupPendingOps(groupId: Data) throws -> [Data] {
        let stmt = try db.prepare("""
            SELECT op_bytes FROM group_pending_ops WHERE group_id = ?
            ORDER BY received_at ASC;
        """)
        try stmt.bindAll(groupId)
        var ops: [Data] = []
        while try stmt.step() {
            if let op = stmt.columnBlob(0) { ops.append(op) }
        }
        return ops
    }

    // MARK: - Group op digests

    private func loadGroupOpDigests(groupId: Data) throws -> [String: Data] {
        let stmt = try db.prepare("""
            SELECT epoch, digest FROM group_op_digests WHERE group_id = ?;
        """)
        try stmt.bindAll(groupId)
        var out: [String: Data] = [:]
        while try stmt.step() {
            let epoch = UInt64(bitPattern: stmt.columnInt64(0))
            if let digest = stmt.columnBlob(1) {
                out[String(epoch)] = digest
            }
        }
        return out
    }

    // MARK: - Outbox

    func loadOutbox() throws -> OutboxStore {
        let stmt = try db.prepare("""
            SELECT message_id, recipient_peer_id, sealed_ciphertext, token,
                   ttl, sent_at, retries, delivered_at, failed_at, relayed_at,
                   attachment_id, chunk_index, chunk_count, group_message_id, read_at
            FROM outbox ORDER BY sent_at ASC;
        """)
        var store = OutboxStore()
        while try stmt.step() {
            let mid = stmt.columnBlob(0) ?? Data()
            let entry = OutboxEntry(
                messageId: mid,
                recipientPeerId: stmt.columnBlob(1) ?? Data(),
                sealedCiphertext: stmt.columnBlob(2) ?? Data(),
                token: stmt.columnBlob(3) ?? Data(),
                ttl: TimeInterval(stmt.columnInt64(4)),
                sentAt: stmt.columnInt64(5).dateFromEpochMs,
                retries: stmt.columnInt(6),
                deliveredAt: stmt.columnOptionalInt64(7).map { $0.dateFromEpochMs },
                failedAt: stmt.columnOptionalInt64(8).map { $0.dateFromEpochMs },
                relayedAt: stmt.columnOptionalInt64(9).map { $0.dateFromEpochMs },
                attachmentId: stmt.columnBlob(10),
                chunkIndex: stmt.columnOptionalInt64(11).map { UInt32($0) },
                chunkCount: stmt.columnOptionalInt64(12).map { UInt32($0) },
                groupMessageId: stmt.columnBlob(13),
                readAt: stmt.columnOptionalInt64(14).map { $0.dateFromEpochMs },
            )
            store.entries[mid] = entry
        }
        return store
    }

    func upsertOutboxEntry(_ e: OutboxEntry) throws {
        let stmt = try db.prepare("""
            INSERT INTO outbox (
                message_id, recipient_peer_id, sealed_ciphertext, token,
                ttl, sent_at, retries, delivered_at, failed_at, relayed_at,
                attachment_id, chunk_index, chunk_count, group_message_id, read_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(message_id) DO UPDATE SET
                recipient_peer_id = excluded.recipient_peer_id,
                sealed_ciphertext = excluded.sealed_ciphertext,
                token = excluded.token,
                ttl = excluded.ttl,
                sent_at = excluded.sent_at,
                retries = excluded.retries,
                delivered_at = excluded.delivered_at,
                failed_at = excluded.failed_at,
                relayed_at = excluded.relayed_at,
                attachment_id = excluded.attachment_id,
                chunk_index = excluded.chunk_index,
                chunk_count = excluded.chunk_count,
                group_message_id = excluded.group_message_id,
                read_at = excluded.read_at;
        """)
        try stmt
            .bind(e.messageId, at: 1)
            .bind(e.recipientPeerId, at: 2)
            .bind(e.sealedCiphertext, at: 3)
            .bind(e.token, at: 4)
            .bind(Int64(e.ttl), at: 5)
            .bind(e.sentAt, at: 6)
            .bind(e.retries, at: 7)
            .bind(e.deliveredAt, at: 8)
            .bind(e.failedAt, at: 9)
            .bind(e.relayedAt, at: 10)
            .bind(e.attachmentId, at: 11)
            .bind(e.chunkIndex.map { Int($0) }, at: 12)
            .bind(e.chunkCount.map { Int($0) }, at: 13)
            .bind(e.groupMessageId, at: 14)
            .bind(e.readAt, at: 15)
            .run()
    }

    func deleteOutboxEntry(messageId: Data) throws {
        try db.prepare("DELETE FROM outbox WHERE message_id = ?;")
            .bindAll(messageId).run()
    }

    func clearOutbox() throws {
        try db.execute("DELETE FROM outbox;")
    }

    // MARK: - Helpers

    /// Concat a set of 33-byte peer ids into one BLOB (group's
    /// `mySkdmRecipients` column). Order is sorted-by-bytes for
    /// reproducibility.
    private static func pack33ByteSet(_ set: Set<Data>) -> Data {
        let sorted = set.sorted { a, b in
            for (l, r) in zip(a, b) {
                if l != r { return l < r }
            }
            return a.count < b.count
        }
        var packed = Data()
        for d in sorted { packed.append(d) }
        return packed
    }

    /// Inverse of `pack33ByteSet`. Each entry is 33 bytes.
    private func unpack33ByteSet(_ blob: Data) -> Set<Data> {
        guard blob.count % 33 == 0 else { return [] }
        var out: Set<Data> = []
        var idx = blob.startIndex
        while idx < blob.endIndex {
            let next = idx + 33
            out.insert(blob.subdata(in: idx..<next))
            idx = next
        }
        return out
    }
}

// MARK: - UUID / Int64 conversions

private extension UUID {
    /// 16-byte representation, matching what's stored in the
    /// `contacts.id` / `messages.id` BLOB columns. Equivalent to
    /// `withUnsafeBytes(of: self.uuid) { Data($0) }`.
    var data: Data {
        withUnsafePointer(to: self.uuid) { ptr in
            Data(bytes: ptr, count: 16)
        }
    }
}

private extension Data {
    func asUUID() -> UUID? {
        guard count == 16 else { return nil }
        return withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return nil }
            return UUID(uuid: base.load(as: uuid_t.self))
        }
    }
}

private extension Int64 {
    var dateFromEpochMs: Date { Date(timeIntervalSince1970: Double(self) / 1000.0) }
}
