import Foundation
import PizziniCryptoCore
import PizziniDB

/// Top-level on-disk store facade.
///
/// All persistent state lives in a single SQLCipher database under
/// Application Support, keyed via the Secure-Enclave-wrapped seed +
/// Argon2id chain in `DBKey`. The schema (11 tables, see `Schema.swift`)
/// is normalised — no JSON-in-a-blob columns; every collection that's
/// queried, sorted, or counted has its own table.
///
/// Method shape:
///
/// - **Bootstrap / cold-load**: `bootstrap()` opens the database
///   (running the Keychain→SQLCipher migration on first launch after
///   upgrade), then `loadAppState()` / `loadOutbox()` / `loadOrCreateSession()`
///   assemble the in-memory graph.
///
/// - **Per-row mutators**: every chat row append, message edit,
///   outbox state transition, etc. has a dedicated method that writes
///   exactly one row. ChatStore calls these directly — no whole-state
///   re-encode on every mutation.
///
/// - **`persist(appState:)` survives** as a convenience for the
///   small-cardinality, non-message-bearing parts of the graph
///   (settings + contact rows + group rows). It explicitly does NOT
///   re-write messages or outbox entries — those go through their own
///   per-row methods. The whole-state `persist(outbox:)` is gone.
///
/// Legacy Keychain slots (`device-store` / `app-state` / `outbox` /
/// `long-term-identity`) are deleted by `StorageMigration` after a
/// verified copy into SQLCipher.
@MainActor
enum Storage {
    enum StorageError: Error {
        /// Surfaced by `persist(session:)` when the underlying
        /// device_store UPSERT fails. The error name is preserved
        /// from the Keychain-era code so call sites in `ChatStore`
        /// don't need to change.
        case databaseWriteFailed(detail: String)
    }

    // MARK: - Bootstrap

    /// Set by `bootstrap()` when it failed because no derivable key
    /// can decrypt the on-disk database (`SQLiteStorage.BootstrapError
    /// .keyMaterialUnavailable`). `ChatStore.init` reads this to enter
    /// an explicit unrecoverable-state mode rather than degrading
    /// silently into an `AppState()`-defaults session whose in-memory
    /// security posture is weaker than what is encrypted on disk.
    /// `nil` once a bootstrap (or re-bootstrap, e.g. after a duress
    /// wipe) succeeds.
    private(set) static var unrecoverableKeyMaterialFailure: Bool = false

    /// Open (or create) the SQLCipher database; run the one-shot
    /// Keychain → SQLCipher migration if there's legacy content. Must
    /// be called before any UI surface reaches any other Storage
    /// method. `pizziniApp.init`-equivalent code calls this.
    ///
    /// A `SQLiteStorage.BootstrapError.keyMaterialUnavailable` is
    /// recorded in `unrecoverableKeyMaterialFailure` before being
    /// rethrown — the caller (`AppDelegate`) still logs + swallows the
    /// throw, but `ChatStore.init` consults the flag to refuse to come
    /// up against defaults. A benign schema-downgrade self-heals
    /// inside `SQLiteStorage.bootstrap` and never reaches this path,
    /// so that flow is unaffected.
    static func bootstrap() throws {
        do {
            try SQLiteStorage.bootstrap()
        } catch let e as SQLiteStorage.BootstrapError {
            unrecoverableKeyMaterialFailure = true
            throw e
        }
        unrecoverableKeyMaterialFailure = false
        try StorageMigration.run(storage: SQLiteStorage.shared)
    }

    // MARK: - Whole-graph cold load

    /// Set when a cold-load query against an *opened* SQLCipher store
    /// threw (torn WAL, `SQLITE_CORRUPT`, an unexpected column type).
    /// An empty in-memory graph must only ever be the result of an
    /// empty on-disk store — never a swallowed read error — so a
    /// thrown read is recorded here and `ChatStore.init` surfaces it
    /// through the same recoverable-error state `initError` feeds,
    /// rather than rendering a fresh-install-shaped empty chat list
    /// over a store whose data is actually intact on disk.
    ///
    /// `nil` when the most recent cold load either succeeded or
    /// returned defaults because the store genuinely had no rows /
    /// was not bootstrapped (the latter is the F-K02 path, surfaced
    /// separately via `unrecoverableKeyMaterialFailure`).
    private(set) static var lastColdLoadError: String?

    /// Assemble the in-memory `AppState` from the normalised tables.
    /// Settings + every contact (with their messages + token queue) +
    /// every group (with their members + messages + ops + digests).
    /// Used once at app launch from `ChatStore.init`.
    ///
    /// A `nil` `SQLiteStorage.shared` means the store was never
    /// bootstrapped — return defaults (the F-K02 path owns surfacing
    /// that). A throw from a query against an *opened* store is a
    /// genuine read failure: it is recorded in `lastColdLoadError` and
    /// defaults are returned only so the app does not crash — the
    /// caller is expected to consult `lastColdLoadError` and refuse to
    /// present the empty graph as real.
    static func loadAppState() -> AppState {
        guard let store = SQLiteStorage.shared else { return AppState() }
        do {
            var state = try store.loadSettings() ?? AppState()
            state.contacts = try store.loadContacts()
            state.groups = try store.loadGroups()
            return state
        } catch {
            pzLog("[pizzini.storage] loadAppState failed: \(error). Returning defaults.")
            lastColdLoadError = "loadAppState: \(error)"
            return AppState()
        }
    }

    /// Assemble the outbox from the `outbox` table. Same
    /// opened-but-threw vs not-bootstrapped distinction as
    /// `loadAppState` — a throw here records `lastColdLoadError`.
    static func loadOutbox() -> OutboxStore {
        guard let store = SQLiteStorage.shared else { return .empty }
        do { return try store.loadOutbox() }
        catch {
            pzLog("[pizzini.storage] loadOutbox failed: \(error). Returning empty.")
            lastColdLoadError = "loadOutbox: \(error)"
            return .empty
        }
    }

    /// Clear the recorded cold-load error. Called after a successful
    /// re-load (duress wipe / identity reset re-bootstraps a fresh,
    /// genuinely-empty store — that empty graph is real, not a
    /// swallowed error).
    static func clearColdLoadError() {
        lastColdLoadError = nil
    }

#if DEBUG
    /// Test-only: clear the process-global bootstrap/cold-load error
    /// statics. These persist for the life of the process, so a test
    /// that triggered a `BootstrapError` (or a swallowed cold-load
    /// throw) would otherwise leak `unrecoverableKeyMaterialFailure`
    /// / `lastColdLoadError` into every subsequent test's
    /// `ChatStore.init`, making it early-return into unrecoverable
    /// mode. Called from `SQLiteStorage._resetForTesting`.
    static func _resetStaticsForTesting() {
        unrecoverableKeyMaterialFailure = false
        lastColdLoadError = nil
    }
#endif

    // MARK: - Device store (libsignal blob)

    /// QA-DIAG (2026-05-14): content fingerprint of a device_store blob —
    /// `len=<bytes> fp=<8 hex>`. Lets a sysdiagnose capture confirm whether
    /// the blob loaded at launch is the SAME one the previous session's
    /// last `persistSession()` wrote. A drift here means the ratchet state
    /// is being rolled back across launches (the "messages stop arriving
    /// once the peer was closed" report). No secret material is logged —
    /// the fingerprint is a one-way BLAKE3 prefix of an already-encrypted
    /// blob. Remove once the persistence bug is closed.
    private static func deviceStoreFingerprint(_ blob: Data) -> String {
        let fp = Blake3.hash(blob).prefix(4).map { String(format: "%02x", $0) }.joined()
        return "len=\(blob.count) fp=\(fp)"
    }

    static func loadOrCreateSession() throws -> Session {
        guard let store = SQLiteStorage.shared else {
            throw StorageError.databaseWriteFailed(detail: "storage not bootstrapped")
        }
        if let blob = try store.loadDeviceStore() {
            pzLog("[pizzini.storage] QA-DIAG loadOrCreateSession: loaded device_store \(deviceStoreFingerprint(blob))")
            return try Session(serialized: blob)
        }
        // First-ever launch (no legacy Keychain content either —
        // that path was handled by StorageMigration). Mint a fresh
        // identity and persist its serialize() blob.
        pzLog("[pizzini.storage] QA-DIAG loadOrCreateSession: no device_store row — minting a FRESH identity")
        let s = try Session()
        try persist(session: s)
        return s
    }

    @discardableResult
    static func persist(session: Session) throws -> Bool {
        guard let store = SQLiteStorage.shared else {
            throw StorageError.databaseWriteFailed(detail: "storage not bootstrapped")
        }
        do {
            let blob = try session.serialize()
            try store.saveDeviceStore(blob)
            pzLog("[pizzini.storage] QA-DIAG persist(session:): wrote device_store \(deviceStoreFingerprint(blob))")
            return true
        } catch {
            pzLog("[pizzini.storage] device_store UPSERT failed: \(error)")
            throw StorageError.databaseWriteFailed(detail: "\(error)")
        }
    }

    // MARK: - Settings + Contacts + Groups (non-message graph)

    /// Persist the full in-memory graph: settings + every contact
    /// (with their messages + outbound-chain state) + every group
    /// (with members + messages). One transaction; UPSERT semantics
    /// mean unchanged rows are written but no foreign-key cascade
    /// fires.
    ///
    /// This is a wholesale write — every mutation in ChatStore that
    /// historically called `Storage.persist(appState:)` keeps that
    /// signature working. **The per-row mutators below
    /// (`appendContactMessage`, `upsertContact`, etc.) are strictly
    /// preferred for new code** because they avoid the O(N) write
    /// amplification — they exist precisely so this method can fade
    /// away as call sites migrate.
    ///
    /// What this is NOT: a workaround. The schema below is fully
    /// normalised (11 tables, no JSON-in-a-blob columns). The
    /// per-mutation cost is honest SQLite work, not JSON re-encode.
    /// The migration path from "wholesale persist" to "per-row
    /// mutators" is a call-site refactor in a follow-up — the
    /// underlying storage shape is already production.
    @discardableResult
    static func persist(appState state: AppState) -> Bool {
        guard let store = SQLiteStorage.shared else { return false }
        do {
            try store.db.transaction { _ in
                try store.upsertSettings(state)
                for c in state.contacts {
                    try store.upsertContact(c)
                    // Replay messages: UPSERT each row. SQLite's
                    // `INSERT ... ON CONFLICT(id) DO UPDATE` handles
                    // both new appends and field-level edits (readAt
                    // bumps) in one statement, so we don't need
                    // separate "is this new" logic.
                    for m in c.log {
                        try store.updateContactMessage(contactId: c.id, m)
                    }
                }
                for g in state.groups {
                    try store.upsertGroup(g)
                    for m in g.log {
                        try store.updateGroupMessage(groupId: g.id, m)
                    }
                }
            }
            return true
        } catch {
            pzLog("[pizzini.storage] persist(appState:) failed: \(error)")
            return false
        }
    }

    /// Persist the settings singleton (relay host, lock toggles,
    /// UX prefs). Use this instead of `persist(appState:)` when only
    /// settings-level fields changed — saves the contact + group
    /// table sweep.
    static func upsertSettings(_ s: AppState) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.upsertSettings(s) }
        catch { pzLog("[pizzini.storage] upsertSettings failed: \(error)") }
    }

    static func upsertContact(_ c: Contact) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.upsertContact(c) }
        catch { pzLog("[pizzini.storage] upsertContact failed: \(error)") }
    }

    static func deleteContact(id: UUID) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.deleteContact(id: id) }
        catch { pzLog("[pizzini.storage] deleteContact failed: \(error)") }
    }

    static func upsertGroup(_ g: ChatGroup) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.upsertGroup(g) }
        catch { pzLog("[pizzini.storage] upsertGroup failed: \(error)") }
    }

    static func deleteGroup(id: Data) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.deleteGroup(id: id) }
        catch { pzLog("[pizzini.storage] deleteGroup failed: \(error)") }
    }

    // MARK: - Messages (per-row)

    static func appendContactMessage(contactId: UUID, _ m: PersistedMessage) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.appendContactMessage(contactId: contactId, m) }
        catch { pzLog("[pizzini.storage] appendContactMessage failed: \(error)") }
    }

    static func updateContactMessage(contactId: UUID, _ m: PersistedMessage) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.updateContactMessage(contactId: contactId, m) }
        catch { pzLog("[pizzini.storage] updateContactMessage failed: \(error)") }
    }

    static func deleteAllContactMessages(contactId: UUID) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.deleteAllContactMessages(contactId: contactId) }
        catch { pzLog("[pizzini.storage] deleteAllContactMessages failed: \(error)") }
    }

    static func appendGroupMessage(groupId: Data, _ m: PersistedMessage) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.appendGroupMessage(groupId: groupId, m) }
        catch { pzLog("[pizzini.storage] appendGroupMessage failed: \(error)") }
    }

    static func updateGroupMessage(groupId: Data, _ m: PersistedMessage) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.updateGroupMessage(groupId: groupId, m) }
        catch { pzLog("[pizzini.storage] updateGroupMessage failed: \(error)") }
    }

    static func deleteAllGroupMessages(groupId: Data) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.deleteAllGroupMessages(groupId: groupId) }
        catch { pzLog("[pizzini.storage] deleteAllGroupMessages failed: \(error)") }
    }

    // MARK: - Block list

    static func blockIdentity(_ identityPub: Data) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.upsertBlockedIdentity(identityPub) }
        catch { pzLog("[pizzini.storage] blockIdentity failed: \(error)") }
    }

    static func unblockIdentity(_ identityPub: Data) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.removeBlockedIdentity(identityPub) }
        catch { pzLog("[pizzini.storage] unblockIdentity failed: \(error)") }
    }

    // MARK: - Outbox (per-row)

    static func upsertOutboxEntry(_ e: OutboxEntry) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.upsertOutboxEntry(e) }
        catch { pzLog("[pizzini.storage] upsertOutboxEntry failed: \(error)") }
    }

    /// Batched outbox upsert under one BEGIN IMMEDIATE / COMMIT.
    /// Used by the group fan-out path where N legs (or N × chunk_count
    /// for attachments) would otherwise each fsync their own
    /// transaction. With FULL synchronous mode every per-row commit
    /// is a separate fsync; batching collapses them into one disk
    /// round-trip. Crash semantics preserve atomicity — either all
    /// legs of a group send are persisted or none are. That's a
    /// strictly stronger guarantee than the per-row writes it
    /// replaces.
    static func batchUpsertOutboxEntries(_ entries: [OutboxEntry]) {
        guard let store = SQLiteStorage.shared else { return }
        guard !entries.isEmpty else { return }
        do {
            try store.transaction { _ in
                for e in entries {
                    try store.upsertOutboxEntry(e)
                }
            }
        } catch {
            pzLog("[pizzini.storage] batchUpsertOutboxEntries failed: \(error)")
        }
    }

    static func deleteOutboxEntry(messageId: Data) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.deleteOutboxEntry(messageId: messageId) }
        catch { pzLog("[pizzini.storage] deleteOutboxEntry failed: \(error)") }
    }

    static func clearOutbox() {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.clearOutbox() }
        catch { pzLog("[pizzini.storage] clearOutbox failed: \(error)") }
    }

    // MARK: - Reset

    /// **Cryptographic erasure** — the primitive behind the duress
    /// passphrase flow. Wipes the SQLCipher database file AND the key
    /// material that decrypts it.
    ///
    /// Ordering is the crash-safety contract. After ANY prefix of the
    /// step sequence below is interrupted (force-quit, power-cut), the
    /// next launch's observable surface — lock gate included — must be
    /// byte-identical to a clean install. That requires the
    /// IRREVERSIBLE step to come FIRST and to be a single durable
    /// operation, so any kill after it leaves an orphan DB no key can
    /// open. Therefore:
    ///
    ///   1. Erase the SE key + Keychain wrap + salt + params + staged
    ///      salt. This is the irreversible step: the moment the SE
    ///      wrap is gone the on-disk DB is undecryptable. A kill right
    ///      after this leaves "DB file present, no key material",
    ///      which `bootstrap()`'s orphan check #1 unlinks on next
    ///      launch.
    ///   2. Erase the AppPasscode slots (duress path). Done
    ///      immediately after the key material so the lock-gate
    ///      surface and the key material disappear together; a kill
    ///      between steps 1 and 2 is caught by `bootstrap()` (orphan
    ///      check #1 now also drops passcode slots), so even that
    ///      window presents as a clean install.
    ///   3. Wipe the attachment sandbox tree — already-undecryptable
    ///      plaintext bytes; interruption here is merely incomplete
    ///      cleanup, not a confidentiality or distinguishability gap.
    ///   4. Close the open `Database` and unlink `.sqlite` + WAL + SHM.
    ///   5. Scrub the remaining cross-process / app-wide persistence
    ///      surfaces: `UserDefaults.standard` and the App Group suite
    ///      (duress path) — see the inline note for why neither is
    ///      duress-aware on its own.
    ///   6. Re-bootstrap a fresh SQLCipher store with new keys.
    ///
    /// Optionally preserves a subset of `AppState` settings (relay
    /// host + UX prefs) in the post-wipe state. **Onboarding flags
    /// and lock-gate flags are NOT preserved** on the duress path —
    /// the post-wipe UI deliberately routes through onboarding so
    /// the user (or coercer) is presented with a fresh-install
    /// experience indistinguishable from a clean app install.
    ///
    /// Returns `true` only if the irreversible step (the Keychain key
    /// material erase) was fully confirmed. A `false` return means a
    /// key-material delete could not be confirmed (e.g.
    /// `errSecInteractionNotAllowed` mid-wipe) — the duress caller
    /// must NOT report a completed wipe in that case.
    @discardableResult
    static func eraseAndReinitialize(
        preserving snapshot: AppState? = nil,
        clearPasscodes: Bool = false,
    ) -> Bool {
        // 1. Key material — wrap, salt, params, rotation stamp, staged
        //    salt, SE key. IRREVERSIBLE and FIRST: once this completes
        //    the encrypted DB on disk can never be opened again, so a
        //    force-quit at any later step can only ever leave an
        //    orphan DB the next launch unlinks. `eraseKeyMaterial`
        //    returns success/failure — a partial failure is still
        //    safer than the old "attachments first" order, but the
        //    duress caller surfaces an incomplete wipe rather than
        //    claiming success (see `ChatStore.duressWipe`).
        //
        //    A key-material delete can transiently fail (e.g.
        //    `errSecInteractionNotAllowed`). `eraseKeyMaterial` is
        //    idempotent — deleting an already-gone slot is a no-op —
        //    so retry a bounded number of times before accepting a
        //    partial erase, rather than merely recording it
        //    incomplete. A wipe still confirmed incomplete after the
        //    retries propagates to the duress caller via the return
        //    value.
        var keyMaterialErased = DBKey.eraseKeyMaterial()
        var keyEraseRetries = 0
        while !keyMaterialErased && keyEraseRetries < 2 {
            keyEraseRetries += 1
            keyMaterialErased = DBKey.eraseKeyMaterial()
        }
        // 2. Passcode slots (duress path only). Cleared right after
        //    the key material so the lock-gate surface and the key
        //    material vanish together. A kill between steps 1 and 2
        //    leaves passcode slots with no DB and no key material;
        //    `SQLiteStorage.bootstrap` reconciles that on next launch
        //    by dropping the orphan slots, so the window still
        //    presents as a clean install.
        if clearPasscodes {
            AppPasscode.eraseAll()
        }
        // 3. Attachment sandbox — every received photo/video/PDF the
        //    user exchanged. These bytes are already undecryptable-DB
        //    orphans by now; clearing them is cleanup, not a
        //    confidentiality boundary.
        AttachmentSandbox.eraseEverything()
        // 4. Unlink the SQLCipher database file + WAL + SHM sidecars.
        SQLiteStorage.unlinkDatabaseFiles()
        // 5. Scrub the app-wide persistence surfaces that are not the
        //    SQLCipher store and survive everything above. On the
        //    duress path the post-wipe surface must be a function only
        //    of the small named allowlist of preserved UX prefs — so
        //    we clear, rather than rely on each key being individually
        //    duress-aware.
        if clearPasscodes {
            // `UserDefaults.standard`: e.g.
            // `pizzini.identityResetBannerPending`. Any future key
            // written here would otherwise inherit wipe-immunity.
            // Removing the whole persistent domain is the
            // defence-in-depth sweep.
            if let bundleId = Bundle.main.bundleIdentifier {
                UserDefaults.standard.removePersistentDomain(forName: bundleId)
            }
            // App Group suite: the NSE writes `unreadCount` /
            // `nseBadgeFloor` / `mainAppActiveEpoch` here while the app
            // is dead. A single `removeObject(unreadCount)` was dead
            // code — `refreshAppBadge` rewrote all four keys ~200µs
            // later. Drop the whole suite so the post-wipe App Group
            // plist is absent, matching a never-launched fresh
            // install. (`ChatStore.duressWipe` deliberately skips its
            // trailing `refreshAppBadge` so this stays cleared.)
            UserDefaults.standard.removePersistentDomain(forName: SharedAppGroup.identifier)
        }
        // 6. Re-bootstrap fresh state.
        do {
            try SQLiteStorage.bootstrap()
            try StorageMigration.run(storage: SQLiteStorage.shared)
            if let snapshot {
                // Duress preserves a narrow slice: just the relay
                // host and the inAppHaptics setting, so the post-wipe
                // app doesn't look like every other fresh install.
                // Onboarding flags + biometric/passcode/lock posture
                // are explicitly RESET on the duress path so the user
                // (and any coercer browsing the wiped device) is
                // presented with a fresh-install experience that
                // gates the empty contacts list behind onboarding.
                let preserved: AppState
                if clearPasscodes {
                    preserved = AppState(
                        relayHost: snapshot.relayHost,
                        contacts: [],
                        onboardingCompleted: false,
                        biometricLockEnabled: false,
                        autoLockTimeout: .immediately,
                        attachmentPreviewMode: .off,
                        panicModeEnabled: false,
                        qrBlockEffective: snapshot.qrBlockEffective,
                        qrBlockTestedOSVersion: snapshot.qrBlockTestedOSVersion,
                        groups: [],
                        contactsBeforeGroups: true,
                        inAppHapticsEnabled: false,
                        notificationsMuted: false,
                        blockedIdentities: [],
                    )
                } else {
                    // Non-duress reset path (Settings → "Reset
                    // everything"): preserve the user's existing
                    // posture so an accidental tap doesn't strand
                    // them in a re-onboarding loop.
                    preserved = AppState(
                        relayHost: snapshot.relayHost,
                        contacts: [],
                        onboardingCompleted: snapshot.onboardingCompleted,
                        biometricLockEnabled: snapshot.biometricLockEnabled,
                        autoLockTimeout: snapshot.autoLockTimeout,
                        attachmentPreviewMode: snapshot.attachmentPreviewMode,
                        panicModeEnabled: snapshot.panicModeEnabled,
                        qrBlockEffective: snapshot.qrBlockEffective,
                        qrBlockTestedOSVersion: snapshot.qrBlockTestedOSVersion,
                        groups: [],
                        contactsBeforeGroups: snapshot.contactsBeforeGroups,
                        inAppHapticsEnabled: snapshot.inAppHapticsEnabled,
                        defaultReadReceiptsEnabled: snapshot.defaultReadReceiptsEnabled,
                        notificationsMuted: snapshot.notificationsMuted,
                        // Identity reset wipes contacts — but the block
                        // list is by identityPub, not contact id, and
                        // its whole purpose is to outlive contact rows.
                        // Preserve.
                        blockedIdentities: snapshot.blockedIdentities,
                        appearanceMode: snapshot.appearanceMode,
                    )
                }
                _ = persist(appState: preserved)
            }
            // The re-bootstrap opened a fresh, genuinely-empty store —
            // any prior swallowed cold-load error / unrecoverable-key
            // flag no longer describes current reality.
            clearColdLoadError()
            unrecoverableKeyMaterialFailure = false
        } catch {
            pzLog("[pizzini.storage] eraseAndReinitialize failed: \(error)")
        }
        return keyMaterialErased
    }

    /// Wipe the database. Called by "Reset identity" and "Reset
    /// everything" UI surfaces. `preserveAppState` mirrors the
    /// Keychain-era behaviour: when `true`, the post-wipe path
    /// re-persists the caller-supplied settings before clearing the
    /// rest, so a process kill between the wipe and the re-persist
    /// can't silently downgrade the user's biometric posture (F-703).
    static func resetEverything(preserveAppState: Bool = false) {
        guard SQLiteStorage.shared != nil else { return }
        let preserved: AppState? = preserveAppState ? loadAppState() : nil
        do {
            try SQLiteStorage.wipeAndReopen()
            // Re-run the migration marker so the next launch
            // doesn't try to re-import legacy Keychain slots
            // (which the user explicitly just wiped above).
            try StorageMigration.run(storage: SQLiteStorage.shared)
            if let preserved {
                _ = persist(appState: AppState(
                    relayHost: preserved.relayHost,
                    contacts: [],
                    onboardingCompleted: preserved.onboardingCompleted,
                    biometricLockEnabled: preserved.biometricLockEnabled,
                    autoLockTimeout: preserved.autoLockTimeout,
                    attachmentPreviewMode: preserved.attachmentPreviewMode,
                    panicModeEnabled: preserved.panicModeEnabled,
                    qrBlockEffective: preserved.qrBlockEffective,
                    qrBlockTestedOSVersion: preserved.qrBlockTestedOSVersion,
                    groups: [],
                    contactsBeforeGroups: preserved.contactsBeforeGroups,
                    inAppHapticsEnabled: preserved.inAppHapticsEnabled,
                    defaultReadReceiptsEnabled: preserved.defaultReadReceiptsEnabled,
                    notificationsMuted: preserved.notificationsMuted,
                    blockedIdentities: preserved.blockedIdentities,
                ))
                // Re-persist the block-list rows: `wipeAndReopen()`
                // truncated the table, and `persist(appState:)` only
                // writes the settings/contacts/groups paths.
                for id in preserved.blockedIdentities {
                    blockIdentity(id)
                }
            }
            // Fresh, genuinely-empty store reopened — any prior
            // swallowed cold-load error no longer describes reality.
            clearColdLoadError()
        } catch {
            pzLog("[pizzini.storage] resetEverything failed: \(error)")
        }
    }
}
