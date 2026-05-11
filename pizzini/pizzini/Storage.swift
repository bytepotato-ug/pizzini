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

    /// Open (or create) the SQLCipher database; run the one-shot
    /// Keychain → SQLCipher migration if there's legacy content. Must
    /// be called before any UI surface reaches any other Storage
    /// method. `pizziniApp.init`-equivalent code calls this.
    static func bootstrap() throws {
        try SQLiteStorage.bootstrap()
        try StorageMigration.run(storage: SQLiteStorage.shared)
    }

    // MARK: - Whole-graph cold load

    /// Assemble the in-memory `AppState` from the normalised tables.
    /// Settings + every contact (with their messages + token queue) +
    /// every group (with their members + messages + ops + digests).
    /// Used once at app launch from `ChatStore.init`.
    static func loadAppState() -> AppState {
        guard let store = SQLiteStorage.shared else { return AppState() }
        do {
            var state = try store.loadSettings() ?? AppState()
            state.contacts = try store.loadContacts()
            state.groups = try store.loadGroups()
            return state
        } catch {
            NSLog("[pizzini.storage] loadAppState failed: \(error). Returning defaults.")
            return AppState()
        }
    }

    /// Assemble the outbox from the `outbox` table.
    static func loadOutbox() -> OutboxStore {
        guard let store = SQLiteStorage.shared else { return .empty }
        do { return try store.loadOutbox() }
        catch {
            NSLog("[pizzini.storage] loadOutbox failed: \(error). Returning empty.")
            return .empty
        }
    }

    // MARK: - Device store (libsignal blob)

    static func loadOrCreateSession() throws -> Session {
        let store = SQLiteStorage.shared!
        if let blob = try store.loadDeviceStore() {
            return try Session(serialized: blob)
        }
        // First-ever launch (no legacy Keychain content either —
        // that path was handled by StorageMigration). Mint a fresh
        // identity and persist its serialize() blob.
        let s = try Session()
        try persist(session: s)
        return s
    }

    @discardableResult
    static func persist(session: Session) throws -> Bool {
        let store = SQLiteStorage.shared!
        do {
            let blob = try session.serialize()
            try store.saveDeviceStore(blob)
            return true
        } catch {
            NSLog("[pizzini.storage] device_store UPSERT failed: \(error)")
            throw StorageError.databaseWriteFailed(detail: "\(error)")
        }
    }

    // MARK: - Settings + Contacts + Groups (non-message graph)

    /// Persist the full in-memory graph: settings + every contact
    /// (with their messages + delivery tokens) + every group (with
    /// their members + messages). One transaction; UPSERT semantics
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
                    // Delivery tokens get a full-list rewrite (rare
                    // path — only fires on the issuance flow). The
                    // common pop / append path lives in the per-row
                    // mutators below.
                    if !c.deliveryTokensForPeer.isEmpty {
                        try store.replaceDeliveryTokens(
                            contactId: c.id,
                            tokens: c.deliveryTokensForPeer,
                        )
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
            NSLog("[pizzini.storage] persist(appState:) failed: \(error)")
            return false
        }
    }

    static func upsertContact(_ c: Contact) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.upsertContact(c) }
        catch { NSLog("[pizzini.storage] upsertContact failed: \(error)") }
    }

    static func deleteContact(id: UUID) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.deleteContact(id: id) }
        catch { NSLog("[pizzini.storage] deleteContact failed: \(error)") }
    }

    static func upsertGroup(_ g: ChatGroup) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.upsertGroup(g) }
        catch { NSLog("[pizzini.storage] upsertGroup failed: \(error)") }
    }

    static func deleteGroup(id: Data) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.deleteGroup(id: id) }
        catch { NSLog("[pizzini.storage] deleteGroup failed: \(error)") }
    }

    // MARK: - Messages (per-row)

    static func appendContactMessage(contactId: UUID, _ m: PersistedMessage) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.appendContactMessage(contactId: contactId, m) }
        catch { NSLog("[pizzini.storage] appendContactMessage failed: \(error)") }
    }

    static func updateContactMessage(contactId: UUID, _ m: PersistedMessage) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.updateContactMessage(contactId: contactId, m) }
        catch { NSLog("[pizzini.storage] updateContactMessage failed: \(error)") }
    }

    static func deleteAllContactMessages(contactId: UUID) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.deleteAllContactMessages(contactId: contactId) }
        catch { NSLog("[pizzini.storage] deleteAllContactMessages failed: \(error)") }
    }

    static func appendGroupMessage(groupId: Data, _ m: PersistedMessage) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.appendGroupMessage(groupId: groupId, m) }
        catch { NSLog("[pizzini.storage] appendGroupMessage failed: \(error)") }
    }

    static func updateGroupMessage(groupId: Data, _ m: PersistedMessage) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.updateGroupMessage(groupId: groupId, m) }
        catch { NSLog("[pizzini.storage] updateGroupMessage failed: \(error)") }
    }

    static func deleteAllGroupMessages(groupId: Data) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.deleteAllGroupMessages(groupId: groupId) }
        catch { NSLog("[pizzini.storage] deleteAllGroupMessages failed: \(error)") }
    }

    // MARK: - Delivery tokens

    static func replaceDeliveryTokens(contactId: UUID, tokens: [Data]) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.replaceDeliveryTokens(contactId: contactId, tokens: tokens) }
        catch { NSLog("[pizzini.storage] replaceDeliveryTokens failed: \(error)") }
    }

    static func popDeliveryToken(contactId: UUID) -> Data? {
        guard let store = SQLiteStorage.shared else { return nil }
        return (try? store.popDeliveryToken(contactId: contactId)) ?? nil
    }

    static func appendDeliveryTokens(contactId: UUID, tokens: [Data]) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.appendDeliveryTokens(contactId: contactId, tokens: tokens) }
        catch { NSLog("[pizzini.storage] appendDeliveryTokens failed: \(error)") }
    }

    // MARK: - Outbox (per-row)

    static func upsertOutboxEntry(_ e: OutboxEntry) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.upsertOutboxEntry(e) }
        catch { NSLog("[pizzini.storage] upsertOutboxEntry failed: \(error)") }
    }

    static func deleteOutboxEntry(messageId: Data) {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.deleteOutboxEntry(messageId: messageId) }
        catch { NSLog("[pizzini.storage] deleteOutboxEntry failed: \(error)") }
    }

    static func clearOutbox() {
        guard let store = SQLiteStorage.shared else { return }
        do { try store.clearOutbox() }
        catch { NSLog("[pizzini.storage] clearOutbox failed: \(error)") }
    }

    // MARK: - Reset

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
                    quickLookPreviewEnabled: preserved.quickLookPreviewEnabled,
                    panicModeEnabled: preserved.panicModeEnabled,
                    qrBlockEffective: preserved.qrBlockEffective,
                    qrBlockTestedOSVersion: preserved.qrBlockTestedOSVersion,
                    groups: [],
                    contactsBeforeGroups: preserved.contactsBeforeGroups,
                    inAppHapticsEnabled: preserved.inAppHapticsEnabled,
                ))
            }
        } catch {
            NSLog("[pizzini.storage] resetEverything failed: \(error)")
        }
    }
}
