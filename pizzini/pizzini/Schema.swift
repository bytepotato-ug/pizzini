import Foundation
import PizziniDB

/// SQLCipher schema for Pizzini's persistent state. Eleven tables —
/// see `docs/storage-architecture.md` and the sign-off recorded in
/// the README's session log for the design rationale.
///
/// Migration model: `PRAGMA user_version` records the schema version
/// that was last applied. `Migrator.run(on:)` walks every migration
/// past the recorded version in order, inside a single transaction.
/// New schema changes are appended as new entries — never edit a
/// migration after it ships, or two databases born under the same
/// version will diverge.
///
/// **Why no JSON-blob columns**: the user's "no workarounds" rule.
/// Every collection that is queried, sorted, or counted has its own
/// table. Only opaque libsignal session state and the relay's
/// SKDM-recipient set (capped at 50 × 33-byte peer ids) live as
/// inline BLOB columns — both are accessed only as a unit.
enum Schema {
    /// Current schema version — read by SQLiteStorage at open time
    /// to decide whether the migration runner needs to fire. Bump
    /// when adding a new migration; never decrease.
    static let currentVersion: Int32 = 1

    /// All migrations, ordered. Index `i` is `from version i`.
    /// Migration 0 → 1 is the initial schema; subsequent entries
    /// run in order without ever skipping. Never edit a published
    /// migration; always append.
    ///
    /// Pre-launch reset: there are no users to migrate, so the
    /// schema collapsed back to a single v1 carrying the final
    /// post-v5 shape (delivery-token v2 chain column, no legacy
    /// `delivery_tokens` table, no v1 token bookkeeping on
    /// contacts). The migration list will grow again post-launch.
    static let migrations: [Migration] = [
        Migration(from: 0, to: 1, sql: v1InitialSchema),
    ]

    private static let v1InitialSchema = """
    -- 1. meta: key/value store for schema versioning + migration
    --    markers + any future "after we open the DB, where do we
    --    record this" needs. Argon2id parameters CANNOT live here
    --    because we need them BEFORE the DB opens (they're an input
    --    to the key derivation that produces the DB key). They
    --    therefore live in Keychain — see `DBKey.loadStoredParams`,
    --    which validates the loaded params against a minimum-strength
    --    floor to defend against pre-planted weak parameters.
    CREATE TABLE meta (
        key   TEXT PRIMARY KEY NOT NULL,
        value BLOB NOT NULL
    ) STRICT;

    -- 2. settings: singleton row of UX/relay-host/lock toggles.
    --    Column-per-setting (rather than key/value) so the schema
    --    itself catches a typo like 'true'-the-string vs 1-the-bool
    --    at insert time.
    CREATE TABLE settings (
        id                              INTEGER PRIMARY KEY CHECK(id = 1),
        relay_host                      TEXT    NOT NULL,
        onboarding_completed            INTEGER NOT NULL,
        biometric_lock_enabled          INTEGER NOT NULL,
        auto_lock_timeout               TEXT    NOT NULL,
        quicklook_preview_enabled       INTEGER NOT NULL,
        panic_mode_enabled              INTEGER NOT NULL,
        qr_block_effective              INTEGER,
        qr_block_tested_os_version      TEXT,
        contacts_before_groups          INTEGER NOT NULL,
        in_app_haptics_enabled          INTEGER NOT NULL,
        default_read_receipts_enabled   INTEGER NOT NULL DEFAULT 0,
        notifications_muted             INTEGER NOT NULL DEFAULT 0
    ) STRICT;

    -- 3. device_store: opaque libsignal session blob (identity +
    --    prekeys + per-peer ratchet sessions). Libsignal owns its
    --    internal serialization layout; we treat this as one blob.
    CREATE TABLE device_store (
        id         INTEGER PRIMARY KEY CHECK(id = 1),
        blob       BLOB    NOT NULL,
        updated_at INTEGER NOT NULL
    ) STRICT;

    -- 4. contacts. Delivery-token v2: outbound chain state lives
    --    inline (88-byte BLOB) — see `HashChainToken.encodeChain`.
    --    No legacy per-token queue; the chain seed alone covers
    --    every future SEND to this peer.
    CREATE TABLE contacts (
        id                              BLOB    PRIMARY KEY NOT NULL,
        identity_pub                    BLOB    UNIQUE NOT NULL,
        display_name                    TEXT    NOT NULL,
        session_established             INTEGER NOT NULL,
        last_message_at                 INTEGER,
        last_seen_at                    INTEGER,
        added_at                        INTEGER NOT NULL,
        last_chain_served_at            INTEGER,
        ttl_seconds                     INTEGER NOT NULL,
        read_receipts_mode              TEXT    NOT NULL DEFAULT 'follow_default',
        peer_verify_key                 BLOB,
        last_bundle_served_at           INTEGER,
        added_via                       TEXT    NOT NULL DEFAULT 'qr_scan',
        verified_at                     INTEGER,
        muted_at                        INTEGER,
        outbound_token_chain            BLOB
    ) STRICT;
    CREATE INDEX idx_contacts_identity ON contacts(identity_pub);

    -- 5. blocked_identities: persistent block list keyed by
    --    identityPub. Outlives any individual contact row.
    CREATE TABLE blocked_identities (
        identity_pub BLOB    PRIMARY KEY NOT NULL,
        blocked_at   INTEGER NOT NULL
    ) STRICT;

    -- 6. groups
    CREATE TABLE groups (
        id                          BLOB    PRIMARY KEY NOT NULL,
        display_name                TEXT    NOT NULL,
        created_at                  INTEGER NOT NULL,
        current_epoch               INTEGER NOT NULL,
        last_op_digest              BLOB    NOT NULL,
        last_seen_at                INTEGER,
        last_message_at             INTEGER,
        my_current_distribution_id  BLOB,
        sent_since_rotation         INTEGER NOT NULL,
        last_rotated_at             INTEGER NOT NULL,
        my_skdm_recipients          BLOB    NOT NULL,
        pending_invitation          INTEGER NOT NULL
    ) STRICT;

    -- 7. group_members: folds in memberDistributionIds via
    --    `current_distribution_id`.
    CREATE TABLE group_members (
        group_id                 BLOB    NOT NULL,
        peer_id                  BLOB    NOT NULL,
        display_name             TEXT    NOT NULL,
        role                     TEXT    NOT NULL,
        joined_at_epoch          INTEGER NOT NULL,
        status                   TEXT    NOT NULL,
        added_by                 BLOB,
        current_distribution_id  BLOB,
        PRIMARY KEY (group_id, peer_id),
        FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
    ) STRICT;

    -- 8. group_pending_ops: per-op rows so apply/drop is one DELETE
    --    rather than a blob rewrite. Keyed by op_bytes for natural
    --    dedup if the same op arrives twice.
    CREATE TABLE group_pending_ops (
        group_id    BLOB    NOT NULL,
        received_at INTEGER NOT NULL,
        op_bytes    BLOB    NOT NULL,
        PRIMARY KEY (group_id, op_bytes),
        FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
    ) STRICT;

    -- 9. group_op_digests: sliding-window anti-equivocation cache.
    --    At 16k × 32 B per group the row count matters — separate
    --    table so insertions/evictions are single-row writes, not
    --    rewrites of a multi-KiB blob on every advance.
    CREATE TABLE group_op_digests (
        group_id BLOB    NOT NULL,
        epoch    INTEGER NOT NULL,
        digest   BLOB    NOT NULL,
        PRIMARY KEY (group_id, epoch),
        FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
    ) STRICT;

    -- 10. messages: 1:1 AND group chat rows in one table. Exactly
    --     one of (contact_id, group_id) is NOT NULL. Attachment
    --     metadata is inlined (1:1 with the row, mostly NULL).
    CREATE TABLE messages (
        id                       BLOB    PRIMARY KEY NOT NULL,
        contact_id               BLOB,
        group_id                 BLOB,
        side                     TEXT    NOT NULL,
        text                     TEXT    NOT NULL,
        kind                     TEXT    NOT NULL,
        bytes                    INTEGER NOT NULL,
        timestamp                INTEGER NOT NULL,
        message_id               BLOB,
        read_at                  INTEGER,
        sender_peer_id           BLOB,
        group_message_id         BLOB,
        attachment_id            BLOB,
        attachment_filename      TEXT,
        attachment_byte_size     INTEGER,
        attachment_mime          TEXT,
        attachment_tier          TEXT,
        attachment_sandbox_path  TEXT,
        attachment_is_inbound    INTEGER,
        CHECK ((contact_id IS NULL) != (group_id IS NULL)),
        FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
        FOREIGN KEY (group_id)   REFERENCES groups(id)   ON DELETE CASCADE
    ) STRICT;
    CREATE INDEX idx_messages_contact_ts ON messages(contact_id, timestamp)  WHERE contact_id IS NOT NULL;
    CREATE INDEX idx_messages_group_ts   ON messages(group_id,   timestamp)  WHERE group_id   IS NOT NULL;
    CREATE INDEX idx_messages_message_id ON messages(message_id)             WHERE message_id IS NOT NULL;
    CREATE INDEX idx_messages_group_msg  ON messages(group_message_id)       WHERE group_message_id IS NOT NULL;

    -- 11. outbox
    CREATE TABLE outbox (
        message_id        BLOB    PRIMARY KEY NOT NULL,
        recipient_peer_id BLOB    NOT NULL,
        sealed_ciphertext BLOB    NOT NULL,
        token             BLOB    NOT NULL,
        ttl               INTEGER NOT NULL,
        sent_at           INTEGER NOT NULL,
        retries           INTEGER NOT NULL,
        delivered_at      INTEGER,
        failed_at         INTEGER,
        relayed_at        INTEGER,
        attachment_id     BLOB,
        chunk_index       INTEGER,
        chunk_count       INTEGER,
        group_message_id  BLOB,
        read_at           INTEGER
    ) STRICT;
    CREATE INDEX idx_outbox_recipient  ON outbox(recipient_peer_id);
    CREATE INDEX idx_outbox_attachment ON outbox(attachment_id)    WHERE attachment_id    IS NOT NULL;
    CREATE INDEX idx_outbox_group      ON outbox(group_message_id) WHERE group_message_id IS NOT NULL;
    """
}

struct Migration {
    let from: Int32
    let to: Int32
    let sql: String
}

enum SchemaError: Error {
    /// On-disk `user_version` is ahead of the code's `currentVersion`.
    /// Caller should treat this as a downgrade signal — typically by
    /// wiping the database files (and any paired Keychain state) and
    /// re-bootstrapping into a fresh schema. Pre-launch this happens
    /// after a schema-collapse refactor; post-launch it would only
    /// fire on a manual app-version downgrade.
    case onDiskAheadOfCode(onDisk: Int32, code: Int32)
}

enum Migrator {
    /// Apply every migration whose `from` version is `≥` the db's
    /// current `PRAGMA user_version`, in order, inside one
    /// transaction. The whole-or-nothing semantics means a torn
    /// schema upgrade leaves the user_version pinned at the last
    /// fully-applied step — the next launch re-runs only the
    /// missing tail.
    ///
    /// Throws `SchemaError.onDiskAheadOfCode` when `user_version`
    /// exceeds `target`. The caller (bootstrap) recovers by wiping
    /// the DB and re-opening; a silent early-return would leave a
    /// stale schema that the new code's SELECTs can't read.
    static func run(on db: Database, target: Int32 = Schema.currentVersion) throws {
        let current = try userVersion(of: db)
        if current > target {
            throw SchemaError.onDiskAheadOfCode(onDisk: current, code: target)
        }
        guard current < target else { return }
        try db.transaction { tx in
            for migration in Schema.migrations where migration.from >= current && migration.to <= target {
                try tx.execute(migration.sql)
                try tx.execute("PRAGMA user_version = \(migration.to);")
            }
        }
    }

    private static func userVersion(of db: Database) throws -> Int32 {
        let stmt = try db.prepare("PRAGMA user_version;")
        guard try stmt.step() else { return 0 }
        return Int32(stmt.columnInt64(0))
    }
}
