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
    static let currentVersion: Int32 = 5

    /// All migrations, ordered. Index `i` is `from version i`.
    /// Migration 0 → 1 is the initial schema; subsequent entries
    /// run in order without ever skipping. Never edit a published
    /// migration; always append.
    static let migrations: [Migration] = [
        Migration(from: 0, to: 1, sql: v1InitialSchema),
        Migration(from: 1, to: 2, sql: v2ContactProvenanceAndVerification),
        Migration(from: 2, to: 3, sql: v3ReadReceiptsModeAndDefault),
        Migration(from: 3, to: 4, sql: v4MuteAndBlockList),
        Migration(from: 4, to: 5, sql: v5HashChainOutboundToken),
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
        id                          INTEGER PRIMARY KEY CHECK(id = 1),
        relay_host                  TEXT    NOT NULL,
        onboarding_completed        INTEGER NOT NULL,
        biometric_lock_enabled      INTEGER NOT NULL,
        auto_lock_timeout           TEXT    NOT NULL,
        quicklook_preview_enabled   INTEGER NOT NULL,
        panic_mode_enabled          INTEGER NOT NULL,
        qr_block_effective          INTEGER,
        qr_block_tested_os_version  TEXT,
        contacts_before_groups      INTEGER NOT NULL,
        in_app_haptics_enabled      INTEGER NOT NULL
    ) STRICT;

    -- 3. device_store: opaque libsignal session blob (identity +
    --    prekeys + per-peer ratchet sessions). Libsignal owns its
    --    internal serialization layout; we treat this as one blob.
    CREATE TABLE device_store (
        id         INTEGER PRIMARY KEY CHECK(id = 1),
        blob       BLOB    NOT NULL,
        updated_at INTEGER NOT NULL
    ) STRICT;

    -- 4. contacts
    CREATE TABLE contacts (
        id                              BLOB    PRIMARY KEY NOT NULL,
        identity_pub                    BLOB    UNIQUE NOT NULL,
        display_name                    TEXT    NOT NULL,
        session_established             INTEGER NOT NULL,
        last_message_at                 INTEGER,
        last_seen_at                    INTEGER,
        added_at                        INTEGER NOT NULL,
        last_refill_request_sent_at     INTEGER,
        last_refill_request_handled_at  INTEGER,
        ttl_seconds                     INTEGER NOT NULL,
        read_receipts_enabled           INTEGER NOT NULL,
        peer_verify_key                 BLOB,
        last_bundle_served_at           INTEGER
    ) STRICT;
    CREATE INDEX idx_contacts_identity ON contacts(identity_pub);

    -- 5. delivery_tokens: FIFO queue per contact. position is
    --    monotonic — pop = MIN(position), refill appends.
    CREATE TABLE delivery_tokens (
        contact_id BLOB    NOT NULL,
        position   INTEGER NOT NULL,
        token      BLOB    NOT NULL,
        PRIMARY KEY (contact_id, position),
        FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
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

    /// v2 — Pizzini safety-number verification.
    ///
    /// Two new contact columns track the provenance of the identity
    /// and whether the user has compared the symmetric 60-digit
    /// safety number with the peer out-of-band:
    ///
    ///   * `added_via` — how the row entered the contact list. One of
    ///     'qr_scan' (camera scanned the QR in person), 'pasted_text'
    ///     (URL pasted from clipboard, no guarantee about the channel
    ///     that carried it), or 'unknown' (pre-v2 row whose provenance
    ///     was not recorded). The column is `NOT NULL` so future code
    ///     never has to handle a three-valued logic on this axis.
    ///     Existing rows backfill to 'qr_scan' because v1 only ever
    ///     materialised contacts through the in-person QR scanner —
    ///     marking them 'unknown' would falsely downgrade users who
    ///     had verified in person before the verification UI shipped.
    ///
    ///   * `verified_at` — wall-clock epoch (ms) when the user clicked
    ///     "matches" on the safety-number screen. NULL means
    ///     unverified. Setting / unsetting this is the only authority
    ///     on the green-checkmark badge across the app.
    ///
    /// Both columns are independent: a `pasted_text` row CAN reach
    /// `verified_at != NULL` (and is then full-trust); a `qr_scan` row
    /// stays "scanned but not SAS-verified" until the user does the
    /// out-of-band comparison.
    private static let v2ContactProvenanceAndVerification = """
    ALTER TABLE contacts ADD COLUMN added_via TEXT NOT NULL DEFAULT 'qr_scan';
    ALTER TABLE contacts ADD COLUMN verified_at INTEGER;
    """

    /// v3 — three-state per-contact read-receipts override + a global
    /// default at the settings level.
    ///
    /// `read_receipts_mode` is a string enum that mirrors
    /// `ReadReceiptsMode` in Models.swift:
    ///   * 'follow_default' — use settings.default_read_receipts_enabled.
    ///   * 'always_on'      — per-chat opt-in.
    ///   * 'always_off'     — per-chat opt-out.
    /// Default value is computed from the legacy per-contact bool:
    ///   * `read_receipts_enabled = 1` → `always_on` so the user's
    ///     explicit opt-in is preserved across the migration.
    ///   * `read_receipts_enabled = 0` → `always_off` so a user who
    ///     had explicitly turned receipts OFF for a chat cannot have
    ///     them silently re-enabled the moment the new global default
    ///     gets toggled on. `follow_default` would have been a privacy
    ///     regression for this case.
    ///
    /// Legacy `read_receipts_enabled` column is left in place rather
    /// than dropped (SQLite < 3.35 has no `DROP COLUMN`; running on
    /// SQLCipher we vendor the older version conservatively). The
    /// legacy column is `NOT NULL` with no default value, so
    /// `SQLiteStorage.upsertContact` still binds it (derived from the
    /// mode) at INSERT time; new code never reads it.
    private static let v3ReadReceiptsModeAndDefault = """
    ALTER TABLE contacts  ADD COLUMN read_receipts_mode TEXT NOT NULL DEFAULT 'follow_default';
    UPDATE contacts SET read_receipts_mode = 'always_on'  WHERE read_receipts_enabled = 1;
    UPDATE contacts SET read_receipts_mode = 'always_off' WHERE read_receipts_enabled = 0;
    ALTER TABLE settings  ADD COLUMN default_read_receipts_enabled INTEGER NOT NULL DEFAULT 0;
    """

    /// v4 — per-contact mute, app-wide notification mute, persistent
    /// block list.
    ///
    /// `contacts.muted_at` is a wall-clock epoch (ms) when the user
    /// muted this peer. NULL = unmuted. When non-NULL, inbound
    /// messages from this peer don't fire haptics or bump the NSE
    /// badge. Delivery and persistence are unchanged.
    ///
    /// `settings.notifications_muted` is the global counterpart.
    /// When 1, the NSE refuses to bump the badge at all and the
    /// in-app haptic is suppressed even on unmuted contacts. Default
    /// 0 (notifications on) so the upgrade is invisible to users who
    /// haven't asked for quiet.
    ///
    /// `blocked_identities` is a denylist keyed on the 33-byte
    /// libsignal IdentityKey wire form. It survives `deleteContact`
    /// → re-add cycles: even after the contact row is gone, an
    /// inbound BUNDLE_RESPONSE / TOKEN_ISSUE / SEND from a blocked
    /// identityPub is dropped at the receive-side gate. Block is
    /// strictly stronger than delete — delete is "I don't want this
    /// in my list right now," block is "I don't want this person to
    /// reach me again." Distinct table rather than a column on
    /// `contacts` because the block list outlives any specific
    /// contact row.
    private static let v4MuteAndBlockList = """
    ALTER TABLE contacts ADD COLUMN muted_at INTEGER;
    ALTER TABLE settings ADD COLUMN notifications_muted INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE blocked_identities (
        identity_pub BLOB    PRIMARY KEY NOT NULL,
        blocked_at   INTEGER NOT NULL
    ) STRICT;
    """

    /// v5 — delivery-token v2 outbound chain. Nullable 88-byte BLOB
    /// column on `contacts` holding `HashChainToken.encodeChain`
    /// output. Nil for pre-v2 contacts; populated once the peer ships
    /// a `chainSeedDelivery` sealed envelope.
    private static let v5HashChainOutboundToken = """
    ALTER TABLE contacts ADD COLUMN outbound_token_chain BLOB;
    """
}

struct Migration {
    let from: Int32
    let to: Int32
    let sql: String
}

enum Migrator {
    /// Apply every migration whose `from` version is `≥` the db's
    /// current `PRAGMA user_version`, in order, inside one
    /// transaction. The whole-or-nothing semantics means a torn
    /// schema upgrade leaves the user_version pinned at the last
    /// fully-applied step — the next launch re-runs only the
    /// missing tail.
    static func run(on db: Database, target: Int32 = Schema.currentVersion) throws {
        let current = try userVersion(of: db)
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
