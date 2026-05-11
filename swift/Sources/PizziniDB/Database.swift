// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Thin SQLCipher wrapper for Pizzini. Three goals, in order:
//
//   1. No new third-party Swift dependencies. Talks to the vendored
//      SQLCipher amalgamation in `PizziniSQLCipher` via the same
//      `sqlite3_*` C ABI used by every other SQLite consumer on the
//      planet. The wrapper layer is intentionally thin so the audit
//      surface stays small.
//   2. Production discipline. Connections are opened with
//      `sqlite3_key_v2(raw_key, 32)` — we bypass SQLCipher's
//      built-in PBKDF2 because the key is already stretched by
//      Argon2id upstream of this layer. WAL + FULL fsync + foreign
//      keys + cipher_memory_security ON are set on every connection.
//   3. No accidental misuse. Statements are reset and finalized on
//      deinit. Transactions are scoped — the closure form
//      auto-rollbacks on throw. Bind helpers refuse to compile if
//      you pass a Swift type SQLite can't store.
//
// Threading: a `Database` is `final class` and NOT `Sendable`. Callers
// own their own serialization (`@MainActor` for the iOS app's use of
// it today, an actor in a follow-up if/when DB work moves off-main).

import Foundation
import PizziniSQLCipher

public final class Database {
    /// The raw SQLite handle. Never crosses the FFI boundary as
    /// anything other than an `OpaquePointer` — `sqlite3` is opaque
    /// in the upstream header and we keep it that way.
    @usableFromInline let handle: OpaquePointer

    /// Open an existing encrypted database, or create one at `path`
    /// and key it with `rawKey` (32 bytes). Subsequent opens must
    /// supply the same key; SQLCipher's `sqlite3_key_v2` rejects
    /// mismatches at the first byte read.
    ///
    /// - Parameters:
    ///   - path: absolute filesystem path. Caller is responsible for
    ///     ensuring the parent directory exists and has the right
    ///     iOS file-protection class applied.
    ///   - rawKey: exactly 32 bytes. Caller is responsible for
    ///     deriving it (Argon2id from a Secure-Enclave-unwrapped
    ///     seed, per the project's key-derivation design).
    public init(path: String, rawKey: Data) throws {
        precondition(rawKey.count == 32, "Database key must be 32 bytes; caller derives via Argon2id")

        var dbHandle: OpaquePointer?
        let flags: Int32 = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        let rc = sqlite3_open_v2(path, &dbHandle, flags, nil)
        guard rc == SQLITE_OK, let dbHandle else {
            if let dbHandle { sqlite3_close_v2(dbHandle) }
            throw DatabaseError.openFailed(code: rc)
        }
        self.handle = dbHandle

        // Provide the raw 32-byte key in SQLCipher's documented hex
        // "x'...'" form. SQLCipher treats a 64-character hex string
        // bracketed by `x'…'` as a raw cipher key and bypasses its
        // internal PBKDF2 derivation entirely — exactly what we want
        // since the key is already stretched upstream by Argon2id
        // with production parameters. The alternative
        // (`sqlite3_key_v2` raw bytes + `PRAGMA cipher_default_kdf_iter = 0`)
        // is documented but fragile in practice — the pragma
        // doesn't always interact correctly with WAL on iOS sim;
        // the hex form is the canonical fast-path.
        let hexKey = rawKey.map { String(format: "%02x", $0) }.joined()
        // Single-quote escaping is not needed for a hex string,
        // but quote the whole literal so the value parses inside
        // `sqlite3_exec`. The pragma is run, not bound — there's
        // no way to parameterise PRAGMA in SQLite, hence the
        // string-build. The hex string is pure ASCII derived from
        // a Data we control, so there's no injection surface.
        try execute("PRAGMA key = \"x'\(hexKey)'\";")

        // PRAGMAs in order: cipher hardening first, then app-side
        // durability + integrity. Memory security on first so the
        // page cache is wiped after use; foreign_keys before any
        // table creation so the cascade rules in the schema take
        // effect; journal_mode=WAL pairs with synchronous=FULL for
        // crash-safe writes on every commit (we persist the libsignal
        // ratchet state on every encrypt/decrypt, so a torn write
        // here would silently lose session continuity).
        let opening: [(String, String)] = [
            ("cipher_memory_security", "ON"),
            ("foreign_keys", "ON"),
            ("journal_mode", "WAL"),
            ("synchronous", "FULL"),
            ("busy_timeout", "5000"),
        ]
        for (name, value) in opening {
            try execute("PRAGMA \(name) = \(value);")
        }

        // Smoke-test the key by reading something that requires
        // page decryption to succeed. `sqlite3_open_v2` is lazy —
        // a wrong key only surfaces on the first read. We force
        // that read here so the constructor either succeeds with
        // a known-good key or throws immediately.
        let smoke = try prepare("SELECT count(*) FROM sqlite_master;")
        guard try smoke.step() else {
            throw DatabaseError.keyingFailed(code: SQLITE_NOTADB)
        }
    }

    deinit {
        sqlite3_close_v2(handle)
    }

    /// Run a single statement with no parameters and no result
    /// iteration. Used for DDL, PRAGMA, and one-shot DML. Throws
    /// `DatabaseError.executeFailed` carrying the SQLite error
    /// message on any non-OK return.
    public func execute(_ sql: String) throws {
        var errMsg: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(handle, sql, nil, nil, &errMsg)
        if rc != SQLITE_OK {
            let message = errMsg.flatMap { String(cString: $0) } ?? "unknown"
            if let errMsg { sqlite3_free(errMsg) }
            throw DatabaseError.executeFailed(code: rc, sql: sql, message: message)
        }
    }

    /// Compile `sql` into a reusable prepared statement. The
    /// caller-side lifecycle is straightforward: bind, step (or
    /// `run`), and let ARC finalize. Holding onto a `Statement` for
    /// repeated execution is the right pattern when the same shape
    /// fires many times in a loop (e.g. row-by-row migration insert).
    public func prepare(_ sql: String) throws -> Statement {
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v3(handle, sql, -1, UInt32(SQLITE_PREPARE_PERSISTENT), &stmt, nil)
        guard rc == SQLITE_OK, let stmt else {
            if let stmt { sqlite3_finalize(stmt) }
            throw DatabaseError.prepareFailed(
                code: rc,
                sql: sql,
                message: String(cString: sqlite3_errmsg(handle)),
            )
        }
        return Statement(stmt: stmt)
    }

    /// Run `body` inside a `BEGIN IMMEDIATE` … `COMMIT` /
    /// `ROLLBACK` envelope. Any throw rolls back; a normal return
    /// commits. `IMMEDIATE` (rather than the default `DEFERRED`)
    /// acquires the reserved lock up front, so two callers racing
    /// for the writer fail-fast at `BEGIN` time rather than at
    /// the first write — matters for the migration path where we
    /// want a hard guarantee that nothing else is writing.
    @discardableResult
    public func transaction<T>(_ body: (Database) throws -> T) throws -> T {
        try execute("BEGIN IMMEDIATE;")
        do {
            let result = try body(self)
            try execute("COMMIT;")
            return result
        } catch {
            // Best-effort rollback — if this fails (e.g. SQLite is
            // already in autocommit because the connection died),
            // we still want to surface the original error rather
            // than this secondary one.
            try? execute("ROLLBACK;")
            throw error
        }
    }

    /// Last `INSERT` rowid for the current connection. Wraps
    /// `sqlite3_last_insert_rowid`. Use immediately after the insert
    /// statement returns DONE; SQLCipher serializes within a
    /// connection so a subsequent insert on the same connection
    /// overwrites this value.
    public var lastInsertRowid: Int64 {
        sqlite3_last_insert_rowid(handle)
    }

    /// Rows modified by the most recent `INSERT` / `UPDATE` /
    /// `DELETE` on this connection.
    public var changes: Int {
        Int(sqlite3_changes(handle))
    }
}

/// Errors surfaced across the SQLCipher boundary. The `code` is the
/// SQLite primary result code (e.g. `SQLITE_NOTADB`, `SQLITE_BUSY`)
/// so call sites can switch on it. `message` is the human-readable
/// detail from `sqlite3_errmsg` where available.
public enum DatabaseError: Error, Sendable, Equatable {
    case openFailed(code: Int32)
    case keyingFailed(code: Int32)
    case executeFailed(code: Int32, sql: String, message: String)
    case prepareFailed(code: Int32, sql: String, message: String)
    case stepFailed(code: Int32, message: String)
    case bindFailed(code: Int32, parameterIndex: Int32)
    case typeMismatch(column: Int32, expected: String)
}
