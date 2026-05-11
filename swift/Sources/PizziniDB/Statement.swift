// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Prepared-statement wrapper. The contract is intentionally narrow:
//   `bind` (variadic for the common case), then either `run` (for
//   write paths that don't iterate rows) or `query` / `step` (for
//   read paths). `reset` returns the statement to its initial state
//   so the same prepared form can be reused across many bindings —
//   the standard SQLite throughput pattern.

import Foundation
import PizziniSQLCipher

public final class Statement {
    @usableFromInline let stmt: OpaquePointer

    init(stmt: OpaquePointer) {
        self.stmt = stmt
    }

    deinit {
        sqlite3_finalize(stmt)
    }

    // MARK: - Lifecycle

    /// Reset the statement to its initial state. Call between
    /// successive runs of the same prepared statement; does NOT
    /// clear bindings (use `clearBindings()` for that — usually
    /// unnecessary since the next bind overwrites).
    @discardableResult
    public func reset() throws -> Self {
        let rc = sqlite3_reset(stmt)
        guard rc == SQLITE_OK else {
            throw DatabaseError.stepFailed(
                code: rc,
                message: String(cString: sqlite3_errmsg(sqlite3_db_handle(stmt))),
            )
        }
        return self
    }

    /// Drop all bound values. Rarely needed — successive `bind`
    /// calls overwrite — but available for completeness.
    public func clearBindings() {
        sqlite3_clear_bindings(stmt)
    }

    /// Step the statement. Returns `true` when a row is ready
    /// (caller should read columns then call `step()` again),
    /// `false` when the statement has finished executing.
    @discardableResult
    public func step() throws -> Bool {
        let rc = sqlite3_step(stmt)
        switch rc {
        case SQLITE_ROW: return true
        case SQLITE_DONE: return false
        default:
            throw DatabaseError.stepFailed(
                code: rc,
                message: String(cString: sqlite3_errmsg(sqlite3_db_handle(stmt))),
            )
        }
    }

    // MARK: - Bindings

    /// Bind a single value at 1-based parameter index `index`.
    @discardableResult
    public func bind(_ value: SQLBindable?, at index: Int32) throws -> Self {
        let rc: Int32
        if let value {
            rc = value.bind(to: stmt, at: index)
        } else {
            rc = sqlite3_bind_null(stmt, index)
        }
        guard rc == SQLITE_OK else {
            throw DatabaseError.bindFailed(code: rc, parameterIndex: index)
        }
        return self
    }

    /// Generic optional overload. Swift doesn't implicitly coerce
    /// `T?` to `P?` even when `T: P`, so `bind(c.lastMessageAt, at: 1)`
    /// where `lastMessageAt: Date?` wouldn't otherwise match the
    /// `SQLBindable?` parameter type. This overload accepts any
    /// `T: SQLBindable` and unwraps the optional before dispatching.
    @discardableResult
    public func bind<T: SQLBindable>(_ value: T?, at index: Int32) throws -> Self {
        try bind(value as SQLBindable?, at: index)
    }

    /// Variadic helper: bind all parameters in order, starting at
    /// index 1. Use for inline single-shot inserts where the
    /// parameter count is small and obvious from the SQL.
    @discardableResult
    public func bindAll(_ values: SQLBindable?...) throws -> Self {
        for (i, v) in values.enumerated() {
            try bind(v, at: Int32(i + 1))
        }
        return self
    }

    /// Run a write statement (INSERT / UPDATE / DELETE) — step
    /// once, expect DONE, reset for the next call. Throws if any
    /// row would actually be returned by this SQL (caller bug
    /// — they should be using `query` / `step` instead).
    public func run() throws {
        let produced = try step()
        if produced {
            throw DatabaseError.stepFailed(
                code: SQLITE_MISUSE,
                message: "Statement.run() invoked on SQL that produced rows; use step()/query()",
            )
        }
        try reset()
    }

    // MARK: - Column reads (called after step()==true)

    public func columnInt64(_ index: Int32) -> Int64 {
        sqlite3_column_int64(stmt, index)
    }

    public func columnInt(_ index: Int32) -> Int {
        Int(sqlite3_column_int64(stmt, index))
    }

    public func columnDouble(_ index: Int32) -> Double {
        sqlite3_column_double(stmt, index)
    }

    public func columnText(_ index: Int32) -> String? {
        guard let cstr = sqlite3_column_text(stmt, index) else { return nil }
        return String(cString: cstr)
    }

    public func columnBlob(_ index: Int32) -> Data? {
        guard let ptr = sqlite3_column_blob(stmt, index) else {
            // SQLite returns NULL pointer for both real NULL and
            // empty blobs. Disambiguate via the value type — a
            // 0-byte blob is legitimate (e.g. group's empty
            // `last_op_digest` on a not-yet-Create'd row).
            if sqlite3_column_type(stmt, index) == SQLITE_BLOB {
                return Data()
            }
            return nil
        }
        let len = Int(sqlite3_column_bytes(stmt, index))
        return Data(bytes: ptr, count: len)
    }

    /// True iff the column at `index` is SQL NULL on the current
    /// row. Useful for nullable INTEGER columns where 0 is a real
    /// value (e.g. `delivered_at` — 0 unix epoch would still be
    /// "delivered", we need NULL = "not delivered").
    public func columnIsNull(_ index: Int32) -> Bool {
        sqlite3_column_type(stmt, index) == SQLITE_NULL
    }

    public func columnOptionalInt64(_ index: Int32) -> Int64? {
        columnIsNull(index) ? nil : columnInt64(index)
    }

    public func columnBool(_ index: Int32) -> Bool {
        columnInt64(index) != 0
    }
}

/// Types Swift can bind into a SQLite parameter slot. Conforming
/// types do the `sqlite3_bind_*` call. Using a protocol (rather
/// than an `Any`-typed overload) means the compiler refuses
/// to compile a bind of, say, a `URL` — call sites must convert
/// to a supported type at the boundary.
public protocol SQLBindable {
    /// Called by `Statement.bind`. Implementations call exactly
    /// one of the `sqlite3_bind_*` family and return its result
    /// code; the caller translates non-OK into `DatabaseError`.
    func bind(to stmt: OpaquePointer, at index: Int32) -> Int32
}

extension Int: SQLBindable {
    public func bind(to stmt: OpaquePointer, at index: Int32) -> Int32 {
        sqlite3_bind_int64(stmt, index, Int64(self))
    }
}
extension Int32: SQLBindable {
    public func bind(to stmt: OpaquePointer, at index: Int32) -> Int32 {
        sqlite3_bind_int(stmt, index, self)
    }
}
extension Int64: SQLBindable {
    public func bind(to stmt: OpaquePointer, at index: Int32) -> Int32 {
        sqlite3_bind_int64(stmt, index, self)
    }
}
extension UInt32: SQLBindable {
    public func bind(to stmt: OpaquePointer, at index: Int32) -> Int32 {
        sqlite3_bind_int64(stmt, index, Int64(self))
    }
}
extension UInt64: SQLBindable {
    public func bind(to stmt: OpaquePointer, at index: Int32) -> Int32 {
        // UInt64 → Int64 bit-pattern preserves the bytes — SQLite
        // stores them as a signed 64-bit integer but readers
        // (`columnInt64`) can reinterpret. Callers that need a
        // true u64 round-trip should convert explicitly.
        sqlite3_bind_int64(stmt, index, Int64(bitPattern: self))
    }
}
extension Bool: SQLBindable {
    public func bind(to stmt: OpaquePointer, at index: Int32) -> Int32 {
        sqlite3_bind_int(stmt, index, self ? 1 : 0)
    }
}
extension Double: SQLBindable {
    public func bind(to stmt: OpaquePointer, at index: Int32) -> Int32 {
        sqlite3_bind_double(stmt, index, self)
    }
}
extension String: SQLBindable {
    public func bind(to stmt: OpaquePointer, at index: Int32) -> Int32 {
        // `SQLITE_TRANSIENT` tells SQLite to make its own copy of
        // the string bytes — necessary because Swift's bridged
        // C-string pointer is only valid for the duration of this
        // call. Without it, SQLite would later read freed memory.
        sqlite3_bind_text(stmt, index, self, -1, SQLITE_TRANSIENT)
    }
}
extension Data: SQLBindable {
    public func bind(to stmt: OpaquePointer, at index: Int32) -> Int32 {
        // Empty-blob case: `sqlite3_bind_blob` with a NULL pointer
        // and zero length stores a real empty BLOB (column type
        // SQLITE_BLOB, length 0), which is what we want for the
        // group's pre-Create `last_op_digest` row. A `sqlite3_bind_null`
        // here would store SQL NULL instead and confuse the schema's
        // NOT NULL guard.
        if isEmpty {
            return sqlite3_bind_zeroblob(stmt, index, 0)
        }
        return withUnsafeBytes { ptr -> Int32 in
            sqlite3_bind_blob(stmt, index, ptr.baseAddress, Int32(count), SQLITE_TRANSIENT)
        }
    }
}
extension Date: SQLBindable {
    /// Stored as unix-epoch *milliseconds* (Int64) so we don't lose
    /// the fractional second precision that
    /// `Date.timeIntervalSince1970` carries. Reading back is the
    /// inverse — `Date(timeIntervalSince1970: Double(ms) / 1000)`.
    /// Sub-millisecond precision is dropped on the round-trip; the
    /// app's timestamps are already at 1 ms granularity (UI clocks,
    /// system clocks) so this is a true no-op for our use cases.
    public func bind(to stmt: OpaquePointer, at index: Int32) -> Int32 {
        let ms = Int64((timeIntervalSince1970 * 1000).rounded())
        return sqlite3_bind_int64(stmt, index, ms)
    }
}

/// `SQLITE_TRANSIENT` is exposed in the C header as
/// `((sqlite3_destructor_type)-1)`, which doesn't survive the C →
/// Swift import as a constant. Materialise it once at module load.
@usableFromInline let SQLITE_TRANSIENT = unsafeBitCast(
    OpaquePointer(bitPattern: -1)!,
    to: sqlite3_destructor_type.self,
)
