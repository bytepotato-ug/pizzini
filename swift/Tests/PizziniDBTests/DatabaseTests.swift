// SPDX-License-Identifier: AGPL-3.0-or-later

import Foundation
import Testing
@testable import PizziniDB

@Suite("PizziniDB — SQLCipher wrapper")
struct DatabaseTests {
    // MARK: - Open / close

    @Test("open + create + close round-trip")
    func openCreateClose() throws {
        try withTempDB(rawKey: Data(repeating: 0xAB, count: 32)) { db in
            try db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT NOT NULL);")
            try db.execute("INSERT INTO t (id, name) VALUES (1, 'pizzini');")
            let s = try db.prepare("SELECT count(*) FROM t;")
            #expect(try s.step() == true)
            #expect(s.columnInt64(0) == 1)
        }
    }

    @Test("data persists across reopen with the same key")
    func persistsAcrossReopen() throws {
        let path = NSTemporaryDirectory() + "pizzini-test-\(UUID()).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let key = Data(repeating: 0x42, count: 32)

        do {
            let db = try Database(path: path, rawKey: key)
            try db.execute("CREATE TABLE notes (n TEXT NOT NULL);")
            let ins = try db.prepare("INSERT INTO notes (n) VALUES (?);")
            try ins.bindAll("alpha").run()
            try ins.bindAll("beta").run()
        }
        do {
            let db = try Database(path: path, rawKey: key)
            let q = try db.prepare("SELECT n FROM notes ORDER BY rowid;")
            var rows: [String] = []
            while try q.step() {
                rows.append(q.columnText(0) ?? "<null>")
            }
            #expect(rows == ["alpha", "beta"])
        }
    }

    @Test("USP #8: rekey rotates the encryption key + previous key fails afterwards")
    func rekeyRotatesKey() throws {
        let path = NSTemporaryDirectory() + "pizzini-test-\(UUID()).db"
        defer {
            try? FileManager.default.removeItem(atPath: path)
            try? FileManager.default.removeItem(atPath: path + "-wal")
            try? FileManager.default.removeItem(atPath: path + "-shm")
        }
        let oldKey = Data(repeating: 0x11, count: 32)
        let newKey = Data(repeating: 0x22, count: 32)

        do {
            let db = try Database(path: path, rawKey: oldKey)
            try db.execute("CREATE TABLE secrets (s TEXT NOT NULL);")
            try db.prepare("INSERT INTO secrets (s) VALUES (?);").bindAll("classified").run()
            // Rotate to the new key + vacuum to purge orphaned
            // pages (matches the production rotation flow in
            // DBKey.rotateKeyMaterial).
            try db.rekey(newRawKey: newKey)
            try db.execute("VACUUM;")
        }

        // New key opens successfully + reads the row back.
        do {
            let db = try Database(path: path, rawKey: newKey)
            let q = try db.prepare("SELECT s FROM secrets;")
            #expect(try q.step())
            #expect(q.columnText(0) == "classified")
        }

        // Old key is now useless. SQLCipher refuses to decrypt;
        // the constructor's smoke-read throws keyingFailed.
        #expect(throws: DatabaseError.self) {
            _ = try Database(path: path, rawKey: oldKey)
        }
    }

    @Test("wrong key on reopen throws keyingFailed")
    func wrongKeyRejected() throws {
        let path = NSTemporaryDirectory() + "pizzini-test-\(UUID()).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let good = Data(repeating: 0xAA, count: 32)
        let bad = Data(repeating: 0xBB, count: 32)

        do {
            let db = try Database(path: path, rawKey: good)
            try db.execute("CREATE TABLE t (x INTEGER);")
            try db.execute("INSERT INTO t (x) VALUES (1);")
            _ = db
        }
        // Reopen with wrong key. SQLCipher returns SQLITE_NOTADB on
        // the first decryption attempt — we surface that as a
        // keyingFailed throw in the smoke-test path inside init.
        #expect(throws: DatabaseError.self) {
            _ = try Database(path: path, rawKey: bad)
        }
    }

    // MARK: - Bindings

    @Test("all SQLBindable types round-trip")
    func bindingRoundTrip() throws {
        try withTempDB(rawKey: Data(repeating: 0x01, count: 32)) { db in
            try db.execute("""
                CREATE TABLE t (
                    a_int INTEGER NOT NULL,
                    a_int64 INTEGER NOT NULL,
                    a_double REAL NOT NULL,
                    a_bool INTEGER NOT NULL,
                    a_text TEXT NOT NULL,
                    a_blob BLOB NOT NULL,
                    a_empty_blob BLOB NOT NULL,
                    a_null_int INTEGER
                );
            """)
            let ins = try db.prepare("INSERT INTO t VALUES (?,?,?,?,?,?,?,?);")
            try ins
                .bind(Int(42), at: 1)
                .bind(Int64.max - 1, at: 2)
                .bind(3.14159, at: 3)
                .bind(true, at: 4)
                .bind("héllo", at: 5)
                .bind(Data([0xDE, 0xAD, 0xBE, 0xEF]), at: 6)
                .bind(Data(), at: 7)
                .bind(nil, at: 8)
                .run()

            let q = try db.prepare("SELECT * FROM t;")
            #expect(try q.step())
            #expect(q.columnInt(0) == 42)
            #expect(q.columnInt64(1) == Int64.max - 1)
            #expect(q.columnDouble(2) == 3.14159)
            #expect(q.columnBool(3))
            #expect(q.columnText(4) == "héllo")
            #expect(q.columnBlob(5) == Data([0xDE, 0xAD, 0xBE, 0xEF]))
            #expect(q.columnBlob(6) == Data())   // empty-blob distinguishable from NULL
            #expect(q.columnIsNull(7))
            #expect(q.columnOptionalInt64(7) == nil)
        }
    }

    @Test("Date round-trips at millisecond precision")
    func dateBinding() throws {
        try withTempDB(rawKey: Data(repeating: 0x02, count: 32)) { db in
            try db.execute("CREATE TABLE t (d INTEGER NOT NULL);")
            // 2026-05-11T10:00:00.123Z — exactly representable as
            // an Int64 unix-epoch millisecond count.
            let original = Date(timeIntervalSince1970: 1_778_580_000.123)
            try db.prepare("INSERT INTO t VALUES (?);").bindAll(original).run()
            let q = try db.prepare("SELECT d FROM t;")
            #expect(try q.step())
            let restored = Date(timeIntervalSince1970: Double(q.columnInt64(0)) / 1000.0)
            // Allow ≤ 1 ms drift from the Int64 rounding.
            #expect(abs(restored.timeIntervalSince(original)) <= 0.001)
        }
    }

    // MARK: - Transactions

    @Test("transaction commits on normal return")
    func transactionCommits() throws {
        try withTempDB(rawKey: Data(repeating: 0x03, count: 32)) { db in
            try db.execute("CREATE TABLE t (x INTEGER);")
            try db.transaction { tx in
                try tx.prepare("INSERT INTO t VALUES (?);").bindAll(1).run()
                try tx.prepare("INSERT INTO t VALUES (?);").bindAll(2).run()
            }
            let q = try db.prepare("SELECT count(*) FROM t;")
            #expect(try q.step())
            #expect(q.columnInt64(0) == 2)
        }
    }

    @Test("transaction rolls back on throw")
    func transactionRollsBack() throws {
        try withTempDB(rawKey: Data(repeating: 0x04, count: 32)) { db in
            try db.execute("CREATE TABLE t (x INTEGER);")
            struct Boom: Error {}
            do {
                try db.transaction { tx in
                    try tx.prepare("INSERT INTO t VALUES (?);").bindAll(99).run()
                    throw Boom()
                }
                Issue.record("transaction body threw but call returned")
            } catch is Boom {
                // expected
            }
            let q = try db.prepare("SELECT count(*) FROM t;")
            #expect(try q.step())
            #expect(q.columnInt64(0) == 0, "row from rolled-back tx is still in the table")
        }
    }

    // MARK: - Foreign keys

    @Test("foreign-key cascade is enforced by default PRAGMA")
    func foreignKeysEnforced() throws {
        try withTempDB(rawKey: Data(repeating: 0x05, count: 32)) { db in
            try db.execute("""
                CREATE TABLE parent (id INTEGER PRIMARY KEY);
                CREATE TABLE child  (
                    id INTEGER PRIMARY KEY,
                    parent_id INTEGER NOT NULL,
                    FOREIGN KEY (parent_id) REFERENCES parent(id) ON DELETE CASCADE
                );
            """)
            try db.execute("INSERT INTO parent (id) VALUES (1), (2);")
            try db.execute("INSERT INTO child (id, parent_id) VALUES (10, 1), (20, 2);")
            try db.execute("DELETE FROM parent WHERE id = 1;")
            let q = try db.prepare("SELECT count(*) FROM child;")
            #expect(try q.step())
            #expect(q.columnInt64(0) == 1, "ON DELETE CASCADE did not fire — PRAGMA foreign_keys not honoured")
        }
    }

    // MARK: - Helpers

    private func withTempDB(rawKey: Data, _ body: (Database) throws -> Void) throws {
        let path = NSTemporaryDirectory() + "pizzini-test-\(UUID()).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let db = try Database(path: path, rawKey: rawKey)
        try body(db)
    }
}
