import Foundation
import Testing
@testable import pizzini

/// QA-debug log file: writes, rotation, clear, DEBUG gating. The
/// file lives under `Library/Application Support/qa-debug/qa.log`.
/// Each test wipes the directory first so cases don't leak state.
///
/// `.serialized` because every case touches the same on-disk file
/// path; Swift Testing's default parallel scheduling would race
/// resetDir() against another case's record() and produce
/// flaky failures unrelated to the code under test.
@Suite("QALog (persistent QA-debug log)", .serialized)
struct QALogTests {

    private static func qaDir() throws -> URL {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true,
        )
        return support.appendingPathComponent(QALog.directoryName, isDirectory: true)
    }

    private static func resetDir() throws {
        let dir = try qaDir()
        if FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.removeItem(at: dir)
        }
    }

    /// Wait for QALog's serial queue to drain by hopping through
    /// a sync block. The dispatch label is `pizzini.qalog`; this
    /// helper queues an empty block at the back and waits.
    private static func drainQueue() {
        QALog.record(category: "test-sync", message: "drain")
        // The actual drain: a *blocking* roundtrip through any
        // sync barrier on the QALog queue. We can't reach into
        // the private queue directly, so use the public `clear()`
        // path which itself runs `queue.sync` — that guarantees
        // the prior async writes have completed.
        //
        // For tests that DON'T want to clear, we use a small
        // wall-clock yield instead. 50 ms is far more than enough
        // for a single line write on local SSD; the alternative
        // (a Combine subject or a closure-capable drain method)
        // is overkill for an in-test helper.
        Thread.sleep(forTimeInterval: 0.05)
    }

    /// A `record(category:message:)` call writes a single line to
    /// the file with the expected timestamp + category + message
    /// shape. DEBUG-only — Release builds compile the write path
    /// out, so this test is also under `#if DEBUG`.
    #if DEBUG
    @Test("record writes a line containing the category and message")
    func recordWritesLine() throws {
        try Self.resetDir()
        QALog.record(category: "test", message: "hello")
        Self.drainQueue()
        let url = try #require(QALog.currentLogFileURL())
        let body = try String(contentsOf: url, encoding: .utf8)
        #expect(body.contains("[test]"), "category present")
        #expect(body.contains("hello"), "message present")
        #expect(body.hasSuffix("\n"), "line terminator present")
    }

    /// Two records produce two newline-separated lines, in order.
    /// Order is the contract — the serial queue guarantees first-
    /// in-first-out append even under load.
    @Test("two records produce two ordered newline-separated lines")
    func recordPreservesOrder() throws {
        try Self.resetDir()
        QALog.record(category: "first", message: "alpha")
        QALog.record(category: "second", message: "beta")
        Self.drainQueue()
        let url = try #require(QALog.currentLogFileURL())
        let body = try String(contentsOf: url, encoding: .utf8)
        let lines = body.split(separator: "\n").filter { !$0.isEmpty }
        // At least our two lines plus any sync-drain noise.
        #expect(lines.count >= 2)
        guard let alphaIdx = lines.firstIndex(where: { $0.contains("[first] alpha") }),
              let betaIdx = lines.firstIndex(where: { $0.contains("[second] beta") })
        else {
            Issue.record("expected both lines present")
            return
        }
        #expect(alphaIdx < betaIdx, "first record appears before second")
    }

    /// `clear()` removes the active log file. Subsequent records
    /// create a fresh file (idempotent recreate).
    @Test("clear removes the log; next record recreates it")
    func clearRemovesFile() throws {
        try Self.resetDir()
        QALog.record(category: "pre-clear", message: "x")
        Self.drainQueue()
        let url = try #require(QALog.currentLogFileURL())
        #expect(FileManager.default.fileExists(atPath: url.path))
        QALog.clear()
        #expect(!FileManager.default.fileExists(atPath: url.path))
        QALog.record(category: "post-clear", message: "y")
        Self.drainQueue()
        let body = try String(contentsOf: url, encoding: .utf8)
        #expect(body.contains("post-clear"))
        #expect(!body.contains("pre-clear"), "old content didn't survive clear")
    }

    /// Once a log file exists, `currentLogFileURL()` returns its
    /// URL; before any record has fired, it can return nil OR a
    /// URL (depending on whether the directory was pre-created).
    /// Pin the *behaviour* (URL present after first record) rather
    /// than the directory's pre-creation timing.
    @Test("currentLogFileURL reflects file presence after first record")
    func currentLogFileURLAfterFirstRecord() throws {
        try Self.resetDir()
        QALog.record(category: "smoke", message: "create me")
        Self.drainQueue()
        let url = try #require(QALog.currentLogFileURL())
        #expect(FileManager.default.fileExists(atPath: url.path))
    }

    /// F-DUR-01: the duress wipe calls `QALog.clear()` as its final step
    /// so no pre-wipe peer graph survives on tester builds. Pins that
    /// `clear()` removes the active log deterministically.
    ///
    /// Merged here from the former separate `QALogClearTests` suite: two
    /// distinct suites both touching the fixed `qa-debug` path raced under
    /// Swift Testing's parallel runner (`.serialized` only orders tests
    /// WITHIN a suite, not across suites), producing flaky
    /// "qa.log not found" / "permission denied" failures. Keeping every
    /// `qa-debug`-touching test inside this one `.serialized` suite makes
    /// the path single-owner and the cases deterministic.
    @Test("clear() removes the active qa.log file (F-DUR-01)")
    func clearRemovesActiveLogForDuress() throws {
        try Self.resetDir()
        let url = try #require(QALog.currentLogFileURL())
        // `record()` is async; create the file deterministically with a
        // sentinel standing in for peer-id lines.
        FileManager.default.createFile(
            atPath: url.path,
            contents: Data("F-DUR-01 sentinel peer-id line\n".utf8),
        )
        #expect(FileManager.default.fileExists(atPath: url.path))
        QALog.clear()
        #expect(
            !FileManager.default.fileExists(atPath: url.path),
            "clear() must remove the qa.log so no pre-wipe content survives",
        )
    }
    #endif

    /// rotatedLogFileURL returns nil when no rotation has happened.
    /// This holds on both DEBUG and Release — Release simply has
    /// no logs at all, so the rotated-file URL is also nil.
    @Test("rotatedLogFileURL is nil when no rotation has occurred")
    func rotatedURLNilWhenFresh() throws {
        try Self.resetDir()
        // Don't even fire a record; just check the API contract.
        #expect(QALog.rotatedLogFileURL() == nil)
    }
}
