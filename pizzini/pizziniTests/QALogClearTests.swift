import Testing
import Foundation
@testable import pizzini

@Suite("QA log clear-on-wipe (F-DUR-01)")
struct QALogClearTests {
    // The DEBUG qa.log accumulates peer-id prefixes + event lines. The duress
    // wipe calls `QALog.clear()` as its final step so no pre-wipe peer graph
    // survives on tester builds. This pins the clear() mechanism: it removes
    // both the active and rotated log files deterministically.
    @Test("clear() removes the active qa.log file")
    func clearRemovesActiveLog() throws {
        // `currentLogFileURL()` resolves (and creates) the qa-debug dir and
        // returns the active log path; nil only on a release build (tests run
        // DEBUG).
        guard let url = QALog.currentLogFileURL() else {
            Issue.record("expected a DEBUG qa-log URL")
            return
        }
        // Deterministically create the file (record() is async; this avoids a
        // queue race) with sentinel content standing in for peer-id lines.
        FileManager.default.createFile(
            atPath: url.path,
            contents: Data("F-DUR-01 sentinel peer-id line\n".utf8)
        )
        #expect(FileManager.default.fileExists(atPath: url.path))

        QALog.clear()
        #expect(
            !FileManager.default.fileExists(atPath: url.path),
            "clear() must remove the qa.log so no pre-wipe content survives"
        )
    }
}
