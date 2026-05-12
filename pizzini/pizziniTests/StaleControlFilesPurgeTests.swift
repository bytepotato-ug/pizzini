import Foundation
import PizziniTor
import Testing

/// Tests for `TorController.purgeStaleControlFiles(in:)` — the
/// load-bearing cleanup that runs before each `TORThread.start()`
/// to evict a previous app process's `control_auth_cookie` /
/// `controlport` files.
///
/// The threat-model rationale is in the doc comment on the helper
/// itself. The TL;DR is: tor's `controlport` file is written
/// synchronously during early startup, but if a leftover one from
/// a prior session is still in the data dir, `waitForControlPortFile`
/// finds it instantly and the controller is built with a dead
/// port — every connect attempt then spends its full deadline
/// dialing nothing. These tests pin the cleanup contract
/// (exactly which filenames, exactly which directory, only these
/// two) so a future refactor that "tidies up" the helper can't
/// silently regress that fix.
@Suite("TorController.purgeStaleControlFiles")
struct StaleControlFilesPurgeTests {

    /// Make a fresh tmp dir and return its URL. Each test cleans
    /// up its own dir in a `defer` block to keep CI artifacts
    /// from piling up.
    private func makeTmpDir() throws -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pizzini-tor-purge-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Both files present (the classic "previous session ran") →
    /// both removed, both flags set.
    @Test func bothFilesPresentAreRemoved() throws {
        let dir = try makeTmpDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cookie = dir.appendingPathComponent("control_auth_cookie")
        let port = dir.appendingPathComponent("controlport")
        try Data("cookiebytes".utf8).write(to: cookie)
        try Data("PORT=127.0.0.1:39021".utf8).write(to: port)

        let result = TorController.purgeStaleControlFiles(in: dir)

        #expect(result.cookieRemoved)
        #expect(result.portRemoved)
        #expect(result.anyRemoved)
        #expect(!FileManager.default.fileExists(atPath: cookie.path))
        #expect(!FileManager.default.fileExists(atPath: port.path))
    }

    /// Empty data dir (first-ever launch) → no-op, both flags
    /// clear. This is the path that runs on a clean install; we
    /// want it to be silent.
    @Test func emptyDirIsNoOp() throws {
        let dir = try makeTmpDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let result = TorController.purgeStaleControlFiles(in: dir)

        #expect(!result.cookieRemoved)
        #expect(!result.portRemoved)
        #expect(!result.anyRemoved)
    }

    /// Only the cookie survived (rare: tor crashed mid-startup
    /// before writing controlport). Cookie goes; port flag stays
    /// clear.
    @Test func onlyCookiePresent() throws {
        let dir = try makeTmpDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cookie = dir.appendingPathComponent("control_auth_cookie")
        try Data("cookiebytes".utf8).write(to: cookie)

        let result = TorController.purgeStaleControlFiles(in: dir)

        #expect(result.cookieRemoved)
        #expect(!result.portRemoved)
        #expect(result.anyRemoved)
        #expect(!FileManager.default.fileExists(atPath: cookie.path))
    }

    /// Only the controlport survived (the exact shape that caused
    /// the bug — port file points at a dead port, but the cookie
    /// got cleaned up some other way). Port goes; cookie flag
    /// stays clear.
    @Test func onlyControlPortPresent() throws {
        let dir = try makeTmpDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let port = dir.appendingPathComponent("controlport")
        try Data("PORT=127.0.0.1:12345".utf8).write(to: port)

        let result = TorController.purgeStaleControlFiles(in: dir)

        #expect(!result.cookieRemoved)
        #expect(result.portRemoved)
        #expect(result.anyRemoved)
        #expect(!FileManager.default.fileExists(atPath: port.path))
    }

    /// Files with similar names BUT NOT EXACT matches must be
    /// preserved. This pins the "exactly which filenames" half
    /// of the contract — a future refactor that switches to
    /// prefix-matching ("any file starting with `control_`")
    /// would also delete tor's own persisted state (`state`,
    /// `cached-microdescs`, …) which the data directory also
    /// holds. Anything tor wrote that survives across launches
    /// (chain state, descriptor caches, the v3 HSDir directory
    /// cache) must NOT be touched here.
    @Test func unrelatedFilesArePreserved() throws {
        let dir = try makeTmpDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cookie = dir.appendingPathComponent("control_auth_cookie")
        let port = dir.appendingPathComponent("controlport")
        let state = dir.appendingPathComponent("state")
        let cachedMicrodescs = dir.appendingPathComponent("cached-microdescs")
        let lookAlike = dir.appendingPathComponent("control_auth_cookie.bak")
        try Data("c".utf8).write(to: cookie)
        try Data("p".utf8).write(to: port)
        try Data("s".utf8).write(to: state)
        try Data("m".utf8).write(to: cachedMicrodescs)
        try Data("b".utf8).write(to: lookAlike)

        let result = TorController.purgeStaleControlFiles(in: dir)

        #expect(result.cookieRemoved)
        #expect(result.portRemoved)
        #expect(!FileManager.default.fileExists(atPath: cookie.path))
        #expect(!FileManager.default.fileExists(atPath: port.path))
        #expect(FileManager.default.fileExists(atPath: state.path))
        #expect(FileManager.default.fileExists(atPath: cachedMicrodescs.path))
        #expect(FileManager.default.fileExists(atPath: lookAlike.path))
    }

    /// The helper is idempotent: a second call after a successful
    /// purge returns "nothing to do" rather than throwing or
    /// returning stale flags. Important because a future caller
    /// could refactor `runBootstrap` to call this from two paths
    /// (cold start AND reconnect) without needing to guard.
    @Test func secondCallIsNoOp() throws {
        let dir = try makeTmpDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cookie = dir.appendingPathComponent("control_auth_cookie")
        try Data("c".utf8).write(to: cookie)

        _ = TorController.purgeStaleControlFiles(in: dir)
        let second = TorController.purgeStaleControlFiles(in: dir)

        #expect(!second.cookieRemoved)
        #expect(!second.portRemoved)
        #expect(!second.anyRemoved)
    }
}
