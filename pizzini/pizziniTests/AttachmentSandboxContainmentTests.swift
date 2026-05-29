import Foundation
import Testing
@testable import pizzini

/// PZ-L6: `AttachmentSandbox.assertContained` must reject any path that
/// escapes the per-attachment sandbox dir — including via a symlinked
/// component, which the old `standardized.path` + `hasPrefix` check did
/// NOT resolve. The fix resolves symlinks on both URLs and compares path
/// components. These run on the simulator (Foundation + a temp-dir
/// filesystem, no entitlements).
@Suite("PZ-L6 attachment sandbox path containment")
struct AttachmentSandboxContainmentTests {
    private func makeTempDir() throws -> URL {
        let base = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pzl6-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }

    @Test("a file directly inside the sandbox is contained")
    func containedFile() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "chunk-00001.bin", directoryHint: .notDirectory)
        // Throws would fail this `throws` test.
        try AttachmentSandbox.assertContained(url: url, in: dir)
    }

    @Test("a file in a real subdirectory of the sandbox is contained")
    func containedSubdir() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let sub = dir.appending(path: "sub", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: sub, withIntermediateDirectories: true)
        let url = sub.appending(path: "file.bin", directoryHint: .notDirectory)
        try AttachmentSandbox.assertContained(url: url, in: dir)
    }

    @Test("a .. escape is rejected")
    func dotDotEscapeRejected() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "../escapee.bin", directoryHint: .notDirectory)
        #expect(throws: AttachmentSandbox.SandboxError.self) {
            try AttachmentSandbox.assertContained(url: url, in: dir)
        }
    }

    @Test("a sibling dir sharing a textual name prefix is rejected")
    func siblingPrefixRejected() throws {
        let base = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: base) }
        let dir = base.appending(path: "abc", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // "abcEVIL" shares the textual prefix "abc" but is a different dir.
        let url = base.appending(path: "abcEVIL/loot.bin", directoryHint: .notDirectory)
        #expect(throws: AttachmentSandbox.SandboxError.self) {
            try AttachmentSandbox.assertContained(url: url, in: dir)
        }
    }

    @Test("a symlinked component escaping the sandbox is rejected (PZ-L6 core)")
    func symlinkEscapeRejected() throws {
        let base = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: base) }
        let sandbox = base.appending(path: "sandbox", directoryHint: .isDirectory)
        let outside = base.appending(path: "outside", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: sandbox, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        // A symlink INSIDE the sandbox pointing OUT of it. Under the old
        // string-prefix check (no symlink resolution) "sandbox/link/x"
        // textually starts with "sandbox/" and would PASS; resolving the
        // symlink reveals it lands under "outside/".
        let link = sandbox.appending(path: "link", directoryHint: .isDirectory)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)
        let url = link.appending(path: "secret.bin", directoryHint: .notDirectory)
        #expect(throws: AttachmentSandbox.SandboxError.self) {
            try AttachmentSandbox.assertContained(url: url, in: sandbox)
        }
    }

    @Test("the sandbox directory itself is not contained (must be strictly inside)")
    func dirItselfRejected() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(throws: AttachmentSandbox.SandboxError.self) {
            try AttachmentSandbox.assertContained(url: dir, in: dir)
        }
    }
}
