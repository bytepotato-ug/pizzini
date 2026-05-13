import Foundation

/// Persistent QA-debug log. Captures every meaningful event the iOS
/// app emits on a real device so the operator can review a complete
/// timeline after a test session without having to keep Console.app
/// streaming or Xcode tethered.
///
/// **DEBUG-only by design.** The recording path compiles to a
/// no-op under Release so a TestFlight or App Store build never
/// carries the forensic-attack-surface log file. A DEBUG build
/// produced by Xcode's "Run on device" automatically activates it;
/// no toggle, no setting — the user said "everything gets recorded,"
/// so under DEBUG everything is recorded.
///
/// On-disk layout:
///
///   Library/Application Support/qa-debug/qa.log     (active)
///   Library/Application Support/qa-debug/qa.log.1   (previous, after rotation)
///
/// Permissions:
///   * `FileProtectionType.completeUntilFirstUserAuthentication` —
///     same posture as the SQLCipher DB. Bytes are unreadable until
///     the first unlock after each reboot.
///   * Excluded from iCloud / Finder backup. A QA-debug log syncing
///     to the user's other devices would defeat the privacy story.
///
/// Format: one event per line, plain UTF-8:
///
///   <iso8601 with ms> [<category>] <message>\n
///
/// Plain text rather than JSON Lines so the operator can `tail -f`
/// it via iOS Files share, paste a slice into the bug tracker, or
/// `grep` for a peer-id prefix without firing up `jq`. Lines never
/// contain message bodies or chain seeds — only peer-id prefixes
/// (4-byte short form), inner-kind hex bytes, and event-name text.
enum QALog {
    /// Subdirectory name under Application Support. Public so the
    /// share-sheet code can name the URL it hands to
    /// `UIActivityViewController`.
    static let directoryName = "qa-debug"
    /// Active log filename.
    static let filename = "qa.log"
    /// Rotated (previous-session) log filename. One historical file
    /// kept so a "I just hit the bug, but the log already rotated"
    /// scenario still has the prior chunk available.
    static let rotatedFilename = "qa.log.1"
    /// Rotation threshold. 10 MB ≈ tens of thousands of lines at
    /// our typical line length — enough for a multi-hour test
    /// session before rolling.
    static let rotateBytes: UInt64 = 10 * 1024 * 1024

    /// Serial dispatch queue so file writes are ordered AND happen
    /// off the caller's thread (typically `@MainActor`). `qos:
    /// .utility` because diag logging is observability work that
    /// should never compete with UI / network priority.
    private static let queue = DispatchQueue(
        label: "pizzini.qalog",
        qos: .utility,
    )

    /// One ISO-8601 formatter, lazily initialised, with millisecond
    /// precision so two adjacent events on the same wall-clock
    /// second can still be ordered. `nonisolated(unsafe)` is fine
    /// — every read goes through `queue.async`, which serialises
    /// access.
    nonisolated(unsafe) private static let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    /// Append a single event line. Non-blocking — the caller returns
    /// immediately; the file write hits disk asynchronously on the
    /// serial queue. Errors are swallowed because diag logging must
    /// never crash an app flow; the parallel `os_log` path in
    /// `ChatStore.diagLog` retains observability if disk writes fail.
    ///
    /// `nonisolated` so `pzLog` (a free `nonisolated` function) and
    /// any background-queue caller can write without hopping to the
    /// main actor. The serial dispatch queue inside `record` is the
    /// actual synchronisation primitive.
    nonisolated static func record(category: String, message: String) {
        #if DEBUG
        let ts = isoFormatter.string(from: Date())
        let line = "\(ts) [\(category)] \(message)\n"
        queue.async {
            _ = try? appendLine(line)
        }
        #else
        _ = category
        _ = message
        #endif
    }

    /// URL of the active log file if recording is enabled on this
    /// build. Returns `nil` on Release builds (no file exists).
    /// Used by the DiagnosticsView "Export" button.
    nonisolated static func currentLogFileURL() -> URL? {
        #if DEBUG
        return try? logFileURL()
        #else
        return nil
        #endif
    }

    /// URL of the rotated (previous-session) log if one exists.
    /// Useful for "export both" flows where the operator wants the
    /// historical chunk too.
    nonisolated static func rotatedLogFileURL() -> URL? {
        #if DEBUG
        guard let active = try? logFileURL() else { return nil }
        let rotated = active.deletingLastPathComponent().appendingPathComponent(rotatedFilename)
        return FileManager.default.fileExists(atPath: rotated.path) ? rotated : nil
        #else
        return nil
        #endif
    }

    /// Wipe the QA log file(s). Surfaced as a button in the export
    /// UI so the operator can start a fresh capture cleanly without
    /// reinstalling the app.
    nonisolated static func clear() {
        #if DEBUG
        queue.sync {
            guard let url = try? logFileURL() else { return }
            try? FileManager.default.removeItem(at: url)
            let rotated = url.deletingLastPathComponent().appendingPathComponent(rotatedFilename)
            try? FileManager.default.removeItem(at: rotated)
        }
        #endif
    }

    #if DEBUG
    /// Resolve and lazily-create the qa-debug directory + return the
    /// active log file URL. Marks the directory backup-excluded on
    /// first creation. Throws on any FileManager failure — caller
    /// swallows; we never propagate disk errors to the app's hot
    /// path.
    nonisolated static func logFileURL() throws -> URL {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true,
        )
        var dir = support.appendingPathComponent(directoryName, isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.createDirectory(
                at: dir,
                withIntermediateDirectories: true,
                attributes: [
                    .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
                ],
            )
            var rv = URLResourceValues()
            rv.isExcludedFromBackup = true
            try? dir.setResourceValues(rv)
        }
        return dir.appendingPathComponent(filename, isDirectory: false)
    }

    /// Append a line to the active log, rotating first if the file
    /// would cross `rotateBytes`. File-creation uses
    /// `completeFileProtectionUntilFirstUserAuthentication` to match
    /// the SQLCipher DB's protection posture.
    nonisolated private static func appendLine(_ line: String) throws {
        let url = try logFileURL()
        let data = Data(line.utf8)
        if FileManager.default.fileExists(atPath: url.path) {
            let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
            if let size = attrs?[.size] as? UInt64,
               size + UInt64(data.count) > rotateBytes {
                try rotate(url)
                try data.write(
                    to: url,
                    options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication],
                )
                return
            }
            let handle = try FileHandle(forWritingTo: url)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: data)
        } else {
            try data.write(
                to: url,
                options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication],
            )
        }
    }

    /// Single-step rotation: rename `qa.log` to `qa.log.1`,
    /// overwriting any prior rotated file. Caller then writes a
    /// fresh `qa.log` with the new line.
    nonisolated private static func rotate(_ url: URL) throws {
        let rotated = url.deletingLastPathComponent().appendingPathComponent(rotatedFilename)
        if FileManager.default.fileExists(atPath: rotated.path) {
            try FileManager.default.removeItem(at: rotated)
        }
        try FileManager.default.moveItem(at: url, to: rotated)
    }
    #endif
}
