import Foundation

/// Per-attachment sandbox under `Application Support/attachments/`. Pizzini
/// never writes attachment bytes to `PHPhotoLibrary` (would land in iCloud
/// Photos) or to `Documents/` (iCloud-Documents-backed by default on iOS).
/// Application Support is local-only when paired with the app's "exclude
/// from iCloud backup" flag we set on the directory at create time. File
/// protection is `completeUntilFirstUserAuthentication` — bytes unreadable
/// before unlock, but accessible to the running app on subsequent reads
/// (matches the rest of Pizzini's Keychain accessibility tier).
///
/// Lifecycle:
/// - `directory(for:)` is called once on receive to create a per-message
///   directory (`{messageUUID}/`) inside which chunks are written, then
///   the assembled file at the canonical filename.
/// - `outboundDirectory(for:)` mirrors the same shape for sender-side
///   staging — the post-strip / sanitized bytes live here while the
///   chunked SEND walk drains them.
/// - `cleanup(olderThan:)` is called periodically by `ChatStore` to
///   remove sandbox state after the per-message TTL elapses; the chat
///   row stays (it's just a row of "filename + size + Save to Files
///   was here") but the bytes are gone.
enum AttachmentSandbox {
    enum SandboxError: Error {
        case applicationSupportUnavailable
        case writeFailed(String)
    }

    /// Subdirectory of Application Support that holds every attachment
    /// folder. Created on demand; never written to directly.
    private static let rootName = "attachments"
    /// Per-message subdirectory holding inbound chunks + assembled file.
    private static let inboundName = "incoming"
    /// Per-message subdirectory holding outbound staged bytes.
    private static let outboundName = "outgoing"

    /// Root `attachments/` directory. Created on first call; idempotent.
    /// Excluded from iCloud backup so a journalist's iCloud-backed
    /// account can't leak attachment bytes off the device. Both the
    /// protection class and the backup-exclusion flag are RE-ASSERTED
    /// on every call — a refactor that ever creates the directory
    /// out-of-band can't silently re-enable backup or downgrade the
    /// protection class.
    static func root() throws -> URL {
        let fm = FileManager.default
        guard let appSupport = fm.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            throw SandboxError.applicationSupportUnavailable
        }
        let dir = appSupport.appending(path: rootName, directoryHint: .isDirectory)
        if !fm.fileExists(atPath: dir.path) {
            try fm.createDirectory(
                at: dir,
                withIntermediateDirectories: true,
                attributes: [
                    // completeUntilFirstUserAuthentication: bytes are
                    // protected at-rest until first unlock, which is
                    // when our background-launched code runs anyway.
                    // Tighter `complete` would lock us out during APNs
                    // wake-ups and break the offline-message flow.
                    .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
                ],
            )
        }
        try assertSandboxAttributes(dir)
        return dir
    }

    /// Re-assert the protection class + iCloud backup exclusion on a
    /// sandbox-managed directory. Setting the same value is a no-op,
    /// so this is safe on every call. Belt-and-suspenders against
    /// future code paths that might create a sibling directory without
    /// the attributes.
    private static func assertSandboxAttributes(_ url: URL) throws {
        var v = URLResourceValues()
        v.isExcludedFromBackup = true
        var mutable = url
        try mutable.setResourceValues(v)
    }

    /// Per-attachment inbound directory. Caller passes the 16-byte
    /// attachment id (the wire-format grouping key); we hex-encode it
    /// for filesystem readability.
    static func inboundDirectory(forAttachmentId id: Data) throws -> URL {
        try perAttachmentDirectory(parent: inboundName, id: id)
    }

    /// Per-attachment outbound staging directory. Same shape as inbound
    /// but a separate parent so a periodic GC can target only one tier
    /// at a time (e.g. clean up post-TTL sender entries without
    /// touching incoming reassembly state).
    static func outboundDirectory(forAttachmentId id: Data) throws -> URL {
        try perAttachmentDirectory(parent: outboundName, id: id)
    }

    /// Persist the assembled bytes under their final filename inside
    /// the per-attachment inbound directory. Returns the URL the UI
    /// presents to `UIDocumentInteractionController`.
    static func writeAssembledFile(
        attachmentId: Data,
        sanitizedFilename: String,
        contents: Data
    ) throws -> URL {
        let dir = try inboundDirectory(forAttachmentId: attachmentId)
        let url = dir.appending(path: sanitizedFilename, directoryHint: .notDirectory)
        // Defense in depth on top of FilenameSanitizer: if the URL
        // resolves outside the per-attachment directory (which would
        // require a `..` or absolute-path component that survived
        // sanitization), refuse the write.
        try assertContained(url: url, in: dir)
        do {
            try contents.write(
                to: url,
                options: [
                    .atomic,
                    // Per-file protection on top of the directory-level
                    // setting. iOS evaluates the most restrictive of
                    // the two — having both is belt-and-suspenders.
                    .completeFileProtectionUntilFirstUserAuthentication,
                ],
            )
        } catch {
            throw SandboxError.writeFailed("\(error)")
        }
        return url
    }

    /// Assert that `url` is contained inside `dir` after URL
    /// standardization. Throws `writeFailed` if the resolved path
    /// would escape — the only place a `..`-bearing filename can
    /// reach is here, and we close it at the sandbox layer.
    static func assertContained(url: URL, in dir: URL) throws {
        let resolved = url.standardized.path
        let parent = dir.standardized.path
        let parentPrefix = parent.hasSuffix("/") ? parent : parent + "/"
        if !resolved.hasPrefix(parentPrefix) {
            throw SandboxError.writeFailed("path escapes sandbox dir")
        }
    }

    /// Wipe the entire `attachments/` tree — every inbound directory,
    /// every outbound staging directory, every assembled file. Called
    /// by `Storage.eraseAndReinitialize` as part of the duress flow so
    /// the post-wipe filesystem contains no plaintext attachment bytes
    /// at all. The SQLCipher DB rows that reference these files are
    /// wiped in the same call (different code path), so cross-table
    /// consistency is preserved.
    ///
    /// Idempotent: returns silently if the root directory does not
    /// exist (first-launch pre-attachment state).
    static func eraseEverything() {
        let fm = FileManager.default
        guard let appSupport = fm.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else { return }
        let dir = appSupport.appending(path: rootName, directoryHint: .isDirectory)
        guard fm.fileExists(atPath: dir.path) else { return }
        try? fm.removeItem(at: dir)
    }

    /// Delete every per-attachment directory whose mtime is older than
    /// `cutoff`. Called by ChatStore on a timer (cheap — typically a
    /// dozen folders for an active user). Survives an absent root
    /// directory gracefully (returns 0) so first-launch pre-attachment
    /// state isn't an error case.
    @discardableResult
    static func cleanup(olderThan cutoff: Date) -> Int {
        let fm = FileManager.default
        guard let rootURL = try? root() else { return 0 }
        var removed = 0
        for parent in [inboundName, outboundName] {
            let parentURL = rootURL.appending(path: parent, directoryHint: .isDirectory)
            guard let kids = try? fm.contentsOfDirectory(
                at: parentURL,
                includingPropertiesForKeys: [.contentModificationDateKey],
                options: [.skipsHiddenFiles],
            ) else { continue }
            for child in kids {
                let mtime = (try? child.resourceValues(forKeys: [.contentModificationDateKey])
                    .contentModificationDate) ?? .distantFuture
                if mtime < cutoff {
                    if (try? fm.removeItem(at: child)) != nil {
                        removed += 1
                    }
                }
            }
        }
        return removed
    }

    /// True if any path component in `url` lies under the iCloud-backed
    /// `Documents/` directory or `PHPhotoLibrary` — used by tests to
    /// assert the sandbox path NEVER routes through one of those. Not
    /// a runtime safety check (we control the producer); a regression
    /// guard.
    static func isInPhotoLibraryOrICloudDocs(_ url: URL) -> Bool {
        // Component-exact match. Substring containment would
        // false-positive on any path that happens to contain
        // `/Documents/` as a substring (e.g. `Mobile Documents`).
        let parts = Set(url.standardized.pathComponents)
        return parts.contains("PhotoData")
            || parts.contains("Photos")
            || parts.contains("Documents")
    }

    private static func perAttachmentDirectory(parent: String, id: Data) throws -> URL {
        let r = try root()
        let parentURL = r.appending(path: parent, directoryHint: .isDirectory)
        let hex = id.map { String(format: "%02x", $0) }.joined()
        let dir = parentURL.appending(path: hex, directoryHint: .isDirectory)
        let fm = FileManager.default
        if !fm.fileExists(atPath: parentURL.path) {
            try fm.createDirectory(
                at: parentURL,
                withIntermediateDirectories: true,
                attributes: [
                    .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
                ],
            )
            try assertSandboxAttributes(parentURL)
        }
        if !fm.fileExists(atPath: dir.path) {
            try fm.createDirectory(
                at: dir,
                withIntermediateDirectories: true,
                attributes: [
                    .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
                ],
            )
        }
        try assertSandboxAttributes(dir)
        return dir
    }
}
