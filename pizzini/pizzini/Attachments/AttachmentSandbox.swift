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
    /// Excluded from iCloud backup so a user's iCloud-backed account
    /// can't leak attachment bytes off the device. Both the
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

    /// Per-attachment inbound directory, namespaced by the SENDER's
    /// identity. F-S8-01: the on-disk path MUST include the sender, not
    /// the attachmentId alone. The in-memory reassembler tables are keyed
    /// `(peer, attachmentId)`, but if the disk layout were keyed by
    /// attachmentId alone, a malicious group member who observed another
    /// member's broadcast attachmentId could re-send under that id and
    /// overwrite the bytes behind the first sender's already-delivered
    /// attachment (a sender-attributed content spoof). Putting the sender
    /// hex in the path gives every sender a disjoint namespace, so two
    /// senders reusing one attachmentId can never collide on disk.
    static func inboundDirectory(forAttachmentId id: Data, sender: Data) throws -> URL {
        try perAttachmentDirectory(parent: inboundName, id: id, sender: sender)
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
        sender: Data,
        sanitizedFilename: String,
        contents: Data
    ) throws -> URL {
        let dir = try inboundDirectory(forAttachmentId: attachmentId, sender: sender)
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

    /// Filename prefixes Pizzini uses for its transient staging files in
    /// `NSTemporaryDirectory()`: the picker stages PRE-STRIP originals
    /// (`pick-…`, still carrying EXIF/GPS) and `AttachmentThumbnail` /
    /// QuickLook decrypt-to-temp files (`pzql-…`); the AV stripper stages
    /// `av-in-…`/`av-out-…` round-trip files.
    static let temporaryStagingPrefixes = ["pick-", "av-in-", "av-out-", "pzql-"]

    /// F-S8-03 / F-S7-02: remove Pizzini's transient staging files from
    /// `NSTemporaryDirectory()`. iOS purges tmp on its own schedule — not
    /// promptly, and NOT as part of a duress wipe — so a GPS-bearing
    /// pre-strip original (or a decrypted QuickLook copy) could otherwise
    /// outlive the cryptographic-erasure wipe. Call on launch and on
    /// duress. Only Pizzini-prefixed files are touched; the shared tmp
    /// dir's other contents are left alone.
    static func sweepTemporaryStaging() {
        let fm = FileManager.default
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        guard let kids = try? fm.contentsOfDirectory(
            at: tmp, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles],
        ) else { return }
        for child in kids where temporaryStagingPrefixes.contains(
            where: { child.lastPathComponent.hasPrefix($0) }
        ) {
            try? fm.removeItem(at: child)
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
        // Reap per-attachment `{id}` directories older than the cutoff.
        func reapAttachmentDirs(in parentURL: URL) {
            guard let kids = try? fm.contentsOfDirectory(
                at: parentURL,
                includingPropertiesForKeys: [.contentModificationDateKey],
                options: [.skipsHiddenFiles],
            ) else { return }
            for child in kids {
                let mtime = (try? child.resourceValues(forKeys: [.contentModificationDateKey])
                    .contentModificationDate) ?? .distantFuture
                if mtime < cutoff, (try? fm.removeItem(at: child)) != nil {
                    removed += 1
                }
            }
        }
        // Outbound: `outgoing/{id}` — id dirs directly under the parent.
        reapAttachmentDirs(in: rootURL.appending(path: outboundName, directoryHint: .isDirectory))
        // Inbound: `incoming/{sender}/{id}` since F-S8-01 namespaced it by
        // sender — reap each sender's id dirs, then drop now-empty sender dirs.
        let inboundURL = rootURL.appending(path: inboundName, directoryHint: .isDirectory)
        if let senderDirs = try? fm.contentsOfDirectory(
            at: inboundURL, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles],
        ) {
            for senderDir in senderDirs {
                reapAttachmentDirs(in: senderDir)
                if let remaining = try? fm.contentsOfDirectory(
                    at: senderDir, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles],
                ), remaining.isEmpty {
                    try? fm.removeItem(at: senderDir)
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

    /// `sender`, when non-nil (inbound), inserts a `{senderHex}` path
    /// component before the attachment-id component so every sender gets
    /// a disjoint on-disk namespace (F-S8-01). Outbound staging passes
    /// nil — it is the local user's own staging and has no cross-sender
    /// collision surface. `withIntermediateDirectories` creates the whole
    /// chain; the iCloud-backup exclusion set on the `attachments/` root
    /// in `root()` covers the entire subtree.
    private static func perAttachmentDirectory(
        parent: String, id: Data, sender: Data? = nil
    ) throws -> URL {
        let r = try root()
        let hex = id.map { String(format: "%02x", $0) }.joined()
        var dir = r.appending(path: parent, directoryHint: .isDirectory)
        if let sender {
            let senderHex = sender.map { String(format: "%02x", $0) }.joined()
            dir = dir.appending(path: senderHex, directoryHint: .isDirectory)
        }
        dir = dir.appending(path: hex, directoryHint: .isDirectory)
        let fm = FileManager.default
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
