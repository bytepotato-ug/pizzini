import Foundation
import Testing
import ImageIO
import UniformTypeIdentifiers
import CoreGraphics
@testable import pizzini

@Suite("FilenameSanitizer")
struct FilenameSanitizerTests {
    @Test("strips RTL-override and reveals the real extension")
    func rtlOverride() {
        // U+202E reverses display so `report\u{202E}gpj.exe` looks like
        // `report.exe.jpg` to the user but is actually executable. The
        // sanitizer must drop the override so the displayed name
        // matches the executed extension.
        let attack = "report\u{202E}gpj.exe"
        let cleaned = FilenameSanitizer.sanitize(attack)
        #expect(!cleaned.unicodeScalars.contains(where: { $0.value == 0x202E }))
        #expect(cleaned == "reportgpj.exe")
        // `.exe` falls through to desktop-execute on receive — the red
        // banner kicks in there.
        #expect(AttachmentTierClassifier.isDesktopExecutable(filename: cleaned))
    }

    @Test("strips path separators (and leading dots after, defeating dotfile + path-escape)")
    func pathSeparators() {
        // `../../etc/passwd`: separators stripped → `....etcpasswd`,
        // then leading-dot strip → `etcpasswd`. The second pass is
        // important: it kills the ".bashrc" / ".htaccess" hidden-on-
        // unix-ls trick a malicious sender could use.
        #expect(FilenameSanitizer.sanitize("../../etc/passwd") == "etcpasswd")
        #expect(FilenameSanitizer.sanitize("a\\b\\c.txt") == "abc.txt")
        #expect(FilenameSanitizer.sanitize("name\u{0000}with\u{0000}null.bin") == "namewithnull.bin")
    }

    @Test("normalises Unicode (composed form)")
    func unicodeNormalisation() {
        // `é` in composed (U+00E9) vs decomposed (e + U+0301) — both
        // come out the same after sanitize.
        let composed = "caf\u{00E9}.jpg"
        let decomposed = "cafe\u{0301}.jpg"
        #expect(FilenameSanitizer.sanitize(composed) == FilenameSanitizer.sanitize(decomposed))
    }

    @Test("caps length at 255 bytes preserving extension")
    func lengthCap() {
        let stem = String(repeating: "a", count: 400)
        let name = "\(stem).docx"
        let cleaned = FilenameSanitizer.sanitize(name)
        #expect(cleaned.utf8.count <= FilenameSanitizer.maxLength)
        #expect(cleaned.hasSuffix(".docx"))
    }

    @Test("falls back to 'untitled' on empty / dot-only input")
    func fallback() {
        #expect(FilenameSanitizer.sanitize("") == FilenameSanitizer.fallbackName)
        #expect(FilenameSanitizer.sanitize("...") == FilenameSanitizer.fallbackName)
        #expect(FilenameSanitizer.sanitize("\u{202E}\u{202D}") == FilenameSanitizer.fallbackName)
    }

    @Test("idempotent — sanitize twice == sanitize once")
    func idempotent() {
        let inputs = [
            "report\u{202E}gpj.exe",
            "../../etc/passwd",
            "café.jpg",
            "  spaces  .pdf",
            "...hidden",
        ]
        for s in inputs {
            let once = FilenameSanitizer.sanitize(s)
            let twice = FilenameSanitizer.sanitize(once)
            #expect(once == twice, "non-idempotent for \(s)")
        }
    }
}

@Suite("AttachmentTierClassifier")
struct AttachmentTierTests {
    @Test("text-family is no-warn pass-through")
    func textFamily() {
        for ext in ["txt", "md", "json", "csv", "tsv", "log", "yaml"] {
            #expect(
                AttachmentTierClassifier.tier(forFilename: "x.\(ext)") == .textFamily,
                "expected textFamily for \(ext)"
            )
        }
    }

    @Test("media triggers strip + warn")
    func media() {
        for ext in ["jpg", "jpeg", "heic", "png", "mp4", "mov", "mp3", "m4a"] {
            #expect(
                AttachmentTierClassifier.tier(forFilename: "x.\(ext)") == .mediaStripAndWarn,
                "expected mediaStripAndWarn for \(ext)"
            )
        }
    }

    @Test("author-leaking docs warn at receive")
    func authorLeakingDocs() {
        for ext in ["pdf", "docx", "xlsx", "pptx", "epub"] {
            #expect(
                AttachmentTierClassifier.tier(forFilename: "x.\(ext)") == .authorLeakingDoc
            )
        }
    }

    @Test("iOS-execute-on-tap is blocked at picker")
    func iosExecuteBlocked() {
        for ext in ["mobileconfig", "shortcut", "svg"] {
            #expect(
                AttachmentTierClassifier.isBlockedAtSend(filename: "x.\(ext)"),
                "expected blocked-at-send for \(ext)"
            )
            #expect(
                AttachmentTierClassifier.tier(forFilename: "x.\(ext)") == .codeOnTap
            )
        }
    }

    @Test("desktop-execute passes send but red-bannered on receive")
    func desktopExecute() {
        for ext in ["exe", "dll", "bat", "command", "applescript"] {
            #expect(
                !AttachmentTierClassifier.isBlockedAtSend(filename: "x.\(ext)"),
                "should not block-at-send for \(ext)"
            )
            #expect(
                AttachmentTierClassifier.isDesktopExecutable(filename: "x.\(ext)"),
                "expected desktop-executable for \(ext)"
            )
        }
    }
}

@Suite("AttachmentSandbox")
struct AttachmentSandboxTests {
    @Test("inbound directory not under PhotoLibrary or iCloud Documents")
    func sandboxLocation() throws {
        let id = Data(repeating: 0xAB, count: 16)
        let dir = try AttachmentSandbox.inboundDirectory(forAttachmentId: id)
        #expect(!AttachmentSandbox.isInPhotoLibraryOrICloudDocs(dir))
        // Also: must be inside Application Support (not /tmp, not Documents).
        #expect(dir.path.contains("Application Support"))
        try? FileManager.default.removeItem(at: dir)
    }

    @Test("writeAssembledFile round-trips bytes")
    func writeAssembled() throws {
        let id = Data(repeating: 0xCD, count: 16)
        let url = try AttachmentSandbox.writeAssembledFile(
            attachmentId: id,
            sanitizedFilename: "hello.txt",
            contents: Data("hi".utf8),
        )
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let read = try Data(contentsOf: url)
        #expect(read == Data("hi".utf8))
        #expect(url.lastPathComponent == "hello.txt")
    }
}

@Suite("MetadataStripper")
struct MetadataStripperTests {
    /// Build a 4×4 JPEG with GPS, software, and camera-make tags
    /// embedded — exactly the fingerprinting metadata a leaked photo
    /// might carry.
    private func makeJPEGWithFingerprintingMetadata() throws -> Data {
        let width = 4
        let height = 4
        let space = CGColorSpaceCreateDeviceRGB()
        guard let ctx = CGContext(
            data: nil,
            width: width, height: height,
            bitsPerComponent: 8, bytesPerRow: 0,
            space: space,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ) else { throw MetadataStripper.StripError.encodeFailed }
        ctx.setFillColor(CGColor(red: 1, green: 0, blue: 0, alpha: 1))
        ctx.fill(CGRect(x: 0, y: 0, width: width, height: height))
        guard let image = ctx.makeImage() else {
            throw MetadataStripper.StripError.encodeFailed
        }

        let buf = NSMutableData()
        guard let dst = CGImageDestinationCreateWithData(
            buf as CFMutableData, UTType.jpeg.identifier as CFString, 1, nil
        ) else { throw MetadataStripper.StripError.encodeFailed }

        let gps: [CFString: Any] = [
            kCGImagePropertyGPSLatitude: 47.3769,
            kCGImagePropertyGPSLongitude: 8.5417,
            kCGImagePropertyGPSLatitudeRef: "N",
            kCGImagePropertyGPSLongitudeRef: "E",
        ]
        let exif: [CFString: Any] = [
            kCGImagePropertyExifMakerNote: Data([0xDE, 0xAD, 0xBE, 0xEF]),
            kCGImagePropertyExifBodySerialNumber: "ABC123",
        ]
        let tiff: [CFString: Any] = [
            kCGImagePropertyTIFFMake: "ACME Camera",
            kCGImagePropertyTIFFSoftware: "PizziniTestSuite/1.0",
        ]
        let props: [CFString: Any] = [
            kCGImagePropertyGPSDictionary: gps,
            kCGImagePropertyExifDictionary: exif,
            kCGImagePropertyTIFFDictionary: tiff,
        ]
        CGImageDestinationAddImage(dst, image, props as CFDictionary)
        guard CGImageDestinationFinalize(dst) else {
            throw MetadataStripper.StripError.encodeFailed
        }
        return buf as Data
    }

    private func props(of data: Data) -> [CFString: Any] {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil),
              let p = CGImageSourceCopyPropertiesAtIndex(src, 0, nil)
                as? [CFString: Any]
        else { return [:] }
        return p
    }

    @Test("strips GPS from a JPEG with location embedded")
    func stripsGPS() throws {
        let original = try makeJPEGWithFingerprintingMetadata()
        // Sanity: the original *does* carry GPS.
        #expect(props(of: original)[kCGImagePropertyGPSDictionary] != nil)
        let stripped = try MetadataStripper.stripped(
            original, filename: "x.jpg", mimeType: "image/jpeg"
        )
        #expect(props(of: stripped)[kCGImagePropertyGPSDictionary] == nil)
    }

    @Test("strips camera serial / software / make")
    func stripsCameraTags() throws {
        let original = try makeJPEGWithFingerprintingMetadata()
        let stripped = try MetadataStripper.stripped(
            original, filename: "x.jpg", mimeType: "image/jpeg"
        )
        let p = props(of: stripped)
        let exif = p[kCGImagePropertyExifDictionary] as? [CFString: Any] ?? [:]
        let tiff = p[kCGImagePropertyTIFFDictionary] as? [CFString: Any] ?? [:]
        #expect(exif[kCGImagePropertyExifMakerNote] == nil)
        #expect(exif[kCGImagePropertyExifBodySerialNumber] == nil)
        // CGImageDestination may rewrite TIFFMake to a default; check
        // it's not the value we planted.
        let make = tiff[kCGImagePropertyTIFFMake] as? String
        let software = tiff[kCGImagePropertyTIFFSoftware] as? String
        #expect(make != "ACME Camera")
        #expect(software != "PizziniTestSuite/1.0")
    }

    @Test("text-family file: pass-through, identical bytes")
    func passThroughText() throws {
        let original = Data("hello world".utf8)
        let out = try MetadataStripper.stripped(
            original, filename: "notes.txt", mimeType: "text/plain"
        )
        #expect(out == original)
    }

    @Test("PDF (Tier 4): pass-through — we don't strip what we don't understand")
    func passThroughPDF() throws {
        let original = Data([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37]) // %PDF-1.7
        let out = try MetadataStripper.stripped(
            original, filename: "report.pdf", mimeType: "application/pdf"
        )
        #expect(out == original)
    }
}

@Suite("FileChunkEnvelope codec")
struct FileChunkEnvelopeTests {
    private func sample(index: UInt32 = 0, count: UInt32 = 3, payload: Data = Data([1, 2, 3])) -> FileChunkEnvelope {
        FileChunkEnvelope(
            attachmentId: Data(repeating: 0xA5, count: 16),
            totalSize: 9,
            chunkIndex: index,
            chunkCount: count,
            mime: "image/jpeg",
            filename: "kitten.jpg",
            chunkBytes: payload,
        )
    }

    @Test("round-trip preserves every field")
    func roundTrip() throws {
        let env = sample()
        let wire = env.encode()
        let decoded = try FileChunkEnvelope.decode(wire)
        #expect(decoded == env)
    }

    @Test("rejects oversize chunk count (>1024)")
    func rejectsOversizeChunkCount() {
        var bytes = Data(repeating: 0xA5, count: 16)        // attachment_id
        bytes.append(contentsOf: [UInt8](repeating: 0, count: 8))  // total_size
        // chunk_index = 0, chunk_count = 99999 — over the 1024 cap.
        bytes.append(contentsOf: [0, 0, 0, 0])
        var bigCount = UInt32(99999).bigEndian
        withUnsafeBytes(of: &bigCount) { bytes.append(contentsOf: $0) }
        // mime_len = 0, filename_len = 0
        bytes.append(contentsOf: [0, 0])
        bytes.append(contentsOf: [0, 0])
        #expect(throws: FileChunkEnvelope.CodecError.oversizedChunkCount) {
            _ = try FileChunkEnvelope.decode(bytes)
        }
    }

    @Test("rejects chunk_index out of range")
    func rejectsBadIndex() {
        var bytes = Data(repeating: 0, count: 16)
        bytes.append(contentsOf: [UInt8](repeating: 0, count: 8))   // total_size
        var idx = UInt32(5).bigEndian
        var cnt = UInt32(3).bigEndian
        withUnsafeBytes(of: &idx) { bytes.append(contentsOf: $0) }
        withUnsafeBytes(of: &cnt) { bytes.append(contentsOf: $0) }
        bytes.append(contentsOf: [0, 0, 0, 0])
        #expect(throws: FileChunkEnvelope.CodecError.chunkIndexOutOfRange) {
            _ = try FileChunkEnvelope.decode(bytes)
        }
    }

    @Test("rejects oversized chunk plaintext")
    func rejectsOversizedChunk() throws {
        let env = FileChunkEnvelope(
            attachmentId: Data(repeating: 0, count: 16),
            totalSize: UInt64(FileChunkEnvelope.maxChunkPlaintextBytes + 1),
            chunkIndex: 0,
            chunkCount: 1,
            mime: "x",
            filename: "x",
            chunkBytes: Data(repeating: 0, count: FileChunkEnvelope.maxChunkPlaintextBytes + 1),
        )
        let wire = env.encode()
        #expect(throws: FileChunkEnvelope.CodecError.oversizedChunk) {
            _ = try FileChunkEnvelope.decode(wire)
        }
    }

    @Test("rejects truncated buffer")
    func rejectsTruncated() {
        let bytes = Data(repeating: 0, count: 10)
        #expect(throws: FileChunkEnvelope.CodecError.truncated) {
            _ = try FileChunkEnvelope.decode(bytes)
        }
    }
}

@MainActor
@Suite("AttachmentReassembler state machine", .serialized)
struct AttachmentReassemblerTests {
    private func makeEnv(
        attachmentId: Data,
        index: UInt32,
        count: UInt32,
        totalSize: UInt64,
        chunkBytes: Data,
        filename: String = "doc.pdf",
        mime: String = "application/pdf"
    ) -> FileChunkEnvelope {
        FileChunkEnvelope(
            attachmentId: attachmentId,
            totalSize: totalSize,
            chunkIndex: index,
            chunkCount: count,
            mime: mime,
            filename: filename,
            chunkBytes: chunkBytes,
        )
    }

    @Test("two chunks land out of order, file assembles correctly")
    func reassembleTwoChunksOutOfOrder() throws {
        let r = AttachmentReassembler()
        let aid = Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })
        let peer = Data(repeating: 0xBB, count: 33)
        let part0 = Data("hello-".utf8)
        let part1 = Data("world!".utf8)
        let total = UInt64(part0.count + part1.count)

        // Chunk 1 first.
        let r1 = r.feed(envelope: makeEnv(
            attachmentId: aid, index: 1, count: 2, totalSize: total, chunkBytes: part1
        ), fromPeer: peer)
        if case .progress(let received, let expected) = r1 {
            #expect(received == 1)
            #expect(expected == 2)
        } else {
            Issue.record("expected progress, got \(r1)")
        }

        // Chunk 0 last → completion.
        let r0 = r.feed(envelope: makeEnv(
            attachmentId: aid, index: 0, count: 2, totalSize: total, chunkBytes: part0
        ), fromPeer: peer)
        switch r0 {
        case .complete(let comp):
            let assembled = try Data(contentsOf: comp.url)
            #expect(assembled == part0 + part1)
            #expect(comp.sanitizedFilename == "doc.pdf")
            #expect(comp.tier == .authorLeakingDoc)
            // Cleanup so subsequent tests don't see the dir.
            try? FileManager.default.removeItem(at: comp.url.deletingLastPathComponent())
        default:
            Issue.record("expected complete, got \(r0)")
        }
    }

    /// Adversarial: sender claims chunk_count=64 but only ships 1 chunk.
    /// Reassembler must time out and clean up partial state, not leak
    /// storage. We force-expire the entry by reaching past `partialTTL`
    /// with a custom now and confirm `staleEntries(now:)` flags it.
    @Test("partial transfer (1 of 64) flagged stale and discarded")
    func adversarialPartial() throws {
        let r = AttachmentReassembler()
        let aid = Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })
        let peer = Data(repeating: 0xCC, count: 33)
        // Sender claims 64 chunks but only sends one.
        let chunk = Data(repeating: 0x42, count: 16)
        let r0 = r.feed(envelope: makeEnv(
            attachmentId: aid,
            index: 0,
            count: 64,
            totalSize: UInt64(chunk.count) * 64,
            chunkBytes: chunk,
        ), fromPeer: peer)
        if case .progress = r0 {} else {
            Issue.record("expected progress, got \(r0)")
        }
        // No chunks 1..63 ever arrive. After partialTTL the entry is
        // stale.
        let future = Date().addingTimeInterval(AttachmentReassembler.partialTTL + 1)
        let stale = r.staleEntries(now: future)
        #expect(stale.count == 1)
        #expect(stale.first?.attachmentId == aid)
        // Discard wipes both the in-memory entry and the on-disk
        // staging dir.
        r.discard(peer: peer, attachmentId: aid)
        // After discard, staleEntries returns empty.
        #expect(r.staleEntries(now: future).isEmpty)
        // And the directory is gone.
        let dir = try AttachmentSandbox.inboundDirectory(forAttachmentId: aid)
        let exists = (try? FileManager.default.attributesOfItem(atPath: dir.path)) != nil
        // The next inboundDirectory call recreated it; the chunk file
        // we wrote earlier should be gone.
        let chunkFile = dir.appending(path: "chunk-00000.bin", directoryHint: .notDirectory)
        #expect(!FileManager.default.fileExists(atPath: chunkFile.path))
        if exists { try? FileManager.default.removeItem(at: dir) }
    }

    @Test("rejects mid-transfer if sender flips total_size")
    func rejectsTotalSizeFlip() {
        let r = AttachmentReassembler()
        let aid = Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })
        let peer = Data(repeating: 0xDD, count: 33)
        _ = r.feed(envelope: makeEnv(
            attachmentId: aid, index: 0, count: 2, totalSize: 200,
            chunkBytes: Data(repeating: 0, count: 100),
        ), fromPeer: peer)
        // Now ship chunk 1 with a different total_size — paired peer
        // trying to confuse reassembly. Drop.
        let result = r.feed(envelope: makeEnv(
            attachmentId: aid, index: 1, count: 2, totalSize: 999,
            chunkBytes: Data(repeating: 0, count: 100),
        ), fromPeer: peer)
        #expect(result == .rejected(.attachmentIdMismatch))
        // Cleanup.
        r.discard(peer: peer, attachmentId: aid)
    }

    @Test("rejects when bytes summed don't match total_size")
    func rejectsSizeMismatch() {
        let r = AttachmentReassembler()
        let aid = Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) })
        let peer = Data(repeating: 0xEE, count: 33)
        // Both chunks consistent with total_size=300, but actual bytes
        // sum to 200.
        _ = r.feed(envelope: makeEnv(
            attachmentId: aid, index: 0, count: 2, totalSize: 300,
            chunkBytes: Data(repeating: 0, count: 100),
        ), fromPeer: peer)
        let result = r.feed(envelope: makeEnv(
            attachmentId: aid, index: 1, count: 2, totalSize: 300,
            chunkBytes: Data(repeating: 0, count: 100),
        ), fromPeer: peer)
        if case .rejected(let reason) = result {
            #expect(reason == .sizeMismatch)
        } else {
            Issue.record("expected rejected(.sizeMismatch), got \(result)")
        }
        // Discard cleans up partial state.
        r.discard(peer: peer, attachmentId: aid)
    }
}

extension AttachmentReassembler.FeedResult: Equatable {
    public static func == (lhs: AttachmentReassembler.FeedResult, rhs: AttachmentReassembler.FeedResult) -> Bool {
        switch (lhs, rhs) {
        case (.progress(let lr, let le), .progress(let rr, let re)):
            return lr == rr && le == re
        case (.complete(let lc), .complete(let rc)):
            return lc.attachmentId == rc.attachmentId && lc.url == rc.url
        case (.rejected(let lr), .rejected(let rr)):
            return lr == rr
        default:
            return false
        }
    }
}

@Suite("OutboxStore.attachmentStatus")
struct OutboxAttachmentRollupTests {
    private func chunk(
        attachmentId: Data,
        idx: UInt32,
        count: UInt32 = 3,
        delivered: Bool = false,
        relayed: Bool = false,
        failed: Bool = false
    ) -> OutboxEntry {
        OutboxEntry(
            messageId: Data((0..<16).map { _ in UInt8.random(in: 0...UInt8.max) }),
            recipientPeerId: Data(repeating: 0xBB, count: 33),
            sealedCiphertext: Data([0xCA]),
            token: Data(),
            ttl: 24 * 60 * 60,
            sentAt: Date(),
            retries: 0,
            deliveredAt: delivered ? Date() : nil,
            failedAt: failed ? Date() : nil,
            relayedAt: relayed ? Date() : nil,
            attachmentId: attachmentId,
            chunkIndex: idx,
            chunkCount: count,
        )
    }

    @Test("all delivered → delivered (✓✓)")
    func allDelivered() {
        var s = OutboxStore.empty
        let aid = Data(repeating: 0x01, count: 16)
        for i in 0..<3 {
            let e = chunk(attachmentId: aid, idx: UInt32(i), delivered: true, relayed: true)
            s.entries[e.messageId] = e
        }
        #expect(s.attachmentStatus(forId: aid) == .delivered)
    }

    @Test("any failed → failed (✗) wins")
    func anyFailed() {
        var s = OutboxStore.empty
        let aid = Data(repeating: 0x02, count: 16)
        let e0 = chunk(attachmentId: aid, idx: 0, delivered: true, relayed: true)
        let e1 = chunk(attachmentId: aid, idx: 1, failed: true)
        let e2 = chunk(attachmentId: aid, idx: 2, relayed: true)
        s.entries[e0.messageId] = e0
        s.entries[e1.messageId] = e1
        s.entries[e2.messageId] = e2
        #expect(s.attachmentStatus(forId: aid) == .failed)
    }

    @Test("any pending → pending (⏳) over relayed")
    func pendingWinsOverRelayed() {
        var s = OutboxStore.empty
        let aid = Data(repeating: 0x03, count: 16)
        let e0 = chunk(attachmentId: aid, idx: 0, relayed: true)
        let e1 = chunk(attachmentId: aid, idx: 1)  // pending
        s.entries[e0.messageId] = e0
        s.entries[e1.messageId] = e1
        #expect(s.attachmentStatus(forId: aid) == .pending)
    }

    @Test("no entries → nil")
    func noEntries() {
        let s = OutboxStore.empty
        #expect(s.attachmentStatus(forId: Data(repeating: 0x99, count: 16)) == nil)
    }
}
