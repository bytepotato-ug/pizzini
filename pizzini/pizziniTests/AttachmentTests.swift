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
