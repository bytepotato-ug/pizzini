import Foundation
import Testing
@testable import pizzini

/// Pre-decode guard tests for the tier-3 inline-thumbnail surface.
/// Every predicate is security-relevant — a missing check is the
/// difference between "user opted into a parser" and "user opted into
/// every malformed-image CVE in the wild." Boundary coverage on each.
@Suite("AttachmentThumbnail pre-decode guards")
struct AttachmentThumbnailGuardsTests {
    // MARK: - Magic-byte validator

    @Test("JPEG SOI marker is accepted")
    func jpegMagicAccepted() {
        let prefix = Data([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46])
        #expect(AttachmentThumbnail.hasValidMagic(prefix: prefix))
    }

    @Test("PNG signature is accepted")
    func pngMagicAccepted() {
        let prefix = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        #expect(AttachmentThumbnail.hasValidMagic(prefix: prefix))
    }

    @Test("HEIC ftyp box with heic brand is accepted")
    func heicMagicAccepted() {
        let prefix = Data([
            0x00, 0x00, 0x00, 0x18,
            0x66, 0x74, 0x79, 0x70,
            0x68, 0x65, 0x69, 0x63,
        ])
        #expect(AttachmentThumbnail.hasValidMagic(prefix: prefix))
    }

    @Test("HEIC mif1 generic brand is accepted")
    func mif1BrandAccepted() {
        let prefix = Data([
            0x00, 0x00, 0x00, 0x18,
            0x66, 0x74, 0x79, 0x70,
            0x6D, 0x69, 0x66, 0x31,
        ])
        #expect(AttachmentThumbnail.hasValidMagic(prefix: prefix))
    }

    @Test("PDF body with .jpg extension is rejected by magic check")
    func pdfWithJpgExtensionRejected() {
        let prefix = Data([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34])
        #expect(!AttachmentThumbnail.hasValidMagic(prefix: prefix))
    }

    @Test("GIF87a magic is rejected")
    func gifRejected() {
        let prefix = Data([0x47, 0x49, 0x46, 0x38, 0x37, 0x61])
        #expect(!AttachmentThumbnail.hasValidMagic(prefix: prefix))
    }

    @Test("RIFF/WebP ftyp-shaped header without a HEIC brand is rejected")
    func ftypShapedButWrongBrandRejected() {
        let prefix = Data([
            0x00, 0x00, 0x00, 0x18,
            0x66, 0x74, 0x79, 0x70,
            0x68, 0x65, 0x76, 0x63,
        ])
        #expect(!AttachmentThumbnail.hasValidMagic(prefix: prefix))
    }

    @Test("Truncated prefix below minimum signature length is rejected")
    func tooShortRejected() {
        #expect(!AttachmentThumbnail.hasValidMagic(prefix: Data([0xFF, 0xD8])))
        #expect(!AttachmentThumbnail.hasValidMagic(prefix: Data()))
    }

    // MARK: - Size cap

    @Test("File exactly at the 5 MB cap passes the guard")
    func sizeAtCapPasses() throws {
        let path = try writeFixture(
            bytes: jpegBytes(padTo: Int(AttachmentThumbnail.maxByteSize)),
            ext: "jpg",
        )
        defer { try? FileManager.default.removeItem(at: path) }
        #expect(AttachmentThumbnail.canAttempt(
            filename: "photo.jpg",
            byteSize: AttachmentThumbnail.maxByteSize,
            url: path,
        ))
    }

    @Test("File one byte over the cap fails the guard")
    func sizeOverCapFails() throws {
        let oneOver = AttachmentThumbnail.maxByteSize + 1
        let path = try writeFixture(bytes: jpegBytes(padTo: Int(oneOver)), ext: "jpg")
        defer { try? FileManager.default.removeItem(at: path) }
        #expect(!AttachmentThumbnail.canAttempt(
            filename: "photo.jpg",
            byteSize: oneOver,
            url: path,
        ))
    }

    // MARK: - Whitelist

    @Test("Whitelisted extensions are accepted")
    func whitelistedExtensionsAccepted() {
        for name in ["photo.jpg", "PHOTO.JPEG", "scan.png", "iphone.heic", "ios.heif"] {
            #expect(
                AttachmentThumbnail.isAllowedExtension(name),
                "expected \(name) to be allowed",
            )
        }
    }

    @Test("Rejected extensions stay out of the thumbnail tier")
    func rejectedExtensionsRejected() {
        for name in [
            "loop.gif", "vec.svg", "next-gen.webp",
            "phone.mov", "clip.mp4", "doc.pdf",
        ] {
            #expect(
                !AttachmentThumbnail.isAllowedExtension(name),
                "expected \(name) to be rejected",
            )
        }
    }

    @Test("Whitelist is strictly narrower than the media-strip tier")
    func whitelistIsNarrowerThanMediaTier() {
        // gif/webp classify as `.mediaStripAndWarn` for SEND-time
        // metadata stripping, but must NOT reach the in-process
        // thumbnail decoder. The gap is intentional — strip pipelines
        // run in AVFoundation / ImageIO sandboxes; the thumbnail
        // decoder runs in Pizzini's process.
        // (Note: removed-from-tier formats like gif now classify as
        // `.textFamily` since 2026-05-11, which is even stricter.)
        #expect(!AttachmentThumbnail.isAllowedExtension("loop.gif"))
        #expect(!AttachmentThumbnail.isAllowedExtension("anim.webp"))
    }

    // MARK: - Helpers

    private func jpegBytes(padTo size: Int) -> Data {
        var bytes = Data([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        if size > bytes.count {
            bytes.append(Data(repeating: 0x00, count: size - bytes.count))
        }
        return bytes
    }

    private func writeFixture(bytes: Data, ext: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("pz-thumb-\(UUID().uuidString).\(ext)")
        try bytes.write(to: url)
        return url
    }
}
