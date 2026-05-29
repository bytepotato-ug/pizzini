import Foundation
import Testing
import ImageIO
import UniformTypeIdentifiers
@testable import pizzini

/// PZ-L5: GIFs are now metadata-stripped before send. The strip must
/// drop identifying metadata (XMP / comment author tags) WITHOUT
/// breaking the animation — frame count, per-frame delays, and the
/// container loop count must survive. Pure ImageIO; runs on the sim.
@Suite("PZ-L5 GIF metadata strip")
struct MetadataStripperGIFTests {
    // MARK: fixtures

    private func makeSolidImage(gray: Double) -> CGImage {
        let ctx = CGContext(
            data: nil, width: 2, height: 2, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        )!
        ctx.setFillColor(red: gray, green: gray, blue: gray, alpha: 1)
        ctx.fill(CGRect(x: 0, y: 0, width: 2, height: 2))
        return ctx.makeImage()!
    }

    private func makeAnimatedGIF(frames: Int, loopCount: Int, delay: Double) -> Data {
        let out = NSMutableData()
        let dst = CGImageDestinationCreateWithData(
            out, UTType.gif.identifier as CFString, frames, nil
        )!
        CGImageDestinationSetProperties(dst, [
            kCGImagePropertyGIFDictionary: [kCGImagePropertyGIFLoopCount: loopCount],
        ] as CFDictionary)
        for i in 0..<frames {
            CGImageDestinationAddImage(dst, makeSolidImage(gray: Double(i) / Double(frames)), [
                kCGImagePropertyGIFDictionary: [kCGImagePropertyGIFDelayTime: delay],
            ] as CFDictionary)
        }
        #expect(CGImageDestinationFinalize(dst))
        return out as Data
    }

    /// A valid 1-frame GIF with a hand-injected Comment Extension
    /// (`0x21 0xFE …`) carrying `comment`. ImageIO won't *write* GIF XMP
    /// via `CGImageDestinationAddImageAndMetadata` (it silently drops
    /// it — a fixture built that way is only ~68 bytes with no tag), so
    /// we inject a comment block straight into the byte stream: a real
    /// GIF metadata surface we fully control.
    private func makeGIFWithComment(_ comment: String) -> Data {
        var bytes = [UInt8](makeAnimatedGIF(frames: 1, loopCount: 0, delay: 0.1))
        let ascii = Array(comment.utf8)
        precondition(ascii.count < 256)
        // Comment Extension: introducer 0x21, comment label 0xFE, one
        // length-prefixed sub-block, block terminator 0x00.
        var block: [UInt8] = [0x21, 0xFE, UInt8(ascii.count)]
        block.append(contentsOf: ascii)
        block.append(0x00)
        // Insert just before the GIF trailer (0x3B) — a valid trailing
        // data block a compliant parser skips.
        if bytes.last == 0x3B {
            bytes.insert(contentsOf: block, at: bytes.count - 1)
        } else {
            bytes.append(contentsOf: block)
        }
        return Data(bytes)
    }

    /// Search the raw container bytes for an ASCII marker. The XMP
    /// Application Extension in a GIF is an ASCII packet, so an embedded
    /// author tag is findable directly in the bytes — more robust than
    /// the read-back API, which for GIF surfaces XMP inconsistently
    /// (container- vs frame-level).
    private func bytesContain(_ data: Data, _ marker: String) -> Bool {
        String(decoding: data, as: UTF8.self).contains(marker)
    }

    // MARK: tests

    @Test("strip preserves frame count, loop count, and per-frame delay")
    func animationPreserved() throws {
        let original = makeAnimatedGIF(frames: 3, loopCount: 5, delay: 0.2)
        let stripped = try MetadataStripper.stripped(
            original, filename: "anim.gif", mimeType: "image/gif"
        )
        let src = try #require(CGImageSourceCreateWithData(stripped as CFData, nil))
        // Still a GIF (not transcoded to another format).
        #expect(CGImageSourceGetType(src) == UTType.gif.identifier as CFString)
        // Frames preserved.
        #expect(CGImageSourceGetCount(src) == 3)
        // Loop count preserved.
        let props = CGImageSourceCopyProperties(src, nil) as? [CFString: Any]
        let gif = props?[kCGImagePropertyGIFDictionary] as? [CFString: Any]
        #expect((gif?[kCGImagePropertyGIFLoopCount] as? Int) == 5)
        // Per-frame delay preserved (within GIF's centisecond quantization).
        let frameProps = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as? [CFString: Any]
        let frameGif = frameProps?[kCGImagePropertyGIFDictionary] as? [CFString: Any]
        let delay = (frameGif?[kCGImagePropertyGIFDelayTime] as? Double) ?? -1
        #expect(abs(delay - 0.2) < 0.05, "delay was \(delay)")
    }

    @Test("strip removes an embedded GIF comment-extension tag")
    func commentExtensionRemoved() throws {
        let dirty = makeGIFWithComment("SECRET-AUTHOR-7f3a")
        // Precondition 1: the comment is really in the bytes (else the
        // test would pass vacuously).
        #expect(
            bytesContain(dirty, "SECRET-AUTHOR-7f3a"),
            "fixture must embed the comment for this test to mean anything",
        )
        // Precondition 2: the doctored GIF still parses, so the strip's
        // round-trip is actually exercised (not just rejected outright).
        let dirtySrc = try #require(CGImageSourceCreateWithData(dirty as CFData, nil))
        #expect(CGImageSourceGetCount(dirtySrc) == 1)

        let stripped = try MetadataStripper.stripped(
            dirty, filename: "x.gif", mimeType: "image/gif"
        )
        #expect(
            !bytesContain(stripped, "SECRET-AUTHOR-7f3a"),
            "the comment must not survive the strip",
        )
        // Still a valid single-frame GIF.
        let src = try #require(CGImageSourceCreateWithData(stripped as CFData, nil))
        #expect(CGImageSourceGetType(src) == UTType.gif.identifier as CFString)
        #expect(CGImageSourceGetCount(src) == 1)
    }
}
