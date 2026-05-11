import Foundation
import ImageIO
import UniformTypeIdentifiers
import AVFoundation

/// Strips identifying metadata from media files BEFORE they leave the
/// device. Threat model:
///
/// - **Removable**: EXIF tags (location, timestamp, software,
///   camera make/model + serial), XMP edit-history, IPTC, GPS — anything
///   in container metadata. `CGImageDestination` rebuilds the file
///   without these.
/// - **NOT removable**: PRNU (Photo Response Non-Uniformity) — the
///   sensor's unique noise pattern in the pixel data. Voice-biometric
///   features in audio waveforms. The brief explicitly forbids
///   PRNU-anonymization passes — current research shows
///   detection-of-anonymization wins, and a "this image was anonymized"
///   signal becomes prosecutorial evidence in a leak case. Pizzini's
///   honest answer: strip what we can, surface the un-removable risk
///   in UI copy, recommend a borrowed device for highest-risk material.
///
/// Pass-through is the default for anything we don't recognise — Tier
/// 1 (text) and Tier 2 (archives) need no stripping; Tier 4 (PDF/Office)
/// hides its author info inside the format and the maintainer's
/// decision is "warn the user, do not pretend to clean."
enum MetadataStripper {
    enum StripError: Error {
        case decodeFailed
        case encodeFailed
        case underlying(String)
    }

    /// Top-level entry. Inspects extension/mime to decide which path,
    /// returns the bytes to put on the wire (which may be the input
    /// unchanged for pass-through tiers).
    static func stripped(_ data: Data, filename: String, mimeType: String) throws -> Data {
        let tier = AttachmentTierClassifier.tier(forFilename: filename)
        guard tier == .mediaStripAndWarn else {
            // Tier 1, 2, 4, 5 → pass-through. We don't strip what we
            // don't understand; the warning copy at attach/receive
            // time is the user-facing safety net.
            return data
        }
        let lowerExt = (FilenameSanitizer.trailingExtension(of: filename) ?? "")
            .lowercased()
        if Self.imageExtensions.contains(lowerExt) {
            return try stripImageMetadata(data)
        }
        if Self.audioVideoExtensions.contains(lowerExt) {
            // AV stripping is async + needs a temp file round-trip.
            // The synchronous wrapper `awaitAVStrip` blocks the caller;
            // ChatStore.sendFile dispatches off the main thread before
            // calling.
            return try awaitAVStrip(data, ext: lowerExt)
        }
        // Tier-3 fall-through: a media-ish extension we don't have a
        // pipeline for (e.g. `.gif`). Return as-is; the warning copy
        // still applies.
        return data
    }

    // MARK: - Image strip

    /// CGImageSource → CGImageDestination round-trip with metadata
    /// suppressed. Preserves the pixel data + critical color metadata
    /// (orientation, ICC profile so image renders the same) while
    /// dropping EXIF, GPS, IPTC, XMP, MakerNote, TIFF auxiliaries.
    private static func stripImageMetadata(_ data: Data) throws -> Data {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil) else {
            throw StripError.decodeFailed
        }
        // CGImageDestination needs a UTType — pull it from the source.
        // Falling back to JPEG would change the file format on the
        // wire, surprising the recipient; throw instead.
        guard let typeId = CGImageSourceGetType(src) else {
            throw StripError.decodeFailed
        }
        let count = CGImageSourceGetCount(src)
        guard count > 0 else { throw StripError.decodeFailed }

        let outBuf = NSMutableData()
        guard let dst = CGImageDestinationCreateWithData(
            outBuf as CFMutableData, typeId, count, nil
        ) else {
            throw StripError.encodeFailed
        }

        // Per-image rebuild. Clearing the XMP block alone (via
        // `kCGImageDestinationMetadata`) leaves the EXIF / TIFF / GPS
        // / IPTC / Maker dictionaries intact — those carry GPS, camera
        // serial, software version, the actually fingerprinting tags.
        // Set each of those keys to `kCFNull` to instruct
        // ImageIO to *drop* them on write. Orientation is preserved
        // from the source so the recipient sees the same picture; ICC
        // colour profile is preserved by ImageIO automatically.
        let blank = CGImageMetadataCreateMutable()
        for i in 0..<count {
            var perImageOpts: [CFString: Any] = [
                kCGImageDestinationMetadata: blank,
                kCGImagePropertyExifDictionary: kCFNull as Any,
                kCGImagePropertyTIFFDictionary: kCFNull as Any,
                kCGImagePropertyGPSDictionary: kCFNull as Any,
                kCGImagePropertyIPTCDictionary: kCFNull as Any,
                kCGImagePropertyExifAuxDictionary: kCFNull as Any,
                // Format-specific dictionaries. ImageIO on recent iOS
                // *does* drop PNG `tEXt`/`iTXt`/`zTXt` chunks during a
                // round-trip, but the behaviour is implementation
                // detail, not contract — explicitly clearing the
                // dict pins the strip behavior across iOS releases.
                // PNG carries Author/Copyright/CreationTime/Software
                // in this dictionary; HEICS / JFIF / TGA / WebP have
                // their own dicts that can carry source-app fingerprints.
                kCGImagePropertyPNGDictionary: kCFNull as Any,
                kCGImagePropertyJFIFDictionary: kCFNull as Any,
                kCGImagePropertyHEICSDictionary: kCFNull as Any,
                kCGImagePropertyTGADictionary: kCFNull as Any,
                kCGImagePropertyWebPDictionary: kCFNull as Any,
                kCGImagePropertyMakerCanonDictionary: kCFNull as Any,
                kCGImagePropertyMakerNikonDictionary: kCFNull as Any,
                kCGImagePropertyMakerAppleDictionary: kCFNull as Any,
                kCGImagePropertyMakerMinoltaDictionary: kCFNull as Any,
                kCGImagePropertyMakerOlympusDictionary: kCFNull as Any,
                kCGImagePropertyMakerPentaxDictionary: kCFNull as Any,
                kCGImagePropertyMakerFujiDictionary: kCFNull as Any,
            ]
            if let srcProps = CGImageSourceCopyPropertiesAtIndex(src, i, nil)
                as? [CFString: Any],
               let orientation = srcProps[kCGImagePropertyOrientation]
            {
                perImageOpts[kCGImagePropertyOrientation] = orientation
            }
            CGImageDestinationAddImageFromSource(
                dst, src, i, perImageOpts as CFDictionary
            )
        }
        guard CGImageDestinationFinalize(dst) else {
            throw StripError.encodeFailed
        }
        return outBuf as Data
    }

    // MARK: - Audio / video strip

    /// AVAssetExportSession with an empty `metadata` array. Uses the
    /// passthrough preset to avoid a lossy re-encode — speeds the
    /// strip from "minutes for a 4K clip" to "near-instant", and is
    /// the right semantics: we don't want to alter the recipient's
    /// view of the actual content.
    private static func awaitAVStrip(_ data: Data, ext: String) throws -> Data {
        // AVAssetExportSession needs a file URL on the input side.
        // Stage to a tmp file in `NSTemporaryDirectory` (purged on
        // app death — fine for this transient).
        let tmpDir = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        let inURL = tmpDir.appending(path: "av-in-\(UUID().uuidString).\(ext)", directoryHint: .notDirectory)
        let outURL = tmpDir.appending(path: "av-out-\(UUID().uuidString).\(ext)", directoryHint: .notDirectory)
        defer {
            try? FileManager.default.removeItem(at: inURL)
            try? FileManager.default.removeItem(at: outURL)
        }
        try data.write(to: inURL, options: [.atomic])

        // iOS 18 deprecated `AVAsset(url:)`, `exportAsynchronously(...)`,
        // `session.error`, and `session.status`. Migrated to the
        // async `export(to:as:) async throws` and the explicit
        // `AVURLAsset(url:)` initialiser. The semaphore bridge keeps
        // the sync facade (callers run on `DispatchQueue.global` and
        // aren't async themselves) — sync-over-async is a known
        // anti-pattern, but rewriting every send call-site to async
        // is out of scope for a deprecation cleanup. Localised here
        // so the rest of the codebase keeps its current shape.
        let asset = AVURLAsset(url: inURL)
        guard let session = AVAssetExportSession(
            asset: asset, presetName: AVAssetExportPresetPassthrough
        ) else {
            throw StripError.encodeFailed
        }
        // Empty metadata = exporter writes a fresh container with the
        // a/v tracks but no tags. AVFoundation honours this for the
        // standard Voice Memos / iPhone-camera output formats.
        session.metadata = []
        let outputFileType = avFileType(forExt: ext)

        let semaphore = DispatchSemaphore(value: 0)
        var exportError: Error?
        let task = Task {
            do {
                try await session.export(to: outURL, as: outputFileType)
            } catch {
                exportError = error
            }
            semaphore.signal()
        }
        let waitResult = semaphore.wait(timeout: .now() + 60)
        if waitResult == .timedOut {
            task.cancel()
            throw StripError.underlying("AVAssetExportSession export timed out after 60s")
        }
        if let exportError {
            throw StripError.underlying("\(exportError)")
        }
        return try Data(contentsOf: outURL, options: [.mappedIfSafe])
    }

    private static func avFileType(forExt ext: String) -> AVFileType {
        switch ext.lowercased() {
        case "mov": return .mov
        case "mp4", "m4v": return .mp4
        case "m4a": return .m4a
        case "wav": return .wav
        case "aac": return .m4a // .aac as MP4 audio container; bare ADTS .aac is rare on iOS.
        case "mp3": return .mp3
        default:    return .mp4
        }
    }

    // MARK: - Extension sets

    private static let imageExtensions: Set<String> = [
        "jpg", "jpeg", "png", "heic", "heif", "tiff", "tif", "webp",
    ]
    private static let audioVideoExtensions: Set<String> = [
        "mov", "mp4", "m4v", "m4a", "mp3", "wav", "aac",
    ]
}
