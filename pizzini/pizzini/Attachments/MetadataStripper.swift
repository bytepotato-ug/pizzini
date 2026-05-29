import Foundation
import ImageIO
import UniformTypeIdentifiers
import AVFoundation
import PDFKit

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
/// 1 (text) and Tier 2 (archives) need no stripping. Tier 4: PZ-L5 now
/// strips a PDF's document-info dictionary (author / creator / producer
/// / title / dates) via PDFKit, but XMP packets, annotations, and
/// embedded-font names can still carry identifying data — so the
/// attach-time warning is deliberately KEPT. We clean what we can clean
/// cleanly; we do not claim a fully-scrubbed PDF. Office formats
/// (doc/docx/…) remain warn-only (no reliable in-process scrubber).
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
        let lowerExt = (FilenameSanitizer.trailingExtension(of: filename) ?? "")
            .lowercased()
        // PZ-L5: PDF stays Tier-4 (authorLeakingDoc) for the attach-time
        // warning, but we now strip its document-info dictionary on the
        // way out. Handled before the media-tier guard since PDF is not a
        // mediaStripAndWarn tier.
        if lowerExt == "pdf" {
            return try stripPDFMetadata(data)
        }
        let tier = AttachmentTierClassifier.tier(forFilename: filename)
        guard tier == .mediaStripAndWarn else {
            // Tier 1, 2, the rest of Tier 4 (Office), 5 → pass-through.
            // We don't strip what we don't understand; the warning copy
            // at attach/receive time is the user-facing safety net.
            return data
        }
        if lowerExt == "gif" {
            // PZ-L5: GIF gets a dedicated path — it can carry XMP /
            // comment-extension author/software tags, but its frame
            // timing + loop count live in the GIF property dictionary
            // and must be preserved or the animation breaks.
            return try stripGIFMetadata(data)
        }
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
        // Fall-through: a media-ish extension we don't have a pipeline
        // for. Return as-is; the warning copy still applies.
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

    // MARK: - GIF strip

    /// GIF metadata strip that PRESERVES animation. A plain
    /// `stripImageMetadata` round-trip would drop the container loop
    /// count (a file-level property set via `CGImageDestinationSet
    /// Properties`, not per-frame) and could lose the per-frame delays —
    /// turning an animated GIF into a still or a wrong-speed loop. So we
    /// carry forward ONLY the timing keys (`GIFDelayTime` /
    /// `GIFUnclampedDelayTime` per frame, `GIFLoopCount` at the
    /// container) and drop everything else: the XMP packet plus any
    /// Exif/TIFF/GPS/IPTC dictionaries a tool may have stuffed alongside
    /// (comment-extension software/author tags go with the XMP/metadata
    /// rebuild).
    private static func stripGIFMetadata(_ data: Data) throws -> Data {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil) else {
            throw StripError.decodeFailed
        }
        let gifType = UTType.gif.identifier as CFString
        // Extension said .gif but the bytes aren't a GIF: don't silently
        // transcode into another format (would surprise the recipient).
        guard CGImageSourceGetType(src) == gifType else {
            throw StripError.decodeFailed
        }
        let count = CGImageSourceGetCount(src)
        guard count > 0 else { throw StripError.decodeFailed }

        let outBuf = NSMutableData()
        guard let dst = CGImageDestinationCreateWithData(
            outBuf as CFMutableData, gifType, count, nil
        ) else {
            throw StripError.encodeFailed
        }

        // Container-level: preserve ONLY the loop count (0 == loop
        // forever, the GIF default); drop every other container property.
        let containerProps = CGImageSourceCopyProperties(src, nil) as? [CFString: Any]
        let srcGIF = containerProps?[kCGImagePropertyGIFDictionary] as? [CFString: Any]
        let loopCount = srcGIF?[kCGImagePropertyGIFLoopCount] ?? 0
        CGImageDestinationSetProperties(dst, [
            kCGImagePropertyGIFDictionary: [
                kCGImagePropertyGIFLoopCount: loopCount,
            ],
        ] as CFDictionary)

        for i in 0..<count {
            // Carry forward only the per-frame timing.
            var frameGIF: [CFString: Any] = [:]
            if let props = CGImageSourceCopyPropertiesAtIndex(src, i, nil) as? [CFString: Any],
               let srcFrameGIF = props[kCGImagePropertyGIFDictionary] as? [CFString: Any] {
                if let delay = srcFrameGIF[kCGImagePropertyGIFDelayTime] {
                    frameGIF[kCGImagePropertyGIFDelayTime] = delay
                }
                if let unclamped = srcFrameGIF[kCGImagePropertyGIFUnclampedDelayTime] {
                    frameGIF[kCGImagePropertyGIFUnclampedDelayTime] = unclamped
                }
            }
            let opts: [CFString: Any] = [
                // Drop the XMP packet.
                kCGImageDestinationMetadata: CGImageMetadataCreateMutable(),
                // Keep only timing in the GIF dict.
                kCGImagePropertyGIFDictionary: frameGIF,
                // Belt-and-suspenders: null any fingerprinting dicts.
                kCGImagePropertyExifDictionary: kCFNull as Any,
                kCGImagePropertyTIFFDictionary: kCFNull as Any,
                kCGImagePropertyGPSDictionary: kCFNull as Any,
                kCGImagePropertyIPTCDictionary: kCFNull as Any,
            ]
            CGImageDestinationAddImageFromSource(dst, src, i, opts as CFDictionary)
        }
        guard CGImageDestinationFinalize(dst) else {
            throw StripError.encodeFailed
        }
        return outBuf as Data
    }

    // MARK: - PDF strip

    /// PZ-L5: clear a PDF's document-info dictionary (Author, Creator,
    /// Producer, Title, Subject, Keywords, CreationDate, ModDate) via
    /// PDFKit, then re-serialize. Removes the most common PDF identity
    /// leak — the authoring app + author name + timestamps.
    ///
    /// LIMITATION (why the attach-time warning stays): PDFKit does not
    /// expose the XMP `/Metadata` stream, per-annotation data, or
    /// embedded-font names for removal, so a PDF authored by a tool that
    /// duplicates author/date into XMP may retain it. We strip what we
    /// can cleanly strip; we do not claim a fully-scrubbed PDF.
    private static func stripPDFMetadata(_ data: Data) throws -> Data {
        guard let doc = PDFDocument(data: data) else {
            // Not a parseable PDF (corrupt, or mislabeled). Don't
            // transform bytes we can't open — pass through; the
            // attach-time warning still applies.
            return data
        }
        // Empty (not nil) so the re-serialized PDF carries an empty Info
        // dictionary instead of the original author/app/date fields.
        doc.documentAttributes = [:]
        guard let out = doc.dataRepresentation() else {
            throw StripError.encodeFailed
        }
        return out
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
