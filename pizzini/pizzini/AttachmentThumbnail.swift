import Foundation
import ImageIO
import SwiftUI
import UIKit

/// Guard set + decode helper for the `.inlineThumbnail` preview tier.
///
/// Pizzini's default rule is "the OS owns the parser." Inline thumbnails
/// break that rule on purpose — they parse a small whitelist of image
/// formats in-process so a chat row can render a visual preview. The
/// guards in this file exist because a parser surface inside the app
/// process is exactly the FORCEDENTRY shape (CVE-2021-30860) and we
/// don't want the user to opt into "tap to preview" and get "scrolled-
/// past = ran your parser."
///
/// Three predicates gate every decode:
///   1. Extension is in `allowedExtensions` (JPEG / PNG / HEIC only).
///   2. File size is at or below `maxByteSize` (5 MB).
///   3. The first bytes match the format's magic-number prefix —
///      `.jpg` extension on a PDF body never reaches `UIImage.init`.
///
/// The actual decode runs on `Task.detached(priority: .utility)` with
/// a 5-second timeout, so a memory-bomb or hang never blocks the main
/// actor. A rendered thumbnail row carries a visible `eye` badge — the
/// user can see at a glance which rows went through Pizzini's parser.
// Every member is `nonisolated` so the guard helpers can run inside a
// `Task.detached` without crossing the file's default main-actor
// isolation. The enum holds only pure functions + immutable
// constants; there is no shared mutable state to protect.
enum AttachmentThumbnail {
    /// Pre-decode size cap. Files larger than this fall back to the
    /// existing Save-to-Files / QuickLook affordances. JPEG / PNG /
    /// HEIC photos straight from a modern phone camera land between
    /// 1.5 and 4 MB; 5 MB covers the common case while keeping a
    /// hard ceiling on memory pressure for a single decode.
    nonisolated static let maxByteSize: UInt64 = 5 * 1024 * 1024

    /// Hard ceiling on a source image's *declared* pixel count, read from
    /// the header before any bitmap is allocated. The 5 MiB byte cap
    /// bounds *encoded* size, not *decoded* size: a few-KiB PNG can
    /// declare 30000×30000 and expand to width×height×4 ≈ 3.6 GB when
    /// fully decoded (a decompression bomb). 100 MP ≈ 400 MiB at 4 B/px
    /// is already well past any legitimate phone photo (~50 MP), so we
    /// refuse anything larger up front (F-ATT-02).
    nonisolated static let maxSourcePixels: UInt64 = 100_000_000

    /// Long-edge ceiling for the downsampled decode. `CGImageSourceCreateThumbnailAtIndex`
    /// produces at most this dimension, so the decoded bitmap is bounded
    /// at ~`thumbnailMaxPixelSize`² × 4 B regardless of the source's
    /// declared size — the "hard ceiling on memory pressure for a single
    /// decode" the byte cap alone never enforced. Large enough that both
    /// the inline 220 pt thumbnail and the full-screen zoom stay crisp.
    nonisolated static let thumbnailMaxPixelSize: Int = 2048

    /// Whether an image whose header declares `width`×`height` may be
    /// decoded in-process. Rejects non-positive dimensions and anything
    /// above `maxSourcePixels`. Pure so it can be unit-tested without
    /// invoking ImageIO.
    nonisolated static func isWithinPixelBudget(width: Int, height: Int) -> Bool {
        guard width > 0, height > 0 else { return false }
        return UInt64(width) * UInt64(height) <= maxSourcePixels
    }

    /// Whitelist of file extensions eligible for in-process decode.
    /// Deliberately narrower than `AttachmentTierClassifier.mediaExtensions`
    /// — GIF / SVG / WebP / video are excluded even though they're
    /// `.mediaStripAndWarn` for send-time stripping. The wider strip
    /// list is fine because the strip pipeline runs in the AVAsset /
    /// ImageIO sandbox; the thumbnail decode runs in our process.
    nonisolated static let allowedExtensions: Set<String> = [
        "jpg", "jpeg", "png", "heic", "heif",
    ]

    nonisolated static func isAllowedExtension(_ filename: String) -> Bool {
        let lower = filename.lowercased()
        let ext = lower.split(separator: ".").last.map(String.init) ?? ""
        return allowedExtensions.contains(ext)
    }

    /// Magic-byte validator. Reads only the prefix bytes, not the full
    /// file, so a malformed body that lies about its extension never
    /// reaches `UIImage(data:)`. JPEG / PNG / HEIC each have a stable
    /// signature in their first 12 bytes.
    ///
    /// - JPEG: `FF D8 FF` at offset 0.
    /// - PNG: `89 50 4E 47 0D 0A 1A 0A` at offset 0.
    /// - HEIC: 4-byte big-endian box length, then `ftyp` at offset 4,
    ///   then a brand code at offset 8 (we accept the HEIC/HEIF brands).
    nonisolated static func hasValidMagic(prefix bytes: Data) -> Bool {
        if bytes.count >= 3,
           bytes[0] == 0xFF, bytes[1] == 0xD8, bytes[2] == 0xFF {
            return true
        }
        if bytes.count >= 8,
           bytes[0] == 0x89, bytes[1] == 0x50, bytes[2] == 0x4E, bytes[3] == 0x47,
           bytes[4] == 0x0D, bytes[5] == 0x0A, bytes[6] == 0x1A, bytes[7] == 0x0A {
            return true
        }
        if bytes.count >= 12,
           bytes[4] == 0x66, bytes[5] == 0x74, bytes[6] == 0x79, bytes[7] == 0x70 {
            let brand = Data(bytes[8..<12])
            if heicBrands.contains(brand) {
                return true
            }
        }
        return false
    }

    /// HEIC `ftyp` brand codes we accept. Apple writes `heic` for
    /// single images and `heix` for higher-bit-depth variants; `mif1`
    /// is the generic HEIF still-image brand emitted by some encoders.
    /// `hevc`/`hevx` are HEVC video and are NOT accepted — the
    /// extension whitelist already excludes video, and the brand
    /// check is the second layer of that.
    nonisolated private static let heicBrands: Set<Data> = [
        Data("heic".utf8),
        Data("heix".utf8),
        Data("mif1".utf8),
    ]

    /// Decode `data` to a `UIImage` on a detached utility task with a
    /// 5-second wall-clock timeout. Returns nil if the decode failed,
    /// timed out, or any guard tripped. The caller has already done
    /// the whitelist + magic-byte + size checks; this function adds
    /// the timeout and process-isolation layer.
    nonisolated static func decode(_ data: Data) async -> UIImage? {
        let task = Task.detached(priority: .utility) { () -> UIImage? in
            downsample(data)
        }
        let timeout = Task.detached(priority: .utility) { () -> UIImage? in
            try? await Task.sleep(nanoseconds: 5 * 1_000_000_000)
            return nil
        }
        let result = await withTaskGroup(of: UIImage?.self, returning: UIImage?.self) { group in
            group.addTask { await task.value }
            group.addTask { await timeout.value }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
        task.cancel()
        timeout.cancel()
        return result
    }

    /// Decode `data` to a downsampled `UIImage` via ImageIO. Unlike
    /// `UIImage(data:)`, this (1) reads the declared pixel dimensions from
    /// the header and refuses anything over `maxSourcePixels` before a
    /// bitmap is allocated, and (2) asks ImageIO for a thumbnail capped at
    /// `thumbnailMaxPixelSize` on the long edge — so the decoded buffer is
    /// bounded regardless of the source's declared dimensions (F-ATT-02).
    nonisolated private static func downsample(_ data: Data) -> UIImage? {
        let sourceOptions: [CFString: Any] = [kCGImageSourceShouldCache: false]
        guard let source = CGImageSourceCreateWithData(data as CFData, sourceOptions as CFDictionary) else {
            return nil
        }
        // Reject decompression bombs by declared dimensions BEFORE
        // decoding any pixels. A header with no usable dimensions is not
        // trusted — fail closed.
        guard let props = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
              let width = props[kCGImagePropertyPixelWidth] as? Int,
              let height = props[kCGImagePropertyPixelHeight] as? Int,
              isWithinPixelBudget(width: width, height: height)
        else {
            return nil
        }
        let thumbOptions: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
            kCGImageSourceThumbnailMaxPixelSize: thumbnailMaxPixelSize,
        ]
        guard let cg = CGImageSourceCreateThumbnailAtIndex(source, 0, thumbOptions as CFDictionary) else {
            return nil
        }
        return UIImage(cgImage: cg)
    }

    /// One-shot guard: applies every pre-decode predicate (whitelist,
    /// size cap, magic bytes) without ever invoking `UIImage(data:)`.
    /// Used by the row to decide whether to even show the "Show
    /// preview" affordance — a row whose filename or size disqualifies
    /// it falls back to the existing Save / QuickLook affordance set.
    nonisolated static func canAttempt(filename: String, byteSize: UInt64, url: URL?) -> Bool {
        guard isAllowedExtension(filename) else { return false }
        guard byteSize <= maxByteSize else { return false }
        guard let url else { return false }
        guard let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        guard let prefix = try? handle.read(upToCount: 16) else { return false }
        return hasValidMagic(prefix: prefix)
    }
}

/// SwiftUI view that owns the placeholder → tap → decode → render flow
/// for a Tier-3 attachment row. The decode never auto-fires on scroll;
/// the user must tap the "Show preview" affordance. A successful render
/// stamps a small `eye` badge on the result so the user can see which
/// bubbles went through Pizzini's parser.
struct InlineThumbnailView: View {
    let url: URL
    let byteSize: UInt64
    let filename: String

    @State private var decoded: UIImage?
    @State private var failed = false
    @State private var inFlight = false
    @State private var expanded = false

    var body: some View {
        Group {
            if let img = decoded {
                renderedThumbnail(img)
            } else if failed {
                placeholder(text: "Couldn't render preview — save and open instead.")
            } else if inFlight {
                placeholder(text: "Decoding…")
            } else {
                Button(action: triggerDecode) {
                    placeholder(text: "Show preview")
                }
                .buttonStyle(.plain)
            }
        }
    }

    private func placeholder(text: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "photo")
                .foregroundStyle(.secondary)
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
            Spacer()
            Image(systemName: "hand.tap")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color(.tertiarySystemFill))
        )
    }

    @ViewBuilder
    private func renderedThumbnail(_ img: UIImage) -> some View {
        let thumb = Image(uiImage: img)
            .resizable()
            .aspectRatio(contentMode: .fit)
            .frame(maxHeight: 220)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(alignment: .topTrailing) {
                Image(systemName: "eye")
                    .font(.caption2.weight(.semibold))
                    .padding(4)
                    .background(.ultraThinMaterial, in: Circle())
                    .padding(6)
                    .accessibilityLabel("Rendered by Pizzini's parser")
            }
        thumb
            .onTapGesture { expanded = true }
            .fullScreenCover(isPresented: $expanded) {
                ZoomableImageSheet(image: img, dismiss: { expanded = false })
            }
    }

    private func triggerDecode() {
        guard !inFlight else { return }
        inFlight = true
        Task {
            // Re-read the bytes off the main actor; the size cap was
            // already enforced by `canAttempt` but we re-check the
            // magic prefix before handing the full buffer to UIImage
            // in case the on-disk file was swapped between gate check
            // and decode (defensive — the sandbox path is per-message
            // and not user-writable, but the cost of re-checking is a
            // 16-byte read).
            let data: Data? = await Task.detached(priority: .utility) {
                guard let bytes = try? Data(contentsOf: url) else { return Data?.none }
                guard bytes.count <= AttachmentThumbnail.maxByteSize else { return nil }
                guard AttachmentThumbnail.hasValidMagic(prefix: bytes.prefix(16)) else { return nil }
                return bytes
            }.value
            guard let data else {
                failed = true
                inFlight = false
                return
            }
            let image = await AttachmentThumbnail.decode(data)
            if let image {
                decoded = image
            } else {
                failed = true
            }
            inFlight = false
        }
    }
}

private struct ZoomableImageSheet: View {
    let image: UIImage
    let dismiss: () -> Void

    var body: some View {
        ZStack(alignment: .topTrailing) {
            // Shield the decoded image content only. `.fullScreenCover`
            // presents above the chat-level shield, and live recording
            // is a separate pipeline from the window-level mask, so the
            // full-screen image needs its own shield. The dismiss
            // button is deliberately kept OUTSIDE the shield: an opaque
            // shield over the viewer's only exit would trap the user in
            // the full-screen view while a recording / external display
            // is active.
            ZStack {
                Color.black.ignoresSafeArea()
                Image(uiImage: image)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .ignoresSafeArea()
            }
            .screenCaptureShielded()
            Button(action: dismiss) {
                Image(systemName: "xmark.circle.fill")
                    .font(.title)
                    .foregroundStyle(.white, .black.opacity(0.4))
                    .padding()
            }
        }
    }
}
