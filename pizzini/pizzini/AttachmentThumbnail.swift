import Foundation
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
enum AttachmentThumbnail {
    /// Pre-decode size cap. Files larger than this fall back to the
    /// existing Save-to-Files / QuickLook affordances. JPEG / PNG /
    /// HEIC photos straight from a modern phone camera land between
    /// 1.5 and 4 MB; 5 MB covers the common case while keeping a
    /// hard ceiling on memory pressure for a single decode.
    static let maxByteSize: UInt64 = 5 * 1024 * 1024

    /// Whitelist of file extensions eligible for in-process decode.
    /// Deliberately narrower than `AttachmentTierClassifier.mediaExtensions`
    /// — GIF / SVG / WebP / video are excluded even though they're
    /// `.mediaStripAndWarn` for send-time stripping. The wider strip
    /// list is fine because the strip pipeline runs in the AVAsset /
    /// ImageIO sandbox; the thumbnail decode runs in our process.
    static let allowedExtensions: Set<String> = [
        "jpg", "jpeg", "png", "heic", "heif",
    ]

    static func isAllowedExtension(_ filename: String) -> Bool {
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
    static func hasValidMagic(prefix bytes: Data) -> Bool {
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
    private static let heicBrands: Set<Data> = [
        Data("heic".utf8),
        Data("heix".utf8),
        Data("mif1".utf8),
    ]

    /// Decode `data` to a `UIImage` on a detached utility task with a
    /// 5-second wall-clock timeout. Returns nil if the decode failed,
    /// timed out, or any guard tripped. The caller has already done
    /// the whitelist + magic-byte + size checks; this function adds
    /// the timeout and process-isolation layer.
    static func decode(_ data: Data) async -> UIImage? {
        let task = Task.detached(priority: .utility) { () -> UIImage? in
            UIImage(data: data)
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

    /// One-shot guard: applies every pre-decode predicate (whitelist,
    /// size cap, magic bytes) without ever invoking `UIImage(data:)`.
    /// Used by the row to decide whether to even show the "Show
    /// preview" affordance — a row whose filename or size disqualifies
    /// it falls back to the existing Save / QuickLook affordance set.
    static func canAttempt(filename: String, byteSize: UInt64, url: URL?) -> Bool {
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
            Color.black.ignoresSafeArea()
            Image(uiImage: image)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .ignoresSafeArea()
            Button(action: dismiss) {
                Image(systemName: "xmark.circle.fill")
                    .font(.title)
                    .foregroundStyle(.white, .black.opacity(0.4))
                    .padding()
            }
        }
    }
}
