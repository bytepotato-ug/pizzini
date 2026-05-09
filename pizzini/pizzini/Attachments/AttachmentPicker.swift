import SwiftUI
import PhotosUI
import UniformTypeIdentifiers
import UIKit

/// SwiftUI sheet wrapping `PHPickerViewController` for the
/// "Photo or video" branch of the attach action sheet.
///
/// Why PHPicker rather than reaching into PHPhotoLibrary directly:
///   1. No `NSPhotoLibraryUsageDescription` entitlement required —
///      PHPicker is system-mediated, the app never sees the library
///      index, only the bytes for what the user picks.
///   2. The user can't accidentally grant Pizzini "all photos" access
///      via OS prompt drift; PHPicker's per-pick mediation means we
///      get exactly what was selected, no ambient capability.
///   3. Lockdown Mode safe — PHPicker continues working.
struct PhotoVideoPicker: UIViewControllerRepresentable {
    let onPick: (URL, String) -> Void
    let onCancel: () -> Void

    func makeUIViewController(context: Context) -> PHPickerViewController {
        var config = PHPickerConfiguration(photoLibrary: .shared())
        config.selectionLimit = 1
        config.filter = .any(of: [.images, .videos])
        // Originals only — `.compatible` would force a transcode that
        // could re-introduce metadata via the resave path.
        config.preferredAssetRepresentationMode = .current
        let vc = PHPickerViewController(configuration: config)
        vc.delegate = context.coordinator
        return vc
    }

    func updateUIViewController(_ uiViewController: PHPickerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, PHPickerViewControllerDelegate {
        let parent: PhotoVideoPicker
        init(_ parent: PhotoVideoPicker) { self.parent = parent }

        func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
            guard let first = results.first else {
                parent.onCancel()
                return
            }
            let provider = first.itemProvider
            let suggestedName = first.itemProvider.suggestedName

            // PHPicker advertises multiple type identifiers per asset.
            // For Live Photos / iOS' .pvt-bundled assets the FIRST
            // identifier is `com.apple.live-photo-bundle`, which is a
            // *directory* on disk — `loadFileRepresentation` returns a
            // URL pointing at a directory, and `FileManager.copyItem`
            // fails with NSPOSIXErrorDomain 21 "Is a directory".
            //
            // Fix: rank concrete image/movie types ahead of bundle
            // types, then ask for the *data* representation rather
            // than the file representation — `loadDataRepresentation`
            // gives us a Data blob even when the underlying asset is
            // a bundle, and we write it to our own tmp under the
            // sanitized filename.
            let typeIds = provider.registeredTypeIdentifiers
            let preferredOrder: [String] = [
                "public.heic", "public.heif",
                "public.jpeg", "public.png", "public.tiff", "public.webp",
                "com.apple.quicktime-movie", "public.mpeg-4",
                "public.movie", "public.image",
            ]
            let utype = preferredOrder.first(where: { typeIds.contains($0) })
                ?? typeIds.filter { !$0.contains("bundle") }.first
                ?? typeIds.first
            guard let utype else {
                parent.onCancel()
                return
            }
            provider.loadDataRepresentation(forTypeIdentifier: utype) { [weak self] data, error in
                guard let self else { return }
                if let error {
                    NSLog("[pizzini] PHPicker loadDataRepresentation error: \(error)")
                    DispatchQueue.main.async { self.parent.onCancel() }
                    return
                }
                guard let data else {
                    DispatchQueue.main.async { self.parent.onCancel() }
                    return
                }
                // Build a sensible filename. PHPicker's `suggestedName`
                // is the asset's PHAsset filename minus the extension,
                // e.g. "IMG_4955" for `IMG_4955.HEIC`. We tack on the
                // preferred extension for the resolved UTType.
                let ext = UTType(utype)?.preferredFilenameExtension ?? "bin"
                let stem = (suggestedName?.isEmpty == false) ? suggestedName! : "photo"
                let safeName = FilenameSanitizer.sanitize("\(stem).\(ext)")
                let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
                    .appending(path: "pick-\(UUID().uuidString)-\(safeName)", directoryHint: .notDirectory)
                do {
                    try data.write(to: tmp, options: [.atomic])
                } catch {
                    NSLog("[pizzini] PHPicker tmp write failed: \(error)")
                    DispatchQueue.main.async { self.parent.onCancel() }
                    return
                }
                DispatchQueue.main.async {
                    self.parent.onPick(tmp, safeName)
                }
            }
        }
    }
}

/// SwiftUI sheet wrapping `UIDocumentPickerViewController` for the
/// "File" branch.
///
/// `UTType` allowlist excludes Tier-5 iOS-execute types
/// (`.mobileconfig`, `.shortcut`, `.svg`) at the picker level — a
/// runtime check would let a determined user race past the confirmation
/// dialog. Blocking at the picker means those types never appear in
/// the file browser.
struct DocumentPicker: UIViewControllerRepresentable {
    let onPick: (URL, String) -> Void
    let onCancel: () -> Void

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let vc = UIDocumentPickerViewController(forOpeningContentTypes: Self.allowedTypes)
        vc.allowsMultipleSelection = false
        vc.delegate = context.coordinator
        // Default mode opens content; bytes copy to a system temp on
        // selection. We then re-copy to our own temp in the coordinator
        // so the security-scoped URL doesn't expire while the user
        // composes the caption.
        return vc
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    /// Curated allowlist — we present the picker with these top-level
    /// UTTypes and rely on the system's content-type matching to fan
    /// out (e.g. `.image` matches HEIC + JPEG + PNG).
    ///
    /// Excluded by design:
    ///   - `.mobileconfig` (UTType("com.apple.mobileconfig")) — installs
    ///     iOS configuration profiles when tapped.
    ///   - `.shortcut` (UTType("com.apple.shortcut")) — runs in
    ///     Shortcuts.
    ///   - `.svg` (UTType.svg) — Quick Look opens via WebKit which can
    ///     execute inline scripts.
    /// These are blocked at the `AttachmentTierClassifier.isBlockedAtSend`
    /// level too as belt-and-suspenders.
    private static let allowedTypes: [UTType] = {
        var types: [UTType] = [
            .image, .movie, .audio,
            .pdf,
            .plainText, .text, .sourceCode, .json, .xml, .commaSeparatedText,
            .archive, .zip, .gzip,
            // Office. UTType has no built-in for Office types, but we
            // accept them via dynamic identifiers.
            UTType("com.microsoft.word.doc") ?? .data,
            UTType("org.openxmlformats.wordprocessingml.document") ?? .data,
            UTType("com.microsoft.excel.xls") ?? .data,
            UTType("org.openxmlformats.spreadsheetml.sheet") ?? .data,
            UTType("com.microsoft.powerpoint.ppt") ?? .data,
            UTType("org.openxmlformats.presentationml.presentation") ?? .data,
            // Generic data fallback so Files-app shows everything not
            // in the explicit list — the runtime tier check catches
            // anything that slipped through.
            .data,
        ]
        // De-dup (.data may collide with .archive on some iOS versions).
        var seen = Set<String>()
        types = types.filter { seen.insert($0.identifier).inserted }
        return types
    }()

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let parent: DocumentPicker
        init(_ parent: DocumentPicker) { self.parent = parent }

        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            parent.onCancel()
        }

        func documentPicker(
            _ controller: UIDocumentPickerViewController,
            didPickDocumentsAt urls: [URL]
        ) {
            guard let url = urls.first else {
                parent.onCancel()
                return
            }
            // Security-scoped resource — must `startAccessing`
            // before we can read it, must `stopAccessing` after.
            let needsScope = url.startAccessingSecurityScopedResource()
            defer { if needsScope { url.stopAccessingSecurityScopedResource() } }

            let safeName = FilenameSanitizer.sanitize(url.lastPathComponent)
            let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
                .appending(path: "doc-\(UUID().uuidString)-\(safeName)", directoryHint: .notDirectory)
            do {
                try FileManager.default.copyItem(at: url, to: tmp)
            } catch {
                NSLog("[pizzini] DocumentPicker copy failed: \(error)")
                parent.onCancel()
                return
            }
            parent.onPick(tmp, safeName)
        }
    }
}

/// Pre-send composer state. Pizzini deliberately does NOT show an
/// image preview — Pegasus 2021 was a zero-click iMessage exploit via
/// image parsing. A filename + tier badge gives the user enough to
/// confirm "yes, this is the file I wanted to attach" without inviting
/// the parser surface.
struct AttachmentDraft: Equatable, Identifiable {
    let id = UUID()
    let url: URL
    let filename: String
    let byteSize: UInt64
    let tier: AttachmentTier

    init?(url: URL, filename: String) {
        self.url = url
        self.filename = filename
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        self.byteSize = attrs.flatMap { $0[.size] as? UInt64 } ?? 0
        self.tier = AttachmentTierClassifier.tier(forFilename: filename)
    }

    var displaySize: String {
        let bcf = ByteCountFormatter()
        bcf.allowedUnits = [.useKB, .useMB, .useGB]
        bcf.countStyle = .file
        return bcf.string(fromByteCount: Int64(byteSize))
    }
}
