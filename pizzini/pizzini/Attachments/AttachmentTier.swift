import Foundation
import UniformTypeIdentifiers

/// Attachment-tier classification. Pizzini transports opaque bytes; the
/// tier governs only the **UI** behaviour at attach- and receive-time and
/// whether `MetadataStripper` will try to scrub the bytes before they go
/// on the wire.
///
/// - **textFamily** — text/source/structured-data. No author-leaking
///   metadata convention; UI shows nothing extra.
/// - **archive** — risk lives inside the container; recipient extractor's
///   problem.
/// - **mediaStripAndWarn** — image/video/audio. Strip metadata pre-send
///   (EXIF, GPS, camera serial, edit history). Surface the PRNU /
///   voice-biometric warning at attach AND receive — the sensor / vocal-
///   tract fingerprint in the *pixels / waveform* is unremovable.
/// - **authorLeakingDoc** — PDF / Office. Recipient banner: "may contain
///   hidden author info — sanitize on a desktop first." (Reality Winner
///   case, 2017: TheIntercept's leaked PDF carried printer-tracking dots.)
/// - **codeOnTap** — files that *execute on tap* on iOS (`.mobileconfig`,
///   `.shortcut`, `.svg` via Quick Look's WebKit path). Block at the
///   picker so a journalist cannot accidentally ship one. Desktop-execute
///   types (`.exe`, `.dll`, `.bat`, `.command`, `.applescript`) get a
///   red banner on receive — they won't run on iOS, but a journalist
///   forwarding to a desktop colleague matters.
enum AttachmentTier: String, Codable, Sendable {
    case textFamily
    case archive
    case mediaStripAndWarn
    case authorLeakingDoc
    case codeOnTap
}

enum AttachmentTierClassifier {
    /// Classify a file by its (already-sanitized) filename. We classify on
    /// the *extension* rather than libmagic-style sniffing for two
    /// reasons:
    ///   1. Sniffing requires reading the file, which the strict "never
    ///      parse" rule forbids beyond what metadata stripping demands.
    ///   2. Recipient-side tier display is whatever the sender's filename
    ///      claimed; we already commit to "OS owns what's inside" once
    ///      the user taps Save to Files.
    static func tier(forFilename filename: String) -> AttachmentTier {
        let lower = filename.lowercased()
        let ext: String
        if let dot = lower.lastIndex(of: ".") {
            ext = String(lower[lower.index(after: dot)...])
        } else {
            ext = ""
        }
        if codeOnTapExtensions.contains(ext) { return .codeOnTap }
        if authorLeakingExtensions.contains(ext) { return .authorLeakingDoc }
        if mediaExtensions.contains(ext) { return .mediaStripAndWarn }
        if archiveExtensions.contains(ext) { return .archive }
        // Default everything else to text-family. The picker's UTType
        // allowlist already keeps Tier-5 out; opaque "unknown" types
        // landing here cost the user nothing — Pizzini doesn't preview,
        // OS owns the open path.
        return .textFamily
    }

    /// Picker-time gate: `true` blocks at the `UTType` allowlist level
    /// (not a runtime check the user can race past). Maintains parity
    /// with the receive-side red banner for desktop-executes; the
    /// difference is the iOS-tap-executes are blocked at send while
    /// desktop-executes pass through (recipient may still legitimately
    /// be archiving a binary they were sent for analysis).
    static func isBlockedAtSend(filename: String) -> Bool {
        let lower = filename.lowercased()
        let ext = lower.split(separator: ".").last.map(String.init) ?? ""
        return iosExecuteOnTapExtensions.contains(ext)
    }

    /// Tier-5 desktop-execute extensions. These pass the sender gate but
    /// receive a red banner on the recipient side. (`.app` is a directory
    /// in macOS but is shipped as `.zip` in practice — included for
    /// completeness against a sender who tarred one up.)
    private static let desktopExecuteExtensions: Set<String> = [
        "exe", "dll", "bat", "cmd", "command", "applescript", "scpt", "app",
        "msi", "ps1", "vbs", "jar",
    ]

    /// Tier-5 iOS-execute-on-tap extensions. These are BLOCKED at the
    /// picker. `.mobileconfig` installs profiles; `.shortcut` runs in
    /// Shortcuts; `.svg` opens via WebKit and can carry inline scripts.
    private static let iosExecuteOnTapExtensions: Set<String> = [
        "mobileconfig", "shortcut", "svg",
    ]

    /// Union of both Tier-5 sets — receive-side classifier returns
    /// `.codeOnTap` for either, but only iOS-execute is blocked at send.
    private static let codeOnTapExtensions: Set<String> = {
        var s = iosExecuteOnTapExtensions
        s.formUnion(desktopExecuteExtensions)
        return s
    }()

    /// Tier-4: warn on receive. PDF + Office + iWork + ePub.
    private static let authorLeakingExtensions: Set<String> = [
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "iwa", "pages", "numbers", "key", "epub",
    ]

    /// Tier-3: strip + warn. Common mobile-camera output formats plus
    /// the audio formats Voice Memos / WhatsApp / Signal default to.
    private static let mediaExtensions: Set<String> = [
        "jpg", "jpeg", "heic", "heif", "png", "webp", "gif", "tiff", "tif",
        "mp4", "mov", "m4v", "avi", "webm",
        "mp3", "m4a", "wav", "aac", "ogg", "flac", "opus", "amr",
    ]

    /// Tier-2: archives. No stripping; risk lives in contents.
    private static let archiveExtensions: Set<String> = [
        "zip", "7z", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "rar",
    ]

    /// Receive-side helper: is this filename a desktop-execute that we
    /// should red-banner even though it can't run on iOS itself?
    static func isDesktopExecutable(filename: String) -> Bool {
        let lower = filename.lowercased()
        let ext = lower.split(separator: ".").last.map(String.init) ?? ""
        return desktopExecuteExtensions.contains(ext)
    }
}
