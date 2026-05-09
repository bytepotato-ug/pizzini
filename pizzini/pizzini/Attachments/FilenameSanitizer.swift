import Foundation

/// Always-on filename sanitization for both inbound and outbound
/// attachments. Filenames are user-rendered strings that can carry
/// attacks — RTL-override codepoints (U+202E) flipping `report‮gpj.exe`
/// to display as `report.exe.jpg`, path separators escaping the sandbox,
/// length-bomb names from a malicious sender. We normalise once at the
/// boundary so every later layer (UI, sandbox path, save-to-Files
/// presentation) gets a flat, well-formed name.
enum FilenameSanitizer {
    /// Maximum byte length of the sanitized name (pre-UTF-8). 255 matches
    /// the HFS+/APFS filesystem cap and keeps the saved file from ever
    /// being rejected by the OS at write time.
    static let maxLength = 255
    /// Default name when sanitization strips the input down to nothing.
    /// "untitled" is the same fallback Apple's own document apps use, so
    /// the recipient sees something familiar when they hit Save to Files.
    static let fallbackName = "untitled"

    /// Strip path separators, normalise Unicode, drop bidi-override
    /// codepoints + control codes, and cap length while preserving the
    /// last extension. Idempotent: `sanitize(sanitize(x)) == sanitize(x)`.
    static func sanitize(_ raw: String) -> String {
        let normalized = raw.precomposedStringWithCanonicalMapping
        var scrubbed = ""
        scrubbed.reserveCapacity(normalized.count)
        for scalar in normalized.unicodeScalars {
            // Bidi-override + isolate codepoints (U+202A–U+202E,
            // U+2066–U+2069). The RTL-override attack hides a real
            // extension behind a fake one in the rendered name; the
            // bytes are still `report.exe.jpg` but the display reverses
            // a chunk so the user sees `report.jpg`. Every reputable
            // mail client strips these in attachment names and Pizzini
            // does too.
            switch scalar.value {
            case 0x202A...0x202E, 0x2066...0x2069:
                continue
            default:
                break
            }
            // Path separators (forward + backslash + null). Forward
            // slash is the obvious one; backslash matters because
            // Save to Files presents to other apps that may run on
            // macOS / Windows-mounted filesystems where `\` separates.
            // Null bytes terminate C strings and can confuse anything
            // unwrapping our name through a low-level API.
            switch scalar {
            case "/", "\\", "\0":
                continue
            default:
                break
            }
            // Strip ASCII control codes (TAB, LF, CR, ESC, DEL, …).
            // They're invisible in most renderers but show up as
            // squares / boxes in some — and they can break terminal
            // pasteboard flows.
            if scalar.value < 0x20 || scalar.value == 0x7F { continue }
            scrubbed.unicodeScalars.append(scalar)
        }

        // Strip leading dots so a sender can't ship `.htaccess` /
        // `.bashrc` looking files that hide on Unix `ls` output.
        while scrubbed.hasPrefix(".") {
            scrubbed.removeFirst()
        }
        scrubbed = scrubbed.trimmingCharacters(in: .whitespaces)
        if scrubbed.isEmpty { return fallbackName }

        // Length cap. Preserve the final extension if there is one so
        // the OS still picks the right Save-to-Files default app.
        let utf8Count = scrubbed.utf8.count
        if utf8Count <= maxLength { return scrubbed }
        let extPart = trailingExtension(of: scrubbed)
        let extWithDot = extPart.map { "." + $0 } ?? ""
        let extByteLen = extWithDot.utf8.count
        let stemBudget = maxLength - extByteLen
        // Pathological input where the extension itself overflows the
        // cap — rare (extension >245 bytes) but we still produce
        // something usable rather than erroring out.
        guard stemBudget > 0 else {
            return String(scrubbed.prefix(maxLength))
        }
        let stem: String
        if let extPart, scrubbed.hasSuffix("." + extPart) {
            stem = String(scrubbed.dropLast(extPart.count + 1))
        } else {
            stem = scrubbed
        }
        // Truncate the stem to fit, walking BYTE budget — Swift's
        // `prefix(_:Int)` is character-based and a single emoji can
        // burn 4 bytes, so we trim from the back until utf8Count fits.
        var truncatedStem = stem
        while truncatedStem.utf8.count > stemBudget {
            truncatedStem.removeLast()
        }
        return truncatedStem + extWithDot
    }

    /// Returns the final extension if any, e.g. `"jpg"` for
    /// `"photo.jpg"`. Nil if the name has no `.` or only a leading
    /// `.foo` (which we strip in `sanitize` anyway).
    static func trailingExtension(of name: String) -> String? {
        guard let dot = name.lastIndex(of: ".") else { return nil }
        let after = name.index(after: dot)
        guard after < name.endIndex else { return nil }
        let ext = String(name[after...])
        return ext.isEmpty ? nil : ext
    }
}
