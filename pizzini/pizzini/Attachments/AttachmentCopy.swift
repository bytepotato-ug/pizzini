import Foundation

/// One source of truth for tier-specific UI copy. Both attach-time
/// (composer warning banner) and receive-time (chat row banner) read
/// from here so the message can't drift between the two surfaces.
///
/// Wording is the maintainer's: explicit about what we strip, explicit
/// about what we cannot. The PRNU note in particular is the recommended
/// copy from the brief — surfacing the un-removable risk at attach AND
/// receive is the entire point.
enum AttachmentCopy {
    /// Banner shown above the composer once an attachment is selected.
    static func attachWarning(forTier tier: AttachmentTier) -> String? {
        switch tier {
        case .textFamily, .archive:
            return nil
        case .mediaStripAndWarn:
            return """
            Metadata removed (location, camera, edit history). The camera's \
            sensor leaves a fingerprint in the pixels we cannot remove — \
            for highest-risk material, use a borrowed device.
            """
        case .authorLeakingDoc:
            return """
            This file may contain hidden author info (track-changes, \
            embedded user names, printer-tracking dots). Sanitize on a \
            desktop before sending if the source matters.
            """
        case .codeOnTap:
            // The picker blocks the iOS-execute subset; if the user
            // somehow lands here with a desktop-execute, give them a
            // clear "you should know what you're doing" prompt.
            return """
            This file is executable on macOS / Windows. Don't send it to \
            anyone you haven't briefed.
            """
        }
    }

    /// Banner shown above the Save-to-Files action on a received
    /// attachment row.
    static func receiveWarning(forTier tier: AttachmentTier, isDesktopExecutable: Bool) -> ReceiveBanner? {
        if isDesktopExecutable {
            return ReceiveBanner(
                tone: .danger,
                text: "This file is executable on macOS / Windows. Do not open."
            )
        }
        switch tier {
        case .textFamily, .archive:
            return nil
        case .mediaStripAndWarn:
            return ReceiveBanner(
                tone: .warning,
                text: """
                The sender stripped metadata, but the camera's sensor leaves \
                a fingerprint in the pixels.
                """,
            )
        case .authorLeakingDoc:
            return ReceiveBanner(
                tone: .warning,
                text: """
                This file may contain hidden author info. Sanitize on a \
                desktop before opening.
                """,
            )
        case .codeOnTap:
            return ReceiveBanner(
                tone: .danger,
                text: "This file is executable. Do not open.",
            )
        }
    }

    /// Tone the row's banner takes — drives the color in ChatView.
    enum ReceiveTone: Sendable { case warning, danger }
    struct ReceiveBanner: Sendable {
        let tone: ReceiveTone
        let text: String
    }
}
