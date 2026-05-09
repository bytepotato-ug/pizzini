import Foundation

/// One source of truth for tier-specific UI copy. Both attach-time
/// (composer warning banner) and receive-time (chat row banner) read
/// from here so the message can't drift between the two surfaces.
///
/// Wording is the maintainer's: explicit about what we strip, explicit
/// about what we cannot. Short factual statements; the attachment
/// banner now also carries an optional deep-link into FAQView so the
/// user can read more without the chat row turning into a wall of
/// text.
enum AttachmentCopy {
    /// Banner shown above the composer once an attachment is selected.
    static func attachWarning(forTier tier: AttachmentTier) -> String? {
        switch tier {
        case .textFamily, .archive:
            return nil
        case .mediaStripAndWarn:
            return "Pizzini will remove location, camera, and edit-history info before sending."
        case .authorLeakingDoc:
            return "This file may contain hidden author info. Sanitize on a desktop first if it matters."
        case .codeOnTap:
            return "This file is executable on macOS / Windows. Don’t send it to anyone you haven’t briefed."
        }
    }

    /// FAQ section a tap on the (i) info button next to the
    /// `attachWarning` should jump to. Nil = no info button rendered.
    static func attachFaqAnchor(forTier tier: AttachmentTier) -> FAQSection? {
        switch tier {
        case .textFamily, .archive: return nil
        case .mediaStripAndWarn: return .mediaStripping
        case .authorLeakingDoc: return .documentMetadata
        case .codeOnTap: return .executableWarning
        }
    }

    /// Banner shown above the Save-to-Files action on a received
    /// attachment row. Returns both the wording AND a stable FAQ
    /// section identifier so the row can render an (i) button that
    /// deep-links into FAQView for the curious user.
    static func receiveWarning(forTier tier: AttachmentTier, isDesktopExecutable: Bool) -> ReceiveBanner? {
        if isDesktopExecutable {
            return ReceiveBanner(
                tone: .danger,
                text: "This file is executable on macOS / Windows. Do not open.",
                faqSection: .executableWarning,
            )
        }
        switch tier {
        case .textFamily, .archive:
            return nil
        case .mediaStripAndWarn:
            return ReceiveBanner(
                tone: .warning,
                // Attribute the strip to Pizzini, not "the sender" —
                // the recipient can be sure their app did this; they
                // can't be sure what tooling the sender used. Shorter
                // wording with the technical detail moved to FAQ.
                text: "Pizzini removed location and camera info before sending. The pixels may still carry a unique sensor signature.",
                faqSection: .prnu,
            )
        case .authorLeakingDoc:
            return ReceiveBanner(
                tone: .warning,
                text: "This file may contain hidden author info.",
                faqSection: .documentMetadata,
            )
        case .codeOnTap:
            return ReceiveBanner(
                tone: .danger,
                text: "This file is executable. Do not open.",
                faqSection: .executableWarning,
            )
        }
    }

    /// Tone the row's banner takes — drives the color in ChatView.
    enum ReceiveTone: Sendable { case warning, danger }
    struct ReceiveBanner: Sendable {
        let tone: ReceiveTone
        let text: String
        /// FAQ section to scroll to when the (i) info button is
        /// tapped. Nil hides the button entirely (e.g. an
        /// architectural variant that doesn't merit a deeper read).
        let faqSection: FAQSection?
    }
}
