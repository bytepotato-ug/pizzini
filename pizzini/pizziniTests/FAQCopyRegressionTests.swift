import Foundation
import Testing
@testable import pizzini

/// FAQ copy regression tests.
///
/// The 2026-05-14 release audit caught the in-app FAQ describing
/// three already-shipped features as "still on the roadmap" and the
/// `relayVisibility` section claiming the relay binds to "plain TCP
/// on your LAN" months after the production onion fleet went live.
/// Neither code review nor `cargo clippy` would have flagged any
/// of it — both saw a perfectly valid `String` literal.
///
/// These tests pin specific stale phrases OUT of specific FAQ
/// section bodies, and pin specific shipped facts IN. When the
/// state of the world changes (a roadmap item ships; a new gap
/// opens), the test forces an update to *both* the FAQ body and
/// this test in the same change. That coupling is the point: the
/// FAQ and the truth can't drift independently anymore.
///
/// Assertions read from `body + advancedBody` rather than `body`
/// alone, because the 2026-05-16 rewrite split each section into a
/// basics body and an optional advanced body. The pins live on the
/// combined contract — a fact may be surfaced in either tier.
@Suite("FAQ copy regression")
struct FAQCopyRegressionTests {

    /// `relayVisibility` must not regress to the pre-audit wording
    /// that claimed the production fleet didn't exist + that the
    /// relay kept everything in RAM only. Both were false from at
    /// least 2026-05-11 (the multi-onion-fleet ship date) onward.
    @Test
    func relayVisibilityDescribesProductionFleet() {
        let combined = FAQSection.relayVisibility.combinedBody
        // Stale strings from the pre-2026-05-14 wording. If any of
        // these come back, the FAQ has regressed to claiming the
        // production fleet doesn't exist or the relay queue is
        // ephemeral.
        #expect(!combined.localizedCaseInsensitiveContains("plain TCP on your LAN"))
        #expect(!combined.localizedCaseInsensitiveContains("still on the roadmap"))
        #expect(!combined.localizedCaseInsensitiveContains("keeps everything in RAM only"))
        #expect(!combined.localizedCaseInsensitiveContains("a relay restart wipes the queue"))
        // Facts that MUST be reflected in the current copy. If the
        // fleet grows beyond DE/NO/US these assertions update in
        // the same change as the FAQ body.
        #expect(combined.contains("Tor"))
        #expect(combined.contains("ChaCha20-Poly1305"))
        #expect(combined.contains("Germany"))
        #expect(combined.contains("Norway"))
        #expect(combined.contains("USA"))
    }

    /// `notYetShipped` must not list features as pending after they
    /// ship. The three items below were the regression captured on
    /// 2026-05-14 — all had shipped weeks earlier.
    @Test
    func notYetShippedReflectsActualGaps() {
        let combined = FAQSection.notYetShipped.combinedBody
        #expect(!combined.contains("Production Tor onion service"))
        #expect(!combined.contains("Reproducible build script"))
        #expect(!combined.contains("Multi-relay client fanout"))
        // Items that genuinely remain pending per the README's
        // status section. These are the ones an honest threat-model
        // read still needs surfaced.
        #expect(combined.contains("App Attest"))
        #expect(combined.localizedCaseInsensitiveContains("audit"))
    }

    /// Belt-and-braces: no FAQ section should ship with an empty
    /// title or no copy at all (basics OR advanced), and no body
    /// (either tier) may contain a placeholder marker. Catches the
    /// class of "added an enum case, forgot the copy" bug at
    /// compile + test time instead of in production.
    @Test
    func everyFAQSectionHasContent() {
        for section in FAQSection.allCases {
            let title = section.title
            let body = section.body
            let advanced = section.advancedBody ?? ""
            #expect(!title.isEmpty, "FAQ section \(section) has empty title")
            #expect(
                !(body.isEmpty && advanced.isEmpty),
                "FAQ section \(section) has no basics or advanced copy"
            )
            // Advanced-only sections legitimately have empty basics
            // bodies — the toggle is what makes them visible. Every
            // non-advanced-only section MUST have a basics body.
            if !section.advancedOnly {
                #expect(
                    !body.isEmpty,
                    "FAQ section \(section) is not advanced-only but has no basics body"
                )
            }
            for placeholder in ["TODO", "FIXME", "XXX", "HACK", "PLACEHOLDER", "lorem ipsum"] {
                #expect(
                    !body.localizedCaseInsensitiveContains(placeholder),
                    "FAQ section \(section) body contains \(placeholder) marker"
                )
                #expect(
                    !advanced.localizedCaseInsensitiveContains(placeholder),
                    "FAQ section \(section) advancedBody contains \(placeholder) marker"
                )
                #expect(
                    !title.localizedCaseInsensitiveContains(placeholder),
                    "FAQ section \(section) title contains \(placeholder) marker"
                )
            }
        }
    }

    /// Every section's category resolves through `FAQCategory.sections`
    /// — i.e., no section is orphaned from the category render.
    @Test
    func everySectionIsReachableViaItsCategory() {
        for section in FAQSection.allCases {
            #expect(
                section.category.sections.contains(section),
                "FAQ section \(section) is not in its category's sections list"
            )
        }
    }

    /// Existing deep-link sites (banners (i) buttons) target these
    /// specific cases. Renaming or removing any of them silently
    /// breaks the banner. The compile-time `initialSection:` typing
    /// catches removed cases; this test catches renames-without-
    /// updating-callsites by pinning the rawValue.
    @Test
    func deepLinkSectionsAreStable() {
        #expect(FAQSection.deviceIntegrity.rawValue == "deviceIntegrity")
        #expect(FAQSection.screenCapture.rawValue == "screenCapture")
        #expect(FAQSection.prnu.rawValue == "prnu")
        #expect(FAQSection.documentMetadata.rawValue == "documentMetadata")
        #expect(FAQSection.executableWarning.rawValue == "executableWarning")
    }
}

private extension FAQSection {
    /// `body + advancedBody` — the surface that copy regressions are
    /// pinned against. Reading either tier in isolation would let a
    /// fact silently migrate between them without the test noticing.
    var combinedBody: String {
        body + (advancedBody.map { "\n" + $0 } ?? "")
    }
}
