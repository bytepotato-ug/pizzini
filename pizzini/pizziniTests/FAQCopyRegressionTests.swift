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
@Suite("FAQ copy regression")
struct FAQCopyRegressionTests {

    /// `relayVisibility` must not regress to the pre-audit wording
    /// that claimed the production fleet didn't exist + that the
    /// relay kept everything in RAM only. Both were false from at
    /// least 2026-05-11 (the multi-onion-fleet ship date) onward.
    @Test
    func relayVisibilityDescribesProductionFleet() {
        let body = FAQSection.relayVisibility.body
        // Stale strings from the pre-2026-05-14 wording. If any of
        // these come back, the FAQ has regressed to claiming the
        // production fleet doesn't exist or the relay queue is
        // ephemeral.
        #expect(!body.localizedCaseInsensitiveContains("plain TCP on your LAN"))
        #expect(!body.localizedCaseInsensitiveContains("still on the roadmap"))
        #expect(!body.localizedCaseInsensitiveContains("keeps everything in RAM only"))
        #expect(!body.localizedCaseInsensitiveContains("a relay restart wipes the queue"))
        // Facts that MUST be reflected in the current copy. If the
        // fleet grows beyond DE/NO/US these assertions update in
        // the same change as the FAQ body.
        #expect(body.contains("Tor"))
        #expect(body.contains("ChaCha20-Poly1305"))
        #expect(body.contains("Germany"))
        #expect(body.contains("Norway"))
        #expect(body.contains("USA"))
    }

    /// `notYetShipped` must not list features as pending after they
    /// ship. The three items below were the regression captured on
    /// 2026-05-14 — all had shipped weeks earlier.
    @Test
    func notYetShippedReflectsActualGaps() {
        let body = FAQSection.notYetShipped.body
        #expect(!body.contains("Production Tor onion service"))
        #expect(!body.contains("Reproducible build script"))
        #expect(!body.contains("Multi-relay client fanout"))
        // Items that genuinely remain pending per the README's
        // status section. These are the ones an honest threat-model
        // read still needs surfaced.
        #expect(body.contains("App Attest"))
        #expect(body.localizedCaseInsensitiveContains("audit"))
    }

    /// Belt-and-braces: no FAQ section should ship with an empty
    /// body, a literal TODO marker, or lorem-ipsum placeholder text.
    /// Catches the class of "added an enum case, forgot the copy"
    /// bug at compile + test time instead of in production.
    @Test
    func everyFAQSectionHasContent() {
        for section in FAQSection.allCases {
            let title = section.title
            let body = section.body
            #expect(!title.isEmpty, "FAQ section \(section) has empty title")
            #expect(!body.isEmpty, "FAQ section \(section) has empty body")
            for placeholder in ["TODO", "FIXME", "XXX", "HACK", "PLACEHOLDER", "lorem ipsum"] {
                #expect(
                    !body.localizedCaseInsensitiveContains(placeholder),
                    "FAQ section \(section) body contains \(placeholder) marker"
                )
                #expect(
                    !title.localizedCaseInsensitiveContains(placeholder),
                    "FAQ section \(section) title contains \(placeholder) marker"
                )
            }
        }
    }
}
