import Foundation
import Testing
@testable import pizzini

/// Tests for `onboardingExplainerText(jurisdictions:)`.
///
/// The function generates the first-launch network-step copy from the
/// bundled `RelayRegistry.trusted` jurisdiction list. The contract is
/// the user-visible string; pinning it here means a one-character
/// edit to the copy (or a regression that drops the jurisdiction
/// list) breaks the build instead of shipping silently to TestFlight.
@Suite("onboardingExplainerText(jurisdictions:)")
struct OnboardingExplainerTests {

    @Test func emptyListFallsBackToCountryless() {
        let copy = onboardingExplainerText(jurisdictions: [])
        // No "through {country}" clause when the registry is empty.
        // Pizzini ships with three relays, so this path is defence
        // against a future refactor returning an empty list, not a
        // real user-visible state — but the fallback must still be a
        // sensible sentence.
        #expect(copy == "Setting up a private network connection. About 30 seconds.")
    }

    @Test func singleJurisdictionUsesItVerbatim() {
        let copy = onboardingExplainerText(jurisdictions: ["Germany"])
        #expect(copy == "Setting up a private network connection through Germany. About 30 seconds.")
    }

    @Test func twoJurisdictionsJoinWithAnd() {
        let copy = onboardingExplainerText(jurisdictions: ["Germany", "Norway"])
        // No Oxford comma at arity 2 — the standard English "X and Y"
        // form. ListFormatter handles this without us picking a rule.
        #expect(copy == "Setting up a private network connection through Germany and Norway. About 30 seconds.")
    }

    @Test func threeJurisdictionsUseOxfordComma() {
        let copy = onboardingExplainerText(jurisdictions: ["Germany", "Norway", "USA"])
        // The shipped fleet shape. Oxford comma — pinned to en_US_POSIX
        // inside the helper so a future locale-default change can't
        // silently strip it.
        #expect(copy == "Setting up a private network connection through Germany, Norway, and USA. About 30 seconds.")
    }

    @Test func fourJurisdictionsExtendCleanly() {
        let copy = onboardingExplainerText(jurisdictions: [
            "Germany", "Norway", "USA", "Iceland",
        ])
        // Adding relays must not require a copy edit. The helper
        // delegates list shape to ListFormatter; verify the 4-item
        // form looks right end-to-end.
        #expect(copy == "Setting up a private network connection through Germany, Norway, USA, and Iceland. About 30 seconds.")
    }

    @Test func bannedMarkersAbsent() {
        // CONTRIBUTING bans TODO/FIXME/XXX/HACK/STUB/PLACEHOLDER in
        // shipped strings. Cheap to assert against the generated copy
        // here so a future edit can't sneak one in via the explainer
        // template.
        let copy = onboardingExplainerText(jurisdictions: ["Germany", "Norway", "USA"])
        for marker in ["TODO", "FIXME", "XXX", "HACK", "STUB", "PLACEHOLDER"] {
            #expect(!copy.contains(marker), "explainer contains banned marker \(marker)")
        }
    }

    /// The registry-derived jurisdiction list is the actual source of
    /// truth for onboarding copy. Pin the current fleet shape so a
    /// silent drop of "USA" → "United States" (or similar) breaks
    /// here in the same change that touched the registry, not on
    /// first launch after a TestFlight rollout.
    @Test func currentRegistryYieldsExpectedFleet() {
        let jurisdictions = currentTrustedJurisdictions()
        #expect(jurisdictions == ["Germany", "Norway", "USA"])
    }
}
