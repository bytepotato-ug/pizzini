import Foundation
import Testing
@testable import pizzini

/// PZ-M11: at duress-PIN setup we reject a duress value within a
/// fat-finger typo of the real PIN, so a single slip of the real PIN at
/// the lock screen can't silently trigger the wipe. The decision is the
/// pure `AppPasscode.osaDistance` / `duressTooSimilarToReal` pair — no
/// Keychain, no Argon2id — so these run on the simulator without
/// entitlements. (The live re-auth + store path is entitlement-gated and
/// covered by the device checklist, not here.)
@Suite("PZ-M11 duress/real PIN confusability")
struct DuressPinSimilarityTests {
    @Test("OSA distance counts the four typo classes")
    func osaDistanceCountsTypoClasses() {
        // Identical.
        #expect(AppPasscode.osaDistance("123456", "123456") == 0)
        // Single substitution.
        #expect(AppPasscode.osaDistance("123456", "123457") == 1)
        // Single deletion.
        #expect(AppPasscode.osaDistance("123456", "12346") == 1)
        // Single insertion.
        #expect(AppPasscode.osaDistance("123456", "1234567") == 1)
        // Single adjacent transposition ("…56" → "…65").
        #expect(AppPasscode.osaDistance("123456", "123465") == 1)
        // Two substitutions → distance 2.
        #expect(AppPasscode.osaDistance("123456", "123478") == 2)
        // Empty-string edges.
        #expect(AppPasscode.osaDistance("", "abc") == 3)
        #expect(AppPasscode.osaDistance("abc", "") == 3)
    }

    @Test("threshold is the immediate typo neighbourhood")
    func thresholdIsOne() {
        #expect(AppPasscode.maxConfusableEditDistance == 1)
    }

    @Test("rejects a duress PIN one typo away from the real PIN")
    func rejectsTypoNeighbourhood() {
        let real = "918273"
        #expect(AppPasscode.duressTooSimilarToReal(real: real, duress: "918273")) // identical
        #expect(AppPasscode.duressTooSimilarToReal(real: real, duress: "918274")) // substitution
        #expect(AppPasscode.duressTooSimilarToReal(real: real, duress: "91827"))  // deletion
        #expect(AppPasscode.duressTooSimilarToReal(real: real, duress: "9182730")) // insertion
        #expect(AppPasscode.duressTooSimilarToReal(real: real, duress: "918237")) // adjacent swap
    }

    @Test("accepts a duress PIN at least two edits away")
    func acceptsClearlyDifferent() {
        let real = "918273"
        // Two substitutions — just past the threshold, so allowed.
        #expect(!AppPasscode.duressTooSimilarToReal(real: real, duress: "918200"))
        // Wholly different.
        #expect(!AppPasscode.duressTooSimilarToReal(real: real, duress: "024681"))
        // Different length by two.
        #expect(!AppPasscode.duressTooSimilarToReal(real: real, duress: "91827300"))
    }
}
