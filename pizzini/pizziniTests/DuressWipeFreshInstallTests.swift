import Foundation
import Testing
@testable import pizzini

/// PZ-H6: a duress wipe must leave `AppState` byte-for-byte equal to a
/// fresh install — preserving NOTHING from the pre-wipe state (not the
/// relay host, not the screenshot self-test cache, not any UX pref) — so
/// a device imaged after the wipe is indistinguishable from one where
/// Pizzini was never configured. `Storage.postWipeAppState` is the pure,
/// `nonisolated` decision point, so these run on the simulator without
/// entitlements.
@Suite("PZ-H6 duress wipe → fresh install")
struct DuressWipeFreshInstallTests {
    /// A configured, lived-in device: every field PZ-H6 cares about (and
    /// several it doesn't) is set to a NON-default value, so a regression
    /// that copies any field from the snapshot onto the duress path
    /// surfaces as an inequality below.
    private func livedInSnapshot() -> AppState {
        AppState(
            relayHost: "wss://my.byo.relay.example:443",
            contacts: [],
            onboardingCompleted: true,
            biometricLockEnabled: true,
            autoLockTimeout: .oneMinute,
            attachmentPreviewMode: .quickLook,
            panicModeEnabled: true,
            qrBlockEffective: true,
            qrBlockTestedOSVersion: "18.4",
            groups: [],
            contactsBeforeGroups: false,
            inAppHapticsEnabled: true,
            defaultReadReceiptsEnabled: true,
            notificationsMuted: true,
            blockedIdentities: [Data([1, 2, 3])],
            appearanceMode: .dark
        )
    }

    /// Compare via the Codable representation (AppState isn't Equatable),
    /// with sorted keys so the comparison is order-independent. This is
    /// exactly the on-disk surface the indistinguishability invariant is
    /// about: the persisted settings blob must match a fresh install's.
    @Test("duress path yields a byte-for-byte fresh-install AppState")
    func duressIsFreshInstall() throws {
        let afterDuress = Storage.postWipeAppState(
            preserving: livedInSnapshot(),
            clearPasscodes: true
        )
        let enc = JSONEncoder()
        enc.outputFormatting = .sortedKeys
        let afterJSON = try enc.encode(afterDuress)
        let freshJSON = try enc.encode(AppState())
        #expect(
            afterJSON == freshJSON,
            "post-duress AppState must encode identically to a fresh-install AppState()"
        )
    }

    /// Spot-check the specific fields PZ-H6 names, independent of the
    /// whole-blob comparison, so a future Codable change can't mask a
    /// regression on exactly these.
    @Test("duress path resets relay host and screenshot self-test cache")
    func duressResetsNamedFields() {
        let afterDuress = Storage.postWipeAppState(
            preserving: livedInSnapshot(),
            clearPasscodes: true
        )
        #expect(afterDuress.relayHost == AppState.defaultRelayHost)
        #expect(afterDuress.relayHost.isEmpty)
        #expect(afterDuress.qrBlockEffective == nil)
        #expect(afterDuress.qrBlockTestedOSVersion == nil)
        #expect(afterDuress.onboardingCompleted == false)
        #expect(afterDuress.biometricLockEnabled == false)
    }

    /// The non-duress "Reset everything" path must still preserve the
    /// user's posture (so an accidental tap doesn't strand them
    /// re-onboarding) while clearing the identity-bound rows.
    @Test("non-duress reset preserves posture, clears identity rows")
    func nonDuressPreservesPosture() {
        let snap = livedInSnapshot()
        let afterReset = Storage.postWipeAppState(preserving: snap, clearPasscodes: false)
        #expect(afterReset.relayHost == snap.relayHost)
        #expect(afterReset.onboardingCompleted == true)
        #expect(afterReset.biometricLockEnabled == true)
        #expect(afterReset.qrBlockEffective == true)
        #expect(afterReset.qrBlockTestedOSVersion == "18.4")
        #expect(afterReset.blockedIdentities == snap.blockedIdentities)
        #expect(afterReset.appearanceMode == .dark)
        // Identity-bound collections are always cleared by a reset.
        #expect(afterReset.contacts.isEmpty)
        #expect(afterReset.groups.isEmpty)
    }
}
