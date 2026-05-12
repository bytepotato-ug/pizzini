import Foundation
import Testing
@testable import pizzini

/// Codable migration coverage for the rename of
/// `quickLookPreviewEnabled: Bool` to
/// `attachmentPreviewMode: AttachmentPreviewMode`. Existing users must
/// land on their previous tier exactly — a user who opted into
/// QuickLook stays opted in; a user who never opted in stays on the
/// strict `.off` default. Missing field also defaults to `.off`.
@Suite("AttachmentPreviewMode legacy decoding")
struct AttachmentPreviewModeMigrationTests {
    @Test("Legacy Bool `true` decodes to `.quickLook`")
    func legacyTrueDecodesToQuickLook() throws {
        let json = """
        {
            "version": 1,
            "relayHost": "127.0.0.1",
            "contacts": [],
            "onboardingCompleted": true,
            "biometricLockEnabled": false,
            "autoLockTimeout": "fiveMinutes",
            "quickLookPreviewEnabled": true
        }
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(AppState.self, from: json)
        #expect(decoded.attachmentPreviewMode == .quickLook)
    }

    @Test("Legacy Bool `false` decodes to `.off`")
    func legacyFalseDecodesToOff() throws {
        let json = """
        {
            "version": 1,
            "relayHost": "127.0.0.1",
            "contacts": [],
            "onboardingCompleted": true,
            "biometricLockEnabled": false,
            "autoLockTimeout": "fiveMinutes",
            "quickLookPreviewEnabled": false
        }
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(AppState.self, from: json)
        #expect(decoded.attachmentPreviewMode == .off)
    }

    @Test("Blob missing both keys defaults to `.off`")
    func missingKeyDefaultsOff() throws {
        let json = """
        {
            "version": 1,
            "relayHost": "127.0.0.1",
            "contacts": [],
            "onboardingCompleted": true,
            "biometricLockEnabled": false,
            "autoLockTimeout": "fiveMinutes"
        }
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(AppState.self, from: json)
        #expect(decoded.attachmentPreviewMode == .off)
    }

    @Test("New-form key overrides legacy when both are present")
    func newKeyWinsOverLegacy() throws {
        let json = """
        {
            "version": 1,
            "relayHost": "127.0.0.1",
            "contacts": [],
            "onboardingCompleted": true,
            "biometricLockEnabled": false,
            "autoLockTimeout": "fiveMinutes",
            "quickLookPreviewEnabled": false,
            "attachmentPreviewMode": "inlineThumbnail"
        }
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(AppState.self, from: json)
        #expect(decoded.attachmentPreviewMode == .inlineThumbnail)
    }

    @Test("Encoded AppState round-trips the new enum")
    func encodeRoundTrip() throws {
        let s = AppState(attachmentPreviewMode: .inlineThumbnail)
        let data = try JSONEncoder().encode(s)
        let back = try JSONDecoder().decode(AppState.self, from: data)
        #expect(back.attachmentPreviewMode == .inlineThumbnail)
        // The encoded form should NOT carry the legacy Bool key —
        // otherwise a future decode could pick the wrong value if the
        // ordering of decode attempts ever changes.
        let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(raw?["quickLookPreviewEnabled"] == nil)
        #expect(raw?["attachmentPreviewMode"] as? String == "inlineThumbnail")
    }
}
