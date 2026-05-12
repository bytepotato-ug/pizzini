import Foundation
import Testing
@testable import pizzini

@Suite("Outbox state machine")
struct OutboxTests {
    private func sample(retries: Int = 0, sentAt: Date = Date()) -> OutboxEntry {
        OutboxEntry(
            messageId: Data(repeating: 0xAA, count: 16),
            recipientPeerId: Data(repeating: 0xBB, count: 33),
            sealedCiphertext: Data([0xCA, 0xFE]),
            token: Data(repeating: 0xCC, count: 84),
            ttl: 24 * 60 * 60,
            sentAt: sentAt,
            retries: retries,
            deliveredAt: nil,
            failedAt: nil,
            relayedAt: nil
        )
    }

    @Test("OutboxEntry encodes / decodes with every field set")
    func codableRoundTrip() throws {
        var e = sample()
        e.relayedAt = Date(timeIntervalSinceReferenceDate: 1)
        e.deliveredAt = Date(timeIntervalSinceReferenceDate: 2)
        e.failedAt = Date(timeIntervalSinceReferenceDate: 3)
        let data = try JSONEncoder().encode(e)
        let decoded = try JSONDecoder().decode(OutboxEntry.self, from: data)
        #expect(decoded.messageId == e.messageId)
        #expect(decoded.recipientPeerId == e.recipientPeerId)
        #expect(decoded.sealedCiphertext == e.sealedCiphertext)
        #expect(decoded.token == e.token)
        #expect(decoded.ttl == e.ttl)
        // JSONEncoder rounds Date to second-precision differently across
        // platforms; equality on epoch-seconds is the safe check.
        #expect(decoded.relayedAt?.timeIntervalSinceReferenceDate ==
                e.relayedAt?.timeIntervalSinceReferenceDate)
        #expect(decoded.deliveredAt?.timeIntervalSinceReferenceDate ==
                e.deliveredAt?.timeIntervalSinceReferenceDate)
        #expect(decoded.failedAt?.timeIntervalSinceReferenceDate ==
                e.failedAt?.timeIntervalSinceReferenceDate)
        #expect(decoded.retries == e.retries)
    }

    @Test("status reflects deliveredAt / failedAt / relayedAt precedence")
    func statusPrecedence() {
        var e = sample()
        #expect(e.status == .pending)
        e.relayedAt = Date()
        #expect(e.status == .relayed)
        e.deliveredAt = Date()
        #expect(e.status == .delivered)
        e.deliveredAt = nil
        e.failedAt = Date()
        #expect(e.status == .failed)
    }

    @Test("shouldRetry waits 30s on first attempt, then increments")
    func retryBackoff() {
        let now = Date()
        let e0 = sample(retries: 0, sentAt: now.addingTimeInterval(-29))
        #expect(!e0.shouldRetry(now: now))
        let e1 = sample(retries: 0, sentAt: now.addingTimeInterval(-31))
        #expect(e1.shouldRetry(now: now))
        // Second retry: floor of 60s.
        let e2 = sample(retries: 1, sentAt: now.addingTimeInterval(-59))
        #expect(!e2.shouldRetry(now: now))
        let e3 = sample(retries: 1, sentAt: now.addingTimeInterval(-61))
        #expect(e3.shouldRetry(now: now))
    }

    @Test("shouldRetry stops at maxRetries")
    func retryCap() {
        let e = sample(retries: OutboxEntry.maxRetries, sentAt: Date(timeIntervalSinceNow: -3600))
        #expect(!e.shouldRetry(now: Date()))
    }

    @Test("hasExpired fires after ttl elapses without ACK")
    func ttlExpiry() {
        let now = Date()
        let young = sample(sentAt: now.addingTimeInterval(-(60 * 60)))      // 1h old, 24h ttl
        #expect(!young.hasExpired(now: now))
        var old = sample(sentAt: now.addingTimeInterval(-(25 * 60 * 60)))   // 25h old
        #expect(old.hasExpired(now: now))
        // …unless we already ACKed.
        old.deliveredAt = now.addingTimeInterval(-100)
        #expect(!old.hasExpired(now: now))
    }
}

@Suite("Contact read-receipt + TTL settings")
struct ContactSettingsTests {
    @Test("readReceiptsMode defaults to .followDefault (off-by-default global)")
    func readReceiptsDefault() {
        let c = Contact(identityPub: Data(repeating: 1, count: 33), displayName: "x")
        #expect(c.readReceiptsMode == .followDefault)
        // Effective value with the default global default (off).
        #expect(c.effectiveReadReceiptsEnabled(globalDefault: false) == false)
    }

    @Test("ttlSeconds defaults to 1 day")
    func ttlDefault() {
        let c = Contact(identityPub: Data(repeating: 1, count: 33), displayName: "x")
        #expect(c.ttlSeconds == Contact.defaultTTLSeconds)
        #expect(c.ttlSeconds == 24 * 60 * 60)
    }

    @Test("effectiveReadReceiptsEnabled: alwaysOff overrides true global default")
    func alwaysOffOverridesGlobal() {
        var c = Contact(identityPub: Data(repeating: 1, count: 33), displayName: "x")
        c.readReceiptsMode = .alwaysOff
        #expect(c.effectiveReadReceiptsEnabled(globalDefault: true) == false)
    }

    @Test("effectiveReadReceiptsEnabled: alwaysOn overrides false global default")
    func alwaysOnOverridesGlobal() {
        var c = Contact(identityPub: Data(repeating: 1, count: 33), displayName: "x")
        c.readReceiptsMode = .alwaysOn
        #expect(c.effectiveReadReceiptsEnabled(globalDefault: false) == true)
    }

    @Test("effectiveReadReceiptsEnabled: followDefault inherits the global")
    func followDefaultInheritsGlobal() {
        var c = Contact(identityPub: Data(repeating: 1, count: 33), displayName: "x")
        c.readReceiptsMode = .followDefault
        #expect(c.effectiveReadReceiptsEnabled(globalDefault: true) == true)
        #expect(c.effectiveReadReceiptsEnabled(globalDefault: false) == false)
    }

    @Test("Codable legacy `readReceiptsEnabled=false` decodes to .alwaysOff (privacy-respecting fallback)")
    func legacyFalseDecodesToAlwaysOff() throws {
        // Construct a JSON payload representing a pre-v3 export
        // that only carried the legacy Bool. The decoder must
        // preserve the user's explicit "off for this chat" intent
        // rather than mapping false to .followDefault (which would
        // silently re-enable receipts as soon as the user later
        // toggled the global default on).
        let legacyJSON: [String: Any] = [
            "id": UUID().uuidString,
            "identityPub": Data(repeating: 1, count: 33).base64EncodedString(),
            "displayName": "x",
            "sessionEstablished": false,
            "log": [],
            "addedAt": Date().timeIntervalSinceReferenceDate,
            "deliveryTokensForPeer": [],
            "ttlSeconds": 86400,
            "readReceiptsEnabled": false,
            "addedVia": "qr_scan",
        ]
        let data = try JSONSerialization.data(withJSONObject: legacyJSON)
        let decoder = JSONDecoder()
        decoder.dataDecodingStrategy = .base64
        decoder.dateDecodingStrategy = .deferredToDate
        let c = try decoder.decode(Contact.self, from: data)
        #expect(c.readReceiptsMode == .alwaysOff)
    }

    @Test("Codable legacy `readReceiptsEnabled=true` decodes to .alwaysOn")
    func legacyTrueDecodesToAlwaysOn() throws {
        let legacyJSON: [String: Any] = [
            "id": UUID().uuidString,
            "identityPub": Data(repeating: 2, count: 33).base64EncodedString(),
            "displayName": "y",
            "sessionEstablished": false,
            "log": [],
            "addedAt": Date().timeIntervalSinceReferenceDate,
            "deliveryTokensForPeer": [],
            "ttlSeconds": 86400,
            "readReceiptsEnabled": true,
            "addedVia": "qr_scan",
        ]
        let data = try JSONSerialization.data(withJSONObject: legacyJSON)
        let decoder = JSONDecoder()
        decoder.dataDecodingStrategy = .base64
        decoder.dateDecodingStrategy = .deferredToDate
        let c = try decoder.decode(Contact.self, from: data)
        #expect(c.readReceiptsMode == .alwaysOn)
    }
}

@Suite("Screenshot self-test result codec")
struct ScreenshotSelfTestCodecTests {
    @Test("qrBlockEffective + qrBlockTestedOSVersion default nil (untested)")
    func defaultsNil() {
        let s = AppState()
        #expect(s.qrBlockEffective == nil)
        #expect(s.qrBlockTestedOSVersion == nil)
    }

    @Test("panicModeEnabled defaults off")
    func panicDefaultOff() {
        let s = AppState()
        #expect(s.panicModeEnabled == false)
    }

    @Test("AppState round-trips the self-test result fields")
    func roundTripSelfTestFields() throws {
        let s = AppState(
            panicModeEnabled: true,
            qrBlockEffective: true,
            qrBlockTestedOSVersion: "26.0",
        )
        let data = try JSONEncoder().encode(s)
        let decoded = try JSONDecoder().decode(AppState.self, from: data)
        #expect(decoded.panicModeEnabled == true)
        #expect(decoded.qrBlockEffective == true)
        #expect(decoded.qrBlockTestedOSVersion == "26.0")
    }

    @Test("legacy AppState JSON carrying removed toggle keys decodes cleanly")
    func legacyTogglesAreIgnored() throws {
        // JSON snapshot from an earlier build that wrote the now-
        // removed `notifyPeerOnScreenshot`, `blockQRScreenshots`,
        // `blockChatScreenshots`, and `blockAppScreenshots` keys.
        // JSONDecoder ignores unknown keys silently, so the blob
        // must still load — losing those (now-meaningless) keys on
        // next encode is the desired outcome.
        let json = """
        {
            "version": 1,
            "relayHost": "127.0.0.1",
            "contacts": [],
            "onboardingCompleted": true,
            "biometricLockEnabled": true,
            "autoLockTimeout": "fiveMinutes",
            "quickLookPreviewEnabled": false,
            "notifyPeerOnScreenshot": true,
            "blockQRScreenshots": false,
            "blockChatScreenshots": true,
            "blockAppScreenshots": false,
            "qrBlockEffective": true,
            "qrBlockTestedOSVersion": "26.0"
        }
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(AppState.self, from: json)
        // Removed keys silently dropped; still-present keys preserved.
        #expect(decoded.relayHost == "127.0.0.1")
        #expect(decoded.biometricLockEnabled == true)
        #expect(decoded.autoLockTimeout == .fiveMinutes)
        #expect(decoded.qrBlockEffective == true)
        #expect(decoded.qrBlockTestedOSVersion == "26.0")
    }

    @Test("legacy AppState JSON without screen-capture fields still decodes")
    func legacyMinimalJsonDecodes() throws {
        let json = """
        {
            "version": 1,
            "relayHost": "127.0.0.1",
            "contacts": [],
            "onboardingCompleted": true,
            "biometricLockEnabled": true,
            "autoLockTimeout": "fiveMinutes",
            "quickLookPreviewEnabled": false
        }
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(AppState.self, from: json)
        #expect(decoded.qrBlockEffective == nil)
        #expect(decoded.qrBlockTestedOSVersion == nil)
        #expect(decoded.relayHost == "127.0.0.1")
        #expect(decoded.biometricLockEnabled == true)
        #expect(decoded.autoLockTimeout == .fiveMinutes)
    }
}

@Suite("Contact upgrade-path Codable backwards-compat (N-001)")
struct ContactUpgradeCompatTests {
    /// Pre-Phase-3 builds wrote Contact rows without `peerVerifyKey` or
    /// `lastBundleServedAt`. After upgrade, those rows decode with the
    /// new fields nil — the precondition for the F-202 upgrade-strand
    /// bug N-001 fixed in ChatStore.relayClient(_:didChange:). This test
    /// guards the Codable backwards-compatibility contract: if a future
    /// refactor accidentally requires the field, an upgraded user's
    /// AppState fails to load entirely instead of just being degraded
    /// — much louder, but worth the regression coverage.
    @Test("legacy Contact JSON decodes with peerVerifyKey == nil")
    func legacyJsonDecodesWithNilVerifyKey() throws {
        // Hand-rolled JSON matching the pre-Phase-3 Contact field set.
        // Mirrors the on-disk bytes a v0.X user upgrading would have.
        let legacyJson = #"""
        {
          "id": "F47AC10B-58CC-4372-A567-0E02B2C3D479",
          "identityPub": "AQIDBAUG",
          "displayName": "Bob",
          "log": [],
          "lastSeenAt": null,
          "addedAt": 0,
          "sessionEstablished": true,
          "deliveryTokensForPeer": [],
          "lastRefillRequestSentAt": null,
          "lastRefillRequestHandledAt": null,
          "ttlSeconds": 86400,
          "readReceiptsEnabled": false
        }
        """#
        let data = Data(legacyJson.utf8)
        let decoded = try JSONDecoder().decode(Contact.self, from: data)
        #expect(decoded.peerVerifyKey == nil)
        #expect(decoded.lastBundleServedAt == nil)
        #expect(decoded.sessionEstablished == true) // upgraded contacts are paired
    }

    /// Symmetric guard: a freshly-constructed Contact also has nil for
    /// the new fields by default (so newly-paired contacts post-upgrade
    /// also rely on the .connected loop's nil check until BUNDLE_RESPONSE
    /// repopulates).
    @Test("default Contact init leaves new fields nil")
    func defaultInitLeavesNewFieldsNil() {
        let c = Contact(identityPub: Data(repeating: 1, count: 33), displayName: "y")
        #expect(c.peerVerifyKey == nil)
        #expect(c.lastBundleServedAt == nil)
    }
}
