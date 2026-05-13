import Foundation
import PizziniCryptoCore
import PizziniDB
import Testing
@testable import pizzini

/// Per-row round-trip tests for `SQLiteStorage`. Confirms each
/// table writes + reads back losslessly, and that the legacy
/// Keychain → SQLCipher migration path lands data in the right
/// shape.
@MainActor
@Suite("SQLiteStorage + migration round-trips")
struct SQLiteStorageTests {
    private func freshStore() throws -> SQLiteStorage {
        let path = NSTemporaryDirectory() + "pizzini-test-\(UUID()).sqlite"
        let key = Data(repeating: 0xAA, count: 32)
        return try SQLiteStorage._bootstrapForTesting(path: path, rawKey: key)
    }

    // MARK: - Settings

    @Test("settings row round-trips every field")
    func settingsRoundTrip() throws {
        let store = try freshStore()
        let s = AppState(
            relayHost: "example.local",
            contacts: [],
            onboardingCompleted: true,
            biometricLockEnabled: true,
            autoLockTimeout: .fiveMinutes,
            attachmentPreviewMode: .inlineThumbnail,
            panicModeEnabled: true,
            qrBlockEffective: false,
            qrBlockTestedOSVersion: "26.0.1",
            groups: [],
            contactsBeforeGroups: false,
            inAppHapticsEnabled: true,
        )
        try store.upsertSettings(s)
        let loaded = try store.loadSettings()
        #expect(loaded?.relayHost == s.relayHost)
        #expect(loaded?.onboardingCompleted == true)
        #expect(loaded?.biometricLockEnabled == true)
        #expect(loaded?.autoLockTimeout == .fiveMinutes)
        #expect(loaded?.attachmentPreviewMode == .inlineThumbnail)
        #expect(loaded?.panicModeEnabled == true)
        #expect(loaded?.qrBlockEffective == false)
        #expect(loaded?.qrBlockTestedOSVersion == "26.0.1")
        #expect(loaded?.contactsBeforeGroups == false)
        #expect(loaded?.inAppHapticsEnabled == true)
    }

    // MARK: - Contacts + messages + tokens

    @Test("contact round-trips outbound token chain (v2)")
    func contactOutboundChainRoundTrip() throws {
        let store = try freshStore()
        let chain = HashChainToken.mintChain(length: 64)
        let identityPub = Data(repeating: 0x09, count: 33)
        let original = Contact(
            identityPub: identityPub,
            displayName: "Bob",
            sessionEstablished: true,
            addedAt: Date(),
            outboundTokenChain: chain,
        )
        try store.upsertContact(original)
        let loaded = try store.loadContacts().first
        #expect(loaded?.outboundTokenChain == chain)
    }

    @Test("contact with no v2 chain loads as nil (legacy compatibility)")
    func contactWithoutOutboundChainLoadsNil() throws {
        let store = try freshStore()
        let identityPub = Data(repeating: 0x0A, count: 33)
        try store.upsertContact(Contact(
            identityPub: identityPub,
            displayName: "Alice",
            sessionEstablished: false,
            addedAt: Date(),
        ))
        let loaded = try store.loadContacts().first
        #expect(loaded?.outboundTokenChain == nil)
    }

    @Test("contact + log round-trip")
    func contactGraphRoundTrip() throws {
        let store = try freshStore()
        let identityPub = Data(repeating: 0x07, count: 33)
        var c = Contact(
            identityPub: identityPub,
            displayName: "Alice",
            sessionEstablished: true,
            log: [],
            lastMessageAt: Date(),
            addedAt: Date(),
            ttlSeconds: 3600,
            readReceiptsMode: .alwaysOn,
            peerVerifyKey: Data(repeating: 0x05, count: 33),
        )
        let msg = PersistedMessage(
            side: .me,
            text: "hello",
            kind: .whisper,
            bytes: 5,
            timestamp: Date(),
            messageId: Data(repeating: 0xCC, count: 16),
        )
        c.log = [msg]
        try store.upsertContact(c)
        try store.appendContactMessage(contactId: c.id, msg)
        let loaded = try store.loadContacts()
        #expect(loaded.count == 1)
        let lc = try #require(loaded.first)
        #expect(lc.id == c.id)
        #expect(lc.identityPub == identityPub)
        #expect(lc.displayName == "Alice")
        #expect(lc.sessionEstablished == true)
        #expect(lc.readReceiptsMode == .alwaysOn)
        #expect(lc.ttlSeconds == 3600)
        #expect(lc.peerVerifyKey == c.peerVerifyKey)
        #expect(lc.log.count == 1)
        #expect(lc.log.first?.text == "hello")
        #expect(lc.log.first?.kind == .whisper)
        #expect(lc.log.first?.messageId == msg.messageId)
    }

    @Test("contact provenance + verification round-trip via v2 columns")
    func contactVerificationRoundTrip() throws {
        let store = try freshStore()
        let when = Date(timeIntervalSince1970: 1_700_000_000)
        // 1) Pasted, unverified — most exposed case from the SAS feature.
        let pasted = Contact(
            identityPub: Data(repeating: 0x11, count: 33),
            displayName: "Pasted Alice",
            addedAt: when,
            addedVia: .pastedText,
            verifiedAt: nil,
        )
        // 2) QR-scanned, then SAS-verified — the green-checkmark case.
        let verified = Contact(
            identityPub: Data(repeating: 0x22, count: 33),
            displayName: "Verified Bob",
            addedAt: when,
            addedVia: .qrScan,
            verifiedAt: when,
        )
        try store.upsertContact(pasted)
        try store.upsertContact(verified)

        let loaded = try store.loadContacts().sorted(by: { $0.displayName < $1.displayName })
        #expect(loaded.count == 2)
        let p = try #require(loaded.first { $0.displayName == "Pasted Alice" })
        let v = try #require(loaded.first { $0.displayName == "Verified Bob" })
        #expect(p.addedVia == .pastedText)
        #expect(p.verifiedAt == nil)
        #expect(p.verificationState == .pastedUnverified)
        #expect(v.addedVia == .qrScan)
        #expect(v.verifiedAt != nil)
        #expect(v.verificationState == .verified)

        // Re-upsert pasted with verifiedAt set — provenance must NOT
        // silently upgrade to `qr_scan`; `verified_at` must accept the
        // new value. This guards the deliberate omission of
        // `added_via` from the ON CONFLICT UPDATE list in upsertContact.
        var nowVerifiedPasted = p
        nowVerifiedPasted.verifiedAt = when
        // Simulate a future re-add path that mistakenly passes `.qrScan`
        // for an already-pasted row by reusing the existing UUID with
        // the new value; addedVia is `let` on Contact so we have to go
        // via a fresh model with the same id.
        let attemptedUpgrade = Contact(
            id: p.id,
            identityPub: p.identityPub,
            displayName: p.displayName,
            sessionEstablished: p.sessionEstablished,
            log: p.log,
            lastMessageAt: p.lastMessageAt,
            lastSeenAt: p.lastSeenAt,
            addedAt: p.addedAt,
            ttlSeconds: p.ttlSeconds,
            readReceiptsMode: p.readReceiptsMode,
            peerVerifyKey: p.peerVerifyKey,
            lastBundleServedAt: p.lastBundleServedAt,
            addedVia: .qrScan,
            verifiedAt: when,
        )
        try store.upsertContact(attemptedUpgrade)
        let reloaded = try store.loadContacts()
        let pAfter = try #require(reloaded.first { $0.id == p.id })
        #expect(pAfter.addedVia == .pastedText, "provenance must be sticky on re-upsert")
        #expect(pAfter.verifiedAt == when, "verifiedAt must be writable on update")
    }


    // MARK: - Outbox

    @Test("outbox entry round-trips")
    func outboxRoundTrip() throws {
        let store = try freshStore()
        let entry = OutboxEntry(
            messageId: Data(repeating: 0xBB, count: 16),
            recipientPeerId: Data(repeating: 0x09, count: 33),
            sealedCiphertext: Data(repeating: 0xCD, count: 200),
            token: Data(repeating: 0x55, count: 84),
            ttl: 86400,
            sentAt: Date(timeIntervalSinceReferenceDate: 0),
            retries: 2,
            deliveredAt: nil,
            failedAt: nil,
            relayedAt: Date(timeIntervalSinceReferenceDate: 5),
        )
        try store.upsertOutboxEntry(entry)
        let loaded = try store.loadOutbox()
        let got = try #require(loaded.entries[entry.messageId])
        #expect(got.messageId == entry.messageId)
        #expect(got.recipientPeerId == entry.recipientPeerId)
        #expect(got.sealedCiphertext == entry.sealedCiphertext)
        #expect(got.token == entry.token)
        #expect(got.retries == 2)
        #expect(got.deliveredAt == nil)
        #expect(got.relayedAt != nil)
    }

    // MARK: - Device store (libsignal blob)

    @Test("device store round-trips the libsignal blob")
    func deviceStoreRoundTrip() throws {
        let store = try freshStore()
        let session = try Session()
        let original = try session.serialize()
        try store.saveDeviceStore(original)
        let restored = try #require(try store.loadDeviceStore())
        #expect(restored == original)
        // And the loaded blob must rehydrate into a working Session
        // — ratchet continuity is the load-bearing invariant for
        // anything stored here.
        let rebuilt = try Session(serialized: restored)
        let rebuiltId = try rebuilt.identityPublic()
        let origId = try session.identityPublic()
        #expect(rebuiltId == origId)
    }

    // MARK: - Migration

    @Test("migration marker prevents re-running on a fresh-content database")
    func migrationMarker() throws {
        // Keychain is shared between the app and the test runner.
        // Whatever the iOS app left in `app-state` / `outbox` /
        // `device-store` would otherwise feed into the migration
        // path and make this test non-deterministic. Clear all four
        // legacy slots up front so the migration sees "fresh
        // install" content.
        Keychain.delete(account: "app-state")
        Keychain.delete(account: "outbox")
        Keychain.delete(account: "device-store")
        Keychain.delete(account: "long-term-identity")

        let store = try freshStore()
        try StorageMigration.run(storage: store)
        let stmt = try store.db.prepare("SELECT count(*) FROM meta WHERE key = ?;")
        try stmt.bindAll(StorageMigration.metaKey)
        #expect(try stmt.step())
        #expect(stmt.columnInt64(0) == 1, "marker row should exist after first run on fresh-content DB")
    }

    @Test("migration copies a Keychain AppState blob into SQLCipher and wipes the slot")
    func migrationCopiesLegacyAppState() throws {
        // Plant a synthetic legacy blob, run the migration, verify
        // SQLCipher has the data + Keychain has been wiped. Same
        // verify-before-delete defense as the production path.
        Keychain.delete(account: "app-state")
        Keychain.delete(account: "outbox")
        Keychain.delete(account: "device-store")
        Keychain.delete(account: "long-term-identity")

        let store = try freshStore()
        // Reset the migration marker so the run actually executes
        // its body — `freshStore` doesn't set it but the migration
        // bails early if it's present from a prior test run on the
        // same SQLCipher file (which can't happen here because the
        // path is per-test, but the assertion is cheap).
        try store.db.prepare("DELETE FROM meta WHERE key = ?;")
            .bindAll(StorageMigration.metaKey).run()

        let contact = Contact(
            identityPub: Data(repeating: 0x11, count: 33),
            displayName: "Migration Test",
            addedAt: Date(timeIntervalSinceReferenceDate: 100),
            ttlSeconds: 86400,
        )
        let legacy = AppState(
            relayHost: "192.168.1.42",
            contacts: [contact],
            onboardingCompleted: true,
        )
        let blob = try JSONEncoder().encode(legacy)
        _ = Keychain.write(blob, account: "app-state")

        try StorageMigration.run(storage: store)

        // Keychain slot should be empty.
        #expect(Keychain.read(account: "app-state") == nil, "legacy slot should be deleted post-migration")

        // SQLCipher should have the contact + settings.
        let settings = try store.loadSettings()
        #expect(settings?.relayHost == "192.168.1.42")
        #expect(settings?.onboardingCompleted == true)
        let contacts = try store.loadContacts()
        #expect(contacts.count == 1)
        #expect(contacts.first?.displayName == "Migration Test")
        #expect(contacts.first?.identityPub == contact.identityPub)
    }
}
