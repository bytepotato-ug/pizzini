import Foundation
import Testing
@testable import pizzini

/// Re-pair UX: pin the post-reset banner flag's persistence + the
/// invariant that duressWipe does NOT set it (coercer-watching
/// design from the README session log Q2b). Full reset/wipe
/// integration is exercised by `xcodebuild test` against the sim;
/// these unit tests cover the flag itself and its UserDefaults
/// round-trip so a future refactor that swaps the storage key or
/// drops the persistence step breaks loudly.
@MainActor
@Suite("Identity-reset banner (re-pair UX)")
struct IdentityResetBannerTests {

    /// UserDefaults key that backs the flag. Must stay stable —
    /// changing it would silently lose a pending banner across an
    /// app upgrade.
    private static let key = "pizzini.identityResetBannerPending"

    /// Fixture: wipe the UserDefaults key before and after each
    /// test so the global state doesn't leak between cases.
    private func withCleanDefaults(_ body: () throws -> Void) rethrows {
        UserDefaults.standard.removeObject(forKey: Self.key)
        defer { UserDefaults.standard.removeObject(forKey: Self.key) }
        try body()
    }

    /// Setting the flag to true persists; clearing it persists too.
    /// The didSet observer is the contract; this test pins it.
    @Test("setting the flag round-trips through UserDefaults")
    func roundTrip() {
        withCleanDefaults {
            let store = ChatStore()
            #expect(store.identityResetBannerPending == false)
            store.identityResetBannerPending = true
            #expect(UserDefaults.standard.bool(forKey: Self.key) == true)
            store.identityResetBannerPending = false
            #expect(UserDefaults.standard.bool(forKey: Self.key) == false)
        }
    }

    /// On bootstrap, the flag picks up the persisted UserDefaults
    /// value. This guards against a crash between
    /// `resetIdentity()` setting the flag and the user tapping
    /// "Got it" — the next launch must still surface the banner.
    @Test("init() restores a pending banner from UserDefaults")
    func initRestoresPersistedFlag() {
        withCleanDefaults {
            UserDefaults.standard.set(true, forKey: Self.key)
            let store = ChatStore()
            #expect(store.identityResetBannerPending == true)
        }
    }

    /// On bootstrap, an absent key reads as false (no banner).
    /// Default behaviour for fresh installs and for users who
    /// have never reset.
    @Test("init() defaults to false when UserDefaults key is unset")
    func initDefaultsFalse() {
        withCleanDefaults {
            let store = ChatStore()
            #expect(store.identityResetBannerPending == false)
        }
    }

    /// `dismissIdentityResetBanner()` clears the flag and the
    /// persisted value in one call. Idempotent — a duplicate call
    /// after the flag is already false is a no-op (no crash, no
    /// state churn beyond the UserDefaults write).
    @Test("dismissIdentityResetBanner clears the flag idempotently")
    func dismissIdempotent() {
        withCleanDefaults {
            let store = ChatStore()
            store.identityResetBannerPending = true
            #expect(store.identityResetBannerPending == true)
            store.dismissIdentityResetBanner()
            #expect(store.identityResetBannerPending == false)
            #expect(UserDefaults.standard.bool(forKey: Self.key) == false)
            // Second call is a no-op.
            store.dismissIdentityResetBanner()
            #expect(store.identityResetBannerPending == false)
        }
    }
}
