import Foundation
import Testing
@testable import pizzini

@Suite("Entitlement tier derivation")
struct EntitlementTierTests {
    private let monthly = SubscriptionProductID.monthly
    private let lifetime = SubscriptionProductID.lifetime

    @Test("empty records → .free")
    func emptyIsFree() {
        #expect(entitlementTier(from: []) == .free)
    }

    @Test("only a monthly transaction → .monthly")
    func monthlyOnly() {
        let r = [EntitlementRecord(productID: monthly, revocationDate: nil)]
        #expect(entitlementTier(from: r) == .monthly)
    }

    @Test("only a lifetime transaction → .lifetime")
    func lifetimeOnly() {
        let r = [EntitlementRecord(productID: lifetime, revocationDate: nil)]
        #expect(entitlementTier(from: r) == .lifetime)
    }

    @Test("lifetime beats monthly when both present")
    func lifetimeBeatsMonthly() {
        let r = [
            EntitlementRecord(productID: monthly, revocationDate: nil),
            EntitlementRecord(productID: lifetime, revocationDate: nil),
        ]
        #expect(entitlementTier(from: r) == .lifetime)
    }

    @Test("revoked lifetime falls back to active monthly")
    func revokedLifetimeFallsBackToMonthly() {
        let r = [
            EntitlementRecord(productID: lifetime, revocationDate: Date()),
            EntitlementRecord(productID: monthly, revocationDate: nil),
        ]
        #expect(entitlementTier(from: r) == .monthly)
    }

    @Test("revoked monthly with no other records → .free")
    func revokedMonthlyIsFree() {
        let r = [EntitlementRecord(productID: monthly, revocationDate: Date())]
        #expect(entitlementTier(from: r) == .free)
    }

    @Test("unknown product IDs are ignored")
    func unknownProductIDsIgnored() {
        let r = [
            EntitlementRecord(productID: "com.bytepotato.pizzini.unrelated", revocationDate: nil),
        ]
        #expect(entitlementTier(from: r) == .free)
    }
}

@Suite("Support banner visibility policy")
struct SupportBannerPolicyTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func install(daysAgo days: Double) -> Date {
        now.addingTimeInterval(-days * 24 * 60 * 60)
    }

    @Test("brand-new install → never show (under 7 days)")
    func freshInstallSilent() {
        #expect(
            SupportBannerPolicy.shouldShow(
                now: now,
                installDate: install(daysAgo: 1),
                lastDismissed: nil,
                tier: .free,
            ) == false
        )
    }

    @Test("exactly at 7-day boundary → show")
    func sevenDayBoundaryShows() {
        #expect(
            SupportBannerPolicy.shouldShow(
                now: now,
                installDate: install(daysAgo: 7),
                lastDismissed: nil,
                tier: .free,
            ) == true
        )
    }

    @Test("entitled user is never shown the banner — monthly")
    func monthlyTierSilencesBanner() {
        #expect(
            SupportBannerPolicy.shouldShow(
                now: now,
                installDate: install(daysAgo: 30),
                lastDismissed: nil,
                tier: .monthly,
            ) == false
        )
    }

    @Test("entitled user is never shown the banner — lifetime")
    func lifetimeTierSilencesBanner() {
        #expect(
            SupportBannerPolicy.shouldShow(
                now: now,
                installDate: install(daysAgo: 365),
                lastDismissed: nil,
                tier: .lifetime,
            ) == false
        )
    }

    @Test("recently dismissed → hide for 30 days")
    func dismissalGracePeriod() {
        let lastDismissed = now.addingTimeInterval(-(20 * 24 * 60 * 60))
        #expect(
            SupportBannerPolicy.shouldShow(
                now: now,
                installDate: install(daysAgo: 60),
                lastDismissed: lastDismissed,
                tier: .free,
            ) == false
        )
    }

    @Test("dismissal grace expires after 30 days → show again")
    func dismissalGraceExpires() {
        let lastDismissed = now.addingTimeInterval(-(31 * 24 * 60 * 60))
        #expect(
            SupportBannerPolicy.shouldShow(
                now: now,
                installDate: install(daysAgo: 60),
                lastDismissed: lastDismissed,
                tier: .free,
            ) == true
        )
    }

    @Test("install < 7 days but already dismissed → still hide on age")
    func ageGateDominatesDismissal() {
        let lastDismissed = now.addingTimeInterval(-(100 * 24 * 60 * 60))
        #expect(
            SupportBannerPolicy.shouldShow(
                now: now,
                installDate: install(daysAgo: 3),
                lastDismissed: lastDismissed,
                tier: .free,
            ) == false
        )
    }
}

@Suite("Subscription tier ordering")
struct SubscriptionTierOrderingTests {
    @Test("rank: free < monthly < lifetime")
    func rankOrder() {
        #expect(SubscriptionTier.free.rank < SubscriptionTier.monthly.rank)
        #expect(SubscriptionTier.monthly.rank < SubscriptionTier.lifetime.rank)
    }

    @Test("label strings are non-empty for every case")
    func labelsAreNonEmpty() {
        for tier in SubscriptionTier.allCases {
            #expect(!tier.label.isEmpty)
        }
    }
}
