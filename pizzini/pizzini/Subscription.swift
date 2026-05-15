import Foundation
import StoreKit
import SwiftUI

/// Optional "Support Pizzini" purchases. Two products, sold side-by-side:
///
///   - `com.bytepotato.pizzini.support.monthly` — auto-renewing $0.99/mo
///   - `com.bytepotato.pizzini.support.lifetime` — non-consumable $199
///
/// The audience is journalists and activists. Gating safety features
/// behind a paywall is unacceptable; these purchases unlock NOTHING in
/// the app beyond a small "Support Pizzini" badge in Settings. They are
/// pure thank-yous. The threat-model rule that we never validate
/// receipts against our own server holds here too: every entitlement
/// decision is taken from a locally-verified StoreKit 2 transaction.
/// Apple's servers are still in the loop — that is documented platform
/// behaviour, not third-party telemetry.
enum SubscriptionTier: String, Sendable, Equatable, CaseIterable {
    case free
    case monthly
    case lifetime

    /// Sort order so lifetime wins over monthly when both are active —
    /// a one-time purchase shouldn't be downgraded by an in-flight
    /// renewal.
    var rank: Int {
        switch self {
        case .free: return 0
        case .monthly: return 1
        case .lifetime: return 2
        }
    }

    var label: String {
        switch self {
        case .free: return "Free"
        case .monthly: return "Monthly supporter"
        case .lifetime: return "Lifetime supporter"
        }
    }
}

/// Stable product identifiers used both by `SubscriptionService` and by
/// the App Store Connect configuration the operator owns. Don't rename
/// without coordinating with the operator — Apple keys purchases by
/// these strings forever.
enum SubscriptionProductID {
    static let monthly = "com.bytepotato.pizzini.support.monthly"
    static let lifetime = "com.bytepotato.pizzini.support.lifetime"

    static let all: Set<String> = [monthly, lifetime]
}

/// Minimal projection of a StoreKit 2 `Transaction` for the tier
/// derivation. Concrete `Transaction` values can't be constructed in
/// unit tests (Apple's struct has no public init), so the derivation
/// function operates on this struct instead and the production path
/// adapts in.
struct EntitlementRecord: Equatable, Sendable {
    let productID: String
    /// Non-nil iff Apple revoked the purchase (chargeback, family-share
    /// removal). A revoked record never grants entitlement.
    let revocationDate: Date?
}

/// Pure derivation function — the only place tier-precedence logic
/// lives. Public so the unit tests can hit every branch without
/// reaching into the actor.
///
/// Rules:
///   1. If any non-revoked lifetime record is present → `.lifetime`.
///   2. Otherwise, if any non-revoked monthly record is present → `.monthly`.
///   3. Otherwise → `.free`.
///
/// A record whose `revocationDate` is non-nil counts as revoked and is
/// ignored — Apple sets this when a chargeback or family-share removal
/// happens.
func entitlementTier(from records: [EntitlementRecord]) -> SubscriptionTier {
    var hasMonthly = false
    for r in records where r.revocationDate == nil {
        if r.productID == SubscriptionProductID.lifetime {
            return .lifetime
        }
        if r.productID == SubscriptionProductID.monthly {
            hasMonthly = true
        }
    }
    return hasMonthly ? .monthly : .free
}

private extension StoreKit.Transaction {
    var entitlementRecord: EntitlementRecord {
        EntitlementRecord(productID: productID, revocationDate: revocationDate)
    }
}

/// Coordinator for the optional support purchases. Single shared
/// instance kicked off at app launch (see `pizziniApp.swift`). Listens
/// to `Transaction.updates` for the app lifetime so a renewal, refund,
/// or family-share change reflects in the UI without a relaunch.
@MainActor
@Observable
final class SubscriptionService {
    static let shared = SubscriptionService()

    /// Current entitlement. SwiftUI views read this directly — the
    /// `@Observable` macro generates the change tracking that triggers
    /// redraws of the Settings row and the sidebar badge.
    private(set) var currentTier: SubscriptionTier = .free

    /// Available products fetched from the App Store. Empty until
    /// `loadProducts` completes — surfaces that state to the UI so the
    /// purchase buttons stay disabled rather than mysteriously
    /// no-opping.
    private(set) var products: [Product] = []

    /// True while a `Product.purchase()` call is in flight. The view
    /// uses it to disable both purchase buttons during the StoreKit
    /// modal so a frustrated double-tap doesn't queue two purchase
    /// attempts.
    private(set) var isPurchasing: Bool = false

    /// Surfaced when a load / purchase / refresh fails. Cleared by the
    /// next successful call. Plain-language string, not the raw
    /// `StoreKitError` — the user can't act on `.systemError(_)`.
    private(set) var lastError: String?

    /// Task that watches `Transaction.updates` for the app's lifetime.
    /// Held as a property so it survives across the actor's iterations
    /// and is never cancelled — losing this stream would mean a
    /// renewal landing in the background never reaches the UI.
    private var updatesTask: Task<Void, Never>?

    /// Convenience accessors for the Settings row layout, so the view
    /// doesn't have to know about product IDs.
    var monthlyProduct: Product? {
        products.first { $0.id == SubscriptionProductID.monthly }
    }

    var lifetimeProduct: Product? {
        products.first { $0.id == SubscriptionProductID.lifetime }
    }

    /// True for any tier other than `.free`. Drives the small thank-you
    /// badge in the Settings sidebar — subtle by design.
    var isEntitled: Bool { currentTier != .free }

    private init() {}

    /// Wire up the service. Idempotent — calling twice does nothing
    /// because the updates Task is already running. Call once from
    /// the AppDelegate.
    func start() {
        if updatesTask != nil { return }
        updatesTask = Task { [weak self] in
            for await update in Transaction.updates {
                await self?.handleTransactionUpdate(update)
            }
        }
        Task { await self.refreshEntitlements() }
        Task { await self.loadProducts() }
    }

    /// Fetch the two products from the App Store. Failure modes:
    ///   - Sandbox account not configured → empty result, no error.
    ///   - Network failure → throws, surfaced via `lastError`.
    /// Both are safe to retry; the view exposes a Retry button.
    func loadProducts() async {
        do {
            let fetched = try await Product.products(for: Array(SubscriptionProductID.all))
            // Stable order: monthly first, then lifetime. Apple's
            // returned order is unspecified.
            self.products = fetched.sorted { a, b in
                if a.id == SubscriptionProductID.monthly { return true }
                if b.id == SubscriptionProductID.monthly { return false }
                return a.id < b.id
            }
            self.lastError = nil
        } catch {
            self.lastError = "Couldn't reach the App Store. Try again."
        }
    }

    /// Walk every current entitlement and recompute the tier. Called
    /// at start-up and after each transaction update.
    func refreshEntitlements() async {
        var records: [EntitlementRecord] = []
        for await result in Transaction.currentEntitlements {
            if let tx = Self.verifiedTransaction(result) {
                records.append(tx.entitlementRecord)
            }
        }
        self.currentTier = entitlementTier(from: records)
    }

    /// Initiate a purchase. The StoreKit 2 modal owns the UX — we just
    /// observe the result, finish the transaction, and refresh.
    func purchase(_ product: Product) async {
        if isPurchasing { return }
        isPurchasing = true
        defer { isPurchasing = false }

        do {
            let result = try await product.purchase()
            switch result {
            case .success(let verification):
                if let tx = Self.verifiedTransaction(verification) {
                    await tx.finish()
                    await refreshEntitlements()
                    lastError = nil
                } else {
                    // Apple returned a transaction the signed-receipt
                    // check rejected. Treat as a failure — never grant
                    // entitlement without verification.
                    lastError = "Purchase couldn't be verified."
                }
            case .userCancelled:
                // Not an error. The user backed out of the sheet.
                break
            case .pending:
                // Ask-to-buy / SCA approval pending. The eventual
                // resolution arrives via Transaction.updates.
                lastError = "Purchase pending approval."
            @unknown default:
                lastError = "Purchase couldn't complete."
            }
        } catch {
            lastError = "Purchase failed."
        }
    }

    /// Re-check entitlements with the App Store. Surfaced as the
    /// "Restore purchases" button — required by App Review for any
    /// app that sells non-consumables.
    func restore() async {
        do {
            try await AppStore.sync()
            await refreshEntitlements()
            lastError = nil
        } catch {
            lastError = "Couldn't refresh from the App Store."
        }
    }

    private func handleTransactionUpdate(_ result: VerificationResult<StoreKit.Transaction>) async {
        guard let tx = Self.verifiedTransaction(result) else { return }
        await tx.finish()
        await refreshEntitlements()
    }

    /// Unwrap a `VerificationResult` and return the transaction only
    /// if StoreKit's local signed-payload check passed. We never use
    /// the unverified branch — Apple's `.unverified` reason is opaque
    /// (clock skew, tampered receipt, devmode) and we don't have a
    /// safe heuristic for distinguishing them. Drop and move on.
    static func verifiedTransaction(_ result: VerificationResult<StoreKit.Transaction>) -> StoreKit.Transaction? {
        switch result {
        case .verified(let tx): return tx
        case .unverified: return nil
        }
    }
}

// MARK: - First-run support banner

/// Heuristic owner for the "after 7 days of use" support banner. Pure
/// in: input dates, dismissal state, current tier. Pure out: should it
/// show? Unit-tested without touching UserDefaults so all branches
/// (entitled / too-fresh / recently-dismissed / re-eligible) are
/// exercisable.
///
/// Rules:
///   - never show if the user holds any paid tier
///   - never show before 7 days have elapsed since the install date
///   - if previously dismissed, hide for 30 days from the dismissal
enum SupportBannerPolicy {
    static let initialDelay: TimeInterval = 7 * 24 * 60 * 60
    static let redisplayInterval: TimeInterval = 30 * 24 * 60 * 60

    static func shouldShow(
        now: Date,
        installDate: Date,
        lastDismissed: Date?,
        tier: SubscriptionTier
    ) -> Bool {
        if tier != .free { return false }
        if now.timeIntervalSince(installDate) < initialDelay { return false }
        if let lastDismissed,
           now.timeIntervalSince(lastDismissed) < redisplayInterval {
            return false
        }
        return true
    }
}

/// Persistent install-date + banner-dismissal state. Lives in
/// `UserDefaults.standard` so a SQLCipher key rotation or a wallet
/// reset doesn't reset the timer — the banner is purely about
/// "how long has this app been on this device", which is the same
/// signal `UserDefaults` survives.
@MainActor
@Observable
final class SupportBannerState {
    static let shared = SupportBannerState()

    private static let installDateKey = "pizzini.installDate"
    private static let dismissedAtKey = "pizzini.supportBannerDismissedAt"

    /// Set on first launch and never written again. Stored as the
    /// epoch-seconds Double — Foundation's date encoding is more
    /// stable across iOS versions than `NSDate` archiving.
    let installDate: Date

    /// `nil` until the user dismisses the banner. Re-set on each
    /// dismiss; the 30-day re-display window measures from this.
    private(set) var lastDismissed: Date?

    private init() {
        let defaults = UserDefaults.standard
        // Read-or-write the install date atomically. First-launch
        // detection by absence: `UserDefaults.double(forKey:)`
        // returns 0 for a missing key and 0 is never a valid epoch
        // value for an app installed in 2026, so we use 0 as the
        // sentinel.
        let stored = defaults.double(forKey: Self.installDateKey)
        if stored > 0 {
            self.installDate = Date(timeIntervalSince1970: stored)
        } else {
            let now = Date()
            self.installDate = now
            defaults.set(now.timeIntervalSince1970, forKey: Self.installDateKey)
        }
        let dismissedAt = defaults.double(forKey: Self.dismissedAtKey)
        self.lastDismissed = dismissedAt > 0
            ? Date(timeIntervalSince1970: dismissedAt)
            : nil
    }

    /// User tapped the banner's close button. Records the moment so
    /// the 30-day re-display window starts ticking.
    func dismiss() {
        let now = Date()
        lastDismissed = now
        UserDefaults.standard.set(now.timeIntervalSince1970, forKey: Self.dismissedAtKey)
    }

    /// View-facing predicate. Combines the persistent install/dismiss
    /// state with the current entitlement tier so the banner reacts
    /// the instant the user buys.
    func shouldShow(now: Date = Date(), tier: SubscriptionTier) -> Bool {
        SupportBannerPolicy.shouldShow(
            now: now,
            installDate: installDate,
            lastDismissed: lastDismissed,
            tier: tier,
        )
    }
}

// MARK: - Views

/// Settings → Support row + the two purchase buttons. Lives inline in
/// `SettingsView` rather than a pushed sub-page: there's nothing on a
/// detail page that doesn't fit in one Form section, and an extra tap
/// distance from a thank-you affordance would feel like a paywall.
struct SupportPizziniSection: View {
    @Bindable var service: SubscriptionService

    var body: some View {
        Section {
            HStack {
                Label("Current tier", systemImage: "heart")
                Spacer()
                Text(service.currentTier.label)
                    .foregroundStyle(.secondary)
            }
            if let monthly = service.monthlyProduct {
                Button {
                    Task { await service.purchase(monthly) }
                } label: {
                    HStack {
                        Text("Monthly — \(monthly.displayPrice)")
                        Spacer()
                        if service.isPurchasing { ProgressView().controlSize(.small) }
                    }
                }
                .disabled(service.isPurchasing || service.currentTier == .lifetime)
            }
            if let lifetime = service.lifetimeProduct {
                Button {
                    Task { await service.purchase(lifetime) }
                } label: {
                    HStack {
                        Text("Lifetime — \(lifetime.displayPrice)")
                        Spacer()
                        if service.isPurchasing { ProgressView().controlSize(.small) }
                    }
                }
                .disabled(service.isPurchasing || service.currentTier == .lifetime)
            }
            if service.products.isEmpty {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Loading…")
                        .foregroundStyle(.secondary)
                }
            }
            Button("Restore purchases") {
                Task { await service.restore() }
            }
            .disabled(service.isPurchasing)
        } header: {
            Text("Support Pizzini")
        } footer: {
            if let err = service.lastError {
                Text(err).foregroundStyle(.red)
            } else {
                Text("Pizzini is free and AGPL. Buying a tier doesn't unlock anything — every safety feature stays available to every user. Treat these as tip jars.")
            }
        }
    }
}

/// First-run banner. Lives above the chat list when
/// `SupportBannerState.shouldShow` returns true. Tap to navigate to
/// Settings, X to dismiss. Designed to be visually quiet — a thin pill,
/// not a card.
struct SupportBanner: View {
    let onTap: () -> Void
    let onDismiss: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "heart.fill")
                .foregroundStyle(.tint)
                .font(.callout)
            Button(action: onTap) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Pizzini is free and AGPL.")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text("$0.99/mo or $199 lifetime keeps it shipping. Tap to support.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }
            .buttonStyle(.plain)
            Spacer(minLength: 0)
            Button(action: onDismiss) {
                Image(systemName: "xmark")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(6)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Dismiss")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(Color(.secondarySystemBackground))
    }
}
