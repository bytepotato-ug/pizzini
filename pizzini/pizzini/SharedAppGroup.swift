import Foundation

/// Constants for the App Group container shared between the main app
/// and the Notification Service Extension. The main app writes the
/// authoritative `unreadCount`; the NSE reads + increments it on push
/// receive while the app is dead.
///
/// Mirror of `pizziniNotificationService/NotificationService.swift`.
/// Keep both in sync.
enum SharedAppGroup {
    static let identifier = "group.com.bytepotato.pizzini"
    static let unreadCountKey = "unreadCount"
    /// Per-resync floor for NSE bumps. Main app writes
    /// `state.totalUnread` here on every `refreshAppBadge`; the NSE
    /// caps its additions at `floor + nseBadgeCap`. Mirrors the
    /// constant in `NotificationService.swift`.
    static let nseBadgeFloorKey = "nseBadgeFloor"
    static let nseBadgeCap = 5
    /// Main app sets this when the user has muted notifications and
    /// the NSE should not touch the badge. Cleared on resume.
    static let suppressBadgeKey = "suppressBadgeBump"

    // ─── Main-app activity heartbeat (S11-03 / S7-07) ─────────────
    //
    // The NSE needs to answer one boolean question before bumping the
    // badge: "did the main app touch the authoritative count within
    // the last `mainAppActiveWindow` seconds?" If yes, the relay is
    // delivering the same payload to the live app and the NSE must NOT
    // double-count.
    //
    // The OLD design stored `Date().timeIntervalSince1970` at full
    // double precision in the App Group plist. That plist is
    // CompleteUntilFirstUserAuthentication (the NSE must read it while
    // locked-after-first-unlock), so it is AFU-readable by a seizure
    // examiner and by any co-resident app holding this App Group
    // entitlement. A precise last-foreground wall-clock timestamp is an
    // identifying engagement signal that undercuts a "lived-in but
    // quiescent" facade — a real metadata leak.
    //
    // Fix: persist the heartbeat COARSENED to a `mainAppActiveWindow`
    // bucket, never the precise epoch. The NSE's only consumer compares
    // `now - heartbeat < window`; a bucket floored to the window size
    // answers that question identically (worst case off by one bucket,
    // which is within the existing 30 s race tolerance) while removing
    // the sub-window engagement precision. The unread COUNT is kept —
    // it is the badge value and is not identifying (and is an already
    // accepted residual, F-PUSH-01).
    //
    // Callers should use `recordMainAppActive()` /
    // `mainAppRecentlyActive(now:)` rather than touching the key
    // directly, so the coarsening lives in one place. The raw
    // `mainAppActiveEpochKey` / `mainAppActiveWindow` constants are
    // retained for compile-stability with any caller still referencing
    // them (and the NSE mirror); the stored value behind the key is now
    // the coarse bucket, not a precise epoch.
    static let mainAppActiveEpochKey = "mainAppActiveEpoch"

    /// Seconds the main app's activity heartbeat suppresses NSE bumps.
    /// 30 s covers the race window between APNs delivery and the
    /// relay's delivery of the same payload (main app processes it
    /// either way), with margin for slower Tor circuits. After this
    /// window, the NSE assumes the main app is dead or background-
    /// suspended and resumes bumping. Doubles as the coarsening
    /// granularity for the persisted heartbeat bucket.
    static let mainAppActiveWindow: TimeInterval = 30

    /// Coarsen `date` to a `mainAppActiveWindow` bucket index
    /// (seconds-since-1970 floored to the window). Storing the bucket
    /// instead of the raw epoch keeps the precise foreground wall-clock
    /// time out of the App Group plist (S11-03) while preserving the
    /// "active within the window?" answer the NSE needs.
    static func activityBucket(for date: Date) -> Double {
        let epoch = date.timeIntervalSince1970
        return (epoch / mainAppActiveWindow).rounded(.down) * mainAppActiveWindow
    }

    /// Record that the main app just refreshed the authoritative badge.
    /// Persists only the coarse activity bucket — never a precise epoch.
    /// Call this from `refreshAppBadge` in place of writing
    /// `Date().timeIntervalSince1970` to `mainAppActiveEpochKey`.
    static func recordMainAppActive(at date: Date = Date(), into defaults: UserDefaults? = SharedAppGroup.defaults) {
        defaults?.set(activityBucket(for: date), forKey: mainAppActiveEpochKey)
    }

    /// True if the main app's last recorded activity bucket is within
    /// `mainAppActiveWindow` of `now`. The NSE calls this to decide
    /// whether to suppress its own badge bump. Because the stored value
    /// is bucket-floored, this can be at most one bucket stale, which is
    /// within the existing race tolerance. Returns false when no
    /// heartbeat has been written.
    static func mainAppRecentlyActive(now: Date = Date(), defaults: UserDefaults? = SharedAppGroup.defaults) -> Bool {
        guard let bucket = defaults?.double(forKey: mainAppActiveEpochKey), bucket > 0 else {
            return false
        }
        // The stored bucket is the FLOOR of the active time, so the real
        // activity could be up to one window later than the bucket.
        // Allow two windows of slack so a genuinely-recent activity that
        // floored to the previous bucket still counts as recent.
        return now.timeIntervalSince1970 - bucket < (mainAppActiveWindow * 2)
    }

    // ─── Duress-wipe sentinel (read by the NSE) ───────────────────
    //
    // Set when the app performs a duress wipe so the NSE can recognise
    // the post-wipe state and avoid resurrecting a badge / acting on a
    // stale count. A plain boolean — non-identifying. Exposed as a
    // getter/setter so both the main app and the NSE use one definition.
    static let duressWipedKey = "duressWiped"

    /// Whether a duress wipe has been performed. Backed by the App Group
    /// plist so the NSE (a separate process) can observe it.
    static var duressWiped: Bool {
        get { defaults?.bool(forKey: duressWipedKey) ?? false }
        set { defaults?.set(newValue, forKey: duressWipedKey) }
    }

    static var defaults: UserDefaults? {
        UserDefaults(suiteName: identifier)
    }
}
