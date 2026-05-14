import UserNotifications

/// Notification Service Extension. iOS invokes this when a push arrives
/// with `mutable-content: 1` set, *before* showing the notification.
///
/// Job: read the locally-stored unread count from the shared App Group
/// container, increment it, and stamp the result on the notification's
/// `badge`. The relay never sees this number — APNs only takes absolute
/// values, and Pizzini's threat model forbids leaking per-recipient
/// counts to the server. So the math runs here, on-device.
///
/// The main app overwrites the shared count with its real
/// `state.totalUnread` whenever it mutates state (`refreshAppBadge`).
/// On every push received while the app is dead, this extension bumps
/// the count by one. On next launch, the app re-syncs from its own
/// authoritative store.
final class NotificationService: UNNotificationServiceExtension {
    private var contentHandler: ((UNNotificationContent) -> Void)?
    private var bestAttemptContent: UNMutableNotificationContent?

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        self.contentHandler = contentHandler
        bestAttemptContent = request.content.mutableCopy() as? UNMutableNotificationContent
        guard let bestAttemptContent else {
            contentHandler(request.content)
            return
        }
        // Rate-limit the bump so a coercer who can see the locked
        // home-screen can't read the badge as an authoritative
        // "messages keep coming" oracle for the user. Cap the
        // extension's contribution at +NSEBadgeCap between main-app
        // resyncs. On resume the main app overwrites this with the
        // real `state.totalUnread`, so the cap is invisible in normal
        // use; it only bounds the visible counter when the app is dead
        // and a flood of pushes arrives. Also drops the cap when the
        // user is in `panicModeEnabled` (the per-chat mute / privacy-
        // first posture extends to badge-as-oracle): no NSE bump at
        // all, the badge stays at whatever the main app last wrote.
        let suite = UserDefaults(suiteName: SharedAppGroup.identifier)
        let panicLockBadge = suite?.bool(forKey: SharedAppGroup.suppressBadgeKey) ?? false
        if panicLockBadge {
            contentHandler(bestAttemptContent)
            return
        }
        // Skip the bump entirely when the main app was active within
        // `mainAppActiveWindow` seconds. In that case the relay also
        // delivered the same payload to the running main app, which
        // already called `refreshAppBadge` with the authoritative
        // count. A second bump here would double-count: the foreground
        // race produced the "badge=N when only 1 is unread" bug
        // reported 2026-05-14. Delivering without touching the badge
        // is correct — the main app's `setBadgeCount` is the
        // authoritative value while it's running.
        let epoch = suite?.double(forKey: SharedAppGroup.mainAppActiveEpochKey) ?? 0
        let now = Date().timeIntervalSince1970
        if epoch > 0, now - epoch < SharedAppGroup.mainAppActiveWindow {
            contentHandler(bestAttemptContent)
            return
        }
        let current = suite?.integer(forKey: SharedAppGroup.unreadCountKey) ?? 0
        let nseFloor = suite?.integer(forKey: SharedAppGroup.nseBadgeFloorKey) ?? 0
        let cap = nseFloor + SharedAppGroup.nseBadgeCap
        let next = min(current + 1, cap)
        suite?.set(next, forKey: SharedAppGroup.unreadCountKey)
        bestAttemptContent.badge = NSNumber(value: next)
        contentHandler(bestAttemptContent)
    }

    override func serviceExtensionTimeWillExpire() {
        // Hard 30s budget for the extension. If we hit it, deliver
        // whatever we've got — at minimum the original "New message"
        // alert without the badge bump.
        if let contentHandler, let bestAttemptContent {
            contentHandler(bestAttemptContent)
        }
    }
}

/// Mirror of `pizzini/SharedAppGroup.swift`. Both targets must agree on
/// these constants — duplicating two short strings is cheaper than
/// pulling in a shared module from a tiny app extension (extensions are
/// memory-budgeted; the smaller, the better).
enum SharedAppGroup {
    static let identifier = "group.com.bytepotato.pizzini"
    static let unreadCountKey = "unreadCount"
    /// Per-resync floor: the main app writes `state.totalUnread` here
    /// every time it refreshes the badge. The NSE will cap its
    /// contribution at `floor + nseBadgeCap`, so a flood of pushes
    /// while the app is dead can never inflate the badge past a
    /// small constant offset above the last truthful value.
    static let nseBadgeFloorKey = "nseBadgeFloor"
    /// Hard ceiling on how many bumps the NSE may add between
    /// main-app resyncs.
    static let nseBadgeCap = 5
    /// Sticky bit set by the main app when the user wants the NSE to
    /// stop touching the badge entirely (used by the per-chat mute
    /// + global-mute paths). Reset on next main-app resume.
    static let suppressBadgeKey = "suppressBadgeBump"
    /// Wall-clock seconds-since-1970 written by the main app on every
    /// `refreshAppBadge`. The NSE reads it; if the main app touched
    /// the badge within `mainAppActiveWindow` seconds, the NSE skips
    /// its own bump (the main app already has the authoritative count
    /// and a second bump here would double-count). See main-app
    /// mirror in `pizzini/SharedAppGroup.swift` for the full reasoning.
    static let mainAppActiveEpochKey = "mainAppActiveEpoch"
    static let mainAppActiveWindow: TimeInterval = 30
}
