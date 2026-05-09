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
        let suite = UserDefaults(suiteName: SharedAppGroup.identifier)
        let current = suite?.integer(forKey: SharedAppGroup.unreadCountKey) ?? 0
        let next = current + 1
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
}
