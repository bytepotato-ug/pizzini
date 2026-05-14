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

    /// Wall-clock seconds-since-1970 written by the main app on every
    /// `refreshAppBadge`. The NSE reads it before bumping; if the main
    /// app touched the badge within `mainAppActiveWindow` seconds, the
    /// NSE skips its own bump entirely on the assumption that the main
    /// app already has the authoritative count.
    ///
    /// Why this exists. The race that motivated this: in-foreground
    /// chat, push arrives. Relay delivers the same message. Main app
    /// processes → `markRead` → `setBadgeCount(0)` → writes
    /// `unreadCountKey=0`. The NSE fires for the same push immediately
    /// after, reads `unreadCountKey=0`, bumps to 1, sets `badge=1`.
    /// Net result: badge=1 for a message the user has already read.
    /// Across 5 messages in a row, the badge ends up at 5.
    static let mainAppActiveEpochKey = "mainAppActiveEpoch"

    /// Seconds the main app's activity epoch suppresses NSE bumps.
    /// 30 s covers the race window between APNs delivery and the
    /// relay's delivery of the same payload (main app processes it
    /// either way), with margin for slower Tor circuits. After this
    /// window, the NSE assumes the main app is dead or background-
    /// suspended and resumes bumping.
    static let mainAppActiveWindow: TimeInterval = 30

    static var defaults: UserDefaults? {
        UserDefaults(suiteName: identifier)
    }
}
