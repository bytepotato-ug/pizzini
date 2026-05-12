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

    static var defaults: UserDefaults? {
        UserDefaults(suiteName: identifier)
    }
}
