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

    static var defaults: UserDefaults? {
        UserDefaults(suiteName: identifier)
    }
}
