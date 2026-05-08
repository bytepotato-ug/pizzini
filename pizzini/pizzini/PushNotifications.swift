import Foundation
import SwiftUI
import UIKit
import UserNotifications

/// `UIApplicationDelegateAdaptor` host. SwiftUI's `App` doesn't surface
/// the AppDelegate hooks we need for APNs token registration, so we
/// pin one here and forward the device token to `ChatStore`.
///
/// What lives here vs. ChatStore: this delegate is the only place that
/// receives the raw APNs token from iOS. ChatStore owns the relay
/// connection that the token needs to be published over. We bridge by
/// calling `ChatStore.shared.publishPushToken(_:)`.
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        Task { await requestAuthorizationAndRegister() }
        return true
    }

    func application(
        _ application: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        Task { @MainActor in
            ChatStore.shared.publishPushToken(deviceToken)
        }
    }

    func application(
        _ application: UIApplication,
        didFailToRegisterForRemoteNotificationsWithError error: Error
    ) {
        NSLog("[pizzini] APNs registration failed: \(error)")
    }

    /// Show alerts even when the app is foregrounded — useful for dev
    /// while we're observing the wake-up flow. In production we'd
    /// probably suppress them when the relevant chat is on screen.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound, .badge])
    }

    private func requestAuthorizationAndRegister() async {
        do {
            let granted = try await UNUserNotificationCenter.current()
                .requestAuthorization(options: [.alert, .sound, .badge])
            guard granted else {
                NSLog("[pizzini] notification authorization not granted")
                return
            }
            await MainActor.run {
                UIApplication.shared.registerForRemoteNotifications()
            }
        } catch {
            NSLog("[pizzini] requestAuthorization failed: \(error)")
        }
    }
}
