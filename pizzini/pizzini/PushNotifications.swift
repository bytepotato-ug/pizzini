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
    /// Captured at `application(_:didFinishLaunchingWithOptions:)`
    /// time so non-AppDelegate code (the onboarding "Enable
    /// notifications" button) can reach the live instance to
    /// trigger `requestAuthorizationAndRegister`. `weak` because
    /// the system owns the lifecycle via `@UIApplicationDelegateAdaptor`.
    nonisolated(unsafe) static weak var shared: AppDelegate?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        Self.shared = self
        // Open the SQLCipher store + run the one-shot Keychain →
        // SQLCipher migration before any other init code constructs
        // `ChatStore.shared`. Storage methods on the SQLite-backed
        // facade dereference `SQLiteStorage.shared`, which is set
        // only after `Storage.bootstrap`; calling them earlier would
        // hit a force-unwrap. A failure here is fatal for app
        // function — surface it through the same diagnostic banner
        // path used for other unrecoverable startup errors.
        do {
            try Storage.bootstrap()
        } catch {
            NSLog("[pizzini] Storage.bootstrap failed: \(error)")
        }
        UNUserNotificationCenter.current().delegate = self
        // Window-level privacy shield: covers sheets and popovers in the
        // multitasking snapshot, which an in-body overlay can't do.
        // Install before any UI work so the observers are armed before
        // the first scene connection.
        PrivacyShieldWindow.shared.install()
        // Window-level screenshot mask: reparents each scene's main
        // window under a secure UITextField's layer, so the entire app
        // (including pushed views, sheets, full-screen covers — any
        // surface presented in the same window) is rendered as a black
        // frame in screenshots / mirroring / AirPlay capture. Layer-
        // only manipulation, view hierarchy untouched, so SwiftUI safe-
        // area handling is unaffected. See class doc for caveats.
        WindowSecureMask.shared.install()
        // Phase 5 self-test for the QR-screenshot-block trick. Runs
        // once on first launch; re-runs whenever the iOS major version
        // changes. Cheap (one offscreen UIView render) and idempotent —
        // the runIfNeeded gate skips work when the result is already
        // cached for the current OS major.
        Task { @MainActor in
            SecureScreenshotSelfTest.runIfNeeded(store: ChatStore.shared)
        }
        // Notification permission is NOT requested here. Onboarding
        // owns that decision — the user gets one clear "Enable
        // notifications?" page with an Enable/Skip pair of buttons,
        // not a system alert bombing them at first launch. After the
        // initial onboarding the iOS Settings app is the path to
        // re-prompt (UNUserNotificationCenter caches the first
        // decision; you can only re-prompt via the OS settings).
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

    /// Public so the onboarding's "Enable notifications" button can
    /// trigger the system prompt at a moment the user expects it.
    /// Returns `true` if the user granted authorization. Calling this
    /// after a previous decision is a no-op at the iOS level — the
    /// cached state stands; the user has to go to iOS Settings to
    /// change it.
    @discardableResult
    func requestAuthorizationAndRegister() async -> Bool {
        do {
            let granted = try await UNUserNotificationCenter.current()
                .requestAuthorization(options: [.alert, .sound, .badge])
            guard granted else {
                NSLog("[pizzini] notification authorization not granted")
                return false
            }
            await MainActor.run {
                UIApplication.shared.registerForRemoteNotifications()
            }
            return true
        } catch {
            NSLog("[pizzini] requestAuthorization failed: \(error)")
            return false
        }
    }
}
