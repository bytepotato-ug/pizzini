import Foundation
import os
import SwiftUI
import UIKit
import UserNotifications

/// Push / APNs lifecycle log channel. Console.app filter:
/// `subsystem:app.pizzini category:push`. Error bodies are
/// `privacy: .private` so they're redacted in sysdiagnose
/// (matches the threat-model concern documented in
/// `PrivateLog.swift`) but stay readable in dev.
private let pushLog = Logger(subsystem: "app.pizzini", category: "push")

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
            pushLog.fault("Storage.bootstrap failed: \(String(describing: error), privacy: .private)")
        }
        // Tor bootstrap is owned by RelayClient.startTorConnection on
        // ChatStore.init → connectRelay. We don't kick it earlier
        // here: cold-launch correctness comes from
        // `TorController.prepareHiddenService(_:)` priming the HS
        // descriptor cache before the first SOCKS5 CONNECT, not from
        // shaving the 1-2 s tor warmup off the launch path.
        UNUserNotificationCenter.current().delegate = self
        // Window-level privacy shield: covers sheets and popovers in the
        // multitasking snapshot, which an in-body overlay can't do.
        // Install before any UI work so the observers are armed before
        // the first scene connection.
        PrivacyShieldWindow.shared.install()
        // **Run the screenshot-mask self-test SYNCHRONOUSLY**, before
        // `WindowSecureMask.install()` so the mask decision is final
        // before the first scene activates. Previously the self-test
        // ran inside a Task, racing scene activation — the first
        // frame on a brand-new iOS major could paint OPTIMISTICALLY
        // (`shouldMaskAppContents` returns true when `qrBlockEffective`
        // is nil) and leak to a screenshot taken in that ~1-2 frame
        // window. One offscreen UIView render is cheap; running it
        // inline here closes that window.
        SecureScreenshotSelfTest.runIfNeeded(store: ChatStore.shared)
        // Window-level screenshot mask: reparents each scene's main
        // window under a secure UITextField's layer, so the entire app
        // (including pushed views, sheets, full-screen covers — any
        // surface presented in the same window) is rendered as a black
        // frame in screenshots / mirroring / AirPlay capture. Layer-
        // only manipulation, view hierarchy untouched, so SwiftUI safe-
        // area handling is unaffected. See class doc for caveats.
        WindowSecureMask.shared.install()
        // Notification permission is NOT requested here. Onboarding
        // owns that decision — the user gets one clear "Enable
        // notifications?" page with an Enable/Skip pair of buttons,
        // not a system alert bombing them at first launch. After the
        // initial onboarding the iOS Settings app is the path to
        // re-prompt (UNUserNotificationCenter caches the first
        // decision; you can only re-prompt via the OS settings).
        //
        // **But we DO re-register for remote notifications on every
        // launch where the user previously authorized.** Apple's
        // documented behaviour: `registerForRemoteNotifications()`
        // is the only way iOS delivers (or refreshes) the device
        // token via `didRegisterForRemoteNotificationsWithDeviceToken`.
        // iOS rotates tokens occasionally and invalidates them when
        // the app is reinstalled / restored to a new device; without
        // this re-registration call, `pushTokenCached` stays nil
        // forever after the first launch, no token reaches the
        // relay, and APNs wake-ups silently never arrive. The
        // permission prompt does NOT re-appear — `registerForRemote
        // Notifications` is a no-op when authorization isn't
        // granted; we gate on the cached `getNotificationSettings`
        // status so we only call it for users who said yes.
        rerequestPushTokenIfAuthorized()
        // Secondary wake-up path: register the BGAppRefreshTask
        // handler before `application:didFinishLaunchingWithOptions`
        // returns. iOS requires the call here — registering later
        // raises a fault and disables the task. The actual
        // SUBMIT is driven from `disconnectForBackground`'s caller
        // (`UIScene.didEnterBackgroundNotification` in
        // `ContentView`), so this line just wires the handler.
        BackgroundRefresh.register { task in
            BackgroundRefresh.handle(task: task)
        }
        // Optional support purchases — start the Transaction.updates
        // listener early so a renewal landing in the background or
        // an Ask-to-Buy approval that arrived overnight is reflected
        // in the UI on first foreground. Idempotent; safe across
        // re-launches.
        SubscriptionService.shared.start()
        // First-run install date — single-shot UserDefaults write
        // on the first launch. Triggering construction here means
        // the timer starts the instant the user opens the app for
        // the first time, not whenever they happen to scroll to the
        // chat list.
        _ = SupportBannerState.shared
        return true
    }

    /// Re-trigger the device-token delivery callback on every launch
    /// where the user has previously granted notification permission.
    /// Idempotent on iOS's side (returns the cached token unless
    /// it's been rotated). Off the main thread because
    /// `getNotificationSettings` is async; the actual
    /// `registerForRemoteNotifications` call hops back to MainActor
    /// because UIApplication's API requires it.
    private func rerequestPushTokenIfAuthorized() {
        Task { @MainActor in
            let settings = await UNUserNotificationCenter.current().notificationSettings()
            switch settings.authorizationStatus {
            case .authorized, .provisional, .ephemeral:
                UIApplication.shared.registerForRemoteNotifications()
            case .notDetermined, .denied:
                // Onboarding will prompt for `notDetermined` users;
                // denied users explicitly opted out and re-prompting
                // would be obnoxious.
                break
            @unknown default:
                break
            }
        }
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
        pushLog.error("APNs registration failed: \(String(describing: error), privacy: .private)")
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
                pushLog.notice("notification authorization not granted")
                return false
            }
            await MainActor.run {
                UIApplication.shared.registerForRemoteNotifications()
            }
            return true
        } catch {
            pushLog.error("requestAuthorization failed: \(String(describing: error), privacy: .private)")
            return false
        }
    }
}
