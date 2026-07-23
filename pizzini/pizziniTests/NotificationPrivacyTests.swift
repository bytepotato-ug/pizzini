import Foundation
import Testing
import UserNotifications
@testable import pizzini

/// F-PUSH-03 pins. Both suites exercise pure decision surfaces —
/// no UNUserNotificationCenter, no ProcessInfo, no UserDefaults — so
/// they run in any test host without entitlements (house pattern, see
/// BackgroundRefreshTests). The FAQ-copy ↔ patched-version coupling for
/// this feature lives in FAQCopyRegressionTests
/// (pushNotificationsNamesTheRealPatchedBuilds).

@Suite("OS notification-retention advisory (CVE-2026-28950)")
struct NotificationRetentionAdvisoryTests {
    private func v(_ major: Int, _ minor: Int, _ patch: Int) -> OperatingSystemVersion {
        OperatingSystemVersion(majorVersion: major, minorVersion: minor, patchVersion: patch)
    }

    @Test("iOS 18 builds below 18.7.8 are vulnerable")
    func ios18Vulnerable() {
        #expect(NotificationRetentionAdvisory.isVulnerable(v(18, 0, 0)))
        #expect(NotificationRetentionAdvisory.isVulnerable(v(18, 6, 2)))
        #expect(NotificationRetentionAdvisory.isVulnerable(v(18, 7, 7)))
    }

    @Test("iOS 18 builds at or past 18.7.8 are patched")
    func ios18Patched() {
        #expect(!NotificationRetentionAdvisory.isVulnerable(v(18, 7, 8)))
        #expect(!NotificationRetentionAdvisory.isVulnerable(v(18, 7, 9)))
        #expect(!NotificationRetentionAdvisory.isVulnerable(v(18, 8, 0)))
    }

    @Test("iOS 26 builds below 26.4.2 are vulnerable")
    func ios26Vulnerable() {
        #expect(NotificationRetentionAdvisory.isVulnerable(v(26, 0, 0)))
        #expect(NotificationRetentionAdvisory.isVulnerable(v(26, 3, 9)))
        #expect(NotificationRetentionAdvisory.isVulnerable(v(26, 4, 1)))
    }

    @Test("iOS 26 builds at or past 26.4.2 are patched")
    func ios26Patched() {
        #expect(!NotificationRetentionAdvisory.isVulnerable(v(26, 4, 2)))
        #expect(!NotificationRetentionAdvisory.isVulnerable(v(26, 5, 0)))
    }

    @Test("majors outside the table never trigger the advisory")
    func unknownMajors() {
        // Below the deployment target (cannot run this app), the
        // skipped 19–25 range, and post-fix majors.
        #expect(!NotificationRetentionAdvisory.isVulnerable(v(17, 7, 10)))
        #expect(!NotificationRetentionAdvisory.isVulnerable(v(19, 0, 0)))
        #expect(!NotificationRetentionAdvisory.isVulnerable(v(25, 9, 9)))
        #expect(!NotificationRetentionAdvisory.isVulnerable(v(27, 0, 0)))
    }

    @Test("dismissal is keyed to the exact OS build")
    func dismissalKeying() {
        let vulnerable = v(26, 4, 0)
        // Never dismissed → show.
        #expect(NotificationRetentionAdvisory.shouldShow(
            current: vulnerable, dismissedVersion: nil))
        // Dismissed on this exact build → hidden.
        #expect(!NotificationRetentionAdvisory.shouldShow(
            current: vulnerable, dismissedVersion: "26.4.0"))
        // Dismissed on an older build, still vulnerable after an OS
        // update → re-raised.
        #expect(NotificationRetentionAdvisory.shouldShow(
            current: v(26, 4, 1), dismissedVersion: "26.4.0"))
        // Patched OS → never shown, regardless of dismissal state.
        #expect(!NotificationRetentionAdvisory.shouldShow(
            current: v(26, 4, 2), dismissedVersion: nil))
    }

    @Test("version string is the canonical dismissal token")
    func versionString() {
        #expect(NotificationRetentionAdvisory.versionString(v(26, 4, 0)) == "26.4.0")
        #expect(NotificationRetentionAdvisory.versionString(v(18, 7, 8)) == "18.7.8")
    }
}

@Suite("Foreground presentation policy")
struct ForegroundPresentationTests {
    @Test("foreground pushes update the badge but never reach the notification store")
    func suppressesStoreWritingOptions() {
        let opts = ForegroundPresentation.options
        // `.badge` stays: when the relay socket is down and APNs is
        // the only delivery path, the NSE badge stamp is the sole
        // thing keeping the icon count honest — and applying it
        // stores nothing.
        #expect(opts.contains(.badge))
        // Everything that would write a record into the OS
        // notification store (the CVE-2026-28950 surface) is off.
        #expect(!opts.contains(.banner))
        #expect(!opts.contains(.list))
        #expect(!opts.contains(.sound))
    }
}
