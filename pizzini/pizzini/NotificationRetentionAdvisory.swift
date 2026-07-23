import Foundation
import Observation

/// CVE-2026-28950 update advisory. Apple's Notification Services bug
/// kept notifications "marked for deletion" on-device — the store the
/// FBI read to recover deleted Signal notification content from a
/// seized iPhone, even after the app was uninstalled. Pizzini's
/// payloads are content-free, so on an unpatched iOS the residue is
/// arrival timestamps plus the fact of Pizzini usage — but that is
/// exactly the metadata the duress wipe promises to destroy, and app-
/// side hygiene (`NotificationHygiene`) cannot reach records the OS
/// already failed to delete. The only real fix is Apple's, so we tell
/// the user to take it.
///
/// Pure version predicate, separated from the `@Observable` dismissal
/// state below so the vulnerable/patched decision is unit-testable
/// without `ProcessInfo` or `UserDefaults` (house pattern: pure
/// decision surface).
enum NotificationRetentionAdvisory {
    /// First patched release per iOS major, from Apple's April 2026
    /// security notes (backports 15.8.8 / 16.7.16 / 17.7.11 omitted:
    /// the deployment target is iOS 18.0, so those majors cannot run
    /// this app). Majors absent from the table are treated as not
    /// vulnerable: 19–25 do not exist (Apple jumped 18 → 26) and 27+
    /// ship after the fix.
    static let patchedByMajor: [Int: OperatingSystemVersion] = [
        18: OperatingSystemVersion(majorVersion: 18, minorVersion: 7, patchVersion: 8),
        26: OperatingSystemVersion(majorVersion: 26, minorVersion: 4, patchVersion: 2),
    ]

    /// Whether this OS build predates its major's CVE-2026-28950 fix.
    static func isVulnerable(_ v: OperatingSystemVersion) -> Bool {
        guard let patched = patchedByMajor[v.majorVersion] else {
            return false
        }
        if v.minorVersion != patched.minorVersion {
            return v.minorVersion < patched.minorVersion
        }
        return v.patchVersion < patched.patchVersion
    }

    /// Canonical "major.minor.patch" form used as the dismissal token.
    static func versionString(_ v: OperatingSystemVersion) -> String {
        "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }

    /// Banner predicate: show on a vulnerable OS unless the user
    /// dismissed the advisory *on this exact OS build*. Keying the
    /// dismissal to the version string means an OS update that is
    /// still vulnerable (e.g. 26.4.0 → 26.4.1) re-raises the advisory,
    /// while updating past the fix retires it with no stored state to
    /// clean up.
    static func shouldShow(current: OperatingSystemVersion, dismissedVersion: String?) -> Bool {
        isVulnerable(current) && dismissedVersion != versionString(current)
    }
}

/// Dismissal persistence for the advisory banner. `UserDefaults
/// .standard` on purpose (same rationale as `SupportBannerState`):
/// this is device-lifecycle state, not identity state, and it carries
/// nothing sensitive.
///
/// Duress-wipe indistinguishability has two halves. On disk it holds
/// for free: `Storage.eraseAndReinitialize` drops the whole standard
/// persistent domain, so a device imaged after the wipe has no
/// dismissal key — a relaunch shows the banner exactly as a fresh
/// install on the same OS would. But the wipe runs *without relaunch*,
/// and this singleton caches `dismissedVersion` in memory, so an
/// in-session observer who watches the wiped app go through onboarding
/// would otherwise see no banner where a true fresh install shows one.
/// `resetForWipe()` closes that in-session gap — the same reason
/// `duressWipe()` resets its `identityResetBannerPending` mirror.
@MainActor
@Observable
final class NotificationRetentionAdvisoryState {
    static let shared = NotificationRetentionAdvisoryState()

    private static let dismissedVersionKey = "pizzini.osNotificationAdvisoryDismissedVersion"

    /// OS build the user last dismissed the advisory on; `nil` until
    /// they do.
    private(set) var dismissedVersion: String?

    private init() {
        dismissedVersion = UserDefaults.standard.string(forKey: Self.dismissedVersionKey)
    }

    var shouldShow: Bool {
        NotificationRetentionAdvisory.shouldShow(
            current: ProcessInfo.processInfo.operatingSystemVersion,
            dismissedVersion: dismissedVersion,
        )
    }

    func dismiss() {
        let v = NotificationRetentionAdvisory.versionString(
            ProcessInfo.processInfo.operatingSystemVersion)
        dismissedVersion = v
        UserDefaults.standard.set(v, forKey: Self.dismissedVersionKey)
    }

    /// Clear the in-memory dismissal so a post-duress-wipe session
    /// presents the banner exactly as a fresh install would. Touches
    /// only memory — the persistent key is already gone with the rest
    /// of the standard domain, and re-writing it here would recreate a
    /// single-key plist a fresh install lacks (the same telltale
    /// `duressWipe()` avoids for the identity-reset banner).
    func resetForWipe() {
        dismissedVersion = nil
    }
}
