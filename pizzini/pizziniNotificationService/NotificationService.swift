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
        // S7-05 — wiped/duress-state awareness.
        //
        // After a duress wipe the relay may still hold the old peer-id →
        // APNs-token mapping for up to its token TTL, so an inbound SEND
        // to the OLD identity can still fire a "New message" push at a
        // device the user just made look freshly installed. With no
        // wiped-state gate the NSE would paint that alert + badge — a
        // tell a coercer reads. If the main app has set the duress-wiped
        // sentinel in the App Group (it MUST set it on the duress path,
        // BEFORE it clears the rest of the suite — that side is owned by
        // the main app and tracked separately), suppress the
        // notification entirely: deliver EMPTY content (no alert, no
        // sound, no badge) so nothing surfaces on the supposedly-fresh
        // device.
        //
        // Robustness: if the key is absent (the normal case, and the
        // case for any build whose main app hasn't set it yet) we fall
        // through to the existing behavior. The NSE never crashes on a
        // missing key.
        if suite?.bool(forKey: SharedAppGroup.duressWipedKey) == true {
            // Deliver content that shows the user nothing. We cannot
            // legally "drop" a delivered push from the NSE, but handing
            // back stripped content with no alert/sound/badge renders
            // it invisible — the device stays looking fresh-installed.
            let silent = UNMutableNotificationContent()
            contentHandler(silent)
            return
        }
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
        // F-PUSH-01 (accepted residual). This count lands in the App
        // Group plist, protected at CompleteUntilFirstUserAuthentication
        // (the NSE must read/write it while locked-after-first-unlock) —
        // weaker than the SQLCipher message store. A forensic extraction
        // after first unlock can therefore read a bounded count
        // (0…nseFloor+nseBadgeCap) of pushes that arrived while the app
        // was dead, plus the plist mtime. It carries no peer identity and
        // the main app overwrites it on next launch. We accept this: the
        // badge cannot be incremented while the app is force-quit without
        // leaving *some* on-disk trace, and a shared-Keychain item would
        // need a new access-group entitlement for marginal benefit. The
        // "no unread-count leakage" claim in docs/threat-model.md is
        // scoped to the payload/server, NOT this on-device plist.
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

    /// S7-05 — duress/wiped sentinel. A `Bool` the MAIN APP must set to
    /// `true` on the duress-wipe path (BEFORE it clears the rest of the
    /// App Group suite / re-bootstraps), signalling that the device has
    /// been duress-wiped and the NSE must NOT surface any "New message"
    /// alert or badge for pushes that arrive against the old identity
    /// (the relay can keep firing them until its token TTL expires).
    /// When absent or `false` the NSE behaves exactly as before.
    ///
    /// NOTE FOR THE MAIN-APP SIDE (owned separately): set this key in
    /// the shared suite at the START of the duress wipe and DO NOT
    /// remove it as part of clearing the suite — a fresh install simply
    /// never has it, which is the same observable as a wiped device that
    /// later clears it on the user's deliberate re-onboarding. Mirror
    /// this constant in `pizzini/SharedAppGroup.swift`.
    static let duressWipedKey = "duressWiped"
}
