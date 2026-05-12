import Foundation
import os.log

/// `pzLog` — internal logger used by ChatStore / ChatStoreGroups and
/// any other peer-id-aware hot paths in place of `NSLog`.
///
/// **Why this exists.** `NSLog` in release builds is captured by
/// Apple's unified logging system and ends up in `sysdiagnose`
/// archives an attacker can extract over a Lightning / USB-C
/// connection. Pizzini's chat-state code routinely formats peer-id
/// prefixes, group ids, payload byte counts, and rejection reasons —
/// every one of those is a metadata signal we don't want surviving
/// in a long-term system log a coercer can demand.
///
/// `os_log(.debug, …)` is dropped at the kernel level on release
/// devices unless the device has had a privacy-violating log
/// configuration profile installed. That matches the `DeviceIntegrity`
/// logging policy adopted in F-NEW-905 and brings the rest of
/// ChatStore in line with it.
///
/// The `%{public}@` formatter is used so the body is *readable*
/// when the debug log IS enabled (default `%{private}@` redacts
/// fields to `<private>` even on dev builds, which made local
/// debugging unproductive). The mitigation lives in the kernel
/// suppression, not in the field-redaction marker.
@inline(__always)
nonisolated func pzLog(_ message: @autoclosure () -> String) {
    #if DEBUG
    os_log(.debug, "%{public}@", message())
    #else
    // Release: drop the message entirely. The `@autoclosure` means
    // the string-interpolation body never runs, so a hot-path log
    // line with peer-id formatting has zero cost in shipped builds.
    _ = ()
    #endif
}
