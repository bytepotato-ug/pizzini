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
    let body = message()
    // Wall-clock `HH:MM:SS.mmm` prefix on the Xcode-console output so
    // when-did-X-happen analysis works without enabling Xcode's
    // console-timestamp preference per developer. Matches the format
    // embedded Tor's own `[notice]` lines use, so a mixed log capture
    // sorts cleanly side-by-side. We do NOT prefix the QA-log copy
    // because QALog.record already stamps each line with an ISO-8601
    // wall-clock — prefixing here would emit duplicate timestamps in
    // the persistent file.
    os_log(.debug, "%{public}@", "\(pzLogStampHHMMSSmmm()) \(body)")
    QALog.record(category: "log", message: body)
    #else
    // Release: drop the message entirely. The `@autoclosure` means
    // the string-interpolation body never runs, so a hot-path log
    // line with peer-id formatting has zero cost in shipped builds.
    _ = ()
    #endif
}

/// Local-time `HH:MM:SS.mmm` used as the wall-clock prefix on
/// every `pzLog` Xcode-console line. Format matches embedded
/// Tor's `[notice]` lines so a mixed log capture sorts cleanly
/// side-by-side. Cheap (~1 µs on an iPhone 15 Pro, dominated by
/// the `DateComponents` extraction); pzLog is hot but not THAT
/// hot, so we don't bother caching the formatter.
nonisolated private func pzLogStampHHMMSSmmm() -> String {
    let now = Date()
    let comp = Calendar(identifier: .gregorian).dateComponents(
        [.hour, .minute, .second, .nanosecond],
        from: now,
    )
    let ms = (comp.nanosecond ?? 0) / 1_000_000
    return String(
        format: "%02d:%02d:%02d.%03d",
        comp.hour ?? 0,
        comp.minute ?? 0,
        comp.second ?? 0,
        ms,
    )
}
