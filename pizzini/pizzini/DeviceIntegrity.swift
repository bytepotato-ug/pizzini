import Darwin
import Foundation
import MachO
import os.log
import SwiftUI
import UIKit

/// Best-effort runtime checks for a compromised iOS environment —
/// jailbreak indicators, debugger attach, suspicious dynamic libraries.
///
/// **What this is**: an honesty layer, not a defence. Every signal it
/// raises can be patched out by an attacker who already controls the
/// runtime. The README's threat model still says "compromised iOS is
/// out of scope"; this file doesn't change that. What it does change
/// is what we tell the user: when the device is visibly compromised,
/// Pizzini's screen-capture defences (and a fair amount else) are
/// best-effort at best, and the user should know.
///
/// **What it does NOT do**:
/// - Refuse to run. A "blocked because jailbroken" splash is theatre;
///   anyone determined enough to jailbreak will patch the splash out.
///   We render the chat normally and surface a banner.
/// - Phone home. No telemetry; consistent with the README's "no
///   analytics" hard rule. The only record of an integrity flag is
///   the in-app banner + Settings notice — nothing recoverable from
///   the system log on a release build. The log call is `os_log` at
///   `.debug` level, which release iOS drops unless debug logging is
///   explicitly enabled, so a coercer reading a later sysdiagnose
///   cannot confirm the check fired.
/// - Use private APIs. `sysctl(KERN_PROC)`, `_dyld_image_count`,
///   `FileManager.fileExists`, and `UIApplication.canOpenURL` are all
///   public; this is App-Store-safe.
///
/// **Bypassability**: high, by design. A jailbroken phone with
/// libtweakloader-style hooks can:
/// - Hide the indicator files from `FileManager.fileExists`.
/// - Spoof `sysctl` to clear the `P_TRACED` flag.
/// - Hide the loaded dylib from `_dyld_image_name`.
/// All of which are documented bypasses and exactly why commercial
/// RASP SDKs add layers we deliberately don't add (private-API
/// fingerprints, anti-tamper Mach-O hash checks). The trade-off:
/// detection-only is honest about what it is; deeper RASP becomes a
/// cat-and-mouse arms race in security-critical code we'd own
/// forever and that an audit would scrutinise heavily.
@MainActor
@Observable
final class DeviceIntegrityMonitor {
    static let shared = DeviceIntegrityMonitor()

    /// True iff one or more jailbreak indicators triggered. Each
    /// individual indicator is below; this is the OR-rolled-up flag
    /// the UI reads.
    private(set) var isJailbroken: Bool = false

    /// True iff `sysctl(KERN_PROC, KERN_PROC_PID, getpid())` reports
    /// `P_TRACED`, i.e. a debugger is attached. Routine in dev builds
    /// (Xcode = ptrace), so we don't surface this in DEBUG.
    private(set) var isDebuggerAttached: Bool = false

    /// True iff `_dyld_image_count` enumerated a loaded image whose
    /// name matches one of the well-known iOS-hook-framework
    /// substrings (frida-gadget, cycript, MobileSubstrate, …).
    private(set) var hasSuspiciousDylib: Bool = false

    /// First wall-clock time any flag flipped on. Surfaced to the
    /// user via the banner so a forensic post-mortem has a timestamp;
    /// nil if everything is clean.
    private(set) var detectedAt: Date?

    /// True iff any of the three flags is set. Drives the banner in
    /// ContentView and the warning section in Settings.
    var isCompromised: Bool {
        isJailbroken || hasSuspiciousDylib
            // Don't escalate the banner for an attached Xcode debugger
            // in DEBUG builds. RELEASE builds DO surface it — a
            // debugger on a release build is a clear signal someone
            // is poking at the binary on the device.
            || (!Self.isDebugBuild && isDebuggerAttached)
    }

    private init() {
        runChecks()
        // Re-poll on every scene activation, not just at
        // launch. A user who unlocks the app, attaches Frida mid-
        // session via USB, then returns to a backgrounded Pizzini
        // would otherwise never see the banner — the first-launch
        // snapshot is stale forever. Re-running the three syscalls
        // on activation is ~free. Use a separate hop so Swift's
        // strict-concurrency checker accepts the self-capture: the
        // observer closure is `@Sendable`, the Task body runs on
        // MainActor where `self` is reachable.
        let monitor = self
        NotificationCenter.default.addObserver(
            forName: UIScene.didActivateNotification,
            object: nil,
            queue: nil,
        ) { _ in
            Task { @MainActor in
                monitor.runChecks()
            }
        }
    }

    /// Run all three checks and update the published flags. Idempotent
    /// — call once at launch is enough; the conditions don't change
    /// at runtime in normal use. Exposed (not private) so a future
    /// "Re-check now" button or a periodic timer can re-poll.
    func runChecks() {
        let jb = Self.checkJailbroken()
        let dbg = Self.checkDebuggerAttached()
        let dylib = Self.checkSuspiciousDylib()
        self.isJailbroken = jb
        self.isDebuggerAttached = dbg
        self.hasSuspiciousDylib = dylib
        if (jb || dylib || (!Self.isDebugBuild && dbg)) && self.detectedAt == nil {
            self.detectedAt = Date()
        }
        // Skip the log line when the ONLY thing that fired is the
        // debugger flag in a DEBUG build — Xcode is always attached
        // during dev work, the user can't act on it, and shipping a
        // line per launch is just noise. Release builds DO log the
        // debugger attach (real signal there).
        let shouldLog: Bool
        if jb || dylib {
            shouldLog = true
        } else if dbg && !Self.isDebugBuild {
            shouldLog = true
        } else {
            shouldLog = false
        }
        if shouldLog {
            // Use os_log at .debug level rather than
            // NSLog. os_log .debug is dropped on release devices
            // unless logging is explicitly enabled, so a coercer
            // who later reads sysdiagnose can't confirm "RASP fired
            // on this device" from the public log stream. The
            // banner + Settings notice are still visible to the
            // user — the forensic post-mortem use-case the audit
            // mentions is preserved for anyone who explicitly
            // enables debug logging via Console.app, but not for
            // an opportunistic attacker.
            let log = OSLog(subsystem: "app.pizzini.security", category: "integrity")
            os_log(
                "device integrity flags — jailbroken=%{public}d debugger=%{public}d suspiciousDylib=%{public}d",
                log: log,
                type: .debug,
                jb ? 1 : 0,
                dbg ? 1 : 0,
                dylib ? 1 : 0,
            )
        }
    }

    // MARK: - Detection routines (nonisolated — pure functions of process state)

    /// File / URL-scheme heuristics for jailbreak indicators. Returns
    /// true the moment any single indicator triggers — short-circuits
    /// to avoid burning IO on a clean device. Simulator returns false
    /// unconditionally (the sim doesn't emulate jailbreak indicators).
    nonisolated static func checkJailbroken() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        // Indicator file paths commonly present on a jailbroken iOS.
        // Not exhaustive — modern jailbreaks (palera1n, Dopamine, …)
        // hide some of these — but the cost of one fileExists check
        // each is negligible and they catch sloppy installs.
        let paths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/blackra1n.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSettings.app",
            "/Applications/WinterBoard.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/usr/bin/sshd",
            "/usr/libexec/sftp-server",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/etc/ssh/sshd_config",
            "/bin/bash",
            "/bin/sh",
            // Rootless-jailbreak paths (palera1n, Dopamine
            // 2.x, etc.). Modern jailbreaks relocate the entire
            // tree under `/var/jb/` to leave `/` mount-read-only and
            // pass Apple's signature checks more easily. The cost
            // of three more fileExists checks is negligible.
            "/var/jb/Applications/Sileo.app",
            "/var/jb/usr/bin/sshd",
            "/var/jb/Library/MobileSubstrate/MobileSubstrate.dylib",
        ]
        for p in paths where FileManager.default.fileExists(atPath: p) {
            return true
        }
        // Sandbox-escape canary. A non-jailbroken iOS app cannot write
        // outside its container; if this succeeds the sandbox has been
        // disabled (the classic jailbreak smell-test).
        let canary = "/private/jb_canary_\(UUID().uuidString)"
        do {
            try "x".write(toFile: canary, atomically: true, encoding: .utf8)
            try? FileManager.default.removeItem(atPath: canary)
            return true
        } catch {
            // Expected on a clean iOS — sandbox refused.
        }
        return false
        #endif
    }

    /// `sysctl(KERN_PROC, KERN_PROC_PID, $self)` returns a
    /// `kinfo_proc` whose `kp_proc.p_flag` includes `P_TRACED` while a
    /// debugger is attached. Documented in Apple's "Detecting the
    /// Debugger" tech note (TN2151) — this is the public, App-Store-
    /// safe path.
    nonisolated static func checkDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout.stride(ofValue: info)
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    /// Walks the loaded-dylib list via `_dyld_image_count` /
    /// `_dyld_get_image_name` and looks for substrings of well-known
    /// iOS hook frameworks. This is the cheapest signal that a hook
    /// runtime is in-process; a determined attacker who renames the
    /// dylib evades it, but most off-the-shelf tooling doesn't bother.
    nonisolated static func checkSuspiciousDylib() -> Bool {
        let count = _dyld_image_count()
        let needles = [
            "frida",
            "cynject",
            "cycript",
            "substrate",
            "substitute",
            "libhooker",
            "rocketbootstrap",
        ]
        for i in 0..<count {
            guard let cstr = _dyld_get_image_name(i) else { continue }
            let name = String(cString: cstr).lowercased()
            for needle in needles where name.contains(needle) {
                return true
            }
        }
        return false
    }

    /// True in DEBUG builds. Used to suppress the debugger-attached
    /// flag in dev — Xcode is always attached in debug runs.
    nonisolated static var isDebugBuild: Bool {
        #if DEBUG
        return true
        #else
        return false
        #endif
    }
}
