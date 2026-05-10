import Foundation
import Testing
@testable import pizzini

/// Test surface for `DeviceIntegrityMonitor`'s static detection
/// helpers. The monitor itself is a singleton with process-wide
/// state, so we exercise the underlying pure functions where we can
/// (jailbreak / dylib are observable in the test runtime; the
/// debugger flag is set BY the test runtime, so we assert on its
/// shape rather than its value).
@Suite("DeviceIntegrityMonitor detection routines")
struct DeviceIntegrityTests {
    @Test("jailbreak check returns false on a clean simulator")
    func jailbreakOnSimulator() {
        // Pure function — no side effects, no MainActor required.
        // The simulator branch returns false unconditionally; this
        // test guards against an accidental future change that
        // removes the `targetEnvironment(simulator)` short-circuit.
        let jb = DeviceIntegrityMonitor.checkJailbroken()
        #expect(jb == false)
    }

    @Test("suspicious-dylib scan returns false on a clean test runtime")
    func suspiciousDylibClean() {
        // None of frida / cycript / substrate / cynject /
        // libhooker / rocketbootstrap / substitute should be loaded
        // in the unit-test process unless something is very wrong
        // with the host machine. False-positive risk: a developer
        // running these tests on a machine with one of those
        // frameworks installed system-wide. Acceptable.
        let sus = DeviceIntegrityMonitor.checkSuspiciousDylib()
        #expect(sus == false)
    }

    @Test("debugger check returns a boolean (xctest may or may not have a tracer)")
    func debuggerCheckShape() {
        // The xctest runner sometimes attaches a debugger and
        // sometimes doesn't, depending on how the test is invoked.
        // We can't assert true OR false; what we CAN assert is that
        // the function returns a Bool without crashing — the failure
        // mode we'd actually catch with a unit test is the sysctl
        // call segfaulting on a layout change.
        let _ = DeviceIntegrityMonitor.checkDebuggerAttached()
    }

    @Test("isCompromised rolls up the three flags correctly")
    @MainActor
    func compromisedRollup() {
        let m = DeviceIntegrityMonitor.shared
        // We can't safely mutate `isJailbroken` etc. on the singleton
        // from a test — they're `private(set)`. What we CAN check is
        // the stable invariant: in a clean test environment, the
        // singleton should report not-compromised.
        // (Suspicious dylibs / a jailbroken sim test box would
        // legitimately flip this; this test then signals a real
        // problem rather than a flaky assertion.)
        if !m.isJailbroken && !m.hasSuspiciousDylib {
            // Debugger-attached doesn't escalate in DEBUG builds, so
            // the rollup should be false on a clean DEBUG test run.
            #if DEBUG
            #expect(m.isCompromised == false)
            #endif
        }
    }

    @Test("isDebugBuild reports the build configuration honestly")
    func debugBuildFlag() {
        #if DEBUG
        #expect(DeviceIntegrityMonitor.isDebugBuild == true)
        #else
        #expect(DeviceIntegrityMonitor.isDebugBuild == false)
        #endif
    }
}
