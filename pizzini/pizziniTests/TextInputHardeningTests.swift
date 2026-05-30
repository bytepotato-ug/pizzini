import Foundation
import Testing
import UIKit
@testable import pizzini

/// PZ-L8: keyboard-cache hardening must (a) turn off the smart-typography
/// + spell-checking flags that train the on-disk `~/Library/Keyboard`
/// caches and clear the input-assistant bar, and (b) be idempotent so it
/// can re-apply on EVERY update — a SwiftUI-replaced field reverts to
/// UIKit defaults and must get re-hardened. UIKit → `@MainActor`; runs on
/// the simulator without entitlements.
@MainActor
@Suite("PZ-L8 keyboard-cache hardening")
struct TextInputHardeningTests {
    @Test("hardens a UITextField's cache-training flags + clears the assistant bar")
    func hardensTextField() {
        let tf = UITextField()
        tf.smartDashesType = .yes
        tf.smartQuotesType = .yes
        tf.smartInsertDeleteType = .yes
        tf.spellCheckingType = .yes

        TextInputHardener.harden(tf)

        #expect(tf.smartDashesType == .no)
        #expect(tf.smartQuotesType == .no)
        #expect(tf.smartInsertDeleteType == .no)
        #expect(tf.spellCheckingType == .no)
        #expect(tf.inputAssistantItem.leadingBarButtonGroups.isEmpty)
        #expect(tf.inputAssistantItem.trailingBarButtonGroups.isEmpty)
    }

    @Test("hardens a UITextView's cache-training flags")
    func hardensTextView() {
        let tv = UITextView()
        tv.smartDashesType = .yes
        tv.smartQuotesType = .yes
        tv.smartInsertDeleteType = .yes
        tv.spellCheckingType = .yes

        TextInputHardener.harden(tv)

        #expect(tv.smartDashesType == .no)
        #expect(tv.smartQuotesType == .no)
        #expect(tv.smartInsertDeleteType == .no)
        #expect(tv.spellCheckingType == .no)
    }

    /// The core of PZ-L8: a field that reverted to UIKit defaults (as a
    /// SwiftUI-replaced field does on re-render) must re-harden on the
    /// next call — proving the operation is safe to run on every update.
    @Test("re-hardens a field that reverted to defaults")
    func reHardensAfterRevert() {
        let tf = UITextField()
        TextInputHardener.harden(tf)
        // Simulate the replacement field coming up with defaults back ON.
        tf.smartQuotesType = .yes
        tf.spellCheckingType = .yes

        TextInputHardener.harden(tf)

        #expect(tf.smartQuotesType == .no)
        #expect(tf.spellCheckingType == .no)
    }
}
