import SwiftUI
import UIKit

/// Per-text-input hardening for every sensitive `TextField` in Pizzini.
///
/// SwiftUI's `TextField` defaults `autocorrect`, `autocap`, and the
/// three smart-typography flags (`smartDashes`, `smartQuotes`,
/// `smartInsertDelete`) to ON. Every accepted substring trains the
/// iOS `UserDictionary` / `UITextChecker` learning state under
/// `~/Library/Keyboard/`; smart-typography substitutions train a
/// separate substitution cache distinct from the autocorrect
/// dictionary. Both are recoverable by Cellebrite-class extraction and
/// have been used to reconstruct chat content the application itself
/// had already deleted.
///
/// SwiftUI as of iOS 18 has no first-class spelling for the smart-*
/// flags — they have to be poked on the underlying `UITextField`. The
/// `UIViewRepresentable` bridge below mounts a hidden input-accessory
/// proxy that finds the active first responder and clears them.
///
/// Apply via `.hardenedTextInput()` to every sensitive `TextField`:
/// - the 1:1 and group composer
/// - every contact/group rename + new-group name field
/// - every search bar
/// - every `SecureField` (passcode entry / setup)
///
/// Disabled flags:
///   - autocorrect          (UserDictionary training)
///   - autocapitalization   (the `.words` / `.sentences` UX nicety
///                           triggers a separate "name dictionary"
///                           heuristic on some iOS versions; default
///                           to `.never` for the hardened flavor)
///   - smartDashes          (-- → em-dash; logged in substitution cache)
///   - smartQuotes          ("foo" → curly; logged)
///   - smartInsertDelete    (trailing-space management; logged)
///   - spellCheckingType    (separate from autocorrect; also trains)
///
/// Callers that need autocap (e.g. a contact-name field where
/// `.words` is the right UX) pass `.words` or `.sentences` via the
/// `autocap:` argument; the default `.never` is the strict path. The
/// other four flags are non-negotiable.
extension View {
    /// Disable every keyboard-cache-training flag on this text input.
    ///
    /// - Parameter autocap: SwiftUI's autocapitalization mode. Default
    ///   `.never` is the strict choice for composers and search bars
    ///   where the user types in lowercase prose / queries. Name
    ///   fields (contact/group rename, new-group sheet) pass `.words`
    ///   for first-letter capitalization without re-enabling autocorrect.
    func hardenedTextInput(
        autocap: TextInputAutocapitalization = .never
    ) -> some View {
        modifier(HardenedTextInput(autocap: autocap))
    }
}

/// PZ-L8: the field-level keyboard-cache hardening, extracted so it can
/// be re-applied on every update AND unit-tested directly. Disables the
/// smart-typography + spell-checking flags that train the on-disk
/// keyboard caches under `~/Library/Keyboard/`, and clears the input-
/// assistant bar groups that shadow the recent draft. Idempotent — safe
/// to call on every render.
enum TextInputHardener {
    @MainActor static func harden(_ field: UITextField) {
        field.smartDashesType = .no
        field.smartQuotesType = .no
        field.smartInsertDeleteType = .no
        field.spellCheckingType = .no
        field.inputAssistantItem.leadingBarButtonGroups = []
        field.inputAssistantItem.trailingBarButtonGroups = []
    }

    @MainActor static func harden(_ view: UITextView) {
        view.smartDashesType = .no
        view.smartQuotesType = .no
        view.smartInsertDeleteType = .no
        view.spellCheckingType = .no
        view.inputAssistantItem.leadingBarButtonGroups = []
        view.inputAssistantItem.trailingBarButtonGroups = []
    }
}

private struct HardenedTextInput: ViewModifier {
    let autocap: TextInputAutocapitalization

    func body(content: Content) -> some View {
        content
            .autocorrectionDisabled(true)
            .textInputAutocapitalization(autocap)
            // acknowledged below in the typography
            // disabler: `inputAssistantItem.leadingBarButtonGroups`
            // is also zeroed there so the keyboard's quick-suggest
            // bar (which shadows the in-RAM draft trail) is wiped.
            // Shake-to-undo proper lives in the responder chain and
            // is OS-managed; the persistence threat model is
            // intact because that history is in-RAM, not on disk.
            //
            // Background `UIViewRepresentable` reaches every
            // `UITextField` / `UITextView` mounted under the modified
            // view and pokes the SwiftUI-unreachable flags.
            .background(SmartTypographyDisabler())
    }
}

/// Hidden zero-size UIView whose `didMoveToWindow` walks the sibling
/// view hierarchy looking for `UITextField` / `UITextView` and
/// disables their smart-typography + spell-checking flags. SwiftUI
/// has no first-class API for these as of iOS 18, so the bridge is
/// the supported path.
///
/// PZ-L8: the walker re-runs on EVERY `updateUIView`, not once per
/// appearance. If SwiftUI replaces the underlying UIKit text input
/// (e.g. a re-render that flips `.textFieldStyle` or the field's
/// identity), the replacement comes up with UIKit's smart-typography /
/// spell-checking defaults ON and would train the keyboard cache from
/// the first keystroke. `harden` is idempotent, so re-applying on each
/// update is safe; the coalescing in `scheduleProbe` bounds it to one
/// walk per update burst while still guaranteeing the FINAL field state
/// is covered — the old one-shot guard could drop that trailing
/// re-harden.
private struct SmartTypographyDisabler: UIViewRepresentable {
    func makeUIView(context: Context) -> ProbeView {
        ProbeView()
    }

    func updateUIView(_ view: ProbeView, context: Context) {
        view.scheduleProbe()
    }

    final class ProbeView: UIView {
        private var probeInFlight = false
        private var rehardenRequested = false

        override init(frame: CGRect) {
            super.init(frame: frame)
            isHidden = true
            isUserInteractionEnabled = false
            isAccessibilityElement = false
        }

        required init?(coder: NSCoder) { nil }

        override func didMoveToWindow() {
            super.didMoveToWindow()
            scheduleProbe()
        }

        func scheduleProbe() {
            // PZ-L8: trailing-coalesced re-harden. Every update requests a
            // (re-)harden; a burst collapses to one in-flight walk, but a
            // request that lands WHILE a walk is running re-arms it, so the
            // final field state is always covered (the old guard dropped
            // that trailing re-harden, leaving a replaced field unhardened).
            rehardenRequested = true
            guard !probeInFlight else { return }
            probeInFlight = true
            // Defer one runloop tick so SwiftUI has finished mounting
            // its UITextField/UITextView children.
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.probeInFlight = false
                guard self.rehardenRequested else { return }
                self.rehardenRequested = false
                self.harden(in: self.superview)
                // An update during the walk leaves `rehardenRequested`
                // set — chase it so the latest field is covered too.
                if self.rehardenRequested { self.scheduleProbe() }
            }
        }

        /// Walk every sibling subtree starting from the modified view's
        /// parent. We can't restrict to the immediate parent because
        /// SwiftUI nests the actual `UITextField` several layers deep
        /// inside its host.
        private func harden(in container: UIView?) {
            guard let root = container else { return }
            applyRecursively(to: root)
        }

        private func applyRecursively(to view: UIView) {
            // Zeroing the input-assistant bar groups (inside `harden`)
            // also stops the keyboard's QuickType / paste suggestions from
            // rendering the last-typed words above the bar after a send.
            if let tf = view as? UITextField {
                TextInputHardener.harden(tf)
            }
            if let tv = view as? UITextView {
                TextInputHardener.harden(tv)
            }
            for sub in view.subviews {
                applyRecursively(to: sub)
            }
        }
    }
}
