import SwiftUI

/// Helper for SwiftUI labels inside `.buttonStyle(.borderedProminent)`
/// buttons when the app's accent colour is the monochrome `Color.label`
/// (black in light mode, white in dark mode).
///
/// **Why this exists.** `.borderedProminent` uses the current `tint`
/// for the button's fill and hardcodes `Color.white` for the label
/// foreground. That works for the system-default blue tint (white on
/// blue, readable in both light and dark). With Pizzini's pure
/// monochrome accent (#000 / #FFF, see `AccentColor.colorset`), the
/// label is invisible in dark mode (white on white) and just barely
/// readable in some light-mode contrasts. Apple's auto-contrast logic
/// inside the prominent button style does not kick in for pure-white
/// tint values — verified on iOS 18 / 26.
///
/// The fix is to override the foreground at the call site, INSIDE the
/// label closure (a `.foregroundStyle` on the outer Button does NOT
/// propagate into the button-style's body). Use this modifier:
///
///     Button { ... } label: {
///         Text("Continue").prominentLabelText()
///     }
///     .buttonStyle(.borderedProminent)
///
/// The result inverts cleanly: white text in light mode (black
/// accent), black text in dark mode (white accent).
///
/// Do NOT use on `.borderedProminent` buttons that pin an explicit
/// semantic tint (`.tint(.red)` / `.tint(.green)`). White text on
/// red or green is the correct rendering for those and the modifier
/// would break the contrast.
extension View {
    /// Force the label foreground to `Color(.systemBackground)` so a
    /// `.borderedProminent` button under the monochrome accent stays
    /// readable in both appearances. Apply INSIDE the label closure,
    /// not on the outer Button — `.borderedProminent` overrides any
    /// foregroundStyle set on the button itself.
    func prominentLabelText() -> some View {
        foregroundStyle(Color(.systemBackground))
    }
}
