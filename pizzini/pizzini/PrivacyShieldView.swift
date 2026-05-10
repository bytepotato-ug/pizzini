import SwiftUI

/// Full-screen overlay shown whenever `scenePhase != .active` — covers
/// the iOS multitasking thumbnail and the brief inactive transitions
/// (Control Centre pull-down, incoming call, etc.). Without this, the
/// system snapshot would freeze whatever chat the user was reading and
/// expose it in the app switcher.
///
/// Visual: solid black, no content. Matches `LaunchScreen.storyboard`
/// and the `WindowSecureMask`-masked app, so every privacy-related
/// cover Pizzini paints looks identical — no Pizzini branding,
/// no app-name text, nothing that hints at what the app is even when
/// the multitasking thumbnail itself is captured. The user still
/// identifies the app in the switcher via the icon + label iOS
/// renders ABOVE the thumbnail, which is system chrome we don't
/// control.
struct PrivacyShieldView: View {
    var body: some View {
        Color.black
            .ignoresSafeArea()
            .accessibilityHidden(true)
    }
}
