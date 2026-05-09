import SwiftUI

/// Full-screen overlay shown whenever `scenePhase != .active` — covers
/// the iOS multitasking thumbnail and the brief inactive transitions
/// (Control Centre pull-down, incoming call, etc.). Without this, the
/// system snapshot would freeze whatever chat the user was reading and
/// expose it in the app switcher.
struct PrivacyShieldView: View {
    var body: some View {
        ZStack {
            Color(.systemBackground)
                .ignoresSafeArea()
            VStack(spacing: 12) {
                Image(systemName: "lock.shield")
                    .font(.system(size: 64))
                    .foregroundStyle(.tint)
                Text("Pizzini")
                    .font(.title2.bold())
            }
        }
    }
}
