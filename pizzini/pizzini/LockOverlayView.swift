import SwiftUI

/// Full-screen lock gate. Visible while `LockManager.shared.isLocked`
/// is true. Auto-fires the biometric prompt on appear; if the user
/// cancels, they retry with the big "Unlock" button. The contacts
/// list and chat content underneath are not rendered (the parent
/// view conditions on `lockManager.isLocked`), so a screen recording
/// at this state shows only this view.
struct LockOverlayView: View {
    @Bindable var lockManager: LockManager

    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            VStack(spacing: 24) {
                Spacer()
                Image(systemName: "lock.shield")
                    .font(.system(size: 96))
                    .foregroundStyle(.tint)
                Text("Pizzini is locked")
                    .font(.title2.bold())
                Text("Authenticate to read your messages.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                if let err = lockManager.lastError {
                    Text(err)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
                Spacer()
                Button {
                    lockManager.attemptUnlock()
                } label: {
                    Label("Unlock", systemImage: "faceid")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                }
                .buttonStyle(.borderedProminent)
                .disabled(lockManager.authInFlight)
                .padding(.horizontal, 32)
                .padding(.bottom, 32)
            }
        }
        .onAppear {
            // Fire Face ID immediately. If the user cancels, the screen
            // stays here and they can retry with the button.
            lockManager.attemptUnlock()
        }
    }
}
