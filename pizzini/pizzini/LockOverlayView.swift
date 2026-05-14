import SwiftUI

/// Full-screen lock gate. Visible while `LockManager.shared.isLocked`
/// is true. The contacts list and chat content underneath are not
/// rendered (the parent view conditions on `lockManager.isLocked`),
/// so a screen recording at this state shows only this view.
///
/// Two unlock paths:
///
/// - **Face ID** (when `state.biometricLockEnabled == true`): auto-
///   fires on appear, retry via the big Unlock button.
/// - **Passcode**: pulled up via a long-press-anywhere gesture (Q1 →
///   option c). When Face ID is disabled but a passcode is set, the
///   sheet appears automatically on launch — there's no other way
///   in. When Face ID is enabled, the passcode is the duress path
///   too; the long-press gesture is intentionally undocumented in
///   the lock-screen UI so a coercer doesn't see "tap here to wipe."
struct LockOverlayView: View {
    @Bindable var lockManager: LockManager
    @Bindable var store: ChatStore

    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            VStack(spacing: 24) {
                Spacer()
                // Pizzini brand logo above the "locked" label.
                // Reinforces the user is in the right app before
                // they authenticate — Face ID UX prompts can be
                // mimicked by malicious apps, so the user seeing
                // "this is the Pizzini lock screen, with the
                // Pizzini logo" before tapping unlock is a real
                // signal.
                Image("AppLogo")
                    .resizable()
                    .interpolation(.high)
                    .aspectRatio(contentMode: .fit)
                    .frame(width: 96, height: 96)
                    .clipShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
                    .shadow(color: .black.opacity(0.15), radius: 6, x: 0, y: 3)
                    .accessibilityLabel("Pizzini logo")
                Text("Pizzini is locked")
                    .font(.title2.bold())
                Text(subtitleText)
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
                Button(action: primaryUnlock) {
                    Label(primaryButtonTitle, systemImage: primaryButtonSymbol)
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .prominentLabelText()
                }
                .buttonStyle(.borderedProminent)
                .disabled(lockManager.authInFlight)
                .padding(.horizontal, 32)
                // When Face ID is enabled AND a real / duress passcode
                // is set, surface a discreet "Use passcode" button so
                // a user whose biometric is wedged (locked out after 5
                // failed attempts, sensor unavailable, etc.) has a
                // visible second path. The long-press gesture below
                // remains the undocumented entry — both reach the same
                // sheet. Hidden when no passcode is configured.
                if faceIDOn,
                   AppPasscode.isPasscodeSet || AppPasscode.isDuressPasscodeSet {
                    Button("Use passcode") {
                        lockManager.isPasscodeSheetPresented = true
                    }
                    .buttonStyle(.bordered)
                    .padding(.horizontal, 32)
                }
                Spacer().frame(height: 32)
            }
        }
        // Long-press anywhere on the lock screen brings up the
        // passcode entry sheet — the documented (in Settings → FAQ)
        // entry point for the duress passcode AND a fallback when
        // Face ID is misbehaving. 0.8s is long enough to avoid
        // accidental triggers from a thumb-rest, short enough to
        // feel responsive when intentional. Gate the gesture on
        // `!isPasscodeSheetPresented` so a thumb-rest inside the
        // sheet's gesture-passthrough region can't re-trigger.
        .contentShape(Rectangle())
        .onLongPressGesture(minimumDuration: 0.8) {
            if !lockManager.isPasscodeSheetPresented {
                lockManager.isPasscodeSheetPresented = true
            }
        }
        .onAppear(perform: handleAppear)
        .sheet(isPresented: Binding(
            get: { lockManager.isPasscodeSheetPresented },
            set: { newValue in
                lockManager.isPasscodeSheetPresented = newValue
            }
        )) {
            PasscodeEntryView(
                lockManager: lockManager,
                onOutcome: handlePasscodeOutcome,
                onCancel: {
                    lockManager.isPasscodeSheetPresented = false
                },
            )
        }
    }

    // MARK: - Decisions

    private var faceIDOn: Bool {
        store.state.biometricLockEnabled
    }

    private var passcodeOnly: Bool {
        // No Face ID + at least one passcode set → passcode is the
        // only way in. Show the entry sheet immediately on appear.
        !faceIDOn && (AppPasscode.isPasscodeSet || AppPasscode.isDuressPasscodeSet)
    }

    private var subtitleText: String {
        if faceIDOn {
            return "Authenticate to read your messages."
        }
        if passcodeOnly {
            return "Enter your passcode to read your messages."
        }
        return "Authenticate to read your messages."
    }

    private var primaryButtonTitle: String {
        passcodeOnly ? "Enter passcode" : "Unlock"
    }

    private var primaryButtonSymbol: String {
        passcodeOnly ? "key.fill" : "faceid"
    }

    // MARK: - Actions

    private func handleAppear() {
        if passcodeOnly {
            // No biometric path — go straight to passcode entry.
            lockManager.isPasscodeSheetPresented = true
            return
        }
        // Face ID path — fire the prompt immediately. Long-press is
        // available as the passcode fallback / duress entry.
        lockManager.attemptUnlock()
    }

    private func primaryUnlock() {
        if passcodeOnly {
            lockManager.isPasscodeSheetPresented = true
        } else {
            lockManager.attemptUnlock()
        }
    }

    private func handlePasscodeOutcome(_ outcome: LockManager.PasscodeOutcome) {
        switch outcome {
        case .unlocked:
            lockManager.isPasscodeSheetPresented = false
        case .duress:
            // **Order matters.** Wipe BEFORE dropping the lock so
            // the chat list view that mounts under the cleared
            // overlay observes the post-wipe (empty) state, not
            // the pre-wipe one. A coercer watching the unlock
            // would otherwise see a flash of the real contacts
            // before they disappear — that single frame is the
            // entire feature's weak point.
            //
            // `beginDuressWipe` gates LockManager.submitPasscode
            // against any racing entry (e.g. panicked second tap
            // arriving after the first cleared the passcode slots).
            lockManager.beginDuressWipe()
            store.duressWipe()
            lockManager.unlockAfterDuress()
        case .wrong:
            // Sheet stays up; PasscodeEntryView shows the error
            // and lets the user retry.
            break
        }
    }
}
