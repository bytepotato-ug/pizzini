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

    /// Wall-clock ceiling, measured from the moment
    /// `handlePasscodeOutcome` is entered to the moment the lock
    /// drops. The duress branch runs a full cryptographic erasure
    /// (Keychain wipes, DB unlink, attachment-tree delete, a fresh
    /// Argon2id derivation + libsignal keygen in the re-bootstrap)
    /// before it can drop the lock; a real unlock does almost nothing
    /// before it drops the lock. Left unpadded, the duress unlock
    /// takes visibly longer — a stopwatch-equipped coercer reads that
    /// delta as "a duress passcode was just used." Padding BOTH the
    /// real and the duress branch to this ceiling makes the
    /// passcode-submit → lock-drop latency statistically identical
    /// for `.real` and `.duress`.
    ///
    /// **S7-04 — the pad must not fail open.** The old code used a
    /// FIXED 3.0 s ceiling. If the synchronous `duressWipe()` overran
    /// 3.0 s on a slow / thermally-throttled device, the duress branch
    /// dropped the lock immediately (`remaining <= 0`), landing the
    /// duress unlock LATER than a real unlock — the exact stopwatch
    /// tell the pad exists to hide. The fix below makes the ceiling an
    /// ADAPTIVE, monotonically-non-decreasing FLOOR that BOTH branches
    /// honor:
    ///
    ///   • Both `.real` and `.duress` pad to `adaptiveCeiling`, so they
    ///     converge on the same observable latency.
    ///   • If a duress wipe is measured to take longer than the current
    ///     ceiling, the ceiling is RAISED (to the measured time plus a
    ///     margin) so every SUBSEQUENT unlock — real or duress — pads to
    ///     the higher value and the two paths stay indistinguishable on
    ///     that device thereafter.
    ///   • The overrunning duress event itself is still padded to the
    ///     (newly-raised) ceiling rather than dropping immediately, so
    ///     it never lands at the bare wipe time. The invariant is: the
    ///     duress path never completes FASTER than the ceiling, and the
    ///     ceiling only ever grows to cover the worst wipe seen — so the
    ///     real path is never observably faster than the duress path.
    ///
    /// `adaptiveCeiling` is process-lifetime in-memory state (a static
    /// var). It is deliberately NOT persisted: a stored "slowest wipe"
    /// value would itself be a faint duress tell at rest, and the
    /// conservative initial value already exceeds the wipe on supported
    /// hardware in the common case.
    private static let initialUnlockLatencyCeiling: TimeInterval = 3.0

    /// Margin added above a measured over-budget wipe when raising the
    /// ceiling, so the raised ceiling sits comfortably ABOVE the worst
    /// observed wipe rather than exactly at it (an exact match would
    /// leave the next duress event landing right at the wipe time again
    /// under jitter).
    private static let ceilingHeadroom: TimeInterval = 0.5

    /// Adaptive ceiling. Starts at `initialUnlockLatencyCeiling` and
    /// only ever grows (see `noteWipeDurationAndCeiling`). Shared by
    /// the real and duress branches so both pad to the same target.
    /// `nonisolated(unsafe)` is safe here: every read/write happens on
    /// the main actor (the view's handlers and the padding `Task` are
    /// all `@MainActor`).
    nonisolated(unsafe) private static var adaptiveCeiling: TimeInterval =
        initialUnlockLatencyCeiling

    /// Raise the adaptive ceiling if `measuredWipe` (the wall-clock the
    /// synchronous duress wipe actually took) came within / exceeded
    /// the current ceiling. Returns the ceiling to pad THIS event to.
    /// Monotonic: the ceiling never shrinks, so a single fast wipe
    /// after a slow one cannot re-open the timing gap.
    @MainActor
    private static func raiseCeilingIfNeeded(forWipe measuredWipe: TimeInterval) -> TimeInterval {
        // If the wipe came close to or past the current ceiling, grow
        // the ceiling to cover it with headroom. "Close to" (>= ceiling
        // − headroom) is included so we raise BEFORE an actual overrun
        // leaks, not only after.
        if measuredWipe >= adaptiveCeiling - ceilingHeadroom {
            adaptiveCeiling = measuredWipe + ceilingHeadroom
        }
        return adaptiveCeiling
    }

    private func handlePasscodeOutcome(_ outcome: LockManager.PasscodeOutcome) {
        let start = CFAbsoluteTimeGetCurrent()
        switch outcome {
        case .unlocked:
            // Pad to the adaptive ceiling so a real unlock is not
            // observably faster than a duress wipe. The pad runs as
            // an async sleep — the sheet stays up (still showing the
            // neutral passcode UI, no flash of contacts) until the
            // ceiling elapses, then the lock drops.
            dropLockAfterPadding(from: start, to: Self.adaptiveCeiling) {
                lockManager.isPasscodeSheetPresented = false
            }
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
            let wipeStart = CFAbsoluteTimeGetCurrent()
            store.duressWipe()
            let measuredWipe = CFAbsoluteTimeGetCurrent() - wipeStart
            // **S7-04 fix.** Measure how long the synchronous wipe took
            // and raise the shared adaptive ceiling if it ran long, so
            // every subsequent real/duress unlock pads to (at least)
            // this duration — keeping the two paths indistinguishable
            // even on a slow device. Pad THIS event to the (possibly
            // raised) ceiling: because the ceiling is now ≥ the wipe
            // time + headroom, there is always a positive pad left and
            // the duress unlock never drops at the bare wipe time.
            let ceiling = Self.raiseCeilingIfNeeded(forWipe: measuredWipe)
            dropLockAfterPadding(from: start, to: ceiling) {
                lockManager.unlockAfterDuress()
            }
        case .wrong:
            // Sheet stays up; PasscodeEntryView shows the error
            // and lets the user retry. No lock-drop event to pad —
            // a `.wrong` entry is already observably distinct from
            // `.real`/`.duress` (the app simply stays locked).
            break
        }
    }

    /// Sleep until `ceiling` seconds have elapsed since `start`, then
    /// run `drop` on the main actor. A non-blocking async pad — the
    /// lock overlay + passcode sheet stay on screen (showing the
    /// neutral passcode UI, never the real contacts) for the duration,
    /// so the only thing the pad equalises is the wall-clock to the
    /// lock-drop, not anything visible mid-pad.
    ///
    /// **Invariant (S7-04):** `ceiling` is the SAME shared adaptive
    /// value for the real and the duress branch, and for the duress
    /// branch it is guaranteed ≥ the just-measured wipe time + headroom.
    /// So `remaining` is non-negative on the duress path (the lock
    /// never drops at the bare wipe time), and both paths land at the
    /// same observable latency. The `remaining <= 0` guard remains only
    /// as a defensive fast-path for the real branch (which does almost
    /// no work and always has time left); it can no longer fail the
    /// duress path open.
    private func dropLockAfterPadding(
        from start: CFAbsoluteTime,
        to ceiling: TimeInterval,
        _ drop: @escaping () -> Void,
    ) {
        let elapsed = CFAbsoluteTimeGetCurrent() - start
        let remaining = ceiling - elapsed
        guard remaining > 0 else {
            drop()
            return
        }
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(remaining * 1_000_000_000))
            drop()
        }
    }
}
