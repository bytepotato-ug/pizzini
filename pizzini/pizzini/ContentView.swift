//
//  ContentView.swift
//  pizzini
//
//  Created by username on 08.05.26.
//

import SwiftUI
import UIKit
import PizziniCryptoCore

struct ContentView: View {
    @State private var store = ChatStore.shared
    @State private var lockManager = LockManager.shared
    @State private var captureMonitor = ScreenCaptureMonitor.shared
    @State private var showScanner = false
    @State private var showMyQR = false
    @State private var showSettings = false
    @State private var pendingCard: ContactCard?
    @State private var pendingName: String = ""

    var body: some View {
        // The body deliberately does NOT depend on `Environment(\.scenePhase)`
        // — see LockManager's header doc for why. Privacy shielding and
        // the lock overlay are driven exclusively by `lockManager.isShielded`
        // / `lockManager.isLocked`, which are mutated by the four
        // `.onReceive` hooks below at exactly the right lifecycle points.
        // Animations are intentionally absent: a fade would let chat
        // content peek through during the transition.
        ZStack {
            Group {
                if let err = store.initError {
                    errorState(err)
                } else {
                    NavigationStack {
                        ContactsListView(
                            store: store,
                            showScanner: $showScanner,
                            showMyQR: $showMyQR,
                            showSettings: $showSettings,
                            onPasteContact: promptForName(decoding:)
                        )
                    }
                    // F-602: surface chronic Keychain.write failures the
                    // user would otherwise never see. The banner sits
                    // inside the chat-content branch (above the nav bar
                    // via .safeAreaInset) so it shows during normal use
                    // but doesn't double up on the initError state. The
                    // copy mirrors the audit's recommended message.
                    .safeAreaInset(edge: .top, spacing: 0) {
                        if store.keychainWriteFailing {
                            keychainFailureBanner
                        }
                    }
                }
            }

            // Lock overlay covers the chat UI when the app is locked. By
            // the time `isLocked` flips to true on a foreground transition,
            // `isShielded` is also still true (cleared only after this),
            // so any frame in between renders the shield, not the chat.
            if lockManager.isLocked {
                LockOverlayView(lockManager: lockManager)
            }

            // Privacy shield. Set on `willDeactivate` so it's already in
            // place by the time iOS captures the multitasking snapshot;
            // cleared on `didActivate` after the lock decision has run.
            if lockManager.isShielded {
                PrivacyShieldView()
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScene.willDeactivateNotification)) { _ in
            lockManager.handleWillDeactivate()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScene.didEnterBackgroundNotification)) { _ in
            lockManager.handleDidEnterBackground()
            // Close the relay socket cleanly. Apple's networking layer
            // doesn't keep TCP alive across iOS suspension; if we
            // leave the connection open, the queued `.failed` callback
            // surfaces only on the *next* foreground and produces a
            // red→green→red flap. Closing here, reconnecting on
            // foreground, eliminates the race.
            store.disconnectForBackground()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScene.willEnterForegroundNotification)) { _ in
            lockManager.handleWillEnterForeground()
            store.reconnectAfterBackground()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScene.didActivateNotification)) { _ in
            lockManager.handleDidActivate()
        }
        .fullScreenCover(isPresented: Binding(
            get: { !store.state.onboardingCompleted && store.initError == nil },
            set: { _ in }
        )) {
            OnboardingView { enableBiometric in
                store.completeOnboarding(enableBiometric: enableBiometric)
            }
        }
        .sheet(isPresented: $showScanner) {
            QRScannerView(
                onScanned: { value in
                    showScanner = false
                    promptForName(decoding: value)
                },
                onCancel: { showScanner = false }
            )
        }
        .alert(
            "Add contact",
            isPresented: Binding(
                get: { pendingCard != nil },
                set: { isPresented in
                    if !isPresented { resetPending() }
                }
            ),
            presenting: pendingCard
        ) { card in
            TextField("name (e.g. Alice)", text: $pendingName)
                .textInputAutocapitalization(.words)
            Button("Cancel", role: .cancel) { resetPending() }
            Button("Add") {
                store.addContact(card: card, displayName: pendingName)
                resetPending()
            }
        } message: { card in
            Text("Fingerprint \(card.fingerprintShort)\nVerify it matches the QR you scanned in person.")
        }
        .sheet(isPresented: $showMyQR) {
            MyQRSheet(card: store.myCard, onDone: { showMyQR = false })
        }
        .sheet(isPresented: $showSettings) {
            SettingsView(store: store, onClose: { showSettings = false })
        }
    }

    private func promptForName(decoding raw: String) {
        guard let card = ContactCard.decode(raw) else { return }
        pendingName = ""
        pendingCard = card
    }

    private func resetPending() {
        pendingCard = nil
        pendingName = ""
    }

    private func errorState(_ msg: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.largeTitle)
                .foregroundStyle(.red)
            Text("init failed")
                .font(.headline)
            Text(msg)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// F-602: persistent banner shown above the nav bar when ChatStore
    /// detects chronic Keychain.write failure. The plain-language copy
    /// names the consequence (sent messages may not survive a relaunch)
    /// rather than the underlying errSec status, which the user can't
    /// act on. NSLog has the technical detail for support.
    private var keychainFailureBanner: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "lock.trianglebadge.exclamationmark")
                .foregroundStyle(.white)
                .imageScale(.large)
            VStack(alignment: .leading, spacing: 2) {
                Text("Storage unavailable")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.white)
                Text(
                    "Pizzini can't write to the Keychain right now. Sent messages may not survive an app restart. Restart the device or check storage and try again."
                )
                .font(.caption)
                .foregroundStyle(.white.opacity(0.95))
                .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red)
    }
}

/// Pairing-QR sheet. The QR encodes the user's long-term peer-id +
/// relay endpoint — both technically public, but a photograph of this
/// code is enough to deanonymize the user on the relay (link "real
/// face" → "peer-id observable in traffic"). The strict-scan +
/// hashcash + contact-gate stack already prevents a stolen QR from
/// being used to *pair* without consent, so the residual risk is
/// purely deanonymization. We surface that explicitly: blur by
/// default, plain-language warning, tap-to-reveal, tap-again-to-hide.
private struct MyQRSheet: View {
    let card: ContactCard?
    let onDone: () -> Void

    /// Hidden by default. The user has to make an explicit reveal
    /// gesture, after reading the warning above the surface. Re-tap
    /// rehides; backgrounding the app re-hides too — F-802 fix below.
    @State private var revealed = false
    @State private var showDetails = false
    @State private var copyConfirmation = false
    @State private var store = ChatStore.shared

    /// True when the QR-block trick should be applied: the user hasn't
    /// turned it off in Settings AND the runtime self-test hasn't
    /// determined that the trick is broken on this iOS version.
    /// `qrBlockEffective == nil` is treated as "may work" — the
    /// self-test runs at app launch and writes a result before the
    /// user can typically open this sheet.
    private var qrBlockActive: Bool {
        guard store.state.blockQRScreenshots else { return false }
        return store.state.qrBlockEffective != false
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    privacyWarning
                    qrSurface
                    if revealed {
                        usageHint
                        actions
                    }
                }
                .padding(.horizontal, 24)
                .padding(.top, 8)
                .padding(.bottom, 32)
            }
            .navigationTitle("Your QR code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done", action: onDone)
                }
            }
            // Cover the QR sheet during a screen recording or external
            // display — this is the highest-leak surface in the app
            // (a single capture deanonymises the user), so the shield
            // applies even if `revealed == false`. Done button stays
            // available in the toolbar.
            .screenCaptureShielded()
            // F-802: re-hide the QR whenever the scene deactivates
            // (background, Control Centre pull-down, incoming call,
            // app-switcher peek). The privacy shield masks the
            // multitasking SNAPSHOT but the sheet itself remains
            // presented across foreground transitions, so without this
            // a bystander grabbing the unlocked phone seconds after
            // the user resumes captures the deanonymising QR. Matches
            // the verbal promise the privacy-warning copy makes.
            .onReceive(
                NotificationCenter.default.publisher(
                    for: UIScene.willDeactivateNotification,
                ),
            ) { _ in
                revealed = false
            }
        }
    }

    private var privacyWarning: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "exclamationmark.shield.fill")
                .font(.title3)
                .foregroundStyle(.orange)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 6) {
                Text("Show this only to the person you want to chat with.")
                    .font(.callout.weight(.semibold))
                Text("A photo of this code — even from a window, a security camera, or someone behind you — identifies you on Pizzini's network. Make sure no one else can see your screen before you reveal it.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(Color.orange.opacity(0.10))
        )
    }

    @ViewBuilder
    private var qrSurface: some View {
        if let card {
            ZStack {
                if revealed {
                    Button {
                        withAnimation(.easeInOut(duration: 0.15)) { revealed = false }
                    } label: {
                        // Wrap the rendered QR in a SecureScreenshotShield
                        // when the toggle is on AND the runtime self-test
                        // didn't fail on this iOS version. The shield
                        // makes iOS render this subtree blank in the
                        // captured framebuffer for screenshots and
                        // mirroring. Falls back to the plain image if
                        // the trick has been disabled.
                        if qrBlockActive {
                            SecureScreenshotShield {
                                ContactQRImage(card: card)
                            }
                            .frame(width: 196, height: 196)
                        } else {
                            ContactQRImage(card: card)
                        }
                    }
                    .buttonStyle(.plain)
                } else {
                    hiddenPlaceholder
                }
            }
            .frame(maxWidth: .infinity)
        } else {
            ProgressView("preparing identity…")
                .frame(minHeight: 304)
        }
    }

    private var hiddenPlaceholder: some View {
        Button {
            withAnimation(.easeInOut(duration: 0.15)) { revealed = true }
        } label: {
            VStack(spacing: 14) {
                Image(systemName: "eye.slash.fill")
                    .font(.system(size: 44))
                    .foregroundStyle(.secondary)
                Text("Code hidden for privacy")
                    .font(.headline)
                    .foregroundStyle(.primary)
                Text("Tap to reveal")
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(.tint)
            }
            .frame(maxWidth: .infinity, minHeight: 304)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(Color(uiColor: .secondarySystemBackground))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .strokeBorder(Color.secondary.opacity(0.20), lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
        .accessibilityLabel("QR code hidden. Tap to reveal.")
    }

    private var usageHint: some View {
        VStack(spacing: 6) {
            Text("Tap the code to hide it again.")
                .font(.footnote)
                .foregroundStyle(.tertiary)
            Text("They scan this with Pizzini, then show you theirs. Both scans unlock the chat.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
    }

    @ViewBuilder
    private var actions: some View {
        // Copy is gated behind reveal: the user has already accepted
        // the warning by tapping reveal. Without this gating, a careful
        // user could be tripped up by accidentally tapping "Copy" and
        // pushing their identity to the system pasteboard before
        // realising it's the same risk surface.
        if let card {
            VStack(spacing: 8) {
                Button {
                    UIPasteboard.general.string = card.encoded
                    copyConfirmation = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        copyConfirmation = false
                    }
                } label: {
                    Label(copyConfirmation ? "Copied" : "Copy as text", systemImage: copyConfirmation ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.bordered)
                Text("Pasting it into another app exposes your identity the same way a photo does. Use only with someone you'd hand the QR to.")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 16)
            }

            DisclosureGroup("Show technical details", isExpanded: $showDetails) {
                ContactCardDetails(card: card)
                    .padding(.top, 8)
            }
            .font(.callout)
            .foregroundStyle(.secondary)
            .padding(.top, 4)
        }
    }
}

#Preview {
    ContentView()
}
