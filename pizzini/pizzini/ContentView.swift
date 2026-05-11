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
    @State private var integrity = DeviceIntegrityMonitor.shared
    @State private var showScanner = false
    @State private var showMyQR = false
    @State private var pendingCard: ContactCard?
    @State private var pendingName: String = ""
    /// FAQ deep-link target for the integrity banner's (i) button. Nil
    /// means no sheet; setting it presents the FAQ at that section.
    @State private var integrityFAQ: FAQSection?

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
                        VStack(spacing: 0) {
                            if store.keychainWriteFailing {
                                keychainFailureBanner
                            }
                            if integrity.isCompromised {
                                integrityBanner
                            }
                            // View-level fallback for the screenshot
                            // mask. `WindowSecureMask` silently no-ops
                            // when `SecureScreenshotSelfTest` failed on
                            // this iOS major — without this persistent
                            // banner the user has no in-app signal
                            // that screenshot protection is degraded
                            // (only a Settings notice they may never
                            // see). Surface it where they'll notice.
                            if !store.shouldMaskAppContents {
                                screenshotDegradedBanner
                            }
                        }
                    }
                }
            }

            // Lock overlay covers the chat UI when the app is locked. By
            // the time `isLocked` flips to true on a foreground transition,
            // `isShielded` is also still true (cleared only after this),
            // so any frame in between renders the shield, not the chat.
            if lockManager.isLocked {
                LockOverlayView(lockManager: lockManager, store: store)
            }

            // Privacy shield. Set on `willDeactivate` so it's already in
            // place by the time iOS captures the multitasking snapshot;
            // cleared on `didActivate` after the lock decision has run.
            if lockManager.isShielded {
                PrivacyShieldView()
            }
        }
        // App-wide screenshot mask is applied at the window-CALayer
        // level by `WindowSecureMask` — installed once from
        // `AppDelegate.application(_:didFinishLaunchingWithOptions:)`
        // and propagating to every surface presented in the same
        // window (the contacts UI, sheets, full-screen covers, the
        // lock overlay). The view hierarchy is left untouched, which
        // is why Form / `.insetGrouped` List backgrounds extend
        // through the safe areas correctly. Sheets and covers do NOT
        // need a per-presentation modifier — they share the window.
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
                .hardenedTextInput(autocap: .words)
            Button("Cancel", role: .cancel) { resetPending() }
            Button("Add") {
                // QR scanner is the only entry point today. A future
                // paste/deep-link path would pass `.pastedText` here so
                // the contact row starts in the red "needs SAS"
                // verification state.
                store.addContact(card: card, displayName: pendingName, source: .qrScan)
                resetPending()
            }
        } message: { card in
            Text("Fingerprint \(card.fingerprintShort)\nVerify it matches the QR you scanned in person.")
        }
        .sheet(isPresented: $showMyQR) {
            MyQRSheet(card: store.myCard, onDone: { showMyQR = false })
        }
        .sheet(item: $integrityFAQ) { anchor in
            FAQView(initialSection: anchor) { integrityFAQ = nil }
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

    /// Persistent banner shown when `DeviceIntegrityMonitor` flagged
    /// the device as compromised (jailbroken, suspicious dylib loaded,
    /// or — in release builds — a debugger attached). Plain-language
    /// copy names the consequence ("our protections are weakened")
    /// rather than the technical signal; (i) deep-links into the FAQ
    /// for the user who wants to know what was actually detected.
    private var integrityBanner: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.shield.fill")
                .foregroundStyle(.white)
                .imageScale(.large)
            VStack(alignment: .leading, spacing: 2) {
                Text(integrityHeadline)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.white)
                Text("Pizzini's screen-capture defences are best-effort on a compromised device. The encryption itself is unaffected.")
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.95))
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            Button {
                integrityFAQ = .deviceIntegrity
            } label: {
                Image(systemName: "info.circle.fill")
                    .foregroundStyle(.white)
                    .imageScale(.large)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("More info on this warning")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange)
    }

    /// First-line headline for the integrity banner — names the most
    /// load-bearing detected condition. Order: jailbreak > dylib >
    /// debugger (debugger only surfaces in release per the monitor).
    private var integrityHeadline: String {
        if integrity.isJailbroken {
            return "This device appears jailbroken"
        }
        if integrity.hasSuspiciousDylib {
            return "A debugging or hook framework is loaded"
        }
        if integrity.isDebuggerAttached {
            return "A debugger is attached to Pizzini"
        }
        return "Device integrity warning"
    }

    /// Persistent banner shown when the screenshot-mask self-test
    /// failed on this iOS major version. `WindowSecureMask` silently
    /// no-ops in that state; without this banner the user could
    /// reasonably believe protection is in place when it isn't.
    /// Deep-links into the `screenCapture` FAQ section.
    private var screenshotDegradedBanner: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "camera.viewfinder")
                .foregroundStyle(.white)
                .imageScale(.large)
            VStack(alignment: .leading, spacing: 2) {
                Text("Screenshot protection degraded")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.white)
                Text("This iOS version no longer hides Pizzini's content in screenshots or mirroring. Encryption is unaffected; treat the screen itself as visible.")
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.95))
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            Button {
                integrityFAQ = .screenCapture
            } label: {
                Image(systemName: "info.circle.fill")
                    .foregroundStyle(.white)
                    .imageScale(.large)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("More info on screenshot protection")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange)
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
                        // The window-level `WindowSecureMask` masks
                        // every surface in the app's window — sheets,
                        // covers, this QR — from the screenshot /
                        // mirroring / AirPlay capture pipeline. No
                        // per-view shield is required here.
                        ContactQRImage(card: card)
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
