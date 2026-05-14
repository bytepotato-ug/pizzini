//
//  ContentView.swift
//  pizzini
//
//  Created by username on 08.05.26.
//

import SwiftUI
import UIKit
import PizziniCryptoCore

/// SwiftUI bridge for the model-layer `AppearanceMode`. Kept on this
/// side of the import boundary so `Models.swift` stays Foundation-only
/// (it has no SwiftUI dependency today and we'd rather not introduce
/// one for a single mapping).
extension AppearanceMode {
    var preferredColorScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }
}

struct ContentView: View {
    /// Tabs in the floating bottom bar. `TabKind` rather than `Tab` to
    /// avoid colliding with SwiftUI's `Tab` view in iOS 26's typed
    /// `TabView` initialiser. Stable raw cases keep a future
    /// `@SceneStorage` tab-restoration value sound across app updates.
    /// Order matches on-screen left-to-right.
    enum TabKind: Hashable {
        case chats
        case profile
        case settings
    }

    @State private var store = ChatStore.shared
    @State private var lockManager = LockManager.shared
    @State private var captureMonitor = ScreenCaptureMonitor.shared
    @State private var integrity = DeviceIntegrityMonitor.shared
    @State private var selectedTab: TabKind = .chats
    @State private var showScanner = false
    /// What the in-flight "Add contact" alert is keyed on: the
    /// validated card AND the source path it arrived on (QR scan vs
    /// clipboard paste). Source matters because `ChatStore.addContact`
    /// records it on the contact row, and the chat surface shows a
    /// stronger "needs SAS verification" affordance for `.pastedText`
    /// (the user couldn't physically see the QR, so the safety-number
    /// check is more load-bearing). Previously the source was
    /// hardcoded to `.qrScan` regardless of how the card arrived —
    /// a paste from a hostile clipboard would have presented as
    /// trusted-on-first-sight. Fixed.
    @State private var pendingCard: PendingContact?
    @State private var pendingName: String = ""

    private struct PendingContact: Equatable {
        let card: ContactCard
        let source: ContactSource
    }
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
                    tabSurface
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
        // Override the system light/dark setting when the user pinned
        // an explicit appearance in Settings → Appearance. `.system`
        // resolves to `nil`, which lets SwiftUI follow `UITraitCollection`
        // exactly as before.
        .preferredColorScheme(store.state.appearanceMode.preferredColorScheme)
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
                    // QR path: run through the same evaluator paste
                    // uses, so self / blocked / duplicate are caught
                    // consistently. Malformed-QR feedback isn't
                    // surfaced here — the scanner shows its own
                    // "couldn't read" UI before this even fires.
                    if case .ready(let card) = store.evaluatePastedContact(value) {
                        promptForName(card: card, source: .qrScan)
                    }
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
        ) { pending in
            TextField("name (e.g. Alice)", text: $pendingName)
                .hardenedTextInput(autocap: .words)
            Button("Cancel", role: .cancel) { resetPending() }
            Button("Add") {
                store.addContact(
                    card: pending.card,
                    displayName: pendingName,
                    source: pending.source,
                )
                resetPending()
            }
        } message: { pending in
            // Verification copy depends on how the card arrived:
            //   • `.qrScan`     — the user physically saw the QR; the
            //                     SAS check is a confirmation step.
            //   • `.pastedText` — the user can't vouch for the
            //                     clipboard content; the SAS check
            //                     is load-bearing (could be a card
            //                     from a man-in-the-middle).
            switch pending.source {
            case .qrScan:
                Text("Fingerprint \(pending.card.fingerprintShort)\nVerify it matches the QR you scanned in person.")
            case .pastedText:
                Text("Fingerprint \(pending.card.fingerprintShort)\nPasted cards aren't physically verified — confirm this fingerprint with your contact over a trusted channel before sending anything sensitive.")
            case .unknown:
                // Migrated rows from earlier schemas; in practice the
                // alert never opens for them because they're already
                // saved contacts, but the switch must cover the case.
                Text("Fingerprint \(pending.card.fingerprintShort)")
            }
        }
        .sheet(item: $integrityFAQ) { anchor in
            FAQView(initialSection: anchor) { integrityFAQ = nil }
        }
    }

    /// iOS 26 floating-pill `TabView`. Each tab is its own
    /// `NavigationStack` so pushed surfaces (ChatView, SettingsView's
    /// sub-pages) live inside the tab, and tapping the same tab again
    /// pops to root — the iOS convention. The global banners
    /// (keychain failure, integrity, screenshot degraded) live on the
    /// TabView container via `.safeAreaInset(.top)` so they show
    /// regardless of which tab is active. The floating pill at the
    /// bottom doesn't clip them.
    private var tabSurface: some View {
        TabView(selection: $selectedTab) {
            Tab("Chats", systemImage: "bubble.left.and.bubble.right.fill", value: TabKind.chats) {
                NavigationStack {
                    ContactsListView(
                        store: store,
                        showScanner: $showScanner,
                        onPasteContact: { card in
                            promptForName(card: card, source: .pastedText)
                        },
                        onRevealMyQR: { selectedTab = .profile }
                    )
                }
            }
            Tab("Profil", systemImage: "person.crop.circle", value: TabKind.profile) {
                NavigationStack {
                    ProfileView(card: store.myCard)
                }
            }
            Tab("Einstellungen", systemImage: "gearshape", value: TabKind.settings) {
                NavigationStack {
                    SettingsView(store: store)
                }
            }
        }
        // F-602 + integrity + screenshot-degraded banners. Hoisted to
        // the TabView so they're visible in every tab — previously they
        // sat above ContactsListView only, which meant a user reading
        // Settings or their QR wouldn't see a fresh "Storage
        // unavailable" warning.
        //
        // The relay connection state used to sit here too as a full-
        // width "Connecting…" strip. It overlapped pushed-view nav
        // bars (back arrow + Save buttons in Settings sub-pages
        // disappeared behind it) and felt loud for what's usually a
        // 2–5s transient state on cold launch. The compact equivalent
        // is now a single toolbar item inside ContactsListView's nav
        // bar — invisible at `.connected`, a small spinner during
        // connect, a tappable red badge on `.failed`. The other tabs
        // get no indicator; Settings → Trusted relays is the canonical
        // detail surface.
        .safeAreaInset(edge: .top, spacing: 0) {
            VStack(spacing: 0) {
                // Tor restart CTA outranks every other banner — the
                // user can't send a single message until they tap it.
                if store.torRequiresAppRestart {
                    torRestartBanner
                }
                if store.keychainWriteFailing {
                    keychainFailureBanner
                }
                if integrity.isCompromised {
                    integrityBanner
                }
                if !store.shouldMaskAppContents {
                    screenshotDegradedBanner
                }
            }
        }
    }

    private func promptForName(card: ContactCard, source: ContactSource) {
        pendingName = ""
        pendingCard = PendingContact(card: card, source: source)
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
    ///
    /// The checks behind these flags are best-effort and easily evaded
    /// (see `DeviceIntegrity.swift`'s header), so the headline reports
    /// *indicators*, not a device verdict — it must never claim more
    /// certainty than the detection can support. There is deliberately
    /// no "device looks clean" counterpart: the absence of this banner
    /// is not an affirmation, because a competent adversary produces no
    /// indicators at all.
    private var integrityHeadline: String {
        if integrity.isJailbroken {
            return "Possible jailbreak indicators detected"
        }
        if integrity.hasSuspiciousDylib {
            return "A debugging or hook framework may be loaded"
        }
        if integrity.isDebuggerAttached {
            return "A debugger appears to be attached to Pizzini"
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

    /// Non-dismissable banner shown when the embedded tor daemon
    /// has exited mid-process. tor_run_main() is single-shot, so
    /// there's no in-process recovery; the only path to a working
    /// connection is a fresh process. The Restart button calls
    /// `exit(0)` — iOS treats user-initiated termination as
    /// equivalent to a force-quit and immediately relaunches when
    /// the user taps the app icon next. The action is documented in
    /// the user's prompt as the intended recovery for this state.
    private var torRestartBanner: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "arrow.clockwise.circle.fill")
                .foregroundStyle(.white)
                .imageScale(.large)
            VStack(alignment: .leading, spacing: 2) {
                Text("Pizzini needs to restart")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.white)
                Text("The privacy network exited unexpectedly. Restart the app to reconnect.")
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.95))
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            Button {
                exit(0)
            } label: {
                Text("Restart")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.red)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(
                        Capsule().fill(Color.white)
                    )
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Restart Pizzini")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.red)
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

/// Profil tab. Surfaces the user's pairing QR + identity details. The
/// QR encodes the long-term peer-id + relay endpoint — both technically
/// public, but a photograph is enough to deanonymize the user on the
/// relay. We render that risk explicitly: blur by default, plain-
/// language warning, tap-to-reveal, tap-again-to-hide, auto-rehide on
/// scene deactivate (F-802).
///
/// Renders as a tab root (no sheet chrome) — the enclosing
/// `NavigationStack` inside the Profil tab supplies the title and the
/// safe-area handling for the bottom tab pill.
struct ProfileView: View {
    let card: ContactCard?

    /// Hidden by default. The user has to make an explicit reveal
    /// gesture, after reading the warning above the surface. Re-tap
    /// rehides; backgrounding the app re-hides too — F-802 fix below.
    @State private var revealed = false
    @State private var showDetails = false
    @State private var copyConfirmation = false

    /// Seconds until the `Copy as text` button's pasteboard entry
    /// auto-expires. The card is written to the *system-wide*
    /// pasteboard, which any other app on the device can read for as
    /// long as it sits there — so the window is kept short. 60 s
    /// covers a quick paste-and-go (switch to the messenger, paste)
    /// while keeping the exposure window tight for the user who
    /// copies and walks away. `expirationDate` is best-effort (some
    /// iOS versions ignore it), so an app-side timer below clears the
    /// pasteboard at the same deadline as a hard backstop.
    static let pasteboardExpirySeconds: TimeInterval = 60

    var body: some View {
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
        // Cover this surface during a screen recording or external
        // display — this is the highest-leak surface in the app
        // (a single capture deanonymises the user), so the shield
        // applies even if `revealed == false`.
        .screenCaptureShielded()
        // F-802: re-hide the QR whenever the scene deactivates
        // (background, Control Centre pull-down, incoming call,
        // app-switcher peek). The privacy shield masks the
        // multitasking SNAPSHOT but the tab itself remains mounted
        // across foreground transitions, so without this a bystander
        // grabbing the unlocked phone seconds after the user resumes
        // captures the deanonymising QR. Matches the verbal promise
        // the privacy-warning copy makes.
        .onReceive(
            NotificationCenter.default.publisher(
                for: UIScene.willDeactivateNotification,
            ),
        ) { _ in
            revealed = false
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
                    // This writes the identity card to
                    // `UIPasteboard.general` — the SYSTEM-WIDE
                    // pasteboard. `localOnly: true` only suppresses
                    // Universal Clipboard sync to other devices on the
                    // same iCloud account; it does NOT scope the write
                    // to Pizzini. Any other app on this device can read
                    // the card (e.g. on `UIPasteboard.changedNotification`)
                    // until it is cleared. There is no app-private
                    // pasteboard that survives a hand-off to a
                    // third-party messenger, so this exposure is
                    // inherent to the text-copy affordance — the window
                    // is kept short and force-cleared instead.
                    //
                    // `expirationDate` asks iOS to drop the item after
                    // the window, but iOS honours it inconsistently
                    // across versions. The `asyncAfter` below clears
                    // the pasteboard ourselves at the same deadline so
                    // the card cannot outlive the stated window while
                    // Pizzini is alive, regardless of the OS.
                    //
                    // Routed through `setObjects(_:localOnly:expirationDate:)`
                    // — the modern UIPasteboard write API. The prior code
                    // used `setItems(_:options:)` with
                    // `UIPasteboard.typeAutomatic` as the key; that
                    // combination silently writes nothing on iOS Simulator
                    // under recent Xcodes (a real-device-vs-simulator
                    // divergence in how the type-autodetect path resolves
                    // a Swift `String` value). `setObjects` takes a
                    // `[String]` directly, conforms-as-NSItemProviderWriting
                    // under the hood, and gives us a deterministic
                    // `public.utf8-plain-text` write on both surfaces.
                    //
                    // CRITICAL: do NOT read the pasteboard on the copy
                    // path. `pb.string`, `pb.types`, `pb.items`, `pb.url`,
                    // and friends all trigger iOS's paste banner — and
                    // on a device with Universal Clipboard active and
                    // content on a paired Mac, that banner becomes a
                    // Handoff prompt "Paste from Mac Studio?" which is
                    // both confusing and the opposite of what the user
                    // asked for. The cheap predicate accessors
                    // (`hasStrings`, `hasURLs`, `numberOfItems`) don't
                    // trigger the banner, but for a copy action we
                    // don't need any of them — `setObjects` is the
                    // authoritative write API and its contract is
                    // "the data is on the pasteboard when this call
                    // returns." The `pzLog` line below confirms the
                    // button fired with the right payload size; the
                    // round-trip test (copy → paste in chats → see the
                    // "self-paste" alert) already verified end-to-end
                    // correctness, so we no longer need post-write
                    // verification on every tap.
                    let cardLen = card.encoded.count
                    UIPasteboard.general.setObjects(
                        [card.encoded],
                        localOnly: true,
                        expirationDate: Date().addingTimeInterval(Self.pasteboardExpirySeconds),
                    )
                    // Capture the generation counter from the write we
                    // just made (a metadata-only accessor — does not
                    // trigger the paste banner). At the expiry deadline
                    // we clear the pasteboard ourselves, but only if it
                    // hasn't changed since: if `changeCount` moved, the
                    // user (or another app) replaced the contents and
                    // wiping would destroy whatever they put there.
                    let writeGeneration = UIPasteboard.general.changeCount
                    DispatchQueue.main.asyncAfter(
                        deadline: .now() + Self.pasteboardExpirySeconds
                    ) {
                        guard UIPasteboard.general.changeCount == writeGeneration else { return }
                        UIPasteboard.general.items = []
                        pzLog("[pizzini.paste] copy card: cleared expired pasteboard entry")
                    }
                    pzLog(
                        "[pizzini.paste] copy card: wrote cardLen=\(cardLen)"
                        + " (no pasteboard read — would trigger Handoff banner)"
                    )
                    copyConfirmation = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        copyConfirmation = false
                    }
                } label: {
                    Label(copyConfirmation ? "Copied" : "Copy as text", systemImage: copyConfirmation ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.bordered)
                Text("This copies your identity to the device clipboard. Until it clears (about a minute), any other app on this device can read it — not just the one you paste into. Use only with someone you'd hand the QR to, and paste it right away.")
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
