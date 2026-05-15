import SwiftUI

/// In-app FAQ. Reached from:
///   - Settings → Help → FAQ (push presentation, no Done button)
///   - The (i) button on an attachment row's warning banner and the
///     device-integrity / screenshot-degraded banners (sheet
///     presentation, with Done — `FAQView` wraps `FAQContent`)
///
/// Layout: a "Basics" / "Advanced" segmented picker at the top, then
/// sections grouped under category headers. Each section has a
/// short basics body and an optional advanced body that only shows
/// while Advanced is selected. A handful of advanced-only sections
/// exist for techy topics that don't belong in the basics flow.
///
/// Deep-link contract: every section reachable from a banner's (i)
/// button is a stable `FAQSection` enum case. Adding/removing cases
/// is fine; renaming or deleting an existing case breaks the
/// banners' `initialSection:` parameter at compile time.
struct FAQView: View {
    let initialSection: FAQSection?
    let onDone: () -> Void

    init(initialSection: FAQSection? = nil, onDone: @escaping () -> Void) {
        self.initialSection = initialSection
        self.onDone = onDone
    }

    var body: some View {
        NavigationStack {
            FAQContent(initialSection: initialSection)
                .navigationTitle("FAQ")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done", action: onDone)
                    }
                }
        }
    }
}

/// Pure-content scroll view. Embed via `NavigationLink` for push
/// presentation (Settings → Help → FAQ), or via `FAQView` for sheet
/// presentation with a Done button.
struct FAQContent: View {
    let initialSection: FAQSection?

    /// Persists across launches so a user who flipped to Advanced
    /// once doesn't have to re-flip on the next visit. The default
    /// is Basics — most users never need the deeper material.
    @AppStorage("faq.showAdvanced") private var showAdvanced: Bool = false

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    Picker("Detail level", selection: $showAdvanced) {
                        Text("Basics").tag(false)
                        Text("Advanced").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .padding(.horizontal, 20)
                    .padding(.top, 12)
                    .padding(.bottom, 4)

                    Text(showAdvanced
                         ? "Mechanism, primitives, and code-level detail. Includes everything in Basics."
                         : "Plain-language answers to the questions people ask most. Switch to Advanced for the technical version.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 20)
                        .padding(.bottom, 12)

                    ForEach(FAQCategory.allCases) { category in
                        let visible = category.sections.filter { showAdvanced || !$0.advancedOnly }
                        if !visible.isEmpty {
                            Text(category.title)
                                .font(.title2.weight(.bold))
                                .padding(.horizontal, 20)
                                .padding(.top, 22)
                                .padding(.bottom, 8)

                            VStack(alignment: .leading, spacing: 22) {
                                ForEach(visible) { section in
                                    sectionView(section)
                                        .id(section)
                                }
                            }
                            .padding(.horizontal, 20)
                        }
                    }

                    Spacer(minLength: 32)
                }
            }
            .onAppear {
                guard let target = initialSection else { return }
                // An advanced-only section deep-linked from a banner
                // would otherwise scroll to a row that's hidden — flip
                // the toggle so the row is visible before we scroll.
                if target.advancedOnly && !showAdvanced {
                    showAdvanced = true
                }
                // Defer one runloop so layout settles before we scroll
                // — without this the scroll fires while the ScrollView
                // is still computing offsets.
                DispatchQueue.main.async {
                    withAnimation(.easeInOut(duration: 0.25)) {
                        proxy.scrollTo(target, anchor: .top)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func sectionView(_ section: FAQSection) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(section.title)
                .font(.title3.weight(.semibold))
            if !section.body.isEmpty {
                Text(section.body)
                    .font(.body)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if showAdvanced, let advanced = section.advancedBody, !advanced.isEmpty {
                if !section.body.isEmpty {
                    Text("More detail")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(.secondary)
                        .padding(.top, 4)
                }
                Text(advanced)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

/// Top-level groupings shown as headers in the FAQ. Order is the
/// reading order the FAQ presents.
enum FAQCategory: String, CaseIterable, Identifiable, Sendable {
    case gettingStarted
    case privacyBasics
    case relayFleet
    case filesAndMedia
    case safetyFeatures
    case knownLimits

    var id: String { rawValue }

    var title: String {
        switch self {
        case .gettingStarted: return "Getting started"
        case .privacyBasics:  return "Privacy basics"
        case .relayFleet:     return "The relay fleet"
        case .filesAndMedia:  return "Files and media"
        case .safetyFeatures: return "Safety features"
        case .knownLimits:    return "Known limits"
        }
    }

    /// Sections in this category, in the order they should render.
    var sections: [FAQSection] {
        FAQSection.allCases.filter { $0.category == self }
    }
}

/// Stable identifiers for each FAQ topic. Used both as the in-page
/// anchor (`ScrollViewReader.scrollTo`) and as the deep-link target
/// from attachment / integrity / screenshot banners.
///
/// Existing cases are deep-link-stable — see `ChatView`,
/// `GroupChatView`, `ContentView`, and `Attachments/AttachmentCopy`
/// for the call sites. Advanced-only cases at the end are unreached
/// by deep links and only appear under the Advanced toggle.
enum FAQSection: String, CaseIterable, Identifiable, Hashable, Sendable {
    // ── Existing cases (deep-link stable) ─────────────────────────
    case encryption
    case relayVisibility
    case runYourOwnRelay
    case qrCode
    case screenCapture
    case deviceIntegrity
    case panicMode
    case noPhoneNumbers
    case pushNotifications
    case mediaStripping
    case prnu
    case documentMetadata
    case noPreview
    case blockedTypes
    case executableWarning
    case wipingData
    case duressPasscode
    case transparencyLog
    case notYetShipped
    // ── Advanced-only (no deep-links) ─────────────────────────────
    case cryptoPrimitives
    case tokenChains
    case reproducibleBuilds
    case threatModelLimits

    var id: String { rawValue }

    var category: FAQCategory {
        switch self {
        case .encryption, .noPhoneNumbers, .qrCode, .cryptoPrimitives:
            return .gettingStarted
        case .pushNotifications, .screenCapture, .wipingData:
            return .privacyBasics
        case .relayVisibility, .runYourOwnRelay, .transparencyLog,
             .tokenChains, .reproducibleBuilds:
            return .relayFleet
        case .noPreview, .mediaStripping, .prnu, .documentMetadata,
             .blockedTypes, .executableWarning:
            return .filesAndMedia
        case .panicMode, .duressPasscode, .deviceIntegrity:
            return .safetyFeatures
        case .notYetShipped, .threatModelLimits:
            return .knownLimits
        }
    }

    /// True for sections that only appear under the Advanced toggle.
    /// Advanced-only sections have an empty `body` and put all their
    /// content in `advancedBody`.
    var advancedOnly: Bool {
        switch self {
        case .cryptoPrimitives, .tokenChains,
             .reproducibleBuilds, .threatModelLimits:
            return true
        default:
            return false
        }
    }

    var title: String {
        switch self {
        case .encryption:        return "How Pizzini encrypts your messages"
        case .noPhoneNumbers:    return "Why no phone numbers"
        case .qrCode:            return "What's in your QR code"
        case .pushNotifications: return "What notifications leak"
        case .screenCapture:     return "Screenshots, recording, and AirPlay"
        case .wipingData:        return "Deleting your data"
        case .relayVisibility:   return "What the relay can see"
        case .runYourOwnRelay:   return "Running your own relay"
        case .transparencyLog:   return "The transparency log"
        case .noPreview:         return "Why Pizzini doesn't preview files inline"
        case .mediaStripping:    return "What's stripped from images and videos"
        case .prnu:              return "The sensor-fingerprint warning"
        case .documentMetadata:  return "Why documents can still identify you"
        case .blockedTypes:      return "File types Pizzini won't let you send"
        case .executableWarning: return "Files marked \u{201C}executable on desktop\u{201D}"
        case .panicMode:         return "Panic mode (triple-tap to wipe a chat)"
        case .duressPasscode:    return "The duress passcode (silent wipe)"
        case .deviceIntegrity:   return "Device-integrity warnings"
        case .notYetShipped:     return "What Pizzini doesn't do yet"
        case .cryptoPrimitives:  return "Cryptography primitives"
        case .tokenChains:       return "Hash-chain delivery tokens"
        case .reproducibleBuilds:return "Reproducible relay builds"
        case .threatModelLimits: return "What Pizzini doesn't defend against"
        }
    }

    /// Basics body. Empty string for advanced-only sections — the
    /// content lives in `advancedBody` instead.
    var body: String {
        switch self {
        case .encryption:
            return """
            Every message is end-to-end encrypted. Only you and the \
            person you're talking to can read what's sent — not the \
            relay, not us, not anyone in between.

            Pizzini uses Signal's libsignal library — the same protocol \
            Signal Messenger uses, with the post-quantum upgrades \
            Signal shipped in 2025. We don't write our own cryptography.
            """

        case .noPhoneNumbers:
            return """
            Pizzini doesn't ask for a phone number. There's no signup, \
            no account, no central directory.

            Your identity is a random ID generated on your phone. You \
            share it with friends by scanning each other's QR codes in \
            person. That's the whole pairing flow.

            What this gets you:

            • Nothing to subpoena from a phone carrier.
            • SIM-swap attacks against your account aren't possible — \
              there's no number to redirect.
            • Recycled phone numbers can't inherit someone else's chats.

            Both sides must scan each other for a chat to unlock. A \
            one-way scan does not establish a session.
            """

        case .qrCode:
            return """
            Your QR code encodes two things: your random ID and the \
            relay address your phone uses. That's it. No name, no \
            contact list, no history.

            The QR sheet stays hidden behind a "Tap to reveal" gesture \
            and re-hides as soon as you switch away from the app. \
            Sharing the QR via screenshot, AirDrop, or any other app \
            carries the same risk as handing someone a printed copy.

            Even a photograph of the QR — from across a room, a \
            security camera, or a window reflection — links a face to \
            that ID.
            """

        case .pushNotifications:
            return """
            When a message arrives while Pizzini is closed, you get a \
            push notification that just says "New message". No sender \
            name, no preview, no chat ID.

            Why so spartan: iOS keeps every notification you've \
            received in a system-wide database that forensic tools \
            can read. Anything in the notification text sits there in \
            plain text. Pizzini deliberately puts nothing useful in it.
            """

        case .screenCapture:
            return """
            Pizzini blocks screenshots of itself. iOS's screenshot \
            pipeline captures a solid black frame instead of your \
            chats, contacts, or QR.

            The same applies to screen recording, AirPlay mirroring, \
            and an external monitor connected over USB-C or Lightning. \
            While any of those are active, Pizzini drops an opaque \
            shield over the screen.

            What this can't stop: a second camera pointed at your \
            screen. Nothing in iOS can. For the highest-risk \
            situations, take the conversation somewhere no screen \
            exists — in person.

            A "Screenshot protection — degraded" banner appears at the \
            top of the chat list if the technique stops working on \
            your iOS version. Encryption is unaffected; treat the \
            screen as visible until the next iOS update restores the \
            protection.
            """

        case .wipingData:
            return """
            Pizzini offers four levels of delete:

            • Delete chat (per-contact \u{22EF} menu) — wipes that \
              contact's message log only. The contact and the \
              encryption session stay. You can keep chatting; you'll \
              just have an empty chat with them.
            • Delete contact (per-contact \u{22EF} menu) — drops the \
              contact and the encryption session. To talk again, both \
              of you scan again.
            • Delete all chats (Settings → Advanced) — wipes every \
              contact's message log at once. Contacts and sessions stay.
            • Reset identity (Settings → Advanced) — generates a fresh \
              keypair and wipes everything. Everyone you talk to needs \
              to scan you again. Your relay host, app-lock setting, \
              and onboarding state are preserved — those aren't \
              identity-derived.

            None of these are recoverable. There is no "undelete".
            """

        case .relayVisibility:
            return """
            The relay shuttles encrypted bytes from your phone to your \
            contact's phone. It can see:

            • Who the message is FOR (the recipient's random ID)
            • That a message was sent (timing, size)
            • Your IP address — except Tor masks that

            It cannot see:

            • Who SENT the message (sealed-sender envelope hides the \
              sender)
            • What you said or what's in your attachments
            • Your contacts list
            • Any account history (there's no account)

            Today the fleet is three independent Tor onion services in \
            Germany, Norway, and the USA. Your phone connects to all \
            three at once; whichever delivers first wins.
            """

        case .runYourOwnRelay:
            return """
            The relay's source code is in this repo under AGPL-3.0. \
            Anyone can run one — no fee, no token, no vendor.

            To self-host: build with `cargo build -p pizzini-relay \
            --release`, run it on any reachable machine, and each \
            phone in your group enters the address in Settings → \
            Relay host.

            You don't have to. Pizzini ships with three relays already \
            set up (Germany, Norway, USA). On a fresh install the \
            relay-host field is empty, which means "use the bundled \
            fleet" — no setup, no address to type.

            One operator currently runs all three bundled relays. The \
            "multiple jurisdictions" framing is about resilience to a \
            single relay going offline, not yet about independent \
            operators — see "What Pizzini doesn't do yet" below.
            """

        case .transparencyLog:
            return """
            Pizzini publishes a signed log of every relay binary the \
            operator deploys, signed with the operator's Ed25519 key. \
            Your phone checks each relay's running binary against the \
            log on reconnect.

            If a relay is running an unannounced build, Settings → \
            Relay attestation flags it as "mismatch". Today this is \
            detection only — the app surfaces the warning but doesn't \
            yet refuse to talk to a mismatched relay. Enforcement is \
            pending a policy decision.

            The log itself is fetched over plain HTTPS, NOT through \
            Tor. This is one of two documented clearnet exceptions in \
            the app. See the Advanced view for what that leaks and \
            why we accept it today.
            """

        case .noPreview:
            return """
            Pizzini never renders a received file inside the app. You \
            see the filename, the size, and a Save button.

            This rule exists because of attacks like Pegasus (2021), \
            where a maliciously-crafted image could take over an \
            iPhone the moment iMessage previewed it — the victim \
            never tapped anything. Any code that parses incoming \
            bytes is a potential exploit surface, so we run zero of it.

            When you tap "Save to Files", the bytes are handed off to \
            iOS. Apple's own services then decode them in sandboxed \
            processes.
            """

        case .mediaStripping:
            return """
            Before any image or video leaves your phone, Pizzini \
            removes its embedded metadata — GPS coordinates, capture \
            timestamp, camera make / model / serial number, software \
            version, and edit history.

            You don't have to do anything; this happens automatically \
            every send.

            What Pizzini does NOT do is alter the actual pixels. The \
            image looks the same on the other side as it did on yours.
            """

        case .prnu:
            return """
            Every camera sensor has tiny manufacturing variations that \
            imprint a faint, unique noise pattern into every photo. \
            It's invisible to the eye but identical across every \
            photo from the same physical camera. Researchers call it \
            PRNU (Photo Response Non-Uniformity).

            With access to several photos from your camera — like \
            ones you've already posted publicly — an analyst can \
            match a leaked photo back to your specific device.

            Removing metadata doesn't remove this fingerprint. Pizzini \
            deliberately doesn't try to scrub it: anti-PRNU filters \
            are detectable in their own right, and a photo that looks \
            "cleaned" can become evidence on its own.

            For high-risk material, the safest practice is to take \
            the photo on a device that isn't linked to you (a \
            borrowed phone, a disposable camera) rather than scrub \
            the photo afterwards.
            """

        case .documentMetadata:
            return """
            PDFs, Word docs, Excel sheets, PowerPoint slides, and \
            ePub files can carry information that isn't visible when \
            you open them: author name, originating computer or \
            printer, tracked-changes history, comments, embedded \
            thumbnails, even invisible printer-tracking dots.

            Pizzini does NOT try to clean these. The formats are too \
            varied and a "sanitized" claim that turns out to be wrong \
            would be more dangerous than no claim at all.

            If the source matters, sanitize the file on a desktop \
            before sending. Free open-source tools like mat2 \
            (metadata-anonymisation toolkit) strip most of these \
            traces. Apple Preview's "print to PDF" also removes most \
            embedded metadata.
            """

        case .blockedTypes:
            return """
            Three file types — `.mobileconfig`, `.shortcut`, `.svg` — \
            actually run code when tapped on iOS. A configuration \
            profile can change network and security settings; a \
            shortcut can run an arbitrary script; an SVG can carry \
            inline JavaScript that the system viewer executes.

            Pizzini won't let you attach these. The block lives at \
            the picker, not at a runtime check, so a determined \
            sender can't race past a confirmation.

            If you genuinely need to share one with a colleague, \
            AirDrop or email it with explicit context.
            """

        case .executableWarning:
            return """
            Files like `.exe`, `.dll`, `.bat`, or `.command` won't \
            run on iOS — they're built for Windows or macOS. But \
            people often forward attachments to colleagues on those \
            platforms.

            The red banner is a heads-up: if you save this file and \
            forward it to someone with a desktop, opening it on that \
            desktop runs whatever the file says. Treat it like an \
            email attachment from an unknown sender — assume \
            malicious until verified.
            """

        case .panicMode:
            return """
            Panic mode is OFF by default. Turn it on in Settings → \
            Panic mode. Once on, three fast taps anywhere on the chat \
            content inside an open chat instantly delete that chat. \
            Heavy haptic confirms; no dialog, no undo.

            What gets deleted: the message log for that one chat. The \
            contact stays in your list, the encryption session stays \
            intact, you can keep talking — you'll just have an empty \
            chat with them.

            What does NOT happen: your other chats, contacts, \
            identity, and relay settings are untouched. The other \
            side does NOT see a "deleted by you" marker; messages \
            they sent that you already received are gone from your \
            phone but still live on theirs.

            Why off by default: an accidental triple-tap on a chat \
            you wanted to keep would silently destroy it. The only \
            way to arm it is to read this paragraph and decide.
            """

        case .duressPasscode:
            return """
            The duress passcode is a SECOND passcode you can set in \
            Settings → Security → Set duress passcode. If someone \
            forces you to unlock Pizzini, you can enter the duress \
            passcode — it LOOKS like an unlock, but actually wipes \
            every chat, every contact, every key before the lock \
            screen drops.

            The person watching sees an empty app, indistinguishable \
            from a fresh install.

            How to use it:

            • Pick a passcode different from your real one. Six \
              characters minimum. Pick something you can type quickly \
              under pressure.
            • To enter it from the lock screen: long-press and hold \
              for about a second anywhere on the lock screen. A \
              passcode entry sheet appears. Type the duress passcode \
              and tap Unlock. The same gesture lets you enter your \
              real passcode as a Face-ID fallback.
            • After the wipe, you go through onboarding again — \
              fresh-install presentation.

            The duress feature defeats a real-time coercer who hands \
            you back your phone and demands an unlock. It is not \
            retroactive cover for prior leaks.
            """

        case .deviceIntegrity:
            return """
            Pizzini runs three lightweight checks on launch to spot \
            an obviously-compromised iOS:

            • Jailbreak indicators — files and folders that only \
              exist on a jailbroken device (Cydia, Sileo, Substrate \
              dylibs, an SSH server) and a sandbox-escape canary \
              write outside our container.
            • Debugger attachment — only flagged on release builds. \
              A development build with Xcode attached doesn't show \
              the banner.
            • Hook frameworks — loaded dynamic libraries scanned for \
              the names of common iOS hook tools (Frida, Cycript, \
              MobileSubstrate, libhooker).

            What the warning means: encryption is unaffected. Messages \
            still encrypt and decrypt correctly. What weakens is the \
            screen-capture stack — a jailbreak with a kernel-level \
            screen-recording tweak can capture frames without iOS's \
            flags noticing, which is what our shield reads.

            What the warning does NOT mean: Pizzini does not refuse \
            to run, does not phone home, and does not log who you \
            are. The detection is local-only.
            """

        case .notYetShipped:
            return """
            Pizzini is in pre-audit private beta. The protocol \
            surface, storage layer, and relay fleet are \
            feature-complete. Honest open items:

            • First paid external security audit. The protocol has \
              had an internal 32-finding remediation pass; an \
              independent firm hasn't reviewed it yet.
            • App Attest. Binds a device to its app instance so a \
              forged client can't talk to the relay. Roadmap.
            • Multi-maintainer signing on the transparency log. Today \
              one operator signs every relay release; co-signing is \
              the right shape but not built.
            • Independent relay operators. All three onions today run \
              on one provider. The multi-jurisdiction property only \
              holds with N \u{2265} 3 independent operators.
            • Post-quantum identity signature. The handshake and \
              ratchet are already PQ via libsignal; identity keys are \
              still XEd25519. A post-quantum signature scheme \
              (ML-DSA-65 or SLH-DSA-SHA2-128s) is roadmap.

            If any of these matter to your threat model, hold off — \
            the README on GitHub is the authoritative status source.
            """

        case .cryptoPrimitives,
             .tokenChains,
             .reproducibleBuilds,
             .threatModelLimits:
            return ""
        }
    }

    /// Advanced body. Nil when there's no extra detail to surface
    /// under the Advanced toggle.
    var advancedBody: String? {
        switch self {
        case .encryption:
            return """
            Key exchange uses PQXDH, combining classical X25519 with \
            the post-quantum ML-KEM-768. Ongoing messages ride the \
            Triple Ratchet: Signal's classical Double Ratchet plus \
            the SPQR post-quantum ratchet that Signal shipped in \
            October 2025. Message bytes are sealed with \
            ChaCha20-Poly1305.

            Pairwise sessions wrap each outgoing message in a \
            sealed-sender envelope: the relay can route to the \
            recipient without learning who sent it.

            libsignal is pinned at v0.93.2. See the cryptography \
            primitives section below for the full list of algorithms \
            in use.
            """

        case .qrCode:
            return """
            The URL scheme is `pizzini1://` and carries two fields: a \
            33-byte IdentityKey in hex and a `host:port` for the \
            relay endpoint. When the QR encodes the bundled fleet \
            (the default), the host field is empty — the receiving \
            phone uses its own copy of the trusted fleet.

            Encoding a BYO host into a QR you hand to a stranger \
            would pin them to your relay and narrow their anonymity \
            set, so the QR always emits the bundled-fleet sentinel \
            even when you're on a BYO relay yourself.
            """

        case .pushNotifications:
            return """
            The actual encrypted message stays in the relay's offline \
            queue and only reaches your device when the app \
            reconnects to fetch it.

            The unread badge is incremented by a small Notification \
            Service Extension that never sees plaintext — it just \
            bumps a shared counter.

            Push is optional on the relay side. If the operator \
            hasn't configured an APNs auth key, push is simply \
            disabled — Pizzini still works, you just won't be woken \
            up on incoming messages until you open the app.
            """

        case .screenCapture:
            return """
            Two pipelines, two threats.

            The screenshot mask is a Core Animation reparent of the \
            app window under a secure-text-entry container — the \
            same flag Apple uses for password fields. The SwiftUI \
            view hierarchy itself is left untouched, so VoiceOver, \
            long-press → Copy on a chat bubble, and dictation in the \
            composer all keep working. There is no toggle to disable \
            it.

            The live-recording shield is a separate flag-watcher on \
            `UIScreen.isCaptured` and the external-display \
            notifications. A self-test runs on first launch and \
            after every iOS major-version update — if it ever fails, \
            the mask isn't installed and Settings shows the \
            degraded-mode notice.

            What the mask doesn't cover: system-rendered chrome \
            (permission alerts, confirmation-dialog titles, status \
            bar), and the iOS Photo / Document Picker. The picker \
            composites into Pizzini's window but renders in a \
            separate process the secure-text-entry flag doesn't \
            reach — a screenshot taken while the picker is open \
            captures the picker's contents. Treat that screen as \
            fully visible.

            A jailbroken iOS with a kernel-level screen-recording \
            tweak bypasses both pipelines entirely.
            """

        case .relayVisibility:
            return """
            Most relay state is in memory only and is wiped on \
            restart: live route table, verify-key cache, hashcash \
            buckets, token replay set. Two pieces persist across \
            restarts under ChaCha20-Poly1305 with 0600 permissions:

            • The offline-message queue (sealed ciphertexts waiting \
              for the recipient to come online — per-peer cap, TTL \
              up to 7 days).
            • The APNs push-token map (30 days).

            Without that persistence, a relay reboot would silently \
            drop messages and break push for paired devices.

            What the at-rest encryption protects against: operator \
            mistakes — a stray `cp -r`, a forgotten tarball, a \
            careless rsync. The key file lives next to the data, so \
            it's not a defense against someone who physically seizes \
            the machine. Message content is libsignal end-to-end and \
            the relay can't read it regardless of disk-level seizure.
            """

        case .runYourOwnRelay:
            return """
            Access control is layered. Relay-address secrecy is a \
            bonus, not the lock:

            • Contact-gate. Even if a stranger reaches your relay, \
              your phone drops every inbound frame whose sender \
              isn't already in your contacts. Both sides must scan \
              each other.
            • Hashcash. First-contact bundle requests cost ~1 second \
              of CPU work — a speed bump, not a hard wall (a single \
              core can still grind out proofs in bulk). The \
              load-bearing flood control is the relay-side \
              per-recipient cap on accepted bundle requests, \
              enforced per recipient per hour and persisted across \
              relay restarts.
            • Recipient-issued hash-chain tokens. Once paired, every \
              send carries a token derived from a chain seed only \
              you and the relay know. A hostile peer cannot forge \
              one.

            There is no inter-relay federation. Both peers in a \
            conversation must be reachable through a shared relay \
            for messages to route — the bundled fleet satisfies that \
            for everyone on a default install. If your group moves \
            to a BYO relay, everyone updates Settings → Relay host \
            on the same day.
            """

        case .transparencyLog:
            return """
            Three attestation states surfaced in Settings → Relay \
            attestation:

            • Verified — the relay's running binary SHA-256 matches a \
              signed log entry.
            • Mismatch — the binary is in no signed entry (possibly \
              a tampered build).
            • Could not verify — the log fetch failed or was blocked. \
              Shown amber, not as a neutral "not loaded yet".

            The log is hosted on GitHub at \
            `raw.githubusercontent.com` and fetched over plain HTTPS \
            — NOT through Tor. This is one of two documented \
            clearnet exceptions (the other is a captive-portal probe \
            to `captive.apple.com` on stalled-bootstrap networks).

            What that leaks to GitHub / Cloudflare:

            • Your IP address.
            • The fact that you're running Pizzini.
            • The rough cadence at which you reconnect to a relay.

            What it does NOT leak: who you talk to, what you say, or \
            which relay you're using.

            Why we accept it: the end-to-end signature on each log \
            entry is what gives the log its integrity, not the \
            transport. An attacker who controls the host can only \
            delay or truncate the log, never forge an entry.

            Why this isn't routed through Tor today: the embedded \
            Tor daemon runs in "onion traffic only" mode and refuses \
            clearnet exits. Routing the log fetch through Tor would \
            require relaxing that flag, a worse trade-off than the \
            current IP leak.

            What changes this: an operator-hosted .onion mirror of \
            the log. When that ships, your phone fetches it through \
            Tor automatically — the code already detects .onion \
            hosts and routes them through the relay's Tor circuit.
            """

        case .noPreview:
            return """
            Attachment bytes never live in `PHPhotoLibrary` or the \
            iOS `Documents` folder. They land in \
            `Application Support/attachments/` with \
            `FileProtectionType.completeUntilFirstUserAuthentication` \
            and are excluded from iCloud backup at the directory \
            level. The protection class and the backup-exclusion \
            flag are re-asserted on every directory access so a \
            future refactor can't silently downgrade either.

            If you turn on "In-app preview" in Settings, Apple's \
            QuickLook service is invoked from inside Pizzini's \
            process — still sandboxed, slightly more convenient, \
            slightly less paranoid. The default is off.
            """

        case .deviceIntegrity:
            return """
            All three checks are bypassable. A determined attacker \
            with a tweak that hides their dylib name and spoofs \
            `sysctl` will not trigger any of them. We treat the \
            checks the same way we treat the screenshot-detection \
            notification: a best-effort signal we surface honestly, \
            not a security boundary.

            The check log is emitted at a debug level that release \
            iOS drops, so a coercer who reads a sysdiagnose later \
            cannot even confirm the check fired on your device.

            We deliberately do not block jailbroken devices. Some \
            users in our threat model have legitimate reasons to \
            use them (research, accessibility, privacy tooling iOS \
            won't allow). A "blocked" splash would be theatre — \
            anyone who can jailbreak can patch it out.
            """

        case .duressPasscode:
            return """
            What the duress wipe touches:

            • Every chat log (1:1 and group).
            • Every contact and every libsignal session — including \
              the long-term identity key. You'll have a new identity \
              on next launch.
            • Every received attachment file on disk, including those \
              saved to Files via Pizzini.
            • The SQLCipher database file and its WAL/SHM sidecars.
            • The Secure-Enclave wrap, the Argon2id salt, the wrapped \
              seed, and BOTH passcode slots (real and duress).
            • The APNs push token under the old identity. A new \
              token is minted when you re-register through \
              onboarding.

            What survives the wipe (deliberately, to keep the \
            empty-but-lived-in invariant):

            • The relay host you previously configured.
            • The screenshot self-test cache.

            What it does NOT cover:

            • A forensic image taken before the wipe.
            • Messages already in flight at other relays.
            • Copies of your QR photographed or sent via another app.
            """

        case .panicMode:
            return """
            The gesture only works inside an open chat. The contacts \
            list, settings, the QR sheet, and onboarding all ignore \
            it. Composer text-input also ignores it — typing \
            involves taps on the keyboard, which iOS routes \
            separately from the chat-content area.

            Modelled on the triple-tap panic gesture in Bitchat, \
            scoped per-chat rather than wiping the whole app.
            """

        case .cryptoPrimitives:
            return """
            The full list of primitives in use:

            • KEM — X25519 + ML-KEM-768 (libsignal PQXDH).
            • Ratchet — Double Ratchet + SPQR (libsignal Triple \
              Ratchet, October 2025).
            • Signature — XEd25519 and Ed25519 (identity keys, \
              delivery-token verify keys, group-op signatures, \
              transparency-log operator key). Post-quantum identity \
              signature (ML-DSA-65 or SLH-DSA-SHA2-128s) is roadmap.
            • AEAD — ChaCha20-Poly1305 for relay state files. \
              libsignal uses AES-256-GCM internally for sealed-sender \
              envelopes.
            • Hash — BLAKE3 for hashcash, group-op and \
              group-bootstrap digests, delivery-token chains, and \
              SAS digits via BLAKE3-XOF. libsignal uses SHA-256 / \
              SHA-512 internally; application code does not call \
              SHA-3 or SHAKE-256.
            • KDF — HKDF-SHA-512.
            • Password hashing — Argon2id (RustCrypto `argon2` 0.5; \
              M=64 MiB, T=3, P=1, per OWASP 2025 mobile guidance). \
              Two call sites: SQLCipher key derivation and \
              passcode-verification.

            libsignal is pinned at v0.93.2. No custom crypto, ever.
            """

        case .tokenChains:
            return """
            After pairing, you mint a 32-byte chain seed for each \
            contact and register the root with each relay in the \
            fleet. Every outgoing message derives one delivery token \
            by hashing one step along the chain (BLAKE3).

            The relay verifies that the token hash-chains back to \
            your registered root. A hostile peer cannot forge a \
            valid token without your seed, and a replayed token is \
            rejected by the relay's per-recipient replay set.

            Hashcash is layered on top for first-contact only — a \
            sender who isn't yet a chain-holder pays ~1 second of \
            CPU work per bundle request. The relay-side \
            per-recipient hourly cap is what actually bounds \
            incoming-bundle pressure; hashcash is a small speed \
            bump.
            """

        case .reproducibleBuilds:
            return """
            The relay binary is reproducible under a pinned Docker \
            toolchain (`scripts/build-relay-release.sh`):

            • `rust:1.95.0-bookworm` container, pinned by digest.
            • `cargo vendor` for offline dependency resolution.
            • `--remap-path-prefix` to strip build-host paths from \
              the binary.
            • `SOURCE_DATE_EPOCH` pinned to the source commit \
              timestamp.

            Anyone with the source can rebuild the exact same bytes \
            and verify the SHA-256 published in \
            `transparency-log.ndjson`. Each transparency-log entry \
            is signed by the operator's Ed25519 key.

            What this gets you: a relay-binary swap can't be silently \
            slipped past auditors. What it doesn't get you: \
            protection against the operator running a fork of the \
            source — the signed-binary chain only tells you "this \
            is what the operator declared they deployed", not "what \
            the operator deployed is the open-source code". Diffing \
            the source is the user's responsibility.
            """

        case .threatModelLimits:
            return """
            The threat model assumes a healthy iOS underneath. \
            Specifically:

            • A compromised iOS kernel. Pizzini's screenshot mask, \
              QR-block, and live-recording shield all rely on iOS \
              rendering and event flags. A kernel-level capture \
              tweak bypasses all of them. Encryption still holds; \
              UI defenses don't.
            • A physically seized phone. SQLCipher + Argon2id + the \
              Secure-Enclave wrap protect against an attacker who \
              has the device but no passcode. They do not protect \
              against an attacker who has the device AND coerces \
              you into entering the passcode (that's what duress \
              mode is for).
            • A camera pointed at your screen. No iOS messenger can \
              stop a second device from photographing your display.
            • Operator compromise of the relay. A malicious \
              operator sees the metadata listed in "What the relay \
              can see" — recipient IDs, timing, sizes. Content is \
              libsignal end-to-end and they can't read it. The \
              multi-jurisdiction story defends against ONE \
              compromise; not against all three operators colluding \
              (and today they're not even three operators).
            • The transparency-log fetch (one of two documented \
              clearnet exceptions). Your IP leaks to GitHub / \
              Cloudflare on every reconnect. The captive-portal \
              probe to `captive.apple.com` leaks an IP only when \
              Tor bootstrap stalls — typically a sign you're behind \
              a hotel / airport sign-in page.
            • Endpoint malware that the user installed. A \
              keylogger, screenrecorder, or modified Pizzini build \
              still sees what you type and see. Pizzini's \
              device-integrity checks try to surface obvious \
              compromise but they are detection only — see the \
              Device-integrity warnings section.

            Nothing on this list is an unsolved problem in messenger \
            design generally — they are the structural limits of \
            running on someone else's phone.
            """

        // Sections with no advanced-only detail.
        case .noPhoneNumbers,
             .wipingData,
             .mediaStripping,
             .prnu,
             .documentMetadata,
             .blockedTypes,
             .executableWarning,
             .notYetShipped:
            return nil
        }
    }
}
