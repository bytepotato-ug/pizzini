import SwiftUI

/// In-app FAQ. Reached from:
///   - Settings → Help → FAQ
///   - The (i) button on an attachment row's warning banner — those
///     deep-link via `initialSection` so the user lands on the
///     specific topic.
///
/// Content is intentionally short and concrete. Each section has a
/// stable enum case so banner copy can deep-link without string
/// matching, and so a future translation pass can swap strings
/// without touching the routing.
/// Modal-presentation wrapper. Used when (i) info buttons on banners
/// deep-link into a specific section — wraps `FAQContent` in a
/// NavigationStack with a Done button.
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

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    ForEach(FAQSection.allCases) { section in
                        VStack(alignment: .leading, spacing: 10) {
                            Text(section.title)
                                .font(.title3.weight(.semibold))
                            Text(section.body)
                                .font(.body)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .id(section)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 16)
            }
            .onAppear {
                guard let s = initialSection else { return }
                // Defer one runloop so layout settles before we
                // scroll — without this the scroll fires while the
                // ScrollView is still computing offsets.
                DispatchQueue.main.async {
                    withAnimation(.easeInOut(duration: 0.25)) {
                        proxy.scrollTo(s, anchor: .top)
                    }
                }
            }
        }
    }
}

/// Stable identifiers for each FAQ topic. Used both as the in-page
/// anchor (`ScrollViewReader.scrollTo`) and as the deep-link target
/// from attachment banners.
enum FAQSection: String, CaseIterable, Identifiable, Hashable, Sendable {
    case encryption
    case relayVisibility
    case runYourOwnRelay
    case qrCode
    case screenCapture
    case deviceIntegrity
    case noPhoneNumbers
    case pushNotifications
    case mediaStripping
    case prnu
    case documentMetadata
    case noPreview
    case blockedTypes
    case executableWarning
    case wipingData
    case notYetShipped

    var id: String { rawValue }

    var title: String {
        switch self {
        case .encryption:
            return "How Pizzini encrypts messages"
        case .relayVisibility:
            return "What the relay sees (and doesn’t see)"
        case .runYourOwnRelay:
            return "Running your own relay (or using someone else’s)"
        case .qrCode:
            return "What’s in your QR code"
        case .screenCapture:
            return "Screenshots, screen recording, and AirPlay"
        case .deviceIntegrity:
            return "Device integrity warnings"
        case .noPhoneNumbers:
            return "Why no phone numbers"
        case .pushNotifications:
            return "How push notifications work without leaking content"
        case .mediaStripping:
            return "What Pizzini removes from images and videos"
        case .prnu:
            return "About the “sensor fingerprint” warning"
        case .documentMetadata:
            return "Why documents can still leak who you are"
        case .noPreview:
            return "Why Pizzini doesn’t preview files inline"
        case .blockedTypes:
            return "Why some file types are blocked from sending"
        case .executableWarning:
            return "Files marked “executable” on receive"
        case .wipingData:
            return "What each delete option does"
        case .notYetShipped:
            return "What Pizzini doesn’t do yet"
        }
    }

    var body: String {
        switch self {
        case .encryption:
            return """
            Pizzini uses Signal’s open-source libsignal library \
            (pinned at v0.93.2). It handles every cryptographic step; \
            Pizzini does not invent its own crypto.

            Initial key exchange uses PQXDH, which combines classical \
            X25519 with the post-quantum ML-KEM-768. Ongoing messages \
            ride libsignal’s Triple Ratchet (the classical Double \
            Ratchet plus the SPQR post-quantum ratchet that Signal \
            shipped in October 2025). The actual message bytes are \
            sealed with ChaCha20-Poly1305.

            Pairwise sessions are also wrapped in a “sealed sender” \
            envelope — that means the relay can route a message to its \
            recipient without learning who sent it.
            """
        case .relayVisibility:
            return """
            The relay is what shuttles ciphertext from your phone to \
            your contact’s phone. To do its job it sees:

            • the recipient’s peer-id (so it knows where to forward)
            • the sealed-envelope bytes (encrypted; it can’t decrypt)
            • the IP address of any device that connects to it
            • frame sizes and timing

            It does NOT see:

            • the sender’s peer-id (sealed sender hides it)
            • message text or attachment content
            • your contacts list
            • anything across restarts — the relay is stateless, \
              has no user accounts, and keeps everything in RAM only

            Offline messages sit in an in-memory queue (capped at 100 \
            frames per peer, with a sender-chosen TTL up to 7 days). A \
            relay restart wipes the queue.

            Today’s default relay is a dev build over plain TCP on \
            your LAN. Production deployment over Tor onion services is \
            still on the roadmap (see “What Pizzini doesn’t do yet”).
            """
        case .runYourOwnRelay:
            return """
            The relay’s source code lives in this repository under \
            AGPL-3.0. Anyone can run one — no licensing fee, no tokens, \
            no vendor.

            To self-host:

            • Build with `cargo build -p pizzini-relay --release`.
            • Run on any machine your peers can reach over the network \
              (a VPS, a Pi at home, a Tor onion service if you set one \
              up). It binds TCP on port 7777.
            • Each phone in your group enters the relay’s address in \
              Settings → Relay host.

            Outsiders who don’t know your relay’s address can’t \
            connect to it. That said, address secrecy is bonus — not \
            the primary lock. The actual access control is layered:

            • Contact-gate. Even if a stranger reaches your relay, \
              your phone drops every inbound frame whose sender isn’t \
              already in your contacts. Both sides must scan each \
              other.
            • Hashcash. First-contact bundle requests cost ~1 second \
              of CPU work. Trivial on a phone, expensive in bulk.
            • Recipient-issued delivery tokens. Once you’ve paired, \
              your contact gets a batch of 1024 tokens minted by you, \
              one per send/ack. They burn out a hostile peer fast.

            Together these mean a leaked relay address is annoying \
            (your friends might switch) but not catastrophic — \
            strangers still cannot send you anything.

            What if I don’t want to run my own?

            Today: there is no centrally-operated production Pizzini \
            relay. The app starts pointing at 127.0.0.1, which only \
            works in the simulator. On a real phone you have to type \
            in the address of whichever relay your community is \
            running.

            Roadmap: the README plans stateless relays in multiple \
            jurisdictions, deployed initially in Switzerland, Iceland, \
            and Panama, reachable over Tor onion services rather than \
            clearnet IPs. Combined with the post-audit “multi-relay \
            client fanout” feature, an app would be able to try \
            several relays in parallel so a single one going offline \
            wouldn’t take your group offline. None of that \
            infrastructure is live yet; production rollout is queued \
            behind the first external audit.

            Today’s constraint to keep in mind: there is no \
            inter-relay federation. Both peers in a conversation must \
            connect to the same relay instance for messages to route. \
            If your group changes relays, everyone updates Settings → \
            Relay host on the same day.
            """
        case .qrCode:
            return """
            Your QR code encodes a `pizzini1://` URL with two pieces:

            • your 33-byte IdentityKey (peer-id), in hex
            • the relay endpoint (host : port) that contacts should \
              reach you through

            That’s it. No name, no contact list, no message history.

            However, a photograph of the QR — even from across a room, \
            a security camera, or a window — links a face to that \
            peer-id and identifies you on the network. That’s why the \
            in-app QR sheet stays hidden behind an explicit “Tap to \
            reveal” gesture and re-hides as soon as you switch away \
            from the app. Sharing the QR via screenshot, AirDrop, or \
            any other app carries the same risk; treat it as you would \
            handing someone a printed copy.
            """
        case .screenCapture:
            return """
            iOS does not let any app fully prevent screenshots. That’s \
            an Apple policy decision, and Pizzini cannot opt out of it. \
            What we can do, and do, is detect captures and adjust:

            • Screenshots are detected after the fact. When you \
              screenshot inside a chat, Pizzini appends a system row \
              that records it. iOS never gives the app the captured \
              image, only the notification.
            • Screen recording (the Control Centre Record button), \
              AirPlay mirroring, and Apple-cable mirroring all flip an \
              "is captured" flag we can read live. Whenever it’s on, \
              Pizzini swaps your chats, contacts, settings, and QR \
              sheet for an opaque cover. The toolbar stays interactive \
              so you can navigate out without seeing what was on \
              screen.
            • External-display attaches (a TV via cable, an iPad with \
              a connected monitor) trigger the same cover. AirPlay \
              mirroring counts because iOS reports the AirPlay receiver \
              as a connected display.

            Optional: "Tell my contact when I screenshot." Off by \
            default. Most people screenshot for legitimate reasons — \
            saving important text, copying a link to themselves — and \
            we don’t think the app should default to broadcasting that. \
            Turn it on and your contact sees a system row in their \
            copy of the chat when you screenshot one of their messages. \
            They cannot disable it on their end; if you don’t want them \
            to know, leave this off.

            The QR sheet — your one-photo deanonymisation surface — \
            uses an extra technique. The rendered QR is wrapped in an \
            iOS secure-text-entry container, which the screenshot \
            pipeline historically renders blank. This is not a \
            documented API and Apple has been narrowing the technique \
            in recent iOS releases. Pizzini runs a self-test on first \
            launch and after every iOS major-version change to confirm \
            the technique still works on your device; if it fails, the \
            QR sheet silently falls back to the standard cover, and \
            Settings → App lock will tell you. Either way the sheet \
            still opens hidden behind a "Tap to reveal" gesture and \
            re-hides whenever the app deactivates.

            The same technique is available for chat bubbles via \
            Settings → App lock → "Block screenshots of chats". It is \
            off by default because the cost is real: long-press → Copy \
            on a message stops working, and VoiceOver inside the chat \
            is degraded. Turn it on only if you understand and accept \
            those costs in exchange for the additional masking. The \
            same self-test gates this toggle: if the technique fails \
            on your iOS version, turning the toggle on has no effect.

            What none of this defends against:

            • A second camera pointed at your screen. Nothing in iOS \
              can stop another phone from photographing your display.
            • A device whose iOS has been compromised at the kernel \
              level by an unrelated vulnerability. Pizzini’s threat \
              model assumes a healthy iOS underneath.
            • Jailbroken devices with screen-recording rootkits. We \
              detect what iOS tells us; a kernel-level capture \
              bypasses iOS entirely.

            For the highest-risk situations the safest practice is to \
            take the conversation to a place where no screen exists \
            in the first place: hand-to-hand, in person.
            """
        case .deviceIntegrity:
            return """
            Pizzini runs three lightweight checks on launch to spot \
            an obviously-compromised iOS environment:

            • Jailbreak indicators — files and folders that only \
              exist on a jailbroken device (Cydia, Sileo, Substrate \
              dylibs, /private/var/lib/apt, an SSH server) and a \
              sandbox-escape canary write outside our container.
            • Debugger attachment — `sysctl(KERN_PROC)` reports the \
              `P_TRACED` flag when a debugger is attached. We only \
              surface this warning on release builds; a development \
              build with Xcode attached doesn't show the banner.
            • Hook frameworks — Pizzini scans the loaded dynamic \
              libraries and looks for the names of common iOS hook \
              tools (Frida, Cycript, MobileSubstrate, libhooker).

            What the warning means in practice: the encryption is \
            unaffected. Messages still encrypt and decrypt correctly, \
            keys still live in the Secure Enclave-backed Keychain, \
            and the relay still cannot read them. What weakens is \
            the screen-capture stack: a jailbreak with a kernel-level \
            screen-recording tweak can capture frames without \
            triggering iOS's `UIScreen.isCaptured` flag, which is \
            what our shield reads. The QR-block technique relies on \
            iOS rendering secure-text-entry containers as blank — a \
            jailbroken iOS may have that disabled.

            What the warning does NOT mean: Pizzini does not refuse \
            to run, does not phone home, and does not log who you \
            are. The detection is local-only; it goes to the system \
            log for forensic review and to this banner. We \
            deliberately do not block jailbroken devices because some \
            users in our threat model use jailbroken phones for good \
            reasons (research, accessibility, privacy tooling iOS \
            won't allow), and a "blocked" splash is theatre — anyone \
            who can jailbreak can patch the splash out.

            All three checks are bypassable. A determined attacker \
            with a tweak that hides their dylib name and spoofs \
            `sysctl` will not trigger any of them. We treat the \
            checks the same way we treat the screenshot-detection \
            notification: a best-effort signal we surface to you \
            honestly, not a security boundary.
            """
        case .noPhoneNumbers:
            return """
            Pizzini addresses are random IdentityKey-based peer-ids. \
            There is no central directory mapping numbers to accounts \
            and no signup flow that asks for one.

            What that gets you:

            • Nothing to subpoena from a phone carrier.
            • SIM-swap attacks against your account are not possible — \
              there’s no number to redirect.
            • Recycled numbers can’t inherit access to a previous \
              owner’s chats.
            • Pairing happens in person via QR scan, so the choice of \
              who is in your contacts list is entirely yours.

            Both peers must scan each other for chat to unlock — a \
            one-way scan does not establish a session.
            """
        case .pushNotifications:
            return """
            When a message arrives while you’re offline, the relay can \
            ask Apple’s Push Notification Service to wake your phone. \
            The push payload Pizzini sends is the literal string \
            “New message”. That’s it — no sender name, no content \
            preview, no peer-id.

            Why so spartan: iOS keeps incoming notifications in a \
            system-wide database that forensic-extraction tools can \
            read. Anything in the payload sits there in cleartext. The \
            actual encrypted message stays in the relay’s ephemeral \
            queue and only reaches your device when the app reconnects.

            The unread badge on the app icon is updated by a small \
            Notification Service Extension that increments a shared \
            counter — it never decrypts the message either.

            Push is optional on the relay side. If the operator hasn’t \
            configured an APNs auth key, push is simply disabled.
            """
        case .mediaStripping:
            return """
            Before any image or video leaves your phone, Pizzini removes \
            its embedded metadata — GPS coordinates, capture timestamp, \
            camera make / model / serial number, software version, and \
            edit history. You don’t need to do anything; this happens \
            automatically every time you send media.

            What Pizzini does NOT do is alter the actual pixels. The \
            image looks the same on the other side as it did on yours.
            """
        case .prnu:
            return """
            Every camera’s image sensor has tiny manufacturing variations \
            that imprint a unique, faint noise pattern into every photo \
            it takes. Researchers call this PRNU (Photo Response \
            Non-Uniformity). It’s invisible to the eye but is the same \
            for every photo from the same physical camera.

            With access to several photos from your camera (e.g. ones \
            you’ve posted publicly), an analyst can match a leaked \
            photo back to your specific device. Removing metadata does \
            not remove this fingerprint, and Pizzini deliberately does \
            not try to scrub it: published research shows that \
            anti-PRNU filters are detectable, and a photo that looks \
            “anonymized” can become evidence on its own.

            For ordinary chats this almost never matters. For high-risk \
            material — leaks where the camera identity could expose \
            you — the safest practice is to take the photo on a device \
            that isn’t linked to you (a borrowed phone, a disposable \
            camera) rather than to try to scrub the photo afterwards.
            """
        case .documentMetadata:
            return """
            PDFs, Word, Excel, PowerPoint, ePub, and similar files can \
            carry information that isn’t visible when you open them: \
            the author name, the originating computer or printer, \
            tracked-changes history, comments, embedded thumbnails, \
            even invisible printer-tracking dot patterns.

            Pizzini does not try to clean these — the formats are too \
            varied and a “sanitized” claim that turns out to be wrong \
            would be more dangerous than no claim at all.

            If the source matters, sanitize the file on a desktop \
            before sending. Free open-source tools like mat2 \
            (metadata-anonymisation toolkit) can strip most of these \
            traces. Apple Preview can also be used to print a PDF to \
            a fresh PDF, which removes most embedded metadata.
            """
        case .noPreview:
            return """
            Pizzini never renders a received file inside the app. You \
            see the filename, the size, and a button to save it.

            This rule exists because of attacks like Pegasus (2021), \
            where a maliciously-crafted image was enough to take over \
            an iPhone the moment iMessage previewed it — the victim \
            never tapped anything. Any code that parses incoming bytes \
            is a potential exploit surface, so we run zero of it.

            When you tap “Save to Files”, the bytes are handed off to \
            iOS. From that point Apple’s own services (Photos, \
            QuickLook) handle decoding inside their sandboxed \
            processes. If you turn on “In-app preview” in Settings, \
            the same Apple service is invoked from inside the app — \
            still sandboxed, slightly more convenient, slightly less \
            paranoid.
            """
        case .blockedTypes:
            return """
            A few file types — `.mobileconfig`, `.shortcut`, `.svg` — \
            actually run code when tapped on iOS. A configuration \
            profile can change network and security settings; a \
            shortcut can run an arbitrary script; an SVG can carry \
            inline JavaScript that the system viewer executes.

            Pizzini won’t let you attach these. The block lives at the \
            picker level, not at a runtime check, so a determined \
            sender can’t race past a confirmation. If you genuinely \
            need to share one with a colleague, AirDrop or e-mail it \
            with explicit context.
            """
        case .executableWarning:
            return """
            Files like `.exe`, `.dll`, `.bat`, or `.command` won’t run \
            on iOS — they’re built for Windows or macOS. But \
            journalists, researchers, and analysts often forward \
            attachments to colleagues on those platforms.

            The red banner is a heads-up: if you save this file and \
            forward it to someone with a desktop, opening it on that \
            desktop runs whatever the file says. Treat it like an \
            email attachment from an unknown sender — assume malicious \
            until verified.
            """
        case .wipingData:
            return """
            Pizzini gives you four levels of delete:

            • Delete chat (per-contact ⋯ menu): wipes that contact’s \
              message log only. The pairing and the libsignal session \
              stay; you can keep chatting.
            • Delete contact (per-contact ⋯ menu): drops the contact \
              row and the encryption session. To talk again you both \
              need to re-scan.
            • Delete all chats (Settings → Advanced): wipes every \
              contact’s message log at once. Contacts and sessions \
              stay.
            • Reset identity (Settings → Advanced): generates a fresh \
              keypair and wipes contacts, sessions, and message logs. \
              Everyone you talk to needs to scan you again. Your \
              relay host, app-lock setting, auto-lock timeout, and \
              onboarding state are kept — those aren’t identity-derived.

            None of these actions are recoverable. There is no \
            “undelete”.
            """
        case .notYetShipped:
            return """
            Pizzini is in active development. A few things are not \
            yet ready and the README tracks them as open:

            • Production Tor onion service for the relay (the current \
              relay binds to plain TCP on your LAN — fine for testing, \
              not yet what you’d use on the real internet).
            • SQLCipher-backed storage. Your contacts, chats, and \
              outbox currently sit in iOS Keychain JSON, which works \
              for daily use but isn’t designed for very large or \
              long-offline message logs.
            • Duress passphrase + cryptographic erasure (a separate \
              passphrase that wipes everything when entered).
            • App Attest + ATS-strict transport policy.
            • Reproducible build script.
            • First independent security audit.
            • Multi-relay client fanout (sending the same message to \
              multiple jurisdictions in parallel for resilience).

            If any of these matter to your threat model, hold off — \
            the project README and the GitHub status section are the \
            authoritative source of progress.
            """
        }
    }
}
