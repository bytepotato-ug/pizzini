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
    case qrCode
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
        case .qrCode:
            return "What’s in your QR code"
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
