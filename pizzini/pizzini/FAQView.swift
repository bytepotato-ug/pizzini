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
    case mediaStripping
    case prnu
    case documentMetadata
    case noPreview
    case blockedTypes
    case executableWarning

    var id: String { rawValue }

    var title: String {
        switch self {
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
        }
    }

    var body: String {
        switch self {
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
        }
    }
}
