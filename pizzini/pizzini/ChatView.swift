import SwiftUI
import UIKit
import QuickLook

struct ChatView: View {
    @Bindable var store: ChatStore
    let contactID: UUID

    @State private var draft = ""
    @State private var renaming = false
    @State private var renameDraft = ""
    @State private var confirmDeleteChat = false
    @State private var confirmDeleteContact = false
    @State private var showAttachSheet = false
    @State private var showPhotoPicker = false
    @State private var showDocumentPicker = false
    @State private var attachmentDraft: AttachmentDraft?
    @Environment(\.dismiss) private var dismiss

    private var contact: Contact? {
        store.state.contacts.first { $0.id == contactID }
    }

    var body: some View {
        if let contact {
            VStack(spacing: 0) {
                if !contact.sessionEstablished {
                    pairingBanner
                    Divider()
                }
                messages(for: contact)
                if let draft = attachmentDraft {
                    attachmentPreview(draft: draft)
                    Divider()
                }
                composer(disabled: !contact.sessionEstablished, contact: contact)
            }
            .navigationTitle(contact.displayName)
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { store.markRead(contactID: contactID) }
            .onDisappear { store.markRead(contactID: contactID) }
            .onChange(of: contact.log.count) { _, _ in
                store.markRead(contactID: contactID)
            }
            // NB: the `.confirmationDialog` for the paperclip lives on
            // the paperclip button itself (see `composer`) so iOS uses
            // the button as the popover anchor. Attaching it here at
            // the body level made the popover float at the top of the
            // screen with the arrow pointing nowhere.
            .sheet(isPresented: $showPhotoPicker) {
                PhotoVideoPicker(
                    onPick: { url, name in
                        showPhotoPicker = false
                        if let d = AttachmentDraft(url: url, filename: name) {
                            attachmentDraft = d
                        }
                    },
                    onCancel: { showPhotoPicker = false },
                )
            }
            .sheet(isPresented: $showDocumentPicker) {
                DocumentPicker(
                    onPick: { url, name in
                        showDocumentPicker = false
                        if let d = AttachmentDraft(url: url, filename: name) {
                            attachmentDraft = d
                        }
                    },
                    onCancel: { showDocumentPicker = false },
                )
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button {
                            renameDraft = contact.displayName
                            renaming = true
                        } label: { Label("Rename", systemImage: "pencil") }
                        Menu("Expires after") {
                            ForEach(Contact.ttlOptions, id: \.seconds) { opt in
                                Button {
                                    store.setContactTTL(contact, seconds: opt.seconds)
                                } label: {
                                    if contact.ttlSeconds == opt.seconds {
                                        Label(opt.label, systemImage: "checkmark")
                                    } else {
                                        Text(opt.label)
                                    }
                                }
                            }
                        }
                        Toggle(isOn: Binding(
                            get: { contact.readReceiptsEnabled },
                            set: { store.setReadReceipts(contact, enabled: $0) }
                        )) {
                            VStack(alignment: .leading) {
                                Text("Tell \(contact.displayName) when I read their messages")
                                Text("Off by default. Most journalists keep this off. \(contact.displayName) will see ✓✓ when their messages arrive on your phone either way.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        Button(role: .destructive) {
                            confirmDeleteChat = true
                        } label: { Label("Delete chat", systemImage: "trash") }
                        Button(role: .destructive) {
                            confirmDeleteContact = true
                        } label: { Label("Delete contact", systemImage: "person.crop.circle.badge.minus") }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .alert("Rename contact", isPresented: $renaming) {
                TextField("name", text: $renameDraft)
                    .textInputAutocapitalization(.words)
                Button("Cancel", role: .cancel) {}
                Button("Save") {
                    store.rename(contact, to: renameDraft)
                }
            }
            .confirmationDialog(
                "Delete this chat? Messages disappear; the contact stays.",
                isPresented: $confirmDeleteChat,
                titleVisibility: .visible
            ) {
                Button("Delete chat", role: .destructive) {
                    store.deleteChat(contact)
                }
                Button("Cancel", role: .cancel) {}
            }
            .confirmationDialog(
                "Delete this contact? You'll need to scan their QR again to chat.",
                isPresented: $confirmDeleteContact,
                titleVisibility: .visible
            ) {
                Button("Delete contact", role: .destructive) {
                    let captured = contact
                    dismiss()
                    store.deleteContact(captured)
                }
                Button("Cancel", role: .cancel) {}
            }
        } else {
            // Contact deleted from another path — bounce out.
            Color.clear.onAppear { dismiss() }
        }
    }

    private var pairingBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "hourglass")
                .foregroundStyle(.orange)
            Text("Waiting for them to scan you back…")
                .font(.caption)
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(Color.orange.opacity(0.10))
    }

    private func messages(for contact: Contact) -> some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 12) {
                    if contact.log.isEmpty {
                        Text(contact.sessionEstablished ? "Say hi." : "Pairing in progress.")
                            .foregroundStyle(.secondary)
                            .padding(.top, 48)
                    }
                    ForEach(contact.log) { entry in
                        ChatRow(
                            entry: entry,
                            status: rowStatus(forEntry: entry),
                            resolveURL: { info in store.attachmentURL(for: info) },
                            quickLookEnabled: store.state.quickLookPreviewEnabled,
                        ).id(entry.id)
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 12)
            }
            .onAppear {
                // Jump (no animation) to the latest message when the
                // chat opens. Animating here looks janky because the
                // ScrollView lays out mid-scroll.
                if let last = contact.log.last {
                    proxy.scrollTo(last.id, anchor: .bottom)
                }
            }
            .onChange(of: contact.log.count) { _, _ in
                if let last = contact.log.last {
                    withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
            .scrollDismissesKeyboard(.interactively)
        }
    }

    private func composer(disabled: Bool, contact: Contact) -> some View {
        HStack {
            Button {
                showAttachSheet = true
            } label: {
                Image(systemName: "paperclip")
                    .padding(.horizontal, 4)
            }
            .buttonStyle(.bordered)
            .disabled(disabled)
            .accessibilityLabel("Attach a file")
            .confirmationDialog(
                "Attach a file",
                isPresented: $showAttachSheet,
                titleVisibility: .hidden,
            ) {
                Button("Photo or video") { showPhotoPicker = true }
                Button("File") { showDocumentPicker = true }
                Button("Cancel", role: .cancel) {}
            }

            TextField(
                attachmentDraft == nil ? "type a message" : "add a caption (optional)",
                text: $draft,
            )
                .textFieldStyle(.roundedBorder)
                .submitLabel(.send)
                .disabled(disabled)
                .onSubmit { sendDraft(contact: contact) }
            Button {
                sendDraft(contact: contact)
            } label: {
                Image(systemName: "paperplane.fill")
                    .padding(.horizontal, 4)
            }
            .buttonStyle(.borderedProminent)
            .disabled(disabled || !canSend)
        }
        .padding()
    }

    /// Send is enabled if there's an attachment OR a non-blank caption.
    /// "Bare attachment with empty caption" is a perfectly valid send.
    private var canSend: Bool {
        if attachmentDraft != nil { return true }
        return !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Pre-send banner: filename + size + tier-appropriate warning. NO
    /// image preview — the brief is explicit, parser surface is the
    /// thing we're avoiding. Filename + system icon only.
    private func attachmentPreview(draft: AttachmentDraft) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Image(systemName: iconName(forTier: draft.tier))
                    .foregroundStyle(iconColor(forTier: draft.tier))
                    .font(.title2)
                VStack(alignment: .leading, spacing: 2) {
                    Text(draft.filename)
                        .font(.subheadline)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text("\(draft.displaySize) • \(tierLabel(draft.tier))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button(role: .destructive) {
                    discardAttachmentDraft()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Remove attachment")
            }
            if let warning = AttachmentCopy.attachWarning(forTier: draft.tier) {
                Text(warning)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(Color.yellow.opacity(0.15))
                    )
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 10)
        .background(Color(uiColor: .secondarySystemBackground))
    }

    private func iconName(forTier tier: AttachmentTier) -> String {
        switch tier {
        case .textFamily: return "doc.text"
        case .archive: return "doc.zipper"
        case .mediaStripAndWarn: return "photo"
        case .authorLeakingDoc: return "doc.richtext"
        case .codeOnTap: return "exclamationmark.triangle.fill"
        }
    }

    private func iconColor(forTier tier: AttachmentTier) -> Color {
        switch tier {
        case .codeOnTap: return .red
        case .mediaStripAndWarn, .authorLeakingDoc: return .orange
        default: return .secondary
        }
    }

    private func tierLabel(_ tier: AttachmentTier) -> String {
        switch tier {
        case .textFamily: return "text"
        case .archive: return "archive"
        case .mediaStripAndWarn: return "media"
        case .authorLeakingDoc: return "document"
        case .codeOnTap: return "executable"
        }
    }

    private func discardAttachmentDraft() {
        if let url = attachmentDraft?.url {
            try? FileManager.default.removeItem(at: url)
        }
        attachmentDraft = nil
    }

    /// Resolve the right OutboxEntry.Status for a chat row. Plain chat
    /// rows look up by their own messageId; attachment rows roll up
    /// across all chunks via OutboxStore.attachmentStatus(forId:).
    private func rowStatus(forEntry entry: PersistedMessage) -> OutboxEntry.Status? {
        if entry.kind == .attachment, let aid = entry.attachment?.attachmentId {
            return store.outbox.attachmentStatus(forId: aid)
        }
        return entry.messageId.flatMap { store.outboxEntry(forMessageId: $0)?.status }
    }

    private func sendDraft(contact: Contact) {
        // Two paths share this entrypoint: bare-text and attachment+
        // optional-caption. The latter sends one chunked attachment
        // logical message; the caption (if any) is currently embedded
        // as the row's text (sender-side rendering only — receiver gets
        // the attachment row with no caption). A future task can lift
        // the caption into a paired sealed `.chat` envelope so the
        // receiver also sees it; flagged for the maintainer.
        let captionText = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        if let pending = attachmentDraft {
            store.sendFile(pending.url, to: contact, caption: captionText)
            try? FileManager.default.removeItem(at: pending.url)
            attachmentDraft = nil
            draft = ""
            return
        }
        guard !captionText.isEmpty else { return }
        store.send(draft, to: contact)
        draft = ""
    }
}

struct ChatRow: View {
    let entry: PersistedMessage
    let status: OutboxEntry.Status?
    /// Resolves an inbound attachment's sandbox-relative path back to a
    /// concrete URL. Closure rather than direct ChatStore access so the
    /// row stays cheap to construct in tests / previews.
    let resolveURL: (AttachmentInfo) -> URL?
    /// Honours the user's `quickLookPreviewEnabled` setting — when true
    /// AND the row is an inbound attachment, we render a Preview button
    /// that opens QLPreviewController in addition to Save to Files.
    let quickLookEnabled: Bool

    init(
        entry: PersistedMessage,
        status: OutboxEntry.Status? = nil,
        resolveURL: @escaping (AttachmentInfo) -> URL? = { _ in nil },
        quickLookEnabled: Bool = false
    ) {
        self.entry = entry
        self.status = status
        self.resolveURL = resolveURL
        self.quickLookEnabled = quickLookEnabled
    }

    var body: some View {
        HStack(alignment: .bottom) {
            // Standard chat-app convention: my messages on the right,
            // peer's on the left. Spacer goes BEFORE my row's content
            // (pushing it right) and AFTER the peer's (leaving it
            // anchored to the leading edge).
            if entry.side == .me { Spacer(minLength: 32) }
            VStack(alignment: entry.side == .me ? .trailing : .leading, spacing: 4) {
                if entry.kind == .attachment, let info = entry.attachment {
                    AttachmentRowCard(
                        info: info,
                        side: entry.side,
                        bubbleColor: bubbleColor,
                        resolveURL: resolveURL,
                        captionText: entry.text,
                        quickLookEnabled: quickLookEnabled,
                    )
                } else {
                    Text(entry.text)
                        .font(.body)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(bubbleColor)
                        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                }
                metadata
            }
            if entry.side == .peer { Spacer(minLength: 32) }
        }
    }

    private var bubbleColor: Color {
        switch entry.kind {
        case .system: return Color.gray.opacity(0.15)
        case .preKey, .whisper, .attachment:
            return entry.side == .me
                ? Color.blue.opacity(0.18)
                : Color.green.opacity(0.18)
        }
    }

    private var metadata: some View {
        // System rows (e.g. "Session not established yet…") get no
        // metadata — they're the chat layer talking to itself, not a
        // sent message.
        HStack(spacing: 6) {
            if entry.kind != .system {
                Text(timestampText)
                    .foregroundStyle(.secondary)
            }
            if entry.side == .me, let status, entry.kind != .system {
                statusIcon(status)
                if entry.readAt != nil, status == .delivered {
                    Text("Read").foregroundStyle(.blue)
                }
            }
        }
        .font(.caption2)
    }

    private var timestampText: String {
        entry.timestamp.formatted(date: .omitted, time: .shortened)
    }

    // Glyphs match the explainer in OnboardingView's `.icons` step —
    // change one place and you change the other, otherwise the legend
    // and the live UI drift apart.
    @ViewBuilder
    private func statusIcon(_ status: OutboxEntry.Status) -> some View {
        switch status {
        case .pending:
            Text("⏳").help("Queued — waiting for the connection")
        case .relayed:
            Text("✓").foregroundStyle(.secondary).help("Sent")
        case .delivered:
            Text("✓✓").foregroundStyle(.blue).help("Delivered to their phone")
        case .failed:
            Text("✗").foregroundStyle(.red).help("Expired before reaching them")
        }
    }
}

/// Card view for an attachment chat row. Renders filename + size + an
/// icon (NEVER a thumbnail — see Pegasus 2021 / "no in-app preview"
/// hard rule), tier-appropriate warning banner, and either a Save-to-
/// Files button (inbound) or a status hint (outbound — the file came
/// from the user's own picker, no need to save it again).
struct AttachmentRowCard: View {
    let info: AttachmentInfo
    let side: ChatBubbleSide
    let bubbleColor: Color
    let resolveURL: (AttachmentInfo) -> URL?
    let captionText: String
    /// User's `quickLookPreviewEnabled` setting — when true AND this is
    /// an inbound row, we render a Preview button that pops
    /// QLPreviewController. Default false (strict mode).
    let quickLookEnabled: Bool

    @State private var presentingShare = false
    @State private var presentingPreview = false

    init(
        info: AttachmentInfo,
        side: ChatBubbleSide,
        bubbleColor: Color,
        resolveURL: @escaping (AttachmentInfo) -> URL?,
        captionText: String,
        quickLookEnabled: Bool = false
    ) {
        self.info = info
        self.side = side
        self.bubbleColor = bubbleColor
        self.resolveURL = resolveURL
        self.captionText = captionText
        self.quickLookEnabled = quickLookEnabled
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundStyle(iconColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text(info.filename)
                        .font(.subheadline.weight(.medium))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(sizeText)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            if !captionText.isEmpty {
                Text(captionText)
                    .font(.callout)
            }
            // Receive-side banner only on inbound rows — the sender
            // already saw the attach-time warning at compose time, no
            // value re-litigating it on the outbound row.
            if info.isInbound, let banner = receiveBanner {
                bannerView(banner)
            }
            // Save-to-Files / Preview show on BOTH sides as long as
            // the sandbox copy still exists. The cleanup pass GCs
            // outbound copies after the 7-day TTL same as inbound;
            // post-cleanup the row stays as a chat record but the
            // bytes are gone, and `resolveURL` will return nil.
            if resolveURL(info) != nil {
                HStack(spacing: 8) {
                    saveToFilesButton
                    if quickLookEnabled {
                        previewButton
                    }
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(bubbleColor)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .quickLookPreview(
            $presentingPreview,
            url: resolveURL(info),
        )
    }

    /// In-app preview via `QLPreviewController`. The actual rendering
    /// runs in QuickLook's XPC service, NOT in Pizzini's process —
    /// same as Save-to-Files-then-tap. The integration surface here
    /// is wider than strict mode (we hand QuickLook a file URL), but
    /// the bytes still aren't parsed by us.
    private var previewButton: some View {
        Button {
            presentingPreview = true
        } label: {
            Label("Preview", systemImage: "eye")
                .font(.callout)
        }
        .buttonStyle(.bordered)
    }

    private var icon: String {
        switch info.tier {
        case .textFamily: return "doc.text"
        case .archive: return "doc.zipper"
        case .mediaStripAndWarn: return "photo"
        case .authorLeakingDoc: return "doc.richtext"
        case .codeOnTap: return "exclamationmark.triangle.fill"
        }
    }
    private var iconColor: Color {
        if AttachmentTierClassifier.isDesktopExecutable(filename: info.filename) {
            return .red
        }
        switch info.tier {
        case .codeOnTap: return .red
        case .mediaStripAndWarn, .authorLeakingDoc: return .orange
        default: return .secondary
        }
    }

    private var sizeText: String {
        let bcf = ByteCountFormatter()
        bcf.allowedUnits = [.useKB, .useMB, .useGB]
        bcf.countStyle = .file
        return bcf.string(fromByteCount: Int64(info.byteSize))
    }

    private var receiveBanner: AttachmentCopy.ReceiveBanner? {
        AttachmentCopy.receiveWarning(
            forTier: info.tier,
            isDesktopExecutable: AttachmentTierClassifier
                .isDesktopExecutable(filename: info.filename),
        )
    }

    @ViewBuilder
    private func bannerView(_ banner: AttachmentCopy.ReceiveBanner) -> some View {
        let bg: Color = banner.tone == .danger
            ? Color.red.opacity(0.18) : Color.yellow.opacity(0.18)
        let icon = banner.tone == .danger ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill"
        let fg: Color = banner.tone == .danger ? .red : .orange
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: icon).foregroundStyle(fg)
            Text(banner.text).font(.caption2)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous).fill(bg)
        )
    }

    /// Save-to-Files button. Resolves the sandbox URL on tap and
    /// presents `UIDocumentInteractionController.presentOptionsMenu`
    /// — that's the standard iOS surface that includes "Save to
    /// Files" and "Open in…" without opening the bytes in-app. We
    /// deliberately do NOT use Quick Look (in-app preview = parser
    /// surface) and do NOT auto-open.
    private var saveToFilesButton: some View {
        Button {
            presentingShare = true
        } label: {
            Label("Save to Files", systemImage: "square.and.arrow.down")
                .font(.callout)
        }
        .buttonStyle(.bordered)
        .background(
            DocumentInteractionPresenter(
                isPresented: $presentingShare,
                url: resolveURL(info),
            )
        )
    }
}

/// SwiftUI modifier that presents `QLPreviewController` for an
/// optional URL, gated on a binding. `View.quickLookPreview(_:url:)`
/// is shipped by Apple but takes a non-optional `URL` (or expects you
/// to use the `[URL]` form) — and our resolver may legitimately return
/// nil if the sandbox copy was already GC'd post-TTL. Wrap with our
/// own modifier so a nil URL is a no-op rather than a crash.
extension View {
    fileprivate func quickLookPreview(
        _ isPresented: Binding<Bool>,
        url: URL?
    ) -> some View {
        sheet(isPresented: isPresented) {
            if let url {
                QLPreviewWrapper(url: url) {
                    isPresented.wrappedValue = false
                }
                .ignoresSafeArea()
            } else {
                Text("Attachment is no longer available on this device.")
                    .padding()
            }
        }
    }
}

private struct QLPreviewWrapper: UIViewControllerRepresentable {
    let url: URL
    let onDismiss: () -> Void

    func makeUIViewController(context: Context) -> UINavigationController {
        let preview = QLPreviewController()
        preview.dataSource = context.coordinator
        preview.delegate = context.coordinator
        let nav = UINavigationController(rootViewController: preview)
        return nav
    }

    func updateUIViewController(_ uiViewController: UINavigationController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(url: url, onDismiss: onDismiss) }

    final class Coordinator: NSObject, QLPreviewControllerDataSource, QLPreviewControllerDelegate {
        let url: URL
        let onDismiss: () -> Void
        init(url: URL, onDismiss: @escaping () -> Void) {
            self.url = url
            self.onDismiss = onDismiss
        }

        func numberOfPreviewItems(in controller: QLPreviewController) -> Int { 1 }
        func previewController(_ controller: QLPreviewController, previewItemAt index: Int) -> QLPreviewItem {
            url as NSURL
        }
        func previewControllerDidDismiss(_ controller: QLPreviewController) {
            onDismiss()
        }
    }
}

/// Bridges `UIDocumentInteractionController` into SwiftUI. Triggered by
/// flipping `isPresented` to true; the controller calls back to clear
/// the binding when dismissed. The brief specifies this controller
/// rather than ShareLink/UIActivityViewController so the user surface
/// is the focused "Save to Files / Open in…" menu rather than a
/// full share sheet.
struct DocumentInteractionPresenter: UIViewControllerRepresentable {
    @Binding var isPresented: Bool
    let url: URL?

    func makeUIViewController(context: Context) -> UIViewController {
        UIViewController()
    }

    func updateUIViewController(_ uiViewController: UIViewController, context: Context) {
        guard isPresented, let url, uiViewController.view.window != nil else { return }
        let controller = UIDocumentInteractionController(url: url)
        controller.delegate = context.coordinator
        context.coordinator.controller = controller
        let presented = controller.presentOptionsMenu(
            from: uiViewController.view.bounds,
            in: uiViewController.view,
            animated: true,
        )
        // If iOS refused the menu (no apps registered for this UTI),
        // fall back to the standard preview-options sheet so the user
        // can still pick "Save to Files".
        if !presented {
            _ = controller.presentPreview(animated: true)
        }
        DispatchQueue.main.async {
            isPresented = false
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator: NSObject, UIDocumentInteractionControllerDelegate {
        var controller: UIDocumentInteractionController?
        func documentInteractionControllerViewControllerForPreview(
            _ controller: UIDocumentInteractionController
        ) -> UIViewController {
            // Walk up to the key window's root — UIDocumentInteractionController
            // needs a presenting VC for its preview path even though we
            // primarily use presentOptionsMenu.
            let scene = UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .first(where: { $0.activationState == .foregroundActive })
            return scene?.windows.first(where: { $0.isKeyWindow })?
                .rootViewController ?? UIViewController()
        }
    }
}
