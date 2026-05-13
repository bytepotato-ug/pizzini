import SwiftUI

/// Single docked composer used by both `ChatView` and `GroupChatView`.
///
/// Layout:
///
///   ┌──────────────────────────────────────────────────────┐
///   │ 📎 │ ╭───── input field ──────╮ │ ↑ │                │
///   │    │ ╰────────────────────────╯ │   │                │
///   └──────────────────────────────────────────────────────┘
///     ↑       ↑                          ↑
///     │       │                          └ Send: white arrow in
///     │       │                            #005bfd filled circle.
///     │       │                            Disabled → 40% alpha.
///     │       └ TextField with a continuous rounded-rect
///     │         (cornerRadius 20) on `.secondarySystemBackground`,
///     │         hairline `.separator` overlay. Grows vertically up
///     │         to 6 lines; the rounded surface stays well-shaped
///     │         because we use `RoundedRectangle`, not `Capsule`
///     │         (the latter goes elliptical when the field gets
///     │         tall, which looks broken on multi-line drafts).
///     └ Attachment: #005bfd `paperclip` glyph on a transparent
///       background — the brand colour does the work of saying "tap
///       me", no chrome required.
///
/// The composer sits inside each view's `.safeAreaInset(.bottom)`
/// VStack which carries the shared `.bar` background; this view
/// deliberately adds no background of its own.
///
/// Why factor it out: ChatView and GroupChatView had nearly-identical
/// inline composers that drifted on padding, send icon, and button
/// style. A single shared component is the canonical surface and
/// removes the drift surface.
// Generic over the dialog body so call-sites can hand us any
// ViewBuilder content (`Button("Photo")`, `Button("File")`, …)
// without us boxing it into AnyView.
struct MessageComposer<AttachContent: View>: View {
    @Binding var draft: String
    @Binding var showAttachSheet: Bool
    let placeholder: String
    /// Disables the whole composer (e.g. 1:1 chat with an unestablished
    /// session, or a group the user is no longer a member of).
    /// Distinct from `sendDisabled` so the user can still TYPE a draft
    /// while waiting for the session to settle — only Send is
    /// uninvocable. When this is true the attachment trigger is
    /// disabled too.
    let composerDisabled: Bool
    /// Set when the draft is empty AND there's no pending attachment.
    /// Greys out the send button (40% alpha) without changing the
    /// composer's shape — the user gets a stable target for muscle
    /// memory regardless of state.
    let sendDisabled: Bool
    let onSend: () -> Void
    /// `confirmationDialog` body — call-sites pass their photo /
    /// document / cancel buttons. The dialog anchors to the
    /// `showAttachSheet` binding so iOS uses the paperclip as the
    /// popover anchor on iPad without us having to plumb a separate
    /// anchor view.
    @ViewBuilder var attachDialog: () -> AttachContent

    @FocusState.Binding var focused: Bool

    var body: some View {
        HStack(alignment: .bottom, spacing: 10) {
            attachButton
            inputField
            sendButton
        }
        .padding(.horizontal, 12)
        .padding(.top, 8)
        .padding(.bottom, 8)
    }

    private var attachButton: some View {
        Button {
            showAttachSheet = true
        } label: {
            Image(systemName: "paperclip")
                .font(.system(size: 20, weight: .regular))
                .foregroundStyle(Color.accentColor)
                .frame(width: 36, height: 36)
        }
        .buttonStyle(.plain)
        .disabled(composerDisabled)
        .opacity(composerDisabled ? 0.4 : 1.0)
        .accessibilityLabel("Attach a file")
        .confirmationDialog(
            "Attach a file",
            isPresented: $showAttachSheet,
            titleVisibility: .hidden,
        ) {
            attachDialog()
        }
    }

    private var inputField: some View {
        TextField(placeholder, text: $draft, axis: .vertical)
            // F-NEW-801: the highest-volume sensitive-content input in
            // the app. Without these flags every keystroke trains
            // `~/Library/Keyboard/dynamic-text.dat`. `.sentences`
            // autocap keeps the first-letter UX nicety without
            // re-enabling autocorrect or the dictation glyph.
            .hardenedTextInput(autocap: .sentences)
            .lineLimit(1 ... 6)
            .padding(.horizontal, 14)
            .padding(.vertical, 9)
            .background(
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .fill(Color(uiColor: .secondarySystemBackground))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .strokeBorder(Color(uiColor: .separator).opacity(0.6), lineWidth: 0.5)
            )
            .focused($focused)
            .disabled(composerDisabled)
            // Multi-line: Return inserts a newline. We deliberately
            // do NOT set `.submitLabel(.send)` — `axis: .vertical`
            // absorbs the keypress for a newline, so a blue send
            // glyph on the return key would mislead the user. The
            // visible send button is the only send path.
    }

    private var sendButton: some View {
        Button(action: onSend) {
            Image(systemName: "arrow.up")
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(Color(.systemBackground))
                .frame(width: 36, height: 36)
                .background(
                    Circle().fill(Color.accentColor)
                )
        }
        .buttonStyle(.plain)
        .disabled(composerDisabled || sendDisabled)
        .opacity((composerDisabled || sendDisabled) ? 0.4 : 1.0)
        .accessibilityLabel("Send message")
    }
}
