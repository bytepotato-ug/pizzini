import PizziniCryptoCore
import SwiftUI
import UIKit

struct ContactsListView: View {
    @Bindable var store: ChatStore
    @Binding var showScanner: Bool
    /// Called with a validated `ContactCard` once paste survived the
    /// full pipeline (syntactic + self / block / duplicate). The host
    /// (`ContentView`) drives the name-prompt sheet and the final
    /// `ChatStore.addContact` with `source: .pastedText`. Every non-
    /// success path is shown inline as a `pasteAlert` instead of
    /// reaching this callback — see `handlePasteFromClipboard()`.
    let onPasteContact: (ContactCard) -> Void
    /// Empty-state shortcut: tell the host to switch to the Profil
    /// tab so a brand-new user can show THEIR QR to the person they
    /// want to pair with. Without it the empty-state "Show my QR"
    /// button would either disappear or open a sheet that duplicates
    /// the tab.
    let onRevealMyQR: () -> Void
    /// Tapped from the optional first-run support banner — switches
    /// to the Settings tab so the user lands on the Support Pizzini
    /// row. The banner is dismissible (X) and re-displays at most
    /// every 30 days while the user is on the free tier.
    let onOpenSupport: () -> Void

    /// Live state for the first-run support banner. `@Bindable` so
    /// dismissals update the local view tree immediately even before
    /// the next launch.
    @Bindable var subscriptionService: SubscriptionService = .shared
    @Bindable var bannerState: SupportBannerState = .shared

    /// Driver for the `.alert(item:)` that surfaces every paste
    /// outcome that isn't `.ready`. The previous behaviour ("silently
    /// drop on malformed input") was a UX black hole — the user
    /// tapped Paste, nothing happened, no explanation. Each outcome
    /// now maps to a distinct title + message:
    ///   • .empty          — clipboard had nothing
    ///   • .malformed      — wrong scheme / length / non-ASCII /
    ///                       missing port / etc., with the
    ///                       specific reason from
    ///                       `ContactCardDecodeError`
    ///   • .selfPaste      — they pasted their own card
    ///   • .blocked        — the peer is in the block list
    ///   • .alreadyPaired  — non-error "already in your contacts"
    ///                       (we still re-queued the bundle exchange)
    @State private var pasteAlert: PasteAlertContent?

    /// Confirmation-dialog state for the `+` add-contact action sheet.
    /// Local to the toolbar — no need to plumb up to ContentView.
    @State private var showAddContactDialog = false
    /// Sheet that lets the user assemble a new group (name + initial
    /// 1:1 contacts to invite). Local to the list — surfaced via the
    /// "+" toolbar menu.
    @State private var showNewGroupSheet = false
    /// `.searchable` text binding. Non-empty (after trimming) → the
    /// body swaps the normal contacts/groups list for a
    /// `SearchResultsView` that scans every chat log + name
    /// in-memory. Empty → normal list. iOS's search machinery owns
    /// the visible search field, the cancel button, and the keyboard
    /// dismissal flow; we just react to the value it produces.
    @State private var searchQuery = ""

    /// True when the user has tapped the magnifying-glass toolbar
    /// button. Drives a CUSTOM inline search bar that the body
    /// renders above the contacts list — we don't use SwiftUI's
    /// `.searchable` because its `isPresented` binding controls
    /// FOCUS, not visibility (the nav-bar-drawer search field stays
    /// mounted regardless). Cancel button on the custom bar flips
    /// this back to false and clears the query.
    @State private var searchActive = false
    /// Drives the focus on the inline TextField so the keyboard
    /// raises the instant the user taps the magnifying-glass icon,
    /// without needing a separate `.onAppear { searchFocused = true }`
    /// runloop hop.
    @FocusState private var searchFocused: Bool

    /// True when the user typed something searchable (non-blank).
    /// Computed rather than stored so a programmatic mutation to
    /// `searchQuery` flips this through `body` without a second
    /// `onChange` hop.
    private var isSearching: Bool {
        !searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        VStack(spacing: 0) {
            if searchActive {
                customSearchBar
            }
            // First-run support banner. Visibility is policy-driven —
            // 7 days since install + free tier + not recently dismissed
            // — so it's silent on day 0 and silent for any supporter.
            // Hidden while a search is active so it doesn't crowd the
            // results.
            if !searchActive,
               bannerState.shouldShow(tier: subscriptionService.currentTier) {
                SupportBanner(
                    onTap: onOpenSupport,
                    onDismiss: { bannerState.dismiss() }
                )
            }
            ZStack {
                if isSearching {
                    SearchResultsView(store: store, query: searchQuery)
                } else if store.state.contacts.isEmpty, store.state.groups.isEmpty {
                    emptyState
                } else {
                    list
                }
            }
        }
        // Hide the contacts list when iOS reports a screen recording
        // or external display. The toolbar above stays interactive so
        // a user who triggered Control-Centre Record by mistake can
        // still navigate out / open Settings to disable recording.
        .screenCaptureShielded()
        .navigationTitle("Pizzini")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            // Profil + Einstellungen used to live in this toolbar (QR
            // top-leading, gear top-trailing). They moved to the
            // bottom-pill `TabView` in ContentView — keeping them here
            // would double up the navigation. What stays: `+` for
            // add-contact / new-group, relay status, search.
            ToolbarItem(placement: .topBarLeading) {
                Button {
                    showAddContactDialog = true
                } label: {
                    Image(systemName: "plus")
                }
                .accessibilityLabel("Add contact")
                // Attach the dialog to the trigger button so iOS uses
                // it as the popover anchor — placing it on the parent
                // view makes the arrow point at random screen edges.
                .confirmationDialog(
                    "Add a contact or group",
                    isPresented: $showAddContactDialog,
                    titleVisibility: .visible,
                ) {
                    Button { showScanner = true } label: { Text("Scan their QR") }
                    Button {
                        handlePasteFromClipboard()
                    } label: { Text("Paste from clipboard") }
                    Button {
                        showNewGroupSheet = true
                    } label: { Text("New group…") }
                        .disabled(store.state.contacts.isEmpty)
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text("Pair contacts via QR. Groups are made up of contacts you've already paired with.")
                }
            }
            ToolbarItem(placement: .principal) {
                // Brand lockup — small logo + wordmark. The live
                // connection indicator is the separate trailing
                // toolbar item below (visible only on non-connected
                // states), so the principal slot stays clean and the
                // wordmark sits centred regardless of relay state.
                // `.navigationTitle("Pizzini")` below drives the
                // back-button label on pushed surfaces (ChatView,
                // GroupChatView).
                HStack(spacing: 6) {
                    Image("AppLogo")
                        .resizable()
                        .interpolation(.high)
                        .aspectRatio(contentMode: .fit)
                        .frame(width: 24, height: 24)
                        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                        .accessibilityHidden(true)
                    Text("Pizzini")
                        .font(.headline)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Pizzini")
            }
            // Compact relay-state indicator. Replaces the previous
            // full-width "Connecting…" strip that lived above every
            // tab's nav bar via `.safeAreaInset(.top)` — that design
            // overlapped pushed-view nav bars on Settings sub-pages
            // and felt loud for the routine 2–5s cold-launch wait.
            // This sits inside the nav bar's trailing items:
            //   • `.connected` → nothing rendered (steady state has
            //     zero chrome).
            //   • `.connecting` / `.connectingToTor` / `.idle` →
            //     small inline ProgressView (no text, no tap action).
            //   • `.failed` → red badge with exclamation icon, tap
            //     fires `forceReconnectRelays`.
            // The Chats list is the canonical place to glance at
            // connection state; Settings → Trusted relays is the
            // full per-relay detail surface.
            ToolbarItem(placement: .topBarTrailing) {
                relayStateIndicator
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    searchActive = true
                    searchFocused = true
                } label: {
                    Image(systemName: "magnifyingglass")
                }
                .accessibilityLabel("Search chats and messages")
            }
        }
        // Paste-outcome surface. `.alert(item:)` so the binding's
        // identity drives presentation — setting `pasteAlert` from
        // `handlePasteFromClipboard()` shows; the OK button clears
        // it. Title + message come straight from the outcome.
        .alert(item: $pasteAlert) { alert in
            Alert(
                title: Text(alert.title),
                message: Text(alert.message),
                dismissButton: .default(Text("OK")),
            )
        }
        // Re-pair UX: one-shot alert after an explicit identity
        // reset. Wired to ChatStore.identityResetBannerPending,
        // which is set true only by `resetIdentity()` (NOT by
        // duressWipe — see that method's coercer-watching design).
        // The "Show my QR" action deep-links the user to the Profil
        // tab where their fresh QR is rendered.
        .alert(
            "Your identity has been reset",
            isPresented: Binding(
                get: { store.identityResetBannerPending },
                set: { newValue in
                    if !newValue { store.dismissIdentityResetBanner() }
                },
            ),
        ) {
            Button("Show my QR") {
                store.dismissIdentityResetBanner()
                onRevealMyQR()
            }
            Button("Got it", role: .cancel) {
                store.dismissIdentityResetBanner()
            }
        } message: {
            Text(
                "Pizzini gave you a fresh identity. Anyone who had you in "
                + "their contacts before the reset must delete you from "
                + "their list and re-scan your new QR card."
            )
        }
    }

    // ─── Custom search bar ─────────────────────────────────────────────
    // Rolled our own rather than `.searchable` because that modifier's
    // `isPresented` binding controls focus, NOT visibility — its nav-
    // bar drawer field stays mounted regardless. This bar only exists
    // in the view tree when `searchActive` is true, so on first
    // launch the chat list opens to a clean top edge.
    private var customSearchBar: some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search chats and messages", text: $searchQuery)
                    .textFieldStyle(.plain)
                    .focused($searchFocused)
                    .submitLabel(.search)
                    .hardenedTextInput()
                if !searchQuery.isEmpty {
                    Button {
                        searchQuery = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .accessibilityLabel("Clear search")
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            Button("Cancel") {
                searchActive = false
                searchQuery = ""
                searchFocused = false
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color(.systemBackground))
    }

    // ─── Empty state ───────────────────────────────────────────────────
    // Two big primary actions stacked, plus a smaller paste fallback.
    // Replaces the previous "tap the ⋯ menu to scan" instruction
    // (forcing first-run users to discover an overflow menu before they
    // could do anything).
    private var emptyState: some View {
        VStack(spacing: 28) {
            Spacer()
            VStack(spacing: 14) {
                Image(systemName: "qrcode.viewfinder")
                    .font(.system(size: 64))
                    .foregroundStyle(.tint)
                Text("No contacts yet")
                    .font(.title3.weight(.semibold))
                Text("Pair by scanning each other's QR. Both of you have to scan; one-way scans don't unlock chat.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
            VStack(spacing: 10) {
                Button {
                    showScanner = true
                } label: {
                    Label("Scan a QR", systemImage: "qrcode.viewfinder")
                        .frame(maxWidth: .infinity)
                        .prominentLabelText()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                Button {
                    onRevealMyQR()
                } label: {
                    Label("Show my QR", systemImage: "qrcode")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .controlSize(.large)

                Button {
                    handlePasteFromClipboard()
                } label: {
                    Text("Paste contact from clipboard")
                        .font(.footnote)
                }
                .padding(.top, 4)
            }
            .padding(.horizontal, 32)
            Spacer()
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var list: some View {
        List {
            // 1) Pending invitations always pin to the top — they
            //    need an explicit user decision before the group
            //    becomes a normal chat surface. Inline Accept /
            //    Decline buttons; no nested navigation required.
            if !pendingInvitations.isEmpty {
                Section("Invitations") {
                    ForEach(pendingInvitations) { group in
                        InvitationRow(group: group, store: store)
                    }
                }
            }

            // 2) Then contacts and groups, in user-configured order.
            //    When only one section has rows (and no invitations
            //    either), render its rows without a header so the
            //    list doesn't waste a band of empty space at the
            //    top of the view.
            let multipleSections = !pendingInvitations.isEmpty
                || (!store.state.contacts.isEmpty && !acceptedGroups.isEmpty)

            if store.state.contactsBeforeGroups {
                renderContacts(withHeader: multipleSections)
                renderGroups(withHeader: multipleSections)
            } else {
                renderGroups(withHeader: multipleSections)
                renderContacts(withHeader: multipleSections)
            }
        }
        .listStyle(.plain)
        .sheet(isPresented: $showNewGroupSheet) {
            NewGroupSheet(store: store, onDismiss: { showNewGroupSheet = false })
        }
    }

    @ViewBuilder
    private func renderContacts(withHeader: Bool) -> some View {
        if !store.state.contacts.isEmpty {
            if withHeader {
                Section("Contacts") { contactsRows }
            } else {
                contactsRows
            }
        }
    }

    @ViewBuilder
    private func renderGroups(withHeader: Bool) -> some View {
        if !acceptedGroups.isEmpty {
            if withHeader {
                Section("Groups") { groupsRows }
            } else {
                groupsRows
            }
        }
    }

    @ViewBuilder
    private var contactsRows: some View {
        ForEach(store.state.contacts) { contact in
            NavigationLink {
                ChatView(store: store, contactID: contact.id)
            } label: {
                ContactRow(contact: contact)
            }
            .swipeActions(edge: .trailing) {
                Button(role: .destructive) {
                    store.deleteContact(contact)
                } label: {
                    Label("Delete", systemImage: "trash")
                }
            }
        }
    }

    @ViewBuilder
    private var groupsRows: some View {
        ForEach(sortedGroups) { group in
            NavigationLink {
                GroupChatView(store: store, groupID: group.id)
            } label: {
                GroupRow(group: group, store: store)
            }
        }
    }

    /// Pending invitations pinned to the top — sorted by group name
    /// for stable ordering across re-renders.
    private var pendingInvitations: [ChatGroup] {
        store.state.groups
            .filter { $0.pendingInvitation }
            .sorted { $0.displayName < $1.displayName }
    }

    /// Groups the user has actually joined — pending invitations
    /// are filtered out and shown in their dedicated section.
    private var acceptedGroups: [ChatGroup] {
        store.state.groups.filter { !$0.pendingInvitation }
    }

    private var sortedGroups: [ChatGroup] {
        acceptedGroups.sorted { lhs, rhs in
            switch (lhs.lastMessageAt, rhs.lastMessageAt) {
            case let (l?, r?): return l > r
            case (_?, nil): return true
            case (nil, _?): return false
            case (nil, nil): return lhs.displayName < rhs.displayName
            }
        }
    }

    // ─── Relay state indicator (nav bar toolbar item) ─────────────────
    // Five states, all driven by the pure derivation in
    // `ChatStore.pillState`:
    //   • `.bootstrappingTor`  — grey capsule, label "Bootstrapping
    //                            Tor N%", no tap action.
    //   • `.connectingRelays`  — amber capsule, label "Connecting M
    //                            of N", no tap action.
    //   • `.connected`         — green capsule, "Connected", auto-
    //                            hides after a 2 s grace via
    //                            `connectedShownAt` below.
    //   • `.partial`           — amber capsule, label "M of N
    //                            relays", persists. Tells the user
    //                            the fleet has degraded redundancy
    //                            but is still serving traffic.
    //   • `.failed`            — red capsule, label "Couldn't
    //                            connect — tap to retry", taps
    //                            kick `forceReconnectRelays`.
    /// Local @State driving the post-`.connected` 2-second auto-
    /// hide. We stash the timestamp the state first reached
    /// `.connected` and stop rendering the pill once
    /// `connectedHideAfterSeconds` has elapsed since.
    @State private var connectedShownAt: Date?
    private static let connectedHideAfterSeconds: TimeInterval = 2

    /// Current pill state. Computed every render from the store's
    /// live state, so we never lag the fleet by a frame.
    ///
    /// Reads `perRelayState` (observable @Observable member) rather
    /// than `relays.map { $0.state }` — `RelayClient` is a plain
    /// final class outside the @Observable graph, so its `state`
    /// var doesn't trigger redraws. `perRelayState` is kept in
    /// lockstep with the fleet by the delegate handler.
    private var pillState: ChatStore.PillState {
        let pct = store.torBootstrapProgress
        let healths: [ChatStore.RelayHealth] = store.perRelayState.values.map {
            ChatStore.RelayHealth($0)
        }
        return ChatStore.pillState(bootstrap: pct, relays: healths)
    }

    /// Capsule fill colour for the current pill state. Static method
    /// so a screenshot smoke test can render every state without a
    /// live ChatStore.
    private static func pillBackground(for tint: ChatStore.PillState.Tint) -> Color {
        switch tint {
        case .grey:  return Color(.secondarySystemFill)
        case .amber: return Color.orange.opacity(0.20)
        case .green: return Color.green.opacity(0.25)
        case .red:   return Color.red
        }
    }

    /// Foreground (label) colour for the current pill tint. Red
    /// uses white-on-red for contrast; the rest defer to system
    /// foregrounds.
    private static func pillForeground(for tint: ChatStore.PillState.Tint) -> Color {
        switch tint {
        case .red:   return .white
        case .green: return Color.green
        case .amber: return Color.orange
        case .grey:  return .secondary
        }
    }

    @ViewBuilder
    private var relayStateIndicator: some View {
        let state = pillState
        // Hide the pill entirely once `.connected` has been visible
        // long enough — the user has confirmation we made it, and
        // healthy steady state shouldn't waste toolbar real estate.
        // Every non-connected state pulls the timestamp back to nil
        // so the next `.connected` arrival starts a fresh 2 s grace.
        if shouldHidePill(for: state) {
            EmptyView()
        } else {
            pillBody(for: state)
        }
    }

    /// Should the pill be hidden? Returns true only when the pill
    /// state is `.connected` AND the auto-hide grace has elapsed.
    /// Side effect: refreshes `connectedShownAt` as state crosses
    /// into/out of `.connected`.
    private func shouldHidePill(for state: ChatStore.PillState) -> Bool {
        switch state {
        case .connected:
            if let shownAt = connectedShownAt {
                if Date().timeIntervalSince(shownAt) >= Self.connectedHideAfterSeconds {
                    return true
                }
                return false
            }
            // First frame of `.connected` — stamp the timestamp on
            // the next runloop tick (we can't mutate @State from
            // inside `body` evaluation) and keep showing the pill
            // until the grace elapses.
            DispatchQueue.main.async {
                connectedShownAt = Date()
            }
            return false
        default:
            if connectedShownAt != nil {
                DispatchQueue.main.async {
                    connectedShownAt = nil
                }
            }
            return false
        }
    }

    @ViewBuilder
    private func pillBody(for state: ChatStore.PillState) -> some View {
        let bg = Self.pillBackground(for: state.tint)
        let fg = Self.pillForeground(for: state.tint)
        let content = HStack(spacing: 6) {
            if showsSpinner(for: state) {
                ProgressView()
                    .controlSize(.mini)
                    .tint(fg)
            }
            Text(state.label)
                .font(.caption.weight(.medium))
                .foregroundStyle(fg)
                .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 4)
        .background(Capsule().fill(bg))
        if state.isTappable {
            Button {
                store.forceReconnectRelays()
            } label: {
                content
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Couldn't connect. Tap to retry.")
        } else {
            content
                .accessibilityLabel(state.label)
        }
    }

    /// Spinner appears for in-progress states (bootstrapping,
    /// connecting, partial-but-recovering, idle). `.connected`
    /// shows no spinner — the user is done waiting. `.failed`
    /// shows none either — that's a tap-to-act state, not a
    /// loading state.
    private func showsSpinner(for state: ChatStore.PillState) -> Bool {
        switch state {
        case .bootstrappingTor, .connectingRelays, .partial, .idle:
            return true
        case .connected, .failed:
            return false
        }
    }

    // ─── Paste-from-clipboard entry point ─────────────────────────────
    //
    // Single chokepoint used by both paste call sites (the toolbar
    // "+" confirmation dialog and the empty-state inline button).
    // Reading `UIPasteboard.general` triggers iOS's paste banner; we
    // do it exactly once per user action so the banner fires the
    // expected number of times. The actual decision (parse / self /
    // block / duplicate / OK) is delegated to
    // `ChatStore.evaluatePastedContact`, which keeps the validation
    // rules in one place. The view's only job here is to read the
    // clipboard, normalise across iOS's pasteboard type quirks, and
    // map the outcome to a user-visible alert OR to the existing
    // name-prompt flow via `onPasteContact`.
    //
    // Title strings are plain language ("Nothing to paste", "Not a
    // contact card") rather than technical ("EmptyClipboardError",
    // "MalformedContactCardError") — the user is recovering from a
    // mistake, not reading a stack trace.
    //
    // ## Type-fallback (regression 2026-05-13)
    //
    // A user reported "Nothing to paste" with a `pizzini1://…` link
    // clearly in their clipboard. Root cause: iOS stores clipboard
    // contents under one or more UTType identifiers. `general.string`
    // queries `public.utf8-plain-text`. Several common copy paths
    // (Universal Clipboard sync from macOS, Safari's "Copy Link",
    // long-press → Share → Copy on a recognised URL) store the value
    // under `public.url` ONLY — `general.string` returns nil even
    // though the URL is sitting right there. The fix is to fall
    // through to `general.url` and (for some sources) `general.urls`,
    // then finally to coerce to a string. Each accessor here triggers
    // the same single paste-banner under iOS's privacy model — they
    // share one underlying read, not one banner each.
    private func handlePasteFromClipboard() {
        // Entry log — fires on every tap, so the QA capture
        // unambiguously shows the button DID register. A tap that
        // never produces this line means the gesture didn't reach
        // SwiftUI (broken hit-target, overlay swallowing taps,
        // disabled state we didn't anticipate). The snapshot uses
        // metadata-only accessors (`items.count`, `types`,
        // `hasStrings`, `hasURLs`) — none of those trigger iOS's
        // paste banner. Reading `pb.string` here would count as a
        // separate paste attempt under iOS 16+ privacy and could
        // pop a second banner (or, on iOS 26, get the subsequent
        // read in `readPasteboardContactCard()` implicitly denied).
        // `hasStrings` covers the "is there text on the board"
        // signal we'd want from `string?.count` without the
        // content read.
        // Take exactly one `UIPasteboard.general` reference for the
        // whole user action and pass it down into the content read.
        // The pasteboard is a mutable, generation-counted system
        // object; acquiring a second reference in the content reader
        // would let the logged metadata and the parsed card describe
        // two different observations (a TOCTOU on the generation
        // counter). One reference → one observation.
        let pb = UIPasteboard.general
        let entryTypes = pb.types.joined(separator: ",")
        pzLog(
            "[pizzini.paste] paste tap: BEFORE "
            + "items=\(pb.items.count) types=[\(entryTypes)] "
            + "hasStrings=\(pb.hasStrings) hasURLs=\(pb.hasURLs)"
        )
        let raw = Self.readPasteboardContactCard(from: pb)
        let outcome = store.evaluatePastedContact(raw)
        pzLog(
            "[pizzini.paste] paste tap: outcome=\(Self.describe(outcome)) "
            + "rawLen=\(raw.count)"
        )
        switch outcome {
        case .ready(let card):
            onPasteContact(card)
        case .empty:
            pasteAlert = PasteAlertContent(
                title: "Nothing to paste",
                message: Self.emptyClipboardMessage,
            )
        case .malformed(let reason):
            pasteAlert = PasteAlertContent(
                title: "Not a contact card",
                message: reason,
            )
        case .selfPaste:
            pasteAlert = PasteAlertContent(
                title: "That's your own card",
                message: "You can't add yourself as a contact. Share your QR (Profil tab) with someone else, and have THEM scan or paste it.",
            )
        case .blocked:
            pasteAlert = PasteAlertContent(
                title: "You blocked this contact",
                message: "Unblock them from Settings → Blocked contacts before adding them again.",
            )
        case .alreadyPaired(let name):
            pasteAlert = PasteAlertContent(
                title: "Already paired",
                message: "You're already connected with \(name). Pizzini retried the bundle exchange in case the handshake was stuck.",
            )
        }
    }

    /// Copy for the "Nothing to paste" alert. On a real device this
    /// is the usual "copy first, then try again" prompt. On the
    /// iOS Simulator we append a hint about
    /// `Simulator → Edit → Automatically Sync Pasteboard`, because
    /// the most common cause of a truly-empty pasteboard during
    /// development is that toggle silently flipping off across a
    /// simulator state-reset (verified failure 2026-05-13: BEFORE
    /// snapshot showed `items=0 types=[]` — nothing on the
    /// pasteboard for our code to read). Real-device users never
    /// see the simulator hint.
    private static var emptyClipboardMessage: String {
        let base = "Your clipboard is empty. Copy your contact's pizzini1:// card first, then try again."
        #if targetEnvironment(simulator)
        return base + "\n\nRunning in the iOS Simulator? Check Simulator → Edit → Automatically Sync Pasteboard — that toggle resets on state changes and silently breaks Mac→sim clipboard sync."
        #else
        return base
        #endif
    }

    /// One-word label for a `ContactCardPasteOutcome`. Used only by
    /// the debug log to keep the line scannable — the full alert
    /// copy already covers the user-facing surface.
    private static func describe(_ o: ChatStore.ContactCardPasteOutcome) -> String {
        switch o {
        case .ready: return "ready"
        case .empty: return "empty"
        case .malformed: return "malformed"
        case .selfPaste: return "selfPaste"
        case .blocked: return "blocked"
        case .alreadyPaired: return "alreadyPaired"
        }
    }

    /// Best-effort read of a `pizzini1://…` card from the system
    /// pasteboard. Walks the type fallbacks in priority order:
    ///
    ///   1. `string` — `public.utf8-plain-text`. Normal in-app
    ///      copy and any path that bridges through `NSString`.
    ///   2. `url` — `public.url`. Universal Clipboard from macOS,
    ///      Safari "Copy Link", anywhere iOS data-detected the
    ///      value as a URL on the copy side. `general.string`
    ///      returns nil in these cases even though the URL is
    ///      present — this is the bug a user hit on 2026-05-13.
    ///   3. `urls.first` — same as `url` for older copy sources
    ///      that wrote the plural form. iOS sometimes populates
    ///      one or the other.
    ///   4. `items` — last-ditch scan of every entry in the raw
    ///      items dictionary, looking for any value we can coerce
    ///      to a string. Catches exotic UTIs we haven't enumerated
    ///      explicitly (e.g. third-party clipboard managers
    ///      writing under their own type identifier with a
    ///      string-shaped value).
    ///   5. Whitespace-trimmed empty → return the empty string and
    ///      let `evaluatePastedContact` map it to `.empty`.
    ///
    /// On a fully-empty result the helper logs the available
    /// pasteboard `types` and item count so the QA-log capture
    /// shows what was (or wasn't) on the clipboard. Without that
    /// detail an "empty clipboard" report is unfalsifiable — we
    /// can't tell apart "iOS Simulator has clipboard-sync off and
    /// the pasteboard is genuinely empty" from "the pasteboard
    /// has data under a type we don't know how to read."
    ///
    /// Takes the caller's already-acquired `UIPasteboard` reference
    /// rather than reaching for `UIPasteboard.general` itself, so the
    /// metadata logged by `handlePasteFromClipboard` and the content
    /// parsed here come from one observation of the pasteboard.
    ///
    /// Static so the logic is unit-testable in principle (the
    /// `UIPasteboard.general` global makes the integration side
    /// hard to fake without a wrapper protocol, but the policy
    /// can still be exercised against a closure-based stub if a
    /// future refactor wants to add coverage).
    private static func readPasteboardContactCard(from pb: UIPasteboard) -> String {
        if let s = pb.string, !s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return s
        }
        if let u = pb.url?.absoluteString,
           !u.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return u
        }
        if let u = pb.urls?.first?.absoluteString,
           !u.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return u
        }
        // Last-ditch: scan the raw items dictionary. Each item is
        // `[uti: value]`; the value can be `String`, `NSString`,
        // `URL`, `NSURL`, or `Data`. We accept any of those and
        // coerce. This is broader than `string`/`url`/`urls`
        // because those accessors filter by canonical UTIs; the
        // raw items map contains anything any source wrote.
        for item in pb.items {
            for value in item.values {
                if let s = value as? String,
                   !s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    return s
                }
                if let u = value as? URL,
                   !u.absoluteString.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    return u.absoluteString
                }
                if let data = value as? Data,
                   let s = String(data: data, encoding: .utf8),
                   !s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    return s
                }
            }
        }
        // Nothing readable — log what *was* present so the next
        // QA-log capture pinpoints the cause. We do this once per
        // tap (the caller calls us once per user action), so the
        // line count stays sane.
        let types = pb.types.joined(separator: ",")
        pzLog(
            "[pizzini.paste] empty: items=\(pb.items.count) "
            + "types=[\(types)] hasStrings=\(pb.hasStrings) "
            + "hasURLs=\(pb.hasURLs)"
        )
        return ""
    }
}

/// Driver for `ContactsListView`'s `.alert(item:)`. `Identifiable`
/// + a fresh `UUID()` per instance so two failures of the same
/// kind in a row both re-fire the alert (SwiftUI's `.alert(item:)`
/// uses identity-equality to decide whether to re-present).
private struct PasteAlertContent: Identifiable {
    let id = UUID()
    let title: String
    let message: String
}

private struct ContactRow: View {
    let contact: Contact

    var body: some View {
        HStack(spacing: 12) {
            // Leading icon mirrors the group row's three-people
            // glyph at the same size + accent colour, so the eye
            // reads contacts and groups as siblings of one list.
            // No status dot — a solid coloured circle next to a
            // contact's name reads as a presence/online indicator
            // in every other messenger, and Pizzini deliberately
            // doesn't leak that. Handshake-pending state is shown
            // by an explicit hourglass + caption instead.
            Image(systemName: "person.fill")
                .font(.title3)
                .foregroundStyle(Color.accentColor)
                .frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    if !contact.sessionEstablished {
                        Image(systemName: "hourglass")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .accessibilityLabel("waiting for handshake")
                    }
                    Text(contact.displayName)
                        // Always semibold, parity with `GroupRow.displayName`.
                        // The unread cue isn't lost — `unreadBadge` (the
                        // accent-coloured capsule with count) on the trailing
                        // edge still distinguishes unread rows; the bold
                        // contact name is a hierarchy cue (this row's TITLE)
                        // rather than a state cue (read / unread).
                        .font(.body.weight(.semibold))
                    verificationBadge
                }
                if let last = contact.log.last {
                    Text(preview(last))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                } else if !contact.sessionEstablished {
                    Text("waiting for handshake…")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            Spacer(minLength: 8)
            if unread > 0 {
                unreadBadge
            }
        }
        .padding(.vertical, 4)
    }

    private var unread: Int { contact.unreadCount }

    private var unreadBadge: some View {
        // Inverted system colours so the badge stays readable in both
        // light and dark modes once the accent flipped to the label
        // colour (black on light / white on dark). Without the
        // inversion the badge text would collide with its own fill
        // in dark mode.
        Text("\(unread)")
            .font(.caption2.bold().monospacedDigit())
            .foregroundStyle(Color(.systemBackground))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(Capsule().fill(Color(.label)))
            .accessibilityLabel("\(unread) unread")
    }

    /// Small in-line glyph next to the display name reflecting the
    /// `ContactVerificationState`. Verified state gets a green check
    /// seal that is the load-bearing reassurance for users scanning
    /// the list. Unverified states use distinct colours and shapes so
    /// red/green colour-blind users still see a glyph difference.
    /// Tap target is intentionally absent — the row itself navigates
    /// into the chat, where the banner offers the action.
    @ViewBuilder
    private var verificationBadge: some View {
        switch contact.verificationState {
        case .verified:
            Image(systemName: "checkmark.seal.fill")
                .font(.caption)
                .foregroundStyle(.green)
                .accessibilityLabel("verified")
        case .scannedUnverified:
            Image(systemName: "checkmark.shield")
                .font(.caption)
                .foregroundStyle(.orange)
                .accessibilityLabel("scanned but not safety-number verified")
        case .pastedUnverified:
            Image(systemName: "exclamationmark.shield.fill")
                .font(.caption)
                .foregroundStyle(.red)
                .accessibilityLabel("pasted identity, not verified — open chat to verify")
        }
    }

    private func preview(_ msg: PersistedMessage) -> String {
        switch msg.kind {
        case .system: return msg.text
        case .preKey, .whisper:
            let prefix = msg.side == .me ? "you: " : ""
            return prefix + msg.text
        case .attachment:
            let prefix = msg.side == .me ? "you: " : ""
            let name = msg.attachment?.filename ?? "file"
            // The contacts list preview doesn't show the caption in
            // its own line, but the line below is dense enough — name
            // first wins because that's what the user is looking for
            // when scanning the list.
            if msg.text.isEmpty {
                return "\(prefix)📎 \(name)"
            }
            return "\(prefix)📎 \(name) — \(msg.text)"
        }
    }
}

/// One row for a group on the contacts list. Mirrors `ContactRow`'s
/// shape so the user reads the two surfaces with the same eye:
/// title (with optional pending hourglass), one-line preview of the
/// most-recent log entry. We intentionally do NOT render member
/// fingerprints / member counts / "online" indicators on the row —
/// presence and member identity belong on the group's settings
/// screen, not the list.
///
/// Takes a `store` reference so the preview prefix renders the
/// sender's *current* contact display name (audit MEDIUM-7) — a
/// rename in the contacts list immediately propagates to every
/// historical group preview without rewriting `log.text`.
private struct GroupRow: View {
    let group: ChatGroup
    let store: ChatStore

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "person.3.fill")
                .font(.title3)
                .foregroundStyle(Color.accentColor)
                .frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    if group.activeMembers.contains(where: { $0.status == .pendingSKDM }) {
                        Image(systemName: "hourglass")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .accessibilityLabel("waiting for keys to exchange")
                    }
                    Text(group.displayName)
                        .font(.body.weight(.semibold))
                }
                if let last = group.log.last {
                    Text(preview(last))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                } else {
                    Text("\(group.activeMembers.count) members — no messages yet")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 8)
        }
        .padding(.vertical, 4)
    }

    private func preview(_ msg: PersistedMessage) -> String {
        switch msg.kind {
        case .system: return msg.text
        case .preKey, .whisper, .attachment:
            switch msg.side {
            case .me:
                return "you: \(msg.text)"
            case .peer:
                if let peerId = msg.senderPeerId {
                    return "\(store.memberDisplayName(peerId, in: group)): \(msg.text)"
                }
                return msg.text
            }
        }
    }
}

/// Inline accept/decline row for a pending group invitation. Lives
/// in the contacts list's "Invitations" section so the user doesn't
/// have to navigate into a detail view to make their choice.
///
/// Long-press → context menu with "View members" pushes the
/// `GroupInvitationView` for users who want a fuller inspection
/// before deciding (member roster + verification captions).
private struct InvitationRow: View {
    let group: ChatGroup
    let store: ChatStore

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                Image(systemName: "envelope.badge")
                    .font(.title3)
                    .foregroundStyle(Color.orange)
                    .frame(width: 28)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(group.displayName)
                        .font(.body.weight(.semibold))
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 8)
            }
            HStack(spacing: 10) {
                Spacer()
                Button {
                    store.declineGroupInvitation(groupId: group.id)
                } label: {
                    Text("Decline")
                        .frame(minWidth: 70)
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .tint(.red)
                Button {
                    store.acceptGroupInvitation(groupId: group.id)
                } label: {
                    Text("Accept")
                        .frame(minWidth: 70)
                        .prominentLabelText()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }
        }
        .padding(.vertical, 4)
        .contextMenu {
            NavigationLink {
                GroupInvitationView(store: store, groupID: group.id)
            } label: {
                Label("View members", systemImage: "person.2")
            }
        }
    }

    private var subtitle: String {
        let memberCount = group.activeMembers.count
        let memberSuffix = "\(memberCount) member\(memberCount == 1 ? "" : "s")"
        guard let myCard = store.myCard,
              let myRow = group.members.first(where: { $0.peerId == myCard.peerId }),
              let addedBy = myRow.addedBy
        else { return memberSuffix }
        if let contact = store.state.contacts.first(where: { $0.identityPub == addedBy }) {
            return "invited by \(contact.displayName) — \(memberSuffix)"
        }
        return memberSuffix
    }
}
