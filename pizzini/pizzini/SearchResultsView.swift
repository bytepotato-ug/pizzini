import SwiftUI

/// Global search-results surface, shown in place of the normal
/// `ContactsListView` body whenever its `.searchable` text is non-
/// empty. Two sections, mirroring iMessage / Threema / Signal:
///
///   • Chats — contacts and groups whose display name contains the
///     query. Tapping opens the chat with no in-chat focus, just like
///     a normal contacts-list row.
///   • Messages — every matching message across every 1:1 + group
///     log, newest-first. Each row carries the chat name as a
///     leading caption + an AttributedString-highlighted snippet
///     centered on the match. Tapping pushes the chat with a
///     `ChatSearch.Focus(query:messageID:)` deep-link so the chat
///     opens scrolled-to the cited row with the in-chat find-bar
///     already engaged for prev/next cycling through hits in the
///     same chat.
///
/// Pure-render: `searchAll` / `searchChatNames` are pure functions
/// over `state`, called inside computed properties. SwiftUI's
/// `@Observable` integration recomputes when `state` changes, so an
/// inbound message that lands while the user is searching shows up
/// immediately if it matches.
///
/// The view itself does NOT own the query — `ContactsListView` owns
/// it (bound to `.searchable`) and passes it in by value. That keeps
/// `.searchable`'s state, the dismissal flow, and the cancel button
/// all coherent under the NavigationStack's search machinery.
struct SearchResultsView: View {
    @Bindable var store: ChatStore
    /// Current query string, owned by the parent `ContactsListView`'s
    /// `.searchable` binding. We pass by value rather than binding
    /// because the search field is owned by SwiftUI's search bar; we
    /// only need to READ the latest value to recompute results.
    let query: String

    var body: some View {
        let chatHits = ChatSearch.searchChatNames(in: store.state, query: query)
        let messageHits = ChatSearch.searchAll(in: store.state, query: query)
        List {
            if !chatHits.isEmpty {
                Section("Chats") {
                    ForEach(chatHits) { match in
                        chatMatchRow(match)
                    }
                }
            }
            if !messageHits.isEmpty {
                Section("Messages") {
                    ForEach(messageHits) { result in
                        messageResultRow(result)
                    }
                }
            }
            if chatHits.isEmpty && messageHits.isEmpty {
                noResultsHint
                    .listRowSeparator(.hidden)
                    .listRowBackground(Color.clear)
            }
        }
        .listStyle(.plain)
    }

    // MARK: - Chats section

    @ViewBuilder
    private func chatMatchRow(_ match: ChatSearch.ChatMatch) -> some View {
        switch match.surface {
        case .oneOnOne(let contactID):
            NavigationLink {
                ChatView(store: store, contactID: contactID)
            } label: {
                ChatMatchLabel(
                    iconName: "person.fill",
                    displayName: match.displayName,
                    query: query,
                )
            }
        case .group(let groupID):
            NavigationLink {
                GroupChatView(store: store, groupID: groupID)
            } label: {
                ChatMatchLabel(
                    iconName: "person.3.fill",
                    displayName: match.displayName,
                    query: query,
                )
            }
        }
    }

    // MARK: - Messages section

    @ViewBuilder
    private func messageResultRow(_ result: ChatSearch.Result) -> some View {
        switch result.surface {
        case .oneOnOne(let contactID):
            NavigationLink {
                ChatView(
                    store: store,
                    contactID: contactID,
                    initialFocus: ChatSearch.Focus(
                        query: query,
                        messageID: result.messageID,
                    ),
                )
            } label: {
                MessageResultLabel(result: result, query: query)
            }
        case .group(let groupID):
            NavigationLink {
                GroupChatView(
                    store: store,
                    groupID: groupID,
                    initialFocus: ChatSearch.Focus(
                        query: query,
                        messageID: result.messageID,
                    ),
                )
            } label: {
                MessageResultLabel(result: result, query: query)
            }
        }
    }

    // MARK: - Empty state

    private var noResultsHint: some View {
        VStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 36))
                .foregroundStyle(.tertiary)
                .padding(.top, 48)
            Text("No matches for \u{201C}\(query)\u{201D}")
                .font(.headline)
                .foregroundStyle(.secondary)
            Text("Search runs across all chats. Case and accents are ignored.")
                .font(.caption)
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
        }
        .frame(maxWidth: .infinity)
    }
}

/// One row in the "Chats" section — chat icon (person / person.3
/// glyph to match `ContactsListView`'s row glyphs) + display name
/// with the query substring highlighted. Tapping the parent
/// NavigationLink opens the chat normally with no in-chat focus.
private struct ChatMatchLabel: View {
    let iconName: String
    let displayName: String
    let query: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: iconName)
                .font(.title3)
                .foregroundStyle(Color.accentColor)
                .frame(width: 28)
                .accessibilityHidden(true)
            Text(SearchHighlight.attributed(text: displayName, query: query))
                .font(.body)
            Spacer(minLength: 8)
        }
        .padding(.vertical, 4)
    }
}

/// One row in the "Messages" section — chat-name caption on top, the
/// highlighted snippet below. Trailing timestamp aligns right. Mirrors
/// the visual rhythm of a Mail / Notes search result.
private struct MessageResultLabel: View {
    let result: ChatSearch.Result
    let query: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            // Glyph reuses the same person / person.3 chat-row
            // language so the user reads the row as "matches in
            // <chat>" at a glance.
            Image(systemName: chatGlyph)
                .font(.body)
                .foregroundStyle(Color.accentColor)
                .frame(width: 24)
                .padding(.top, 2)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(result.chatDisplayName)
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                    Spacer(minLength: 6)
                    Text(timestampText)
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                Text(SearchHighlight.attributed(
                    text: prefixedSnippet,
                    query: query,
                ))
                .font(.callout)
                .foregroundStyle(.primary)
                .lineLimit(2)
            }
        }
        .padding(.vertical, 4)
    }

    private var chatGlyph: String {
        switch result.surface {
        case .oneOnOne: return "person.fill"
        case .group: return "person.3.fill"
        }
    }

    /// "you: …" prefix on self-attributed rows, matching the conventional
    /// previews in `ContactsListView`'s row + the `last-row preview` line
    /// in iMessage / WhatsApp.
    private var prefixedSnippet: String {
        result.side == .me ? "you: \(result.snippet)" : result.snippet
    }

    private var timestampText: String {
        let now = Date()
        let cal = Calendar.current
        if cal.isDateInToday(result.timestamp) {
            return result.timestamp.formatted(date: .omitted, time: .shortened)
        }
        // If it was earlier this week, show the weekday — the user can
        // place it without month/day overhead. Otherwise show a short
        // month/day. Always omit time; the row's text snippet is the
        // signal, the timestamp is the recency-cue.
        let weekAgo = cal.date(byAdding: .day, value: -6, to: now) ?? now
        if result.timestamp > weekAgo {
            return result.timestamp.formatted(.dateTime.weekday(.abbreviated))
        }
        return result.timestamp.formatted(.dateTime.month(.abbreviated).day())
    }
}

/// AttributedString-based highlight for search hits. Centralised here
/// so the same look is applied identically by `ChatMatchLabel`'s name
/// row, `MessageResultLabel`'s snippet line, AND the in-chat
/// `ChatRow` / `GroupChatBubble` matching-bubble overlays — keeping
/// one yellow across every search surface.
///
/// Implementation note: AttributedString doesn't expose a direct
/// `Range<String.Index>` indexing API, so we look up each match in the
/// underlying `String` (case + diacritic insensitive), convert by
/// character-distance to `AttributedString.Index`, then style the
/// resulting AttributedString range. Character distance is the right
/// metric — `AttributedString.index(_:offsetByCharacters:)` advances
/// by grapheme, matching how `String.distance(...)` counts.
enum SearchHighlight {
    /// Yellow background + primary foreground for matched runs.
    /// Foreground is forced to `.primary` so the highlight reads
    /// correctly in both light and dark mode (default `.secondary`
    /// snippet text would lose contrast against the yellow fill).
    static func attributed(text: String, query: String) -> AttributedString {
        var attr = AttributedString(text)
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !text.isEmpty else { return attr }
        var searchStart = text.startIndex
        while let range = text.range(
            of: trimmed,
            options: [.caseInsensitive, .diacriticInsensitive],
            range: searchStart..<text.endIndex,
        ) {
            let lower = text.distance(from: text.startIndex, to: range.lowerBound)
            let upper = text.distance(from: text.startIndex, to: range.upperBound)
            let attrLower = attr.index(attr.startIndex, offsetByCharacters: lower)
            let attrUpper = attr.index(attr.startIndex, offsetByCharacters: upper)
            attr[attrLower..<attrUpper].backgroundColor = Color.yellow.opacity(0.4)
            attr[attrLower..<attrUpper].foregroundColor = .primary
            // Advance past this match so an overlapping next match
            // (e.g. "aaa" finding three positions in "aaaa") can't
            // re-find the same start and loop forever.
            searchStart = range.upperBound
            if searchStart == text.endIndex { break }
        }
        return attr
    }
}
