import Foundation

/// Pure search primitives over the in-memory chat logs. Two surfaces
/// consume this:
///
///   1. The global search on `ContactsListView` — `searchAll(in:query:)`
///      walks every 1:1 contact log AND every group log, returns a
///      flat list of `ChatSearchResult` rows newest-first, ordered for
///      display in `SearchResultsView`.
///   2. The in-chat find-bar on `ChatView` / `GroupChatView` —
///      `findIDs(in:query:)` returns just the matching message IDs in
///      chronological order so the prev/next pill can cycle through
///      them via `ScrollPosition.scrollTo(id:anchor:)`.
///
/// Deliberately NOT a persistent index. A disk-backed inverted index
/// of message text would be a juicy target on a seized + decrypted
/// device — the threat model already accepts that the message logs
/// themselves live in a Keychain-sealed envelope, but a separate
/// search index either has to ride the same envelope (re-encrypted on
/// every write, defeating the point of incremental indexing) or sit
/// in the clear (unacceptable for an activist tool). On-demand linear
/// scan over the in-RAM logs is sub-millisecond at expected log
/// volumes and a hard floor on the persistence-side attack surface.
///
/// All match comparisons are case-insensitive AND diacritic-insensitive
/// via `String.range(of:options:)`. Searching "cafe" finds "Café";
/// searching "ALICE" finds "alice"; searching "uber" finds "über".
/// This mirrors Spotlight / Finder / Messages where the user expects
/// to type without worrying about accents.
///
/// Pure-function — operates on `AppState` (or a `[PersistedMessage]`),
/// has no `ChatStore` dependency, is trivially unit-testable. The
/// `ChatStore.searchAllChats` thin wrapper just plumbs `state` in.
enum ChatSearch {
    /// Maximum total results returned by `searchAll`. The UI paginates
    /// by truncation rather than incremental fetch — at 200 matches the
    /// user should refine their query, not scroll forever. Same shape
    /// Spotlight uses for its "see more" thresholds.
    static let defaultGlobalLimit = 200

    /// Width in characters of the snippet generated around a match.
    /// ~80 chars centers a typical hit comfortably in the row width
    /// while leaving room for the chat-name prefix and timestamp on
    /// the trailing edge of the row.
    static let defaultSnippetWidth = 80

    // MARK: - Result types

    /// One hit in a global search. Carries everything `SearchResultsView`
    /// needs to render the row AND everything the chat-view deep-link
    /// needs to scroll to the right message on push.
    ///
    /// `id == messageID` keeps `Identifiable` cheap and stable: two
    /// different searches over the same log produce results with the
    /// same identity for the same row, so SwiftUI's diff is a no-op
    /// when the query narrows or widens around the same hit.
    struct Result: Identifiable, Hashable, Sendable {
        /// Which conversation surface this hit lives on. Drives both
        /// the row's chat-name label and the destination of the
        /// NavigationLink that opens it.
        enum Surface: Hashable, Sendable {
            case oneOnOne(contactID: UUID)
            case group(groupID: Data)
        }

        var id: UUID { messageID }
        let surface: Surface
        let messageID: UUID
        /// Snippet of the message text (or attachment filename) with
        /// the match centered, ellipsised on either side if truncation
        /// happened. Already includes only the user-visible bytes;
        /// the rendering layer just AttributedString-highlights it.
        let snippet: String
        let timestamp: Date
        let side: ChatBubbleSide
        /// Display name of the chat AT SEARCH TIME. Captured into the
        /// result rather than re-derived on render so the row stays
        /// cheap to lay out — and so a rename that happens between
        /// query and tap doesn't shift the rows under the user's
        /// finger. The chat-view destination still re-resolves the
        /// current name when it opens.
        let chatDisplayName: String
    }

    /// Bucket of results grouped by chat surface. Used by
    /// `SearchResultsView`'s sectioned layout: one section per chat,
    /// chats ordered by their most-recent-match timestamp DESC.
    struct Bucket: Identifiable, Sendable {
        var id: Result.Surface { surface }
        let surface: Result.Surface
        let chatDisplayName: String
        let results: [Result]
    }

    /// One row in the "Chats" section of the global results view: a
    /// chat whose display name matches the query, independent of
    /// whether any of its messages match. Tapping the row opens the
    /// chat normally (no in-chat focus).
    struct ChatMatch: Identifiable, Sendable {
        var id: Result.Surface { surface }
        let surface: Result.Surface
        let displayName: String
    }

    /// Deep-link descriptor handed from `SearchResultsView` into a
    /// chat view's `init`. The chat view's `onAppear` reads it once,
    /// pre-populates the in-chat find-bar with `query`, scrolls to
    /// `messageID`, and applies a brief flash there so the user lands
    /// on the cited row with the same query already engaged for
    /// prev/next cycling.
    struct Focus: Hashable, Sendable {
        let query: String
        let messageID: UUID
    }

    // MARK: - Global search

    /// Search every 1:1 contact log + every group log in `state` for
    /// messages whose text or attachment-filename matches `query`.
    /// Returns a flat list newest-first, truncated to `limit`.
    ///
    /// Filtering rules:
    ///   • Empty / whitespace query → empty result (the .searchable
    ///     caller treats empty as "show normal list", so we never have
    ///     to be defensive about an empty-query search slipping past
    ///     and dumping every message in the app into a results view).
    ///   • System rows (`.system` kind) are skipped — they're chat-
    ///     layer chrome ("session not established yet…"), not user
    ///     content; matching them would be noise.
    ///   • Outbound ATTACHMENT rows search the caption AND the
    ///     filename; inbound attachment rows search the caption AND
    ///     the filename. The filename is part of what the user reads
    ///     when scanning the log, so "report" should find "report.pdf"
    ///     attached with no caption.
    static func searchAll(
        in state: AppState,
        query: String,
        limit: Int = defaultGlobalLimit,
        snippetWidth: Int = defaultSnippetWidth,
    ) -> [Result] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }
        var hits: [Result] = []
        hits.reserveCapacity(min(limit, 64))

        for contact in state.contacts {
            appendHits(
                from: contact.log,
                surface: .oneOnOne(contactID: contact.id),
                displayName: contact.displayName,
                query: trimmed,
                snippetWidth: snippetWidth,
                into: &hits,
            )
        }
        for group in state.groups where !group.pendingInvitation {
            appendHits(
                from: group.log,
                surface: .group(groupID: group.id),
                displayName: group.displayName,
                query: trimmed,
                snippetWidth: snippetWidth,
                into: &hits,
            )
        }

        // Sort newest-first across the whole flat list. Within a chat,
        // newer messages tend to be what the user is looking for; even
        // across chats, recency is a better default than alphabetical
        // or "most matches per chat" — both of those produce results
        // that bury what the user actually typed three sentences ago.
        hits.sort { $0.timestamp > $1.timestamp }
        if hits.count > limit {
            hits.removeLast(hits.count - limit)
        }
        return hits
    }

    /// Bucket a flat result list into per-chat sections, preserving
    /// the within-bucket newest-first order from `searchAll`. The
    /// section order itself is by each bucket's most-recent-match
    /// timestamp DESC — so chats with very recent matches float to
    /// the top of the results view.
    static func bucket(_ results: [Result]) -> [Bucket] {
        var byID: [Result.Surface: (name: String, hits: [Result])] = [:]
        var order: [Result.Surface] = []
        for hit in results {
            if byID[hit.surface] == nil {
                order.append(hit.surface)
                byID[hit.surface] = (hit.chatDisplayName, [])
            }
            byID[hit.surface]?.hits.append(hit)
        }
        // Re-rank surface order by each bucket's most-recent-hit
        // timestamp DESC. Since results are already newest-first
        // globally, the *first* hit appended to each bucket is its
        // most recent — but the `order` array reflects encounter
        // order, which is the same thing here. Sort explicitly for
        // stability against future result-ordering changes upstream.
        order.sort { lhs, rhs in
            (byID[lhs]?.hits.first?.timestamp ?? .distantPast)
                > (byID[rhs]?.hits.first?.timestamp ?? .distantPast)
        }
        return order.map { surface in
            Bucket(
                surface: surface,
                chatDisplayName: byID[surface]?.name ?? "",
                results: byID[surface]?.hits ?? [],
            )
        }
    }

    // MARK: - Chat-name search

    /// Match the query against contact and group display names. Used
    /// by `SearchResultsView` to populate its "Chats" section so a
    /// user searching "Alice" finds her conversation row even if no
    /// individual message contains the substring.
    ///
    /// 1:1 contacts come first, then groups; within each kind we
    /// preserve `AppState`'s order so the section reads in the same
    /// rhythm as the normal contacts list. Pending-invitation groups
    /// are excluded for the same reason `searchAll` excludes them —
    /// search hits from a group the user hasn't accepted would be
    /// surprising.
    static func searchChatNames(
        in state: AppState,
        query: String,
    ) -> [ChatMatch] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }
        var matches: [ChatMatch] = []
        for contact in state.contacts {
            if contact.displayName.range(
                of: trimmed,
                options: [.caseInsensitive, .diacriticInsensitive],
            ) != nil {
                matches.append(ChatMatch(
                    surface: .oneOnOne(contactID: contact.id),
                    displayName: contact.displayName,
                ))
            }
        }
        for group in state.groups where !group.pendingInvitation {
            if group.displayName.range(
                of: trimmed,
                options: [.caseInsensitive, .diacriticInsensitive],
            ) != nil {
                matches.append(ChatMatch(
                    surface: .group(groupID: group.id),
                    displayName: group.displayName,
                ))
            }
        }
        return matches
    }

    // MARK: - In-chat search

    /// Return the IDs of every message in `log` matching `query`,
    /// in chronological (log-stored) order. The in-chat find-bar uses
    /// this list as the cycle ring for prev/next navigation; the chat
    /// view also uses `Set(matches)` to drive the per-bubble yellow
    /// highlight overlay.
    ///
    /// Same filter rules as `searchAll` (skip `.system`, search text +
    /// attachment filename). Empty / whitespace query → empty list.
    static func findIDs(in log: [PersistedMessage], query: String) -> [UUID] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }
        return log.compactMap { message in
            guard message.kind != .system else { return nil }
            return matches(message: message, query: trimmed) ? message.id : nil
        }
    }

    // MARK: - Snippet builder

    /// Build a `~width`-character window of `text` centered on the
    /// first occurrence of `query` (case+diacritic-insensitive). Adds
    /// a leading ellipsis if we truncated before the window start, and
    /// a trailing ellipsis if we truncated past the window end.
    ///
    /// If `query` doesn't appear in `text` (the caller fed an
    /// attachment row whose match was on filename rather than caption,
    /// or fed a non-matching text), this returns `text` unchanged up
    /// to `width` characters — never lies about a match position by
    /// inventing one.
    static func snippet(
        text: String,
        query: String,
        width: Int = defaultSnippetWidth,
    ) -> String {
        guard !text.isEmpty else { return "" }
        guard text.count > width else { return text }
        let matchRange = text.range(of: query, options: [.caseInsensitive, .diacriticInsensitive])
            ?? text.startIndex..<text.startIndex
        // Center the window on the match's midpoint, then clamp to
        // text bounds. Distance arithmetic is character-counted, not
        // UTF-16 / scalar — emoji and combined characters count as
        // one position each, matching how the AttributedString
        // renderer sizes them.
        let matchLowerOffset = text.distance(from: text.startIndex, to: matchRange.lowerBound)
        let matchUpperOffset = text.distance(from: text.startIndex, to: matchRange.upperBound)
        let matchMid = (matchLowerOffset + matchUpperOffset) / 2
        let halfWindow = width / 2
        let textLength = text.count
        var startOffset = max(0, matchMid - halfWindow)
        let endOffset = min(textLength, startOffset + width)
        // If we're hard against the right edge, pull the start back so
        // the window fills `width` characters rather than ending short.
        if endOffset == textLength {
            startOffset = max(0, endOffset - width)
        }

        let start = text.index(text.startIndex, offsetBy: startOffset)
        let end = text.index(text.startIndex, offsetBy: endOffset)
        let body = String(text[start..<end])

        let leadingEllipsis = startOffset > 0 ? "…" : ""
        let trailingEllipsis = endOffset < textLength ? "…" : ""
        return leadingEllipsis + body + trailingEllipsis
    }

    // MARK: - Internals

    /// Append every match in `log` for `query` to `hits`, capturing
    /// the chat surface and display name on each result. Both the
    /// message text and (for `.attachment` rows) the filename are
    /// candidate haystacks.
    private static func appendHits(
        from log: [PersistedMessage],
        surface: Result.Surface,
        displayName: String,
        query: String,
        snippetWidth: Int,
        into hits: inout [Result],
    ) {
        for message in log {
            guard message.kind != .system else { continue }
            guard matches(message: message, query: query) else { continue }
            // Prefer the text body for the snippet; fall back to the
            // filename if the match was filename-only (text caption
            // empty or didn't contain the query). The snippet builder
            // doesn't invent a match position when the query is
            // absent from the supplied string, so feeding it the
            // wrong haystack would silently produce a "start-of-
            // string" snippet — pick the right haystack here.
            let haystack: String
            if let filename = message.attachment?.filename,
               message.text.range(of: query, options: [.caseInsensitive, .diacriticInsensitive]) == nil,
               filename.range(of: query, options: [.caseInsensitive, .diacriticInsensitive]) != nil {
                haystack = filename
            } else {
                haystack = message.text
            }
            hits.append(Result(
                surface: surface,
                messageID: message.id,
                snippet: snippet(text: haystack, query: query, width: snippetWidth),
                timestamp: message.timestamp,
                side: message.side,
                chatDisplayName: displayName,
            ))
        }
    }

    /// True iff `query` is a substring of `message.text` OR — for
    /// attachment rows — of `message.attachment?.filename`. Case- and
    /// diacritic-insensitive throughout.
    private static func matches(message: PersistedMessage, query: String) -> Bool {
        if message.text.range(
            of: query, options: [.caseInsensitive, .diacriticInsensitive],
        ) != nil {
            return true
        }
        if let filename = message.attachment?.filename,
           filename.range(
            of: query, options: [.caseInsensitive, .diacriticInsensitive],
           ) != nil {
            return true
        }
        return false
    }
}
