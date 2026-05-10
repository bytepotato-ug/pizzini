import Foundation
import Testing
@testable import pizzini

/// Coverage for `ChatSearch` — the pure-function search core consumed
/// by both the global search-results view and the per-chat find-bar.
/// No `ChatStore` instance needed; every test builds the minimal
/// `AppState` it asserts against.
@Suite("ChatSearch")
struct ChatSearchTests {

    // MARK: - Empty / whitespace queries

    @Test("empty query returns no results")
    func emptyQuery() {
        let state = makeState(contacts: [makeContact(name: "Alice", messages: [
            makeMessage(text: "hello world"),
        ])])
        #expect(ChatSearch.searchAll(in: state, query: "").isEmpty)
        #expect(ChatSearch.searchAll(in: state, query: "   ").isEmpty)
        #expect(ChatSearch.findIDs(in: state.contacts[0].log, query: "").isEmpty)
    }

    // MARK: - Basic matching

    @Test("matches text inside a 1:1 chat")
    func oneOnOneMatch() {
        let log = [
            makeMessage(text: "meet at the cafe at 3"),
            makeMessage(text: "see you there"),
        ]
        let state = makeState(contacts: [makeContact(name: "Alice", messages: log)])
        let hits = ChatSearch.searchAll(in: state, query: "cafe")
        #expect(hits.count == 1)
        #expect(hits[0].messageID == log[0].id)
        #expect(hits[0].chatDisplayName == "Alice")
        guard case .oneOnOne(let cid) = hits[0].surface else {
            Issue.record("expected .oneOnOne surface")
            return
        }
        #expect(cid == state.contacts[0].id)
    }

    @Test("matches in a group log too")
    func groupMatch() {
        let group = makeGroup(name: "Operations", messages: [
            makeMessage(text: "the truck arrives at dawn"),
        ])
        let state = makeState(groups: [group])
        let hits = ChatSearch.searchAll(in: state, query: "truck")
        #expect(hits.count == 1)
        #expect(hits[0].chatDisplayName == "Operations")
        guard case .group(let gid) = hits[0].surface else {
            Issue.record("expected .group surface")
            return
        }
        #expect(gid == group.id)
    }

    @Test("merges hits from both 1:1 and group logs into one result list")
    func mixedSurfaces() {
        let now = Date()
        let aliceLog = [makeMessage(text: "alpha bravo", timestamp: now.addingTimeInterval(-100))]
        let groupLog = [makeMessage(text: "alpha gamma", timestamp: now.addingTimeInterval(-50))]
        let state = makeState(
            contacts: [makeContact(name: "Alice", messages: aliceLog)],
            groups: [makeGroup(name: "G", messages: groupLog)],
        )
        let hits = ChatSearch.searchAll(in: state, query: "alpha")
        #expect(hits.count == 2)
        // Newest-first.
        #expect(hits[0].messageID == groupLog[0].id)
        #expect(hits[1].messageID == aliceLog[0].id)
    }

    // MARK: - Insensitivity flags

    @Test("case-insensitive")
    func caseInsensitive() {
        let state = makeState(contacts: [makeContact(name: "A", messages: [
            makeMessage(text: "Quick Brown Fox"),
        ])])
        #expect(ChatSearch.searchAll(in: state, query: "quick").count == 1)
        #expect(ChatSearch.searchAll(in: state, query: "FOX").count == 1)
        #expect(ChatSearch.searchAll(in: state, query: "BrOwN").count == 1)
    }

    @Test("diacritic-insensitive")
    func diacriticInsensitive() {
        let state = makeState(contacts: [makeContact(name: "A", messages: [
            makeMessage(text: "meet at the café before the über ride"),
        ])])
        // Plain ASCII query finds accented text.
        #expect(ChatSearch.searchAll(in: state, query: "cafe").count == 1)
        #expect(ChatSearch.searchAll(in: state, query: "uber").count == 1)
        // And the reverse: accented query finds accented text.
        #expect(ChatSearch.searchAll(in: state, query: "café").count == 1)
    }

    // MARK: - Attachment filename matching

    @Test("attachment row matches on filename even if caption is empty")
    func attachmentFilenameMatch() {
        let attachment = AttachmentInfo(
            attachmentId: Data(repeating: 0xAB, count: 16),
            filename: "evidence_summary.pdf",
            byteSize: 4096,
            mime: "application/pdf",
            tier: .textFamily,
            sandboxRelativePath: nil,
            isInbound: false,
        )
        let msg = makeMessage(text: "", kind: .attachment, attachment: attachment)
        let state = makeState(contacts: [makeContact(name: "A", messages: [msg])])
        let hits = ChatSearch.searchAll(in: state, query: "summary")
        #expect(hits.count == 1)
        // Snippet falls back to the filename when the caption didn't match.
        #expect(hits[0].snippet.contains("evidence_summary.pdf"))
    }

    @Test("attachment row prefers caption snippet when caption matches")
    func attachmentCaptionPreferredOverFilename() {
        let attachment = AttachmentInfo(
            attachmentId: Data(repeating: 0xAB, count: 16),
            filename: "evidence.pdf",
            byteSize: 4096,
            mime: "application/pdf",
            tier: .textFamily,
            sandboxRelativePath: nil,
            isInbound: false,
        )
        let msg = makeMessage(
            text: "here's the evidence I mentioned",
            kind: .attachment,
            attachment: attachment,
        )
        let state = makeState(contacts: [makeContact(name: "A", messages: [msg])])
        let hits = ChatSearch.searchAll(in: state, query: "evidence")
        #expect(hits.count == 1)
        // Snippet should pull from the caption (the text body) since the
        // caption contains the match; the filename is the fallback.
        #expect(hits[0].snippet.contains("evidence I mentioned"))
    }

    // MARK: - Exclusion rules

    @Test("system rows are not matched")
    func systemRowsSkipped() {
        let log = [
            makeMessage(text: "session not established yet — your message will queue", kind: .system),
            makeMessage(text: "hi there", kind: .whisper),
        ]
        let state = makeState(contacts: [makeContact(name: "A", messages: log)])
        let hits = ChatSearch.searchAll(in: state, query: "session")
        #expect(hits.isEmpty)
        // findIDs also skips system rows.
        #expect(ChatSearch.findIDs(in: log, query: "established").isEmpty)
    }

    @Test("pending-invitation groups are excluded from global search")
    func pendingInvitationsExcluded() {
        let acceptedGroup = makeGroup(name: "Accepted", messages: [
            makeMessage(text: "needle"),
        ])
        let pendingGroup = makeGroup(
            name: "Pending",
            messages: [makeMessage(text: "needle")],
            pendingInvitation: true,
        )
        let state = makeState(groups: [acceptedGroup, pendingGroup])
        let hits = ChatSearch.searchAll(in: state, query: "needle")
        // Only the accepted group's hit is included — a user shouldn't
        // see search hits from a group they haven't yet decided to join.
        #expect(hits.count == 1)
        #expect(hits[0].chatDisplayName == "Accepted")
    }

    // MARK: - Limit + ordering

    @Test("results are sorted newest-first")
    func newestFirst() {
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let log = [
            makeMessage(text: "needle 1", timestamp: base.addingTimeInterval(0)),
            makeMessage(text: "needle 2", timestamp: base.addingTimeInterval(100)),
            makeMessage(text: "needle 3", timestamp: base.addingTimeInterval(200)),
        ]
        let state = makeState(contacts: [makeContact(name: "A", messages: log)])
        let hits = ChatSearch.searchAll(in: state, query: "needle")
        #expect(hits.count == 3)
        #expect(hits[0].messageID == log[2].id)
        #expect(hits[1].messageID == log[1].id)
        #expect(hits[2].messageID == log[0].id)
    }

    @Test("respects limit by truncating after newest-first sort")
    func respectsLimit() {
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        var log: [PersistedMessage] = []
        for i in 0..<10 {
            log.append(makeMessage(text: "needle \(i)", timestamp: base.addingTimeInterval(TimeInterval(i))))
        }
        let state = makeState(contacts: [makeContact(name: "A", messages: log)])
        let hits = ChatSearch.searchAll(in: state, query: "needle", limit: 3)
        #expect(hits.count == 3)
        // The three newest, in newest-first order: 9, 8, 7.
        #expect(hits[0].messageID == log[9].id)
        #expect(hits[1].messageID == log[8].id)
        #expect(hits[2].messageID == log[7].id)
    }

    // MARK: - Bucketing

    @Test("bucket groups by surface, preserving newest-first inside each bucket")
    func bucketGroupsBySurface() {
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let aliceLog = [
            makeMessage(text: "needle A1", timestamp: base.addingTimeInterval(0)),
            makeMessage(text: "needle A2", timestamp: base.addingTimeInterval(100)),
        ]
        let bobLog = [
            makeMessage(text: "needle B1", timestamp: base.addingTimeInterval(50)),
        ]
        let state = makeState(contacts: [
            makeContact(name: "Alice", messages: aliceLog),
            makeContact(name: "Bob", messages: bobLog),
        ])
        let buckets = ChatSearch.bucket(ChatSearch.searchAll(in: state, query: "needle"))
        #expect(buckets.count == 2)
        // Alice's bucket leads — her latest hit (A2 @ +100) is newer
        // than Bob's only hit (B1 @ +50).
        #expect(buckets[0].chatDisplayName == "Alice")
        #expect(buckets[0].results.count == 2)
        #expect(buckets[0].results[0].messageID == aliceLog[1].id)
        #expect(buckets[0].results[1].messageID == aliceLog[0].id)
        #expect(buckets[1].chatDisplayName == "Bob")
        #expect(buckets[1].results.count == 1)
    }

    // MARK: - Snippet builder

    @Test("snippet returns short text unchanged")
    func snippetShortText() {
        let s = ChatSearch.snippet(text: "hello world", query: "world", width: 80)
        #expect(s == "hello world")
    }

    @Test("snippet centers on first match with leading + trailing ellipsis")
    func snippetCenters() {
        // 200-char text with the match deep in the middle.
        let prefix = String(repeating: "a", count: 80)
        let suffix = String(repeating: "b", count: 80)
        let text = prefix + " NEEDLE " + suffix
        let s = ChatSearch.snippet(text: text, query: "NEEDLE", width: 40)
        #expect(s.contains("NEEDLE"))
        #expect(s.hasPrefix("…"))
        #expect(s.hasSuffix("…"))
        // Body (snippet minus the two ellipses) ≤ width characters.
        let body = s.dropFirst().dropLast()
        #expect(body.count <= 40)
    }

    @Test("snippet at start-of-text has no leading ellipsis")
    func snippetAtStart() {
        let text = "NEEDLE " + String(repeating: "x", count: 200)
        let s = ChatSearch.snippet(text: text, query: "NEEDLE", width: 40)
        #expect(s.hasPrefix("NEEDLE"))
        #expect(s.hasSuffix("…"))
    }

    @Test("snippet near end-of-text pulls window left, no trailing ellipsis")
    func snippetAtEnd() {
        let text = String(repeating: "x", count: 200) + " NEEDLE"
        let s = ChatSearch.snippet(text: text, query: "NEEDLE", width: 40)
        #expect(s.hasPrefix("…"))
        #expect(s.hasSuffix("NEEDLE"))
    }

    @Test("snippet doesn't invent a match position when query isn't present")
    func snippetMissingMatch() {
        // Caller fed a string that doesn't contain the query (e.g. the
        // match was filename-only and the caller passed the empty
        // caption). Should return the text up to `width`, NOT pretend
        // the match was at position 0.
        let text = String(repeating: "abcdefgh", count: 20)
        let s = ChatSearch.snippet(text: text, query: "needle", width: 20)
        // No infinite loop, no crash; result is bounded by width plus
        // ellipses.
        #expect(s.count <= 20 + 2)
    }

    // MARK: - Chat-name search

    @Test("searchChatNames matches contacts and groups by display name")
    func chatNameSearch() {
        let state = makeState(
            contacts: [
                makeContact(name: "Alice", messages: []),
                makeContact(name: "Bob", messages: []),
            ],
            groups: [
                makeGroup(name: "Alpha Team", messages: []),
                makeGroup(name: "Beta Crew", messages: []),
            ],
        )
        let chatHits = ChatSearch.searchChatNames(in: state, query: "al")
        // "Alice" + "Alpha Team" both contain "al" (case-insensitive).
        #expect(chatHits.count == 2)
        #expect(chatHits[0].displayName == "Alice")
        #expect(chatHits[1].displayName == "Alpha Team")
    }

    @Test("searchChatNames is diacritic-insensitive on names too")
    func chatNameDiacritic() {
        let state = makeState(
            contacts: [makeContact(name: "André", messages: [])],
            groups: [makeGroup(name: "Café Club", messages: [])],
        )
        let hits = ChatSearch.searchChatNames(in: state, query: "cafe")
        #expect(hits.count == 1)
        #expect(hits[0].displayName == "Café Club")
        let hits2 = ChatSearch.searchChatNames(in: state, query: "andre")
        #expect(hits2.count == 1)
        #expect(hits2[0].displayName == "André")
    }

    @Test("searchChatNames excludes pending invitations")
    func chatNamePendingExcluded() {
        let state = makeState(
            groups: [
                makeGroup(name: "Accepted Crew", messages: []),
                makeGroup(name: "Pending Crew", messages: [], pendingInvitation: true),
            ],
        )
        let hits = ChatSearch.searchChatNames(in: state, query: "Crew")
        #expect(hits.count == 1)
        #expect(hits[0].displayName == "Accepted Crew")
    }

    // MARK: - findIDs (in-chat)

    @Test("findIDs returns matching messages in chronological order")
    func findIDsChronological() {
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let log = [
            makeMessage(text: "needle one", timestamp: base.addingTimeInterval(0)),
            makeMessage(text: "no match", timestamp: base.addingTimeInterval(50)),
            makeMessage(text: "needle two", timestamp: base.addingTimeInterval(100)),
            makeMessage(text: "needle three", timestamp: base.addingTimeInterval(150)),
        ]
        let ids = ChatSearch.findIDs(in: log, query: "needle")
        #expect(ids == [log[0].id, log[2].id, log[3].id])
    }

    // MARK: - Fixtures

    private func makeState(
        contacts: [Contact] = [],
        groups: [ChatGroup] = [],
    ) -> AppState {
        AppState(contacts: contacts, groups: groups)
    }

    private func makeContact(name: String, messages: [PersistedMessage]) -> Contact {
        Contact(
            identityPub: Data(name.utf8),
            displayName: name,
            sessionEstablished: true,
            log: messages,
        )
    }

    private func makeGroup(
        name: String,
        messages: [PersistedMessage],
        pendingInvitation: Bool = false,
    ) -> ChatGroup {
        ChatGroup(
            id: Data(name.utf8),
            displayName: name,
            members: [],
            createdAt: Date(timeIntervalSince1970: 0),
            currentEpoch: 0,
            lastOpDigest: Data(repeating: 0, count: 32),
            pendingOps: [],
            log: messages,
            lastSeenAt: nil,
            lastMessageAt: nil,
            myCurrentDistributionId: nil,
            memberDistributionIds: [:],
            sentSinceRotation: 0,
            lastRotatedAt: Date(timeIntervalSince1970: 0),
            mySkdmRecipients: [],
            recentOpDigests: [:],
            pendingInvitation: pendingInvitation,
        )
    }

    private func makeMessage(
        text: String,
        kind: ChatMessageKind = .whisper,
        timestamp: Date = Date(),
        attachment: AttachmentInfo? = nil,
    ) -> PersistedMessage {
        PersistedMessage(
            side: .me,
            text: text,
            kind: kind,
            bytes: text.utf8.count,
            timestamp: timestamp,
            attachment: attachment,
        )
    }
}
