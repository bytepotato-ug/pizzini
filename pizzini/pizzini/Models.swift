import Foundation

enum ChatBubbleSide: String, Codable, Sendable {
    case me
    case peer
}

enum ChatMessageKind: String, Codable, Sendable {
    case preKey
    case whisper
    case system
}

struct PersistedMessage: Codable, Identifiable, Sendable {
    let id: UUID
    let side: ChatBubbleSide
    let text: String
    let kind: ChatMessageKind
    let bytes: Int
    let timestamp: Date

    init(
        id: UUID = UUID(),
        side: ChatBubbleSide,
        text: String,
        kind: ChatMessageKind,
        bytes: Int,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.side = side
        self.text = text
        self.kind = kind
        self.bytes = bytes
        self.timestamp = timestamp
    }
}

/// One row in the contacts list. `identityPub` is the trust anchor — the
/// 33-byte serialized libsignal IdentityKey. Two `Contact` rows with the
/// same `identityPub` should never coexist; uniqueness is enforced at
/// insert.
struct Contact: Codable, Identifiable, Sendable {
    let id: UUID
    let identityPub: Data
    var displayName: String
    var sessionEstablished: Bool
    var log: [PersistedMessage]
    var lastMessageAt: Date?
    /// Wall-clock the user last opened this chat. Inbound messages
    /// (`side == .peer`) with `timestamp > lastSeenAt` are unread. Nil
    /// means "never opened" — every received message is unread.
    var lastSeenAt: Date?
    let addedAt: Date

    init(
        id: UUID = UUID(),
        identityPub: Data,
        displayName: String,
        sessionEstablished: Bool = false,
        log: [PersistedMessage] = [],
        lastMessageAt: Date? = nil,
        lastSeenAt: Date? = nil,
        addedAt: Date = Date()
    ) {
        self.id = id
        self.identityPub = identityPub
        self.displayName = displayName
        self.sessionEstablished = sessionEstablished
        self.log = log
        self.lastMessageAt = lastMessageAt
        self.lastSeenAt = lastSeenAt
        self.addedAt = addedAt
    }

    var unreadCount: Int {
        let cutoff = lastSeenAt ?? .distantPast
        return log.reduce(0) { acc, msg in
            (msg.side == .peer && msg.timestamp > cutoff) ? acc + 1 : acc
        }
    }

    /// Default name for newly-scanned contacts: short fingerprint of the
    /// identity public key. User can rename later.
    static func defaultName(for identityPub: Data) -> String {
        let head = identityPub.prefix(4).map { String(format: "%02x", $0) }.joined()
        let tail = identityPub.suffix(2).map { String(format: "%02x", $0) }.joined()
        return "peer \(head)…\(tail)"
    }
}

extension AppState {
    var totalUnread: Int { contacts.reduce(0) { $0 + $1.unreadCount } }
}

/// Everything the UI needs that lives outside the libsignal store. Encoded
/// to JSON, sealed into Keychain. Bumping `version` lets us migrate.
struct AppState: Codable, Sendable {
    var version: Int
    var relayHost: String
    var contacts: [Contact]

    static let currentVersion = 1
    static let defaultRelayHost = "127.0.0.1"

    init(version: Int = currentVersion, relayHost: String = defaultRelayHost, contacts: [Contact] = []) {
        self.version = version
        self.relayHost = relayHost
        self.contacts = contacts
    }
}
