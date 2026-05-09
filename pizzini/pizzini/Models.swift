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
    /// Phase 3 delivery-token stash: tokens this peer minted and gave us
    /// for use when sending TO them. Each is 84 bytes (nonce + expiry +
    /// XEd25519 sig). Pop from front; refill when it drops below
    /// `Contact.refillThreshold`.
    var deliveryTokensForPeer: [Data]
    /// Last time we *sent* a refill-request to this peer. Rate-limited
    /// to one request per `Contact.refillCooldown` so a malicious peer
    /// can't burn our stash with a tight loop.
    var lastRefillRequestSentAt: Date?
    /// Last time we *handled* a refill-request from this peer. Same
    /// rate-limit applied to incoming requests so we don't pay for
    /// 1024 fresh signatures more than once per cooldown window.
    var lastRefillRequestHandledAt: Date?

    init(
        id: UUID = UUID(),
        identityPub: Data,
        displayName: String,
        sessionEstablished: Bool = false,
        log: [PersistedMessage] = [],
        lastMessageAt: Date? = nil,
        lastSeenAt: Date? = nil,
        addedAt: Date = Date(),
        deliveryTokensForPeer: [Data] = [],
        lastRefillRequestSentAt: Date? = nil,
        lastRefillRequestHandledAt: Date? = nil
    ) {
        self.id = id
        self.identityPub = identityPub
        self.displayName = displayName
        self.sessionEstablished = sessionEstablished
        self.log = log
        self.lastMessageAt = lastMessageAt
        self.lastSeenAt = lastSeenAt
        self.addedAt = addedAt
        self.deliveryTokensForPeer = deliveryTokensForPeer
        self.lastRefillRequestSentAt = lastRefillRequestSentAt
        self.lastRefillRequestHandledAt = lastRefillRequestHandledAt
    }

    /// Restock target. Each fresh issuance refills the stash to this
    /// many tokens. Brief specifies 1024.
    static let initialIssuance: Int = 1024
    /// When the stash drops below this we kick a sealed refill request.
    static let refillThreshold: Int = 256
    /// Minimum time between refill exchanges. 6h matches the brief.
    static let refillCooldown: TimeInterval = 6 * 60 * 60

    private enum CodingKeys: String, CodingKey {
        case id, identityPub, displayName, sessionEstablished, log, lastMessageAt
        case lastSeenAt, addedAt
        case deliveryTokensForPeer, lastRefillRequestSentAt, lastRefillRequestHandledAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(UUID.self, forKey: .id)
        self.identityPub = try c.decode(Data.self, forKey: .identityPub)
        self.displayName = try c.decode(String.self, forKey: .displayName)
        self.sessionEstablished = try c.decode(Bool.self, forKey: .sessionEstablished)
        self.log = try c.decode([PersistedMessage].self, forKey: .log)
        self.lastMessageAt = try c.decodeIfPresent(Date.self, forKey: .lastMessageAt)
        self.lastSeenAt = try c.decodeIfPresent(Date.self, forKey: .lastSeenAt)
        self.addedAt = try c.decode(Date.self, forKey: .addedAt)
        self.deliveryTokensForPeer = try c.decodeIfPresent([Data].self, forKey: .deliveryTokensForPeer) ?? []
        self.lastRefillRequestSentAt = try c.decodeIfPresent(Date.self, forKey: .lastRefillRequestSentAt)
        self.lastRefillRequestHandledAt = try c.decodeIfPresent(Date.self, forKey: .lastRefillRequestHandledAt)
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

enum AutoLockTimeout: String, Codable, CaseIterable, Sendable {
    case immediately
    case oneMinute
    case fiveMinutes
    case fifteenMinutes

    var seconds: TimeInterval {
        switch self {
        case .immediately: return 0
        case .oneMinute: return 60
        case .fiveMinutes: return 5 * 60
        case .fifteenMinutes: return 15 * 60
        }
    }

    var label: String {
        switch self {
        case .immediately: return "Immediately"
        case .oneMinute: return "After 1 minute"
        case .fiveMinutes: return "After 5 minutes"
        case .fifteenMinutes: return "After 15 minutes"
        }
    }
}

/// Everything the UI needs that lives outside the libsignal store. Encoded
/// to JSON, sealed into Keychain. Bumping `version` lets us migrate.
///
/// `init(from:)` decodes the security fields with `decodeIfPresent` so an
/// existing AppState blob (written before those fields existed) still
/// loads cleanly. Synthesized `encode(to:)` writes them all.
struct AppState: Codable, Sendable {
    var version: Int
    var relayHost: String
    var contacts: [Contact]
    var onboardingCompleted: Bool
    var biometricLockEnabled: Bool
    var autoLockTimeout: AutoLockTimeout

    static let currentVersion = 1
    static let defaultRelayHost = "127.0.0.1"

    init(
        version: Int = currentVersion,
        relayHost: String = defaultRelayHost,
        contacts: [Contact] = [],
        onboardingCompleted: Bool = false,
        biometricLockEnabled: Bool = false,
        autoLockTimeout: AutoLockTimeout = .immediately
    ) {
        self.version = version
        self.relayHost = relayHost
        self.contacts = contacts
        self.onboardingCompleted = onboardingCompleted
        self.biometricLockEnabled = biometricLockEnabled
        self.autoLockTimeout = autoLockTimeout
    }

    private enum CodingKeys: String, CodingKey {
        case version
        case relayHost
        case contacts
        case onboardingCompleted
        case biometricLockEnabled
        case autoLockTimeout
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        relayHost = try c.decode(String.self, forKey: .relayHost)
        contacts = try c.decode([Contact].self, forKey: .contacts)
        onboardingCompleted = try c.decodeIfPresent(Bool.self, forKey: .onboardingCompleted) ?? false
        biometricLockEnabled = try c.decodeIfPresent(Bool.self, forKey: .biometricLockEnabled) ?? false
        autoLockTimeout = try c.decodeIfPresent(AutoLockTimeout.self, forKey: .autoLockTimeout) ?? .immediately
    }
}
