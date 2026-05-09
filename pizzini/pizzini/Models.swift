import Foundation

enum ChatBubbleSide: String, Codable, Sendable {
    case me
    case peer
}

enum ChatMessageKind: String, Codable, Sendable {
    case preKey
    case whisper
    case system
    /// An incoming or outgoing attachment row. The text field carries
    /// the optional caption (or "" if the user sent a bare file). All
    /// the attachment-specific metadata lives on the `attachment`
    /// optional.
    case attachment
}

/// Per-attachment metadata attached to a `PersistedMessage` whose kind
/// is `.attachment`. Hangs off the chat row so a single ChatRow can
/// render the filename / size / tier banner / save-to-Files action
/// without re-deriving from the outbox or the sandbox.
///
/// `sandboxRelativePath` is relative to `AttachmentSandbox.root()`. We
/// store the relative form rather than an absolute URL so a future
/// SQLCipher migration that sandbox-relocates the directory doesn't
/// strand existing rows.
struct AttachmentInfo: Codable, Sendable, Equatable {
    let attachmentId: Data
    let filename: String
    let byteSize: UInt64
    let mime: String
    let tier: AttachmentTier
    /// Filesystem path relative to `AttachmentSandbox.root()`. Nil for
    /// outbound rows where the sandbox copy was already cleaned up
    /// post-TTL — the chat row stays as a record but the bytes are gone.
    var sandboxRelativePath: String?
    /// True for attachments we received and reassembled on this device;
    /// false for attachments we sent. Drives row layout (warning banner
    /// only on inbound rows; outbound rows show their post-strip status).
    let isInbound: Bool
}

struct PersistedMessage: Codable, Identifiable, Sendable {
    let id: UUID
    let side: ChatBubbleSide
    let text: String
    let kind: ChatMessageKind
    let bytes: Int
    let timestamp: Date
    /// 16-byte sealed-sender message id. Set for every `.me` chat
    /// message so we can match an incoming ACK back to the right
    /// outbox entry; nil for `.peer` and `.system` rows.
    let messageId: Data?
    /// Set on `.me` rows when the recipient sends a read receipt
    /// covering this message. Drives the "Read" indicator in the chat
    /// row. Nil unless the recipient has read receipts on for us.
    var readAt: Date?
    /// Attachment metadata for `kind == .attachment` rows. Nil for
    /// every other kind. Decoded with `decodeIfPresent` so prior
    /// non-attachment-aware Keychain blobs continue to load.
    var attachment: AttachmentInfo?

    init(
        id: UUID = UUID(),
        side: ChatBubbleSide,
        text: String,
        kind: ChatMessageKind,
        bytes: Int,
        timestamp: Date = Date(),
        messageId: Data? = nil,
        readAt: Date? = nil,
        attachment: AttachmentInfo? = nil
    ) {
        self.id = id
        self.side = side
        self.text = text
        self.kind = kind
        self.bytes = bytes
        self.timestamp = timestamp
        self.messageId = messageId
        self.readAt = readAt
        self.attachment = attachment
    }

    private enum CodingKeys: String, CodingKey {
        case id, side, text, kind, bytes, timestamp, messageId, readAt, attachment
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(UUID.self, forKey: .id)
        self.side = try c.decode(ChatBubbleSide.self, forKey: .side)
        self.text = try c.decode(String.self, forKey: .text)
        self.kind = try c.decode(ChatMessageKind.self, forKey: .kind)
        self.bytes = try c.decode(Int.self, forKey: .bytes)
        self.timestamp = try c.decode(Date.self, forKey: .timestamp)
        self.messageId = try c.decodeIfPresent(Data.self, forKey: .messageId)
        self.readAt = try c.decodeIfPresent(Date.self, forKey: .readAt)
        self.attachment = try c.decodeIfPresent(AttachmentInfo.self, forKey: .attachment)
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
    /// Per-contact default per-message TTL (seconds). Phase 4 picker.
    /// Default is `Contact.defaultTTLSeconds`; user-adjustable via the
    /// chat ⋯ menu. A reduction here doesn't shrink in-flight messages
    /// — only future SENDs pick up the new value.
    var ttlSeconds: UInt32
    /// Per-contact read-receipts toggle. Default OFF — most journalists
    /// keep this off, and we won't surprise them by leaking when they
    /// open a message just because they happened to enable it once at
    /// onboarding. ✓✓ (delivered) is independent and always emitted.
    var readReceiptsEnabled: Bool
    /// Peer's published `delivery_token_verify_key` (33 bytes) extracted
    /// from their BUNDLE_RESPONSE. F-202/F-401: every TOKEN_ISSUE batch
    /// from this peer is verified against this key before any token is
    /// added to `deliveryTokensForPeer`, so a malicious relay cannot
    /// swap legitimate batches for relay-forged bytes. Optional because
    /// pre-Phase-3 contact rows on disk won't have this — the next
    /// successful BUNDLE_RESPONSE re-populates it.
    var peerVerifyKey: Data?
    /// Last time we *served* a BUNDLE_RESPONSE to this peer. F-404: a
    /// paired peer can otherwise loop BUNDLE_REQUEST and burn one
    /// kyber1024 + one one-time prekey per request; we cap at one fresh
    /// publish per `Contact.refillCooldown`. The same gate already
    /// applies to `issueTokens` via `lastRefillRequestHandledAt`.
    var lastBundleServedAt: Date?

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
        lastRefillRequestHandledAt: Date? = nil,
        ttlSeconds: UInt32 = Contact.defaultTTLSeconds,
        readReceiptsEnabled: Bool = false,
        peerVerifyKey: Data? = nil,
        lastBundleServedAt: Date? = nil
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
        self.ttlSeconds = ttlSeconds
        self.readReceiptsEnabled = readReceiptsEnabled
        self.peerVerifyKey = peerVerifyKey
        self.lastBundleServedAt = lastBundleServedAt
    }

    /// Default per-message TTL: 1 day. Picker offers 1h / 1 day / 3d / 7d.
    static let defaultTTLSeconds: UInt32 = 24 * 60 * 60
    static let ttlOptions: [(label: String, seconds: UInt32)] = [
        ("1 hour",  60 * 60),
        ("1 day (recommended)", 24 * 60 * 60),
        ("3 days",  3 * 24 * 60 * 60),
        ("7 days",  7 * 24 * 60 * 60),
    ]

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
        case ttlSeconds, readReceiptsEnabled
        case peerVerifyKey, lastBundleServedAt
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
        self.ttlSeconds = try c.decodeIfPresent(UInt32.self, forKey: .ttlSeconds) ?? Contact.defaultTTLSeconds
        self.readReceiptsEnabled = try c.decodeIfPresent(Bool.self, forKey: .readReceiptsEnabled) ?? false
        self.peerVerifyKey = try c.decodeIfPresent(Data.self, forKey: .peerVerifyKey)
        self.lastBundleServedAt = try c.decodeIfPresent(Date.self, forKey: .lastBundleServedAt)
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
