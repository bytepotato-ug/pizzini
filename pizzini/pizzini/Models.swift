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
    /// 33-byte identity-public of the sender for `.peer` rows in a
    /// group chat — drives render-time member-name resolution
    /// (audit MEDIUM-7) so a 1:1-contact rename propagates to every
    /// historical group log row immediately. Nil for 1:1 chat rows
    /// and for `.me` / `.system` rows in a group log (the row is
    /// implicitly self-attributed or has no sender).
    let senderPeerId: Data?
    /// 16-byte stable id of the LOGICAL group message this row
    /// represents — set on `.me` rows in groups (text and attachment
    /// alike) so the chat-row indicator can roll up status across the
    /// N pairwise outbox legs via
    /// `OutboxStore.groupMessageStatus(forId:)`. Nil for 1:1 rows,
    /// `.peer` rows in groups, and `.system` rows.
    let groupMessageId: Data?

    init(
        id: UUID = UUID(),
        side: ChatBubbleSide,
        text: String,
        kind: ChatMessageKind,
        bytes: Int,
        timestamp: Date = Date(),
        messageId: Data? = nil,
        readAt: Date? = nil,
        attachment: AttachmentInfo? = nil,
        senderPeerId: Data? = nil,
        groupMessageId: Data? = nil
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
        self.senderPeerId = senderPeerId
        self.groupMessageId = groupMessageId
    }

    private enum CodingKeys: String, CodingKey {
        case id, side, text, kind, bytes, timestamp, messageId, readAt, attachment
        case senderPeerId, groupMessageId
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
        self.senderPeerId = try c.decodeIfPresent(Data.self, forKey: .senderPeerId)
        self.groupMessageId = try c.decodeIfPresent(Data.self, forKey: .groupMessageId)
    }
}

/// How a contact's identity entered Pizzini. The single source of
/// truth for "could a network attacker have substituted these bytes
/// in transit?" The verification UI uses this to size the warning it
/// shows before the first send.
///
/// `qrScan` — the camera saw the QR code in person. A MITM has to
///            physically interpose on the visual channel between two
///            phones held centimetres apart; assume out of scope unless
///            the user later admits "actually I scanned it off
///            WhatsApp."
/// `pastedText` — the `pizzini1://…` URL came in via the system
///                clipboard. Any channel could have produced those
///                bytes (SMS, WhatsApp, email, AirDrop). Trust is
///                NOT inferred from the entry mode — the safety
///                number must be compared out of band before the
///                contact is treated as verified.
/// `unknown` — pre-v2 row whose provenance was never recorded. UI
///             treats it identically to `qrScan` (because v1 only
///             ever materialised contacts via the camera scanner) but
///             keeps the distinction so a future audit/forensic flow
///             can tell "we know it was scanned" from "we don't know."
enum ContactSource: String, Codable, Sendable {
    case qrScan = "qr_scan"
    case pastedText = "pasted_text"
    case unknown
}

/// Three-state UI trust ladder used by chat header, contact-list row
/// and verification screen. Always derived from `Contact.addedVia` +
/// `Contact.verifiedAt`; never stored on its own. Order is significant
/// — comparison operators are used by tests to assert "did the state
/// only improve" after a successful SAS confirmation.
enum ContactVerificationState: String, Sendable {
    /// Verified out of band by safety number comparison. Green badge.
    case verified
    /// Scanned in person (or pre-v2 unknown-provenance row) but the
    /// user has not yet confirmed the safety number against the peer's
    /// screen. Yellow badge.
    case scannedUnverified
    /// Pasted from clipboard; the channel that carried the bytes is
    /// untrusted by definition. Red badge with a verification prompt.
    case pastedUnverified
}

/// Three-state per-contact override for the global "send read
/// receipts" preference. Raw string for stable Codable + SQLite
/// serialization — a future addition (e.g. `.confirmEachMessage`)
/// appends a new case without re-numbering anything.
enum ReadReceiptsMode: String, Codable, Sendable {
    /// Use `AppState.defaultReadReceiptsEnabled`. Initial state for
    /// every fresh contact.
    case followDefault = "follow_default"
    /// Per-chat override: always emit a read receipt to this contact
    /// regardless of the global default.
    case alwaysOn      = "always_on"
    /// Per-chat override: never emit a read receipt to this contact
    /// regardless of the global default.
    case alwaysOff     = "always_off"
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
    /// Last time we minted + shipped a fresh outbound chain to this
    /// peer (sealed `chainSeedDelivery`). Rate-limits chain rotations
    /// so a malicious peer can't drive us into a tight mint loop with
    /// repeated BUNDLE_REQUESTs.
    var lastChainServedAt: Date?
    /// Per-contact default per-message TTL (seconds). Phase 4 picker.
    /// Default is `Contact.defaultTTLSeconds`; user-adjustable via the
    /// chat ⋯ menu. A reduction here doesn't shrink in-flight messages
    /// — only future SENDs pick up the new value.
    var ttlSeconds: UInt32
    /// Per-contact read-receipts mode. Three states:
    ///   - `.followDefault`: use `AppState.defaultReadReceiptsEnabled`.
    ///     Toggling the global setting in Settings → Privacy affects
    ///     this contact immediately.
    ///   - `.alwaysOn`: emit read receipts to THIS contact regardless
    ///     of the global default. Per-chat override.
    ///   - `.alwaysOff`: never emit to THIS contact regardless of the
    ///     global default. Per-chat opt-out.
    ///
    /// Default is `.followDefault` so a single global toggle in
    /// Settings is the lowest-friction control; users only reach for
    /// the per-chat override when one specific conversation needs
    /// different treatment from the rest of their contacts.
    ///
    /// ✓✓ (delivered) is independent and always emitted.
    var readReceiptsMode: ReadReceiptsMode

    /// Resolve the effective per-contact setting given the global
    /// default. Cleaner at every read site than re-implementing the
    /// `.followDefault` lookup.
    func effectiveReadReceiptsEnabled(globalDefault: Bool) -> Bool {
        switch readReceiptsMode {
        case .followDefault: return globalDefault
        case .alwaysOn:      return true
        case .alwaysOff:     return false
        }
    }
    /// Peer's libsignal `delivery_token_verify_key` (33 bytes) extracted
    /// from their BUNDLE_RESPONSE. v2 delivery-token validation uses
    /// the chain root registered with the relay, not this key — but
    /// the field is still load-bearing for sealed-sender certificate
    /// verification. Optional because pre-pair rows won't have it.
    var peerVerifyKey: Data?
    /// Last time we *served* a BUNDLE_RESPONSE to this peer. F-404: a
    /// paired peer can otherwise loop BUNDLE_REQUEST and burn one
    /// kyber1024 + one one-time prekey per request; we cap at one fresh
    /// publish per `Contact.chainServeCooldown`.
    var lastBundleServedAt: Date?
    /// How this contact's identity entered the device. The verification
    /// UI relies on this to grade the warning — see `ContactSource`.
    let addedVia: ContactSource
    /// When the user confirmed the symmetric safety number matched the
    /// peer's screen, out of band. NULL means unverified — the chat
    /// header shows the "compare safety number" call to action and the
    /// list-row badge stays warning-coloured until set.
    var verifiedAt: Date?
    /// Per-contact mute: when true, incoming messages from this peer
    /// don't bump the unread badge or fire haptics, and the relay's
    /// "New message" push for this peer is suppressed at receive time.
    /// The chat row still updates and the contact-list row still
    /// surfaces newest-first; "mute" is purely the attention-grab
    /// surface, not message delivery.
    var mutedAt: Date?

    /// Delivery-token v2 outbound chain — the hash chain we use to
    /// derive tokens for SENDs to this peer. The peer minted this
    /// chain, ships the seed via the sealed `chainSeedDelivery`
    /// envelope, and registered the matching root with the relay.
    /// Nil = no v2 chain on file for this contact; sender falls back
    /// to v1 `deliveryTokensForPeer`. Rotated when `shouldRotate`
    /// crosses 80% used.
    var outboundTokenChain: HashChainToken.Chain?

    init(
        id: UUID = UUID(),
        identityPub: Data,
        displayName: String,
        sessionEstablished: Bool = false,
        log: [PersistedMessage] = [],
        lastMessageAt: Date? = nil,
        lastSeenAt: Date? = nil,
        addedAt: Date = Date(),
        lastChainServedAt: Date? = nil,
        ttlSeconds: UInt32 = Contact.defaultTTLSeconds,
        readReceiptsMode: ReadReceiptsMode = .followDefault,
        peerVerifyKey: Data? = nil,
        lastBundleServedAt: Date? = nil,
        addedVia: ContactSource = .qrScan,
        verifiedAt: Date? = nil,
        mutedAt: Date? = nil,
        outboundTokenChain: HashChainToken.Chain? = nil
    ) {
        self.id = id
        self.identityPub = identityPub
        self.displayName = displayName
        self.sessionEstablished = sessionEstablished
        self.log = log
        self.lastMessageAt = lastMessageAt
        self.lastSeenAt = lastSeenAt
        self.addedAt = addedAt
        self.lastChainServedAt = lastChainServedAt
        self.ttlSeconds = ttlSeconds
        self.readReceiptsMode = readReceiptsMode
        self.peerVerifyKey = peerVerifyKey
        self.lastBundleServedAt = lastBundleServedAt
        self.addedVia = addedVia
        self.verifiedAt = verifiedAt
        self.mutedAt = mutedAt
        self.outboundTokenChain = outboundTokenChain
    }

    /// Three-state shorthand for verification status used by the UI.
    /// Treat `unknown` provenance as `qrScan` (pre-v2 contact rows came
    /// in through the camera scanner — see migration v2 in `Schema.swift`).
    var verificationState: ContactVerificationState {
        if verifiedAt != nil { return .verified }
        switch addedVia {
        case .qrScan, .unknown: return .scannedUnverified
        case .pastedText: return .pastedUnverified
        }
    }

    /// Default per-message TTL: 1 day. Picker offers 1h / 1 day / 3d / 7d.
    static let defaultTTLSeconds: UInt32 = 24 * 60 * 60
    static let ttlOptions: [(label: String, seconds: UInt32)] = [
        ("1 hour",  60 * 60),
        ("1 day (recommended)", 24 * 60 * 60),
        ("3 days",  3 * 24 * 60 * 60),
        ("7 days",  7 * 24 * 60 * 60),
    ]

    /// Minimum time between chain mint+ship operations to one peer.
    /// Used to rate-limit how often we re-issue a chain in response
    /// to a peer-initiated BUNDLE_REQUEST. 6 h matches the cost
    /// profile of the bundle-coupled path (kyber1024 keygen + one-
    /// time prekey burn).
    static let chainServeCooldown: TimeInterval = 6 * 60 * 60

    /// Audit M1: minimum time between chain mint+ship operations
    /// triggered by a *sealed* `chainRefreshRequest` envelope. 30 min
    /// matches the cost profile of the chain-only path (BLAKE3 root
    /// derivation, no prekey burn). Independent from
    /// `chainServeCooldown` because the bundle path's 6 h cap was
    /// sized for kyber1024 work that the refresh path skips.
    /// Threshold is short enough that proactive rotation (which
    /// triggers at ~13 000 messages on a 16 384-token chain) never
    /// hits the cap in normal use, and tight enough that a buggy
    /// or compromised paired peer can't flood the recipient with
    /// rotation-replacement frames.
    static let chainRefreshCooldown: TimeInterval = 30 * 60

    private enum CodingKeys: String, CodingKey {
        case id, identityPub, displayName, sessionEstablished, log, lastMessageAt
        case lastSeenAt, addedAt
        case lastChainServedAt
        case ttlSeconds
        // Legacy bool (decode-only for migration); current field is
        // `readReceiptsMode`.
        case readReceiptsEnabled
        case readReceiptsMode
        case peerVerifyKey, lastBundleServedAt
        case addedVia, verifiedAt
        case mutedAt
        case outboundTokenChain
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
        self.lastChainServedAt = try c.decodeIfPresent(Date.self, forKey: .lastChainServedAt)
        self.ttlSeconds = try c.decodeIfPresent(UInt32.self, forKey: .ttlSeconds) ?? Contact.defaultTTLSeconds
        // Backward-compat: new field takes precedence; if absent, fall
        // back to the legacy Bool. Privacy-respecting mapping:
        //   true  → .alwaysOn  (user had explicitly opted-in per chat)
        //   false → .alwaysOff (user had explicitly opted-out per chat;
        //                       mapping to .followDefault would silently
        //                       re-enable receipts the moment the user
        //                       later flipped the global default on).
        if let mode = try c.decodeIfPresent(ReadReceiptsMode.self, forKey: .readReceiptsMode) {
            self.readReceiptsMode = mode
        } else if let legacy = try c.decodeIfPresent(Bool.self, forKey: .readReceiptsEnabled) {
            self.readReceiptsMode = legacy ? .alwaysOn : .alwaysOff
        } else {
            self.readReceiptsMode = .followDefault
        }
        self.peerVerifyKey = try c.decodeIfPresent(Data.self, forKey: .peerVerifyKey)
        self.lastBundleServedAt = try c.decodeIfPresent(Date.self, forKey: .lastBundleServedAt)
        // Codable path is used for previews/tests/in-memory snapshots,
        // not the on-disk schema (SQLite is the source of truth). Pre-v2
        // payloads omit provenance → default to `.unknown` so the UI
        // does not silently upgrade a non-verified contact to "scanned
        // in person" trust.
        self.addedVia = try c.decodeIfPresent(ContactSource.self, forKey: .addedVia) ?? .unknown
        self.verifiedAt = try c.decodeIfPresent(Date.self, forKey: .verifiedAt)
        self.mutedAt = try c.decodeIfPresent(Date.self, forKey: .mutedAt)
        self.outboundTokenChain = try c.decodeIfPresent(HashChainToken.Chain.self, forKey: .outboundTokenChain)
    }

    /// Explicit encode because the legacy `readReceiptsEnabled`
    /// CodingKey above is decode-only (we read it as fallback for
    /// pre-3-state payloads). Synthesised encode would try to emit a
    /// matching property that no longer exists. Everything else is
    /// the standard one-key-per-property pass.
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(identityPub, forKey: .identityPub)
        try c.encode(displayName, forKey: .displayName)
        try c.encode(sessionEstablished, forKey: .sessionEstablished)
        try c.encode(log, forKey: .log)
        try c.encodeIfPresent(lastMessageAt, forKey: .lastMessageAt)
        try c.encodeIfPresent(lastSeenAt, forKey: .lastSeenAt)
        try c.encode(addedAt, forKey: .addedAt)
        try c.encodeIfPresent(lastChainServedAt, forKey: .lastChainServedAt)
        try c.encode(ttlSeconds, forKey: .ttlSeconds)
        try c.encode(readReceiptsMode, forKey: .readReceiptsMode)
        try c.encodeIfPresent(peerVerifyKey, forKey: .peerVerifyKey)
        try c.encodeIfPresent(lastBundleServedAt, forKey: .lastBundleServedAt)
        try c.encode(addedVia, forKey: .addedVia)
        try c.encodeIfPresent(verifiedAt, forKey: .verifiedAt)
        try c.encodeIfPresent(mutedAt, forKey: .mutedAt)
        try c.encodeIfPresent(outboundTokenChain, forKey: .outboundTokenChain)
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
    /// Sum of unread message counts across non-muted contacts. Drives
    /// the app-icon badge. Muted contacts still surface unread counts
    /// in their own row (so the user can see "I have N unread from
    /// Alice"), but they don't push that count to the home-screen
    /// badge — that's the entire point of muting.
    var totalUnread: Int {
        contacts.reduce(0) { acc, c in
            c.mutedAt == nil ? acc + c.unreadCount : acc
        }
    }
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

/// Three tiers of opt-in for received-attachment rendering. Stored in
/// `AppState.attachmentPreviewMode`. Off is the default for every new
/// install AND every upgrade — the strict no-parse posture is the
/// baseline; the user has to flip something to get bytes parsed by
/// Pizzini or by QuickLook.
///
/// `.inlineThumbnail` lives behind a separate explicit opt-in from
/// `.quickLook` because it parses incoming bytes inside Pizzini's
/// process (subject to the MIME whitelist + magic-byte + size-cap
/// guards in `AttachmentThumbnail`), whereas `.quickLook` only ever
/// hands a file URL to Apple's QuickLook XPC.
enum AttachmentPreviewMode: String, Codable, Sendable, CaseIterable {
    case off
    case quickLook
    case inlineThumbnail

    /// SQLCipher migration: the `settings.quicklook_preview_enabled`
    /// INTEGER column stored 0/1 before the three-tier rollout (legacy
    /// Bool); 2 is the new `.inlineThumbnail` value. Unknown integers
    /// land on `.off` — the strict default is the safe failure mode
    /// for an unexpected row.
    init(legacyInt value: Int) {
        switch value {
        case 1: self = .quickLook
        case 2: self = .inlineThumbnail
        default: self = .off
        }
    }

    var legacyIntValue: Int {
        switch self {
        case .off: return 0
        case .quickLook: return 1
        case .inlineThumbnail: return 2
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
    /// Three-tier opt-in for how received attachments render. Default
    /// `.off` — filename + icon + Save-to-Files only; Pizzini never
    /// parses incoming bytes. `.quickLook` adds a Preview button that
    /// pops `QLPreviewController` (Apple's sandboxed XPC). Tier 3,
    /// `.inlineThumbnail`, renders a tap-to-decode thumbnail in
    /// Pizzini's own process for whitelisted image MIMEs only — see
    /// `AttachmentThumbnail` for the size cap / magic-byte / timeout
    /// guards that gate the decode. Tier-3 widens the parser surface
    /// in exchange for one-tap visual identification; opt-in is
    /// explicit on every install.
    var attachmentPreviewMode: AttachmentPreviewMode
    /// When true, three fast taps anywhere on the chat-content area
    /// inside an open chat instantly deletes that chat (the
    /// per-contact log; the contact and the encryption session
    /// stay). Default OFF. Modelled on Bitchat's triple-tap-the-logo
    /// panic gesture, scoped to the chat the user is in rather than
    /// wiping the whole app.
    ///
    /// Why we ship it as off-by-default: an accidental triple-tap
    /// would silently destroy the chat with no undo. A user who
    /// understands and opts in accepts that trade-off in exchange
    /// for being able to scrub a chat in the time it takes to land
    /// three thumb taps.
    var panicModeEnabled: Bool
    /// Result of the most recent runtime self-test for the
    /// `isSecureTextEntry` workaround that powers the app-wide
    /// screenshot mask. Nil = not yet tested. True = the trick
    /// blocked the screenshot pipeline on this iOS version. False =
    /// the trick failed (Apple has narrowed the gap on this version)
    /// and the mask falls back to no-wrap — accessibility is
    /// preserved at the cost of the protection. Internal diagnostic
    /// only; not exposed as a Settings toggle (the mask is
    /// unconditionally on whenever it works).
    var qrBlockEffective: Bool?
    /// `UIDevice.current.systemVersion` at the time `qrBlockEffective`
    /// was determined. We re-run the self-test whenever the major
    /// component differs — Apple has only ever changed
    /// secure-text-entry behaviour in major iOS releases, and a re-test
    /// every minor would be wasteful.
    var qrBlockTestedOSVersion: String?

    /// Phase 6 group chats. Stored alongside `contacts`. A
    /// `ChatGroup` and a `Contact` can coexist for the same peerId
    /// (the contact is the 1:1 channel; the group is a separate
    /// surface). Pre-Phase-6 JSON blobs lack this field and decode
    /// to an empty array.
    var groups: [ChatGroup]

    /// When true, the contacts list renders 1:1 contacts ABOVE the
    /// groups section. Default true because most users open a 1:1
    /// chat more often than a group, and a long groups section
    /// pushed the contacts they cared about off the first viewport.
    /// Toggle exposed in `SettingsView`. Pending invitations always
    /// pin to the top regardless of this setting.
    var contactsBeforeGroups: Bool
    /// When true, a soft haptic fires on the device when a new
    /// message lands in a chat OTHER than the one currently open.
    /// No banner, no sound, no preview — the privacy-first messengers
    /// (Signal / WhatsApp / Threema / iMessage) all skip in-app
    /// banners because a "Alice: meet at 4pm" toast leaks content to
    /// anyone glancing at the screen, exactly the threat model
    /// Pizzini's screenshot-shield + no-thumbnails posture is built
    /// against. Default OFF: silent reliance on the badge + chat
    /// list updates is the safe default; the haptic is opt-in.
    var inAppHapticsEnabled: Bool

    /// App-wide default for "Tell {contact} when I read their messages".
    /// Per-contact `Contact.readReceiptsMode` overrides this per chat.
    /// Default OFF — privacy-first posture; surfaces in Settings →
    /// Privacy as a single switch the user can flip once instead of
    /// touching every chat. Toggling this here immediately affects
    /// every contact whose `readReceiptsMode == .followDefault`.
    var defaultReadReceiptsEnabled: Bool

    /// App-wide notifications mute. When true, the NSE refuses to
    /// bump the badge, the main app fires no haptic on receive, and
    /// the user sees no attention-grab surface until they open the
    /// app themselves. Messages still arrive and persist. The user-
    /// facing copy is "Pause notifications" (Settings → Notifications).
    /// Default OFF — privacy-first posture, but not the *attention*-
    /// first posture; users opt-in when they want quiet hours.
    var notificationsMuted: Bool

    /// Persistent block list. Identity-pub bytes of peers the user
    /// has explicitly blocked. Survives `deleteContact` → re-add
    /// cycles, so a removed peer who later re-pairs the same
    /// identityPub stays blocked. Inbound bundles, tokens, sealed
    /// SENDs, and BUNDLE_REQUESTs from a blocked identity are
    /// dropped at the receive-side gate. Distinct from `deleteContact`
    /// (which only removes the row).
    var blockedIdentities: [Data]

    static let currentVersion = 1
    // Empty = use the bundled trusted-onion fleet from
    // `RelayRegistry.trusted` (D5 default). A non-empty value is a
    // BYO override: the user typed an address into Settings →
    // Custom relay, and we treat it verbatim as a single-relay
    // target (dev `127.0.0.1`, community-run onions, etc.). See
    // `docs/relay-architecture.md` D5 for the override contract.
    static let defaultRelayHost = ""

    init(
        version: Int = currentVersion,
        relayHost: String = defaultRelayHost,
        contacts: [Contact] = [],
        onboardingCompleted: Bool = false,
        biometricLockEnabled: Bool = false,
        autoLockTimeout: AutoLockTimeout = .immediately,
        attachmentPreviewMode: AttachmentPreviewMode = .off,
        panicModeEnabled: Bool = false,
        qrBlockEffective: Bool? = nil,
        qrBlockTestedOSVersion: String? = nil,
        groups: [ChatGroup] = [],
        contactsBeforeGroups: Bool = true,
        inAppHapticsEnabled: Bool = false,
        defaultReadReceiptsEnabled: Bool = false,
        notificationsMuted: Bool = false,
        blockedIdentities: [Data] = []
    ) {
        self.version = version
        self.relayHost = relayHost
        self.contacts = contacts
        self.onboardingCompleted = onboardingCompleted
        self.biometricLockEnabled = biometricLockEnabled
        self.autoLockTimeout = autoLockTimeout
        self.attachmentPreviewMode = attachmentPreviewMode
        self.panicModeEnabled = panicModeEnabled
        self.qrBlockEffective = qrBlockEffective
        self.qrBlockTestedOSVersion = qrBlockTestedOSVersion
        self.groups = groups
        self.contactsBeforeGroups = contactsBeforeGroups
        self.inAppHapticsEnabled = inAppHapticsEnabled
        self.defaultReadReceiptsEnabled = defaultReadReceiptsEnabled
        self.notificationsMuted = notificationsMuted
        self.blockedIdentities = blockedIdentities
    }

    /// Legacy JSON keys that earlier builds wrote but the current
    /// build no longer encodes. Read at decode time for migration, in
    /// a separate container so `encode(to:)` doesn't re-emit them.
    private enum LegacyCodingKeys: String, CodingKey {
        case quickLookPreviewEnabled
    }

    private enum CodingKeys: String, CodingKey {
        case version
        case relayHost
        case contacts
        case onboardingCompleted
        case biometricLockEnabled
        case autoLockTimeout
        case attachmentPreviewMode
        case panicModeEnabled
        case qrBlockEffective
        case qrBlockTestedOSVersion
        case groups
        case contactsBeforeGroups
        case inAppHapticsEnabled
        case defaultReadReceiptsEnabled
        case notificationsMuted
        case blockedIdentities
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        relayHost = try c.decode(String.self, forKey: .relayHost)
        contacts = try c.decode([Contact].self, forKey: .contacts)
        onboardingCompleted = try c.decodeIfPresent(Bool.self, forKey: .onboardingCompleted) ?? false
        biometricLockEnabled = try c.decodeIfPresent(Bool.self, forKey: .biometricLockEnabled) ?? false
        autoLockTimeout = try c.decodeIfPresent(AutoLockTimeout.self, forKey: .autoLockTimeout) ?? .immediately
        // Three-tier mode supersedes the prior `quickLookPreviewEnabled`
        // Bool. Newer blobs carry the explicit enum; older blobs carry
        // the Bool, where true → `.quickLook`, false / absent → `.off`.
        // Preserves the user's existing choice across the upgrade — a
        // user who opted into QuickLook stays opted in, a user who
        // never opted in stays on the strict default. The legacy key
        // is read via a separate `LegacyKeys` container so it doesn't
        // pollute the synthesized `encode(to:)`; the field is not
        // re-emitted on next write.
        if let mode = try c.decodeIfPresent(AttachmentPreviewMode.self, forKey: .attachmentPreviewMode) {
            attachmentPreviewMode = mode
        } else {
            let legacyContainer = try decoder.container(keyedBy: LegacyCodingKeys.self)
            if let legacy = try legacyContainer.decodeIfPresent(Bool.self, forKey: .quickLookPreviewEnabled) {
                attachmentPreviewMode = legacy ? .quickLook : .off
            } else {
                attachmentPreviewMode = .off
            }
        }
        panicModeEnabled = try c.decodeIfPresent(Bool.self, forKey: .panicModeEnabled) ?? false
        qrBlockEffective = try c.decodeIfPresent(Bool.self, forKey: .qrBlockEffective)
        qrBlockTestedOSVersion = try c.decodeIfPresent(String.self, forKey: .qrBlockTestedOSVersion)
        groups = try c.decodeIfPresent([ChatGroup].self, forKey: .groups) ?? []
        contactsBeforeGroups = try c.decodeIfPresent(Bool.self, forKey: .contactsBeforeGroups) ?? true
        inAppHapticsEnabled = try c.decodeIfPresent(Bool.self, forKey: .inAppHapticsEnabled) ?? false
        defaultReadReceiptsEnabled = try c.decodeIfPresent(Bool.self, forKey: .defaultReadReceiptsEnabled) ?? false
        notificationsMuted = try c.decodeIfPresent(Bool.self, forKey: .notificationsMuted) ?? false
        blockedIdentities = try c.decodeIfPresent([Data].self, forKey: .blockedIdentities) ?? []
        // Pre-existing JSON blobs from earlier builds may carry the
        // `notifyPeerOnScreenshot`, `blockQRScreenshots`,
        // `blockChatScreenshots`, and `blockAppScreenshots` keys.
        // JSONDecoder silently ignores unknown keys, so those blobs
        // load cleanly and the legacy keys are dropped on the next
        // encode. No migration code needed.
    }
}
