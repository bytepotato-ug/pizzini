import Foundation
import PizziniCryptoCore

/// One Pizzini group. The group ID is a stable random 16-byte value
/// generated at creation; it is NOT derived from the member list, so
/// renames and membership changes do not change the identity. Groups
/// are local constructs on each member's device — synchronisation is
/// via signed `GroupOp` log entries broadcast over the existing 1:1
/// sealed-sender channels (no new relay protocol).
///
/// **Trust anchor.** A member's view of the group's identity-key
/// bindings is only as strong as their weakest 1:1 verification. The
/// group invite flow is admin-only: the only way to be added is by an
/// existing admin who has already QR-paired with you 1:1. Other group
/// members you have not personally verified appear in the group info
/// screen with an explicit "added by X — you have not verified Y in
/// person" label so the user can never confuse "transitively trusted"
/// with "I scanned them in person."
///
/// **Sender keys.** libsignal's group cipher keys each chain by
/// `(sender, distribution_id)`. The distribution_id is per-chain, NOT
/// per-group: when a member rotates (member-remove or periodic
/// hygiene) they pick a fresh random `UUID` and broadcast a new SKDM.
/// Old chains stay in libsignal's store so late-arriving ciphertext
/// still decrypts; receivers update their `memberDistributionIds`
/// table on every `RotateSenderKey` op they apply. See
/// `crypto-core/tests/group_cipher.rs::rotation_excludes_removed_member`
/// for the round-trip semantics.
struct ChatGroup: Codable, Identifiable, Sendable {
    /// 16-byte stable identifier. Rendered to the user as a short
    /// fingerprint when needed (e.g. group-conflict warnings).
    let id: Data

    /// Human-readable name. Last `Rename` op wins.
    var displayName: String

    /// Active and pending members, including self. Order is the order
    /// in which members were added — display layers may re-sort.
    var members: [GroupMember]

    /// `Date` derived from the timestamp of the `Create` op. Local
    /// display only; never trusted for security decisions (the parent
    /// digest hash-chain in `GroupOp` is what orders ops).
    let createdAt: Date

    /// Epoch of the most recently *applied* op. Newly-arriving ops
    /// must have `epoch == currentEpoch + 1` and a `parentDigest`
    /// matching `lastOpDigest`; everything else queues into
    /// `pendingOps` until the gap closes (or surfaces as an
    /// equivocation warning if two ops claim the same epoch from
    /// different operators).
    var currentEpoch: UInt64

    /// 32-byte BLAKE3 digest of the most recently applied signed op.
    /// Empty for a freshly-created group whose `Create` op has not
    /// landed yet (`ChatGroup(...)` constructed locally before broadcast).
    var lastOpDigest: Data

    /// Ops we received but cannot yet apply because of an epoch gap.
    /// Stored as the signed wire bytes — the op's own signature covers
    /// integrity, so persisting the raw blob is both safe and simpler
    /// than threading `Codable` conformance through `GroupOpKind`'s
    /// associated-value cases. Decode + verify on each application
    /// attempt; drop after `ChatGroup.pendingOpRetention` (
    /// fix — the retention is now actually enforced by `replayPending`).
    var pendingOps: [Data]

    /// Chat history for this group. Same shape as `Contact.log` so the
    /// existing chat-view rendering applies unchanged.
    var log: [PersistedMessage]

    /// Wall-clock the user last opened this group. Drives unread
    /// counting the same way `Contact.lastSeenAt` does.
    var lastSeenAt: Date?

    /// Wall-clock of the most recent log entry — sent or received.
    /// Mirror of `Contact.lastMessageAt`; drives the chronological
    /// sort in the merged groups+contacts list view.
    var lastMessageAt: Date?

    /// Our local sender-key chain id for THIS group's most recent
    /// rotation. Optional because a `ChatGroup` constructed from a
    /// remote `Create` op exists before the local user has had a
    /// chance to mint a chain — the host sets this after calling the
    /// FFI's `sender_key_distribution_create(...)`. On every rotation
    /// (member-remove, periodic hygiene, manual reset) the host swaps
    /// in a fresh `UUID` and broadcasts the corresponding SKDM.
    /// Persisting the value lets us continue encrypting under the same
    /// chain after a relaunch (see also
    /// `crypto-core/tests/group_cipher.rs::alice_round_trips_her_own_sender_key_chain_across_relaunch`).
    var myCurrentDistributionId: UUID?

    /// `peerId → currentDistributionId` for every other member whose
    /// SKDM we have already processed. Updated whenever a peer
    /// broadcasts a `RotateSenderKey` op.
    ///
    /// On-disk shape note: `JSONEncoder` serializes non-`String`/`Int`
    /// keyed dictionaries as alternating-element arrays, so this
    /// persists as `[base64_peerId, uuid_str, base64_peerId, uuid_str, ...]`.
    /// Round-trips cleanly; the choice of `Data`-typed key is
    /// deliberate to avoid hex-encoding noise at every read site.
    var memberDistributionIds: [Data: UUID]

    /// Counter advanced by every successful `group_encrypt` from this
    /// device. Crosses `ChatGroup.rotationMessageThreshold` triggers a
    /// rotation. Reset on rotation.
    var sentSinceRotation: UInt32

    /// When we last rotated our own sender-key chain. Used together
    /// with `ChatGroup.rotationTimeThreshold` to decide periodic rotation.
    var lastRotatedAt: Date

    /// Peers we have already broadcast our CURRENT (post-most-recent-
    /// rotation) sender-key chain to. Reset to empty on every
    /// rotation; populated as we ship SKDM envelopes via
    /// `broadcastSenderKeyDistribution`. The "after-apply" hook in
    /// `ChatStoreGroups` consults this to ship our SKDM to any
    /// newly-active member who isn't yet in the set — closing
    /// audit-finding HIGH-2 (bidirectional SKDM exchange).
    ///
    /// On-disk shape: same alternating-array pattern as
    /// `memberDistributionIds` above. Persisted because a rotation
    /// happens once per session at most and the cost of rebroadcasting
    /// to everyone after every relaunch would burn delivery tokens.
    var mySkdmRecipients: Set<Data>

    /// True for groups we've received a `Create` op (or
    /// `GroupBootstrap`) for from an admin, but the local user has
    /// not yet tapped "Join" on the invitation. While pending:
    ///   - The local user has NOT enrolled their own sender-key
    ///     chain (`myCurrentDistributionId` stays nil).
    ///   - We do NOT broadcast SKDMs outward — peers see us as
    ///     `.pendingSKDM` until we accept.
    ///   - We DO install incoming SKDMs from peers so the chains
    ///     are ready immediately on accept; we DO apply incoming
    ///     ops so the membership / name state stays in sync with
    ///     the admin's broadcasts.
    ///   - We do NOT decrypt incoming `groupChat` messages
    ///     (`handleGroupChat` gates on this flag) and we do NOT
    ///     allow `sendGroupMessage`.
    ///
    /// On accept: the host clears the flag and runs
    /// `enrolMyChainOnFirstJoin`. On decline: the host deletes the
    /// local group; remaining members keep showing us as
    /// `.pendingSKDM` until they manually rotate or remove us
    /// (consistent with `leaveGroup` — peer-to-peer can't enforce
    /// removal at the other end).
    ///
    /// Optional via `decodeIfPresent`-with-default-false so existing
    /// on-disk blobs decode cleanly: groups already created before
    /// the invitation flow shipped continue to behave exactly as
    /// before (auto-joined).
    var pendingInvitation: Bool

    /// Bounded sliding window of `epoch → digest(signed op)` for the
    /// most recently applied ops. Used to detect equivocation: if we
    /// receive an op at an already-applied epoch with a *different*
    /// digest from the one we cached, the operator is forking the
    /// log. Older entries past the window are forgotten — at that
    /// point the equivocation is already moot because we've moved
    /// far enough that the divergent branch can no longer be
    /// applied.
    ///
    /// Keyed by `String(epoch)` rather than `UInt64` because Swift's
    /// `JSONEncoder` is the on-disk serialiser ([Storage.swift:89](pizzini/pizzini/Storage.swift:89))
    /// and it represents non-String/Int dictionary keys as alternating
    /// key/value arrays, which produces a readable blob only when the
    /// key is a string or the dictionary is empty. The accessors
    /// `digest(forEpoch:)` and `recordDigest(_:atEpoch:)` hide the
    /// stringification.
    var recentOpDigests: [String: Data]

    func digest(forEpoch epoch: UInt64) -> Data? {
        recentOpDigests[String(epoch)]
    }

    mutating func recordDigest(_ digest: Data, atEpoch epoch: UInt64) {
        recentOpDigests[String(epoch)] = digest
        // Bounded sliding window. The window is checked AND trimmed at
        // every insertion so the steady-state size is exactly
        // `recentOpDigestsWindow` rather than oscillating between half
        // and double that. Cost is one filter pass over the window
        // each time it overflows — amortised O(1) per insertion since
        // the trim only fires on growth.
        if recentOpDigests.count > ChatGroup.recentOpDigestsWindow {
            let cutoff = epoch >= UInt64(ChatGroup.recentOpDigestsWindow)
                ? epoch - UInt64(ChatGroup.recentOpDigestsWindow) + 1
                : 0
            recentOpDigests = recentOpDigests.filter { entry in
                guard let e = UInt64(entry.key) else { return false }
                return e >= cutoff
            }
        }
    }

    // ─── Constants ─────────────────────────────────────────────────────

    /// Hard cap on group size. Larger groups churn rotation traffic
    /// without bringing meaningful new utility for the activist threat
    /// model. Mirrors Signal's classic group-v2 cap.
    static let maxMembers: Int = 50

    /// Periodic sender-key rotation: time bound. After this much
    /// wall-clock since `lastRotatedAt`, the next outgoing message
    /// triggers a rotation. Bounds the post-compromise window for an
    /// exfiltrated chain key to one week.
    static let rotationTimeThreshold: TimeInterval = 7 * 24 * 60 * 60

    /// Periodic sender-key rotation: message-count bound. After this
    /// many successful sends since the last rotation, the next
    /// outgoing message triggers a rotation. 256 is a clean
    /// power-of-two chain length and well within libsignal's safe
    /// SenderKey operating range.
    static let rotationMessageThreshold: UInt32 = 256

    /// How long an unappliable `pendingOp` lingers before we drop it.
    /// 30 days mirrors the SenderCertificate / delivery-token TTL —
    /// any op older than that whose parent never arrived is almost
    /// certainly lost to a relay outage and re-application would
    /// corrupt state.
    static let pendingOpRetention: TimeInterval = 30 * 24 * 60 * 60

    /// Equivocation-detection window. A divergent op at an
    /// already-applied epoch is caught only when the original op's
    /// digest is still cached. Bumped from the original 1024 to
    /// 16384 after the audit identified that membership-stable groups
    /// produce orders of magnitude more ops than the rotation rate
    /// alone (every message advances the cache via op-chain apply).
    /// 16384 entries × 32 bytes = 512 KiB per group, which is well
    /// within budget for a single-digit number of active groups per
    /// device.
    static let recentOpDigestsWindow: Int = 16_384

    /// Bound on `pendingOps` — future-epoch ops awaiting their parents.
    /// A malicious peer could otherwise stuff us with
    /// signed-but-never-appliable ops; 1024 is well past any plausible
    /// legitimate gap (a member offline catching up).
    static let pendingOpsCap: Int = 1024

    /// Per-operator sub-cap on `pendingOps`. Each admin
    /// can occupy at most this many queue slots; the global cap
    /// (`pendingOpsCap`) bounds the total. Without the sub-cap, one
    /// compromised admin could fill the queue with future-epoch ops
    /// and pin legitimate ops from every other admin out forever.
    /// 64 leaves ~16 admins worth of room before we trip the global
    /// cap, which is well above the realistic admin count for a
    /// healthy group.
    static let pendingOpsPerOperatorCap: Int = 64

    /// Convenience accessor: the active members (excluding `.removed`
    /// rows we keep around for op-log integrity).
    var activeMembers: [GroupMember] {
        members.filter { $0.status != .removed }
    }

    /// Domain-separated canonical hash of the current member set
    /// Verifiable group membership. Stable across every
    /// participant's local view of the same group state — feed it
    /// into the next outgoing `GroupOp.priorMemberSetRoot` so the
    /// receiver's `apply` step can detect equivocation (a "ghost
    /// member" silently added on the sender's side will not appear
    /// in the receiver's local computation, and the apply rejects).
    var memberSetRoot: Data {
        ChatGroup.memberSetRoot(of: members)
    }

    /// Pure form — accepts any member list. Used by tests, by the
    /// bootstrap snapshot codec (which carries its own `members`),
    /// and by `apply` when checking against an op's witness root.
    ///
    /// Encoding (BLAKE3 input, fixed-width per member so the output
    /// is order-independent of every field but `peerId`):
    ///
    /// ```text
    /// domain_tag        ("pizzini.group.member-set.v1")
    /// u32_be(count)
    /// for each member, sorted ascending by peerId bytes:
    ///   [33] peerId
    ///   u8   role.wireByte        (0 = member, 1 = admin)
    ///   u64_be joinedAtEpoch
    ///   u8   status.canonicalRootByte  (0 = removed, 1 otherwise)
    ///   [33] addedBy              (all-zero if nil)
    /// ```
    ///
    /// `displayName` is intentionally absent — receivers may override
    /// the display name locally (audit notes around `GroupMember`),
    /// which would diverge the root across views. Likewise
    /// `pendingSKDM` collapses to `active` (transient SKDM
    /// handshake state that doesn't reach the signed-op log).
    static func memberSetRoot(of members: [GroupMember]) -> Data {
        let domainTag = Data("pizzini.group.member-set.v1".utf8)
        let sorted = members.sorted { a, b in
            byteLexLess(a.peerId, b.peerId)
        }
        var input = Data(capacity: domainTag.count + 4 + sorted.count * 76)
        input.append(domainTag)
        input.appendBigEndian(UInt32(sorted.count))
        let zeroAddedBy = Data(repeating: 0, count: GroupOp.identityKeySize)
        for m in sorted {
            // peerId is the trust anchor — every legitimate member row
            // carries exactly 33 bytes. Guard at the encoder so a
            // corrupted on-disk row surfaces as a different (still
            // deterministic) root rather than a silent hash mismatch
            // with somebody else's view.
            precondition(
                m.peerId.count == GroupOp.identityKeySize,
                "GroupMember.peerId must be \(GroupOp.identityKeySize) bytes"
            )
            input.append(m.peerId)
            input.append(m.role.wireByte)
            input.appendBigEndian(m.joinedAtEpoch)
            input.append(m.status.canonicalRootByte)
            if let added = m.addedBy {
                if added.count == GroupOp.identityKeySize {
                    input.append(added)
                } else {
                    // A corrupted `addedBy` (wrong length) shouldn't
                    // panic the chat list — fall back to the "not
                    // recorded" zero block. The local view's root
                    // will still be self-consistent; if the row was
                    // genuinely tampered the equivocation check
                    // surfaces the divergence.
                    input.append(zeroAddedBy)
                }
            } else {
                input.append(zeroAddedBy)
            }
        }
        return Blake3.hash(input)
    }


    /// Role of `identityPub` in this group, if they are an active
    /// member. The local user's role is derived from this by passing
    /// `store.myCard.identityPub` — the local identity is not stored
    /// inside `ChatGroup` because the auto-synthesized memberwise
    /// initialiser collapses to `private` if any stored property is
    /// `private`, which would block the bootstrap constructor in
    /// `GroupApply.swift` from constructing instances.
    func role(of identityPub: Data) -> GroupRole? {
        members.first(where: { $0.peerId == identityPub })?.role
    }

    /// Receive-side trust gate. Mirrors the inline check at the head
    /// of `handleGroupChat` and `handleGroupFileChunk` (audit
    /// CRITICAL-2): the sender must be an active, non-removed member
    /// of this group. A peer who is not in `members` at all, or is in
    /// the list with `.removed` status, MUST NOT be able to inject
    /// content into the group log even if they're 1:1-paired with us.
    func acceptsIncomingMessage(from senderPeerId: Data) -> Bool {
        members.contains { $0.peerId == senderPeerId && $0.status != .removed }
    }

    /// Send-side trust gate. The local user can post to this group
    /// only if they are an active member, the invitation is no
    /// longer pending, AND they have minted a sender-key chain (no
    /// chain ⇒ no peer can decrypt our output). The composer in
    /// `GroupChatView` and the runtime guards in `sendGroupMessage`
    /// / `sendGroupAttachment` both consult this so the UI affordance
    /// and the wire-level guard never drift.
    func canSend(asLocal localIdentity: Data) -> Bool {
        guard !pendingInvitation else { return false }
        guard myCurrentDistributionId != nil else { return false }
        return members.contains {
            $0.peerId == localIdentity && $0.status != .removed
        }
    }

    /// Append a fully-reassembled inbound attachment to this group's
    /// log and return the persisted row. Centralises the
    /// `PersistedMessage` shape so the receive path can't drift from
    /// the 1:1 attachment row layout — `senderPeerId` is mandatory
    /// (group rendering depends on it for member-name resolution; see
    /// `GroupChatView.senderName(for:in:)`).
    @discardableResult
    mutating func appendIncomingAttachment(
        attachmentId: Data,
        filename: String,
        byteSize: UInt64,
        mime: String,
        tier: AttachmentTier,
        sandboxRelativePath: String?,
        senderPeerId: Data,
    ) -> PersistedMessage {
        let info = AttachmentInfo(
            attachmentId: attachmentId,
            filename: filename,
            byteSize: byteSize,
            mime: mime,
            tier: tier,
            sandboxRelativePath: sandboxRelativePath,
            isInbound: true,
        )
        let row = PersistedMessage(
            side: .peer,
            text: "",
            kind: .attachment,
            bytes: Int(byteSize),
            attachment: info,
            senderPeerId: senderPeerId,
        )
        log.append(row)
        lastMessageAt = row.timestamp
        return row
    }

    /// Decoder is hand-rolled so additive fields land with sensible
    /// defaults on existing on-disk blobs (`mySkdmRecipients` was added
    /// post-audit; older blobs lack it). Synthesizing would otherwise
    /// fail to decode.
    private enum CodingKeys: String, CodingKey {
        case id, displayName, members, createdAt, currentEpoch, lastOpDigest
        case pendingOps, log, lastSeenAt, lastMessageAt
        case myCurrentDistributionId, memberDistributionIds, sentSinceRotation
        case lastRotatedAt, mySkdmRecipients, recentOpDigests, pendingInvitation
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(Data.self, forKey: .id)
        self.displayName = try c.decode(String.self, forKey: .displayName)
        self.members = try c.decode([GroupMember].self, forKey: .members)
        self.createdAt = try c.decode(Date.self, forKey: .createdAt)
        self.currentEpoch = try c.decode(UInt64.self, forKey: .currentEpoch)
        self.lastOpDigest = try c.decode(Data.self, forKey: .lastOpDigest)
        self.pendingOps = try c.decode([Data].self, forKey: .pendingOps)
        self.log = try c.decode([PersistedMessage].self, forKey: .log)
        self.lastSeenAt = try c.decodeIfPresent(Date.self, forKey: .lastSeenAt)
        self.lastMessageAt = try c.decodeIfPresent(Date.self, forKey: .lastMessageAt)
        self.myCurrentDistributionId = try c.decodeIfPresent(UUID.self, forKey: .myCurrentDistributionId)
        self.memberDistributionIds = try c.decodeIfPresent([Data: UUID].self, forKey: .memberDistributionIds) ?? [:]
        self.sentSinceRotation = try c.decode(UInt32.self, forKey: .sentSinceRotation)
        self.lastRotatedAt = try c.decode(Date.self, forKey: .lastRotatedAt)
        self.mySkdmRecipients = try c.decodeIfPresent(Set<Data>.self, forKey: .mySkdmRecipients) ?? []
        self.recentOpDigests = try c.decode([String: Data].self, forKey: .recentOpDigests)
        // Default false so groups created before the invitation flow
        // shipped continue to behave exactly as before (auto-joined).
        self.pendingInvitation = try c.decodeIfPresent(Bool.self, forKey: .pendingInvitation) ?? false
    }

    /// Synthesised-style memberwise init kept explicit because the
    /// custom `init(from:)` above suppresses the implicit one.
    /// `ChatGroup.create(fromCreate:...)` and the receive-side
    /// bootstrap path call this directly.
    init(
        id: Data,
        displayName: String,
        members: [GroupMember],
        createdAt: Date,
        currentEpoch: UInt64,
        lastOpDigest: Data,
        pendingOps: [Data],
        log: [PersistedMessage],
        lastSeenAt: Date?,
        lastMessageAt: Date?,
        myCurrentDistributionId: UUID?,
        memberDistributionIds: [Data: UUID],
        sentSinceRotation: UInt32,
        lastRotatedAt: Date,
        mySkdmRecipients: Set<Data> = [],
        recentOpDigests: [String: Data],
        pendingInvitation: Bool = false
    ) {
        self.id = id
        self.displayName = displayName
        self.members = members
        self.createdAt = createdAt
        self.currentEpoch = currentEpoch
        self.lastOpDigest = lastOpDigest
        self.pendingOps = pendingOps
        self.log = log
        self.lastSeenAt = lastSeenAt
        self.lastMessageAt = lastMessageAt
        self.myCurrentDistributionId = myCurrentDistributionId
        self.memberDistributionIds = memberDistributionIds
        self.sentSinceRotation = sentSinceRotation
        self.lastRotatedAt = lastRotatedAt
        self.mySkdmRecipients = mySkdmRecipients
        self.recentOpDigests = recentOpDigests
        self.pendingInvitation = pendingInvitation
    }
}

/// One row in `ChatGroup.members`. `peerId` is the trust anchor (33-byte
/// serialized libsignal IdentityKey, identical to `Contact.identityPub`
/// for any contact you have a 1:1 session with).
struct GroupMember: Codable, Identifiable, Sendable, Equatable {
    /// 33-byte identity_pub. `id` for `Identifiable`.
    let peerId: Data

    /// Display name copied from the operator's local Contact at the
    /// time of `AddMember`. Receivers may override locally if they
    /// have their own `Contact` for this peer with a different name.
    var displayName: String

    var role: GroupRole

    /// The op epoch at which this member joined the group. Drives the
    /// "no history replay" rule — `PersistedMessage`s with
    /// `groupEpoch < joinedAtEpoch` are filtered out of this member's
    /// view (in practice, never delivered to them in the first place,
    /// but the local invariant catches replay attempts).
    var joinedAtEpoch: UInt64

    var status: MemberStatus

    /// Identity-pub of the admin who introduced this member to the
    /// group — the operator of the `Create` op for initial members,
    /// or of the `AddMember` op for subsequently-added members. Used
    /// by `GroupSettingsView` to render the "added by X — not verified
    /// in person" caption from design point 2 (audit MEDIUM-2).
    /// Optional because pre-audit ChatGroup blobs on disk lack the
    /// field; the next op the user receives that mutates the row
    /// repopulates it. `nil` is rendered as a generic "added by
    /// another admin" caption.
    var addedBy: Data?

    var id: Data { peerId }

    private enum CodingKeys: String, CodingKey {
        case peerId, displayName, role, joinedAtEpoch, status, addedBy
    }

    init(
        peerId: Data,
        displayName: String,
        role: GroupRole,
        joinedAtEpoch: UInt64,
        status: MemberStatus,
        addedBy: Data? = nil
    ) {
        self.peerId = peerId
        self.displayName = displayName
        self.role = role
        self.joinedAtEpoch = joinedAtEpoch
        self.status = status
        self.addedBy = addedBy
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.peerId = try c.decode(Data.self, forKey: .peerId)
        self.displayName = try c.decode(String.self, forKey: .displayName)
        self.role = try c.decode(GroupRole.self, forKey: .role)
        self.joinedAtEpoch = try c.decode(UInt64.self, forKey: .joinedAtEpoch)
        self.status = try c.decode(MemberStatus.self, forKey: .status)
        self.addedBy = try c.decodeIfPresent(Data.self, forKey: .addedBy)
    }
}

enum GroupRole: String, Codable, Sendable {
    case admin
    case member
}

/// Strict byte-lexicographic less-than over two `Data` slices.
/// Used to sort members by `peerId` when computing the canonical
/// member-set root — Swift's default `Data` `<` operator is not
/// defined for general byte arrays, and we need a stable order
/// across platforms / architectures (the relay and Rust core hash
/// the same encoding in a separate fork-proof check, so iOS-side
/// sort stability is the only correctness lever here).
func byteLexLess(_ a: Data, _ b: Data) -> Bool {
    let n = min(a.count, b.count)
    for i in 0..<n {
        let ai = a[a.startIndex + i]
        let bi = b[b.startIndex + i]
        if ai != bi { return ai < bi }
    }
    return a.count < b.count
}

enum MemberStatus: String, Codable, Sendable {
    /// SKDM exchanged in both directions; can encrypt and decrypt.
    case active
    /// `AddMember` op applied locally, but we have not yet sent or
    /// received the SKDMs that would let us decrypt their messages.
    /// Renders as a hourglass in the member list, like
    /// `Contact.sessionEstablished == false` does for 1:1.
    case pendingSKDM
    /// The member was removed by an admin. Kept in the list (rather
    /// than deleted) so the op-log replay reconstructs a consistent
    /// history; UI hides them from `activeMembers`.
    case removed
}
