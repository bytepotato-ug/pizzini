import Foundation
import PizziniCryptoCore

/// Signed group-membership snapshot used to bootstrap a newly-added
/// member's local `ChatGroup` row when they receive an `AddMember` op
/// for a group they have never seen.
///
/// **Why this exists.** The pre-audit code dropped any non-Create op
/// addressed to a group we don't know — so a newcomer received the
/// signed `AddMember` op (broadcast to every current member + the
/// newcomer) but had no way to derive the rest of the group state
/// (other members, current epoch, last digest, name). The audit's
/// HIGH-7 finding documented this as a hard gap.
///
/// **What this is.** A `GroupBootstrap` is a signed point-in-time
/// snapshot the inviting admin produces alongside an `AddMember` op.
/// It carries the post-AddMember state — display name, member roster
/// (with roles, statuses, joinedAtEpoch, addedBy), `currentEpoch`,
/// `lastOpDigest` — and is signed by the admin's identity key. The
/// recipient verifies the signature, verifies the admin is in their
/// 1:1 contacts (the same trust-anchor check that gates Create), and
/// constructs a fresh `ChatGroup` from the snapshot.
///
/// **What this is not.** Not a history-replay primitive — the
/// snapshot does not carry message logs or the op chain. The
/// newcomer sees no messages from before they joined (design point 6,
/// "no history replay when re-added"). Future ops apply normally
/// from the snapshot's `currentEpoch + 1`.
///
/// **Wire format (`bootstrap_version = 1`, big-endian):**
///
/// ```text
/// header (covered by signature):
///   u8   bootstrap_version = 1
///   [16] groupId
///   u64  currentEpoch
///   [32] lastOpDigest
///   [33] operatorIdentityPub          (the issuing admin)
///   u64  timestampMillis
///   u16  nameLen + nameBytes (UTF-8)
///   u8   memberCount                  (≤ ChatGroup.maxMembers)
///   for each member:
///     [33] peerId
///     u8   role                       (0 = member, 1 = admin)
///     u8   status                     (0 = active, 1 = pendingSKDM, 2 = removed)
///     u64  joinedAtEpoch
///     u8   hasAddedBy                 (0 or 1)
///     [33] addedBy                    (only if hasAddedBy = 1)
///     u16  displayNameLen + bytes
/// trailer:
///   [64] signature                    (XEd25519 over the header bytes
///                                        by operatorIdentityPub)
/// ```
struct GroupBootstrap: Sendable, Equatable {
    let groupId: Data
    let displayName: String
    let members: [GroupMember]
    let currentEpoch: UInt64
    let lastOpDigest: Data
    let operatorIdentity: Data
    let timestampMillis: UInt64
    let signature: Data

    static let bootstrapVersion: UInt8 = 1

    /// Encode the full signed wire bytes (header + signature). Used by
    /// the issuing admin to seal into the inner-envelope `0x09` body.
    func encoded() throws -> Data {
        var out = try encodedHeader()
        guard signature.count == GroupOp.signatureSize else {
            throw GroupBootstrapError.malformed("signature must be \(GroupOp.signatureSize) bytes")
        }
        out.append(signature)
        return out
    }

    /// Header bytes — the bytes the signature is computed over. Used
    /// by the host to sign once and assemble the full bootstrap via
    /// `signed(...)`. Also re-encoded on the receive side and fed to
    /// `verifySignature()` to re-derive the canonical bytes.
    func encodedHeader() throws -> Data {
        guard groupId.count == GroupOp.groupIdSize else {
            throw GroupBootstrapError.malformed("groupId must be \(GroupOp.groupIdSize) bytes")
        }
        guard lastOpDigest.count == GroupOp.parentDigestSize else {
            throw GroupBootstrapError.malformed("lastOpDigest must be \(GroupOp.parentDigestSize) bytes")
        }
        guard operatorIdentity.count == GroupOp.identityKeySize else {
            throw GroupBootstrapError.malformed("operatorIdentity must be \(GroupOp.identityKeySize) bytes")
        }
        guard members.count <= ChatGroup.maxMembers else {
            throw GroupBootstrapError.malformed("member count exceeds maxMembers (\(ChatGroup.maxMembers))")
        }

        var out = Data(capacity: 256 + members.count * 90)
        out.append(GroupBootstrap.bootstrapVersion)
        out.append(groupId)
        out.appendBigEndian(currentEpoch)
        out.append(lastOpDigest)
        out.append(operatorIdentity)
        out.appendBigEndian(timestampMillis)
        try writeUTF8U16LenBlob(&out, displayName)
        out.append(UInt8(members.count))
        for m in members {
            guard m.peerId.count == GroupOp.identityKeySize else {
                throw GroupBootstrapError.malformed("member peerId must be \(GroupOp.identityKeySize) bytes")
            }
            out.append(m.peerId)
            out.append(m.role.wireByte)
            out.append(m.status.wireByte)
            out.appendBigEndian(m.joinedAtEpoch)
            if let addedBy = m.addedBy {
                guard addedBy.count == GroupOp.identityKeySize else {
                    throw GroupBootstrapError.malformed("addedBy must be \(GroupOp.identityKeySize) bytes")
                }
                out.append(UInt8(1))
                out.append(addedBy)
            } else {
                out.append(UInt8(0))
            }
            try writeUTF8U16LenBlob(&out, m.displayName)
        }
        return out
    }

    /// Compose a snapshot with a freshly-computed signature. The
    /// caller computes the signature via `Session.identitySign` on the
    /// bytes of `encodedHeader()`; we just glue them together.
    static func signed(
        groupId: Data,
        displayName: String,
        members: [GroupMember],
        currentEpoch: UInt64,
        lastOpDigest: Data,
        operatorIdentity: Data,
        timestampMillis: UInt64,
        signature: Data,
    ) -> GroupBootstrap {
        GroupBootstrap(
            groupId: groupId,
            displayName: displayName,
            members: members,
            currentEpoch: currentEpoch,
            lastOpDigest: lastOpDigest,
            operatorIdentity: operatorIdentity,
            timestampMillis: timestampMillis,
            signature: signature,
        )
    }

    /// Verify the signature against `operatorIdentity`. The caller
    /// MUST also verify (a) the inner-envelope sender is exactly
    /// `operatorIdentity` (no forwarding) and (b) `operatorIdentity`
    /// is in the local 1:1 contacts list, before trusting the
    /// snapshot to bootstrap state.
    func verifySignature() throws -> Bool {
        let header = try encodedHeader()
        return try Session.verifyIdentitySignature(
            identityPub: operatorIdentity,
            message: header,
            signature: signature,
        )
    }

    /// Parse signed wire bytes. Returns nil for malformed input.
    static func decode(_ bytes: Data) -> GroupBootstrap? {
        var c = ByteCursor(bytes)
        guard let version: UInt8 = c.read(1)?.first else { return nil }
        guard version == GroupBootstrap.bootstrapVersion else { return nil }
        guard let groupId = c.read(GroupOp.groupIdSize) else { return nil }
        guard let currentEpoch: UInt64 = c.readBigEndian() else { return nil }
        guard let lastOpDigest = c.read(GroupOp.parentDigestSize) else { return nil }
        guard let operatorIdentity = c.read(GroupOp.identityKeySize) else { return nil }
        guard let timestampMillis: UInt64 = c.readBigEndian() else { return nil }
        guard let displayName = readUTF8U16LenBlob(&c) else { return nil }
        guard let memberCount: UInt8 = c.read(1)?.first else { return nil }
        guard Int(memberCount) <= ChatGroup.maxMembers else { return nil }
        var members: [GroupMember] = []
        members.reserveCapacity(Int(memberCount))
        for _ in 0..<Int(memberCount) {
            guard let peerId = c.read(GroupOp.identityKeySize) else { return nil }
            guard let roleByte: UInt8 = c.read(1)?.first else { return nil }
            guard let role = GroupRole(wireByte: roleByte) else { return nil }
            guard let statusByte: UInt8 = c.read(1)?.first else { return nil }
            guard let status = MemberStatus(wireByte: statusByte) else { return nil }
            guard let joinedAtEpoch: UInt64 = c.readBigEndian() else { return nil }
            guard let hasAddedBy: UInt8 = c.read(1)?.first else { return nil }
            let addedBy: Data?
            switch hasAddedBy {
            case 0:
                addedBy = nil
            case 1:
                guard let bytes = c.read(GroupOp.identityKeySize) else { return nil }
                addedBy = bytes
            default:
                return nil
            }
            guard let display = readUTF8U16LenBlob(&c) else { return nil }
            members.append(GroupMember(
                peerId: peerId,
                displayName: display,
                role: role,
                joinedAtEpoch: joinedAtEpoch,
                status: status,
                addedBy: addedBy,
            ))
        }
        guard let signature = c.read(GroupOp.signatureSize) else { return nil }
        guard c.isExhausted else { return nil }
        return GroupBootstrap(
            groupId: groupId,
            displayName: displayName,
            members: members,
            currentEpoch: currentEpoch,
            lastOpDigest: lastOpDigest,
            operatorIdentity: operatorIdentity,
            timestampMillis: timestampMillis,
            signature: signature,
        )
    }

    /// Project the snapshot into a freshly-constructed `ChatGroup`.
    /// Caller must have already verified the signature, sender, and
    /// 1:1-contact trust anchor. Returns nil if the local user is not
    /// listed in `members` (a snapshot the user can't actually be
    /// bootstrapped from).
    func intoChatGroup(localIdentityPub: Data) -> ChatGroup? {
        guard members.contains(where: { $0.peerId == localIdentityPub }) else { return nil }
        let createdAt = Date(timeIntervalSince1970: TimeInterval(timestampMillis) / 1000)
        // We can't reconstruct true `createdAt`, so use the snapshot's
        // own timestamp. UI surfaces this as "Created" — a small white
        // lie compared to "we don't know" and consistent with what
        // existing members see for the post-AddMember snapshot.
        return ChatGroup(
            id: groupId,
            displayName: displayName,
            members: members,
            createdAt: createdAt,
            currentEpoch: currentEpoch,
            lastOpDigest: lastOpDigest,
            pendingOps: [],
            log: [],
            lastSeenAt: nil,
            lastMessageAt: nil,
            myCurrentDistributionId: nil,
            memberDistributionIds: [:],
            sentSinceRotation: 0,
            lastRotatedAt: createdAt,
            mySkdmRecipients: [],
            recentOpDigests: [String(currentEpoch): lastOpDigest],
        )
    }
}

enum GroupBootstrapError: Error, Equatable, Sendable {
    case malformed(String)
}

// ─── Wire helpers ────────────────────────────────────────────────────

private extension GroupRole {
    var wireByte: UInt8 {
        switch self {
        case .member: 0x00
        case .admin: 0x01
        }
    }

    init?(wireByte: UInt8) {
        switch wireByte {
        case 0x00: self = .member
        case 0x01: self = .admin
        default: return nil
        }
    }
}

extension MemberStatus {
    var wireByte: UInt8 {
        switch self {
        case .active: 0x00
        case .pendingSKDM: 0x01
        case .removed: 0x02
        }
    }

    init?(wireByte: UInt8) {
        switch wireByte {
        case 0x00: self = .active
        case 0x01: self = .pendingSKDM
        case 0x02: self = .removed
        default: return nil
        }
    }
}
