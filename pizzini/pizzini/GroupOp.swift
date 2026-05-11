import Foundation
import PizziniCryptoCore

/// One signed log entry mutating a `ChatGroup`'s state. Group state on
/// every device is derived by replaying the linear sequence of
/// applied ops; each op carries an epoch and a BLAKE3 hash of its
/// parent so equivocation by an admin (two ops claiming the same
/// epoch) is detectable on the receiver side.
///
/// **Wire format (`op_version = 2`, big-endian):**
///
/// ```text
/// header (covered by signature):
///   u8   op_version = 2
///   [16] groupId
///   u64  epoch
///   [32] parentDigest          (BLAKE3 of the previous signed op,
///                                all-zero for the Create op)
///   [33] operatorIdentityPub   (libsignal-native serialised IdentityKey)
///   u64  timestampMillis
///   [32] priorMemberSetRoot    (USP #5: canonical hash of the member
///                                set the operator believed to be
///                                current at signing time. Receiver
///                                recomputes against their local view
///                                and rejects on mismatch — defeats
///                                ghost-member / equivocation attacks.
///                                Constant `ChatGroup.emptyMemberSetRoot`
///                                for the Create op.)
///   u8   opKind
///   u32  payloadLen + payload bytes
/// trailer:
///   [64] signature             (XEd25519 by operator's identity-key
///                                private half over the header bytes)
/// ```
///
/// **v1 → v2 break.** The wire format gained the 32-byte
/// `priorMemberSetRoot` field. The opVersion was bumped, and the
/// signing-context tag bumped in lockstep
/// (`pizzini.group.op.v1` → `.v2`) so a v1 op produced before the
/// upgrade simply fails signature verification under v2 — no risk
/// of a downgrade attack treating new bytes as old ones.
///
/// **Op kinds and payloads:**
///
/// ```text
/// 0x01 Create:
///   u16  nameLen + nameBytes (UTF-8)
///   u8   initialMemberCount     (≤ ChatGroup.maxMembers)
///   for each:
///     [33] memberIdentityPub
///     u8   role                 (0 = member, 1 = admin)
///     u16  displayNameLen + bytes
///
/// 0x02 AddMember:
///   [33] memberIdentityPub
///   u8   role
///   u16  displayNameLen + bytes
///
/// 0x03 RemoveMember:
///   [33] memberIdentityPub
///
/// 0x04 Rename:
///   u16  nameLen + nameBytes
///
/// 0x05 PromoteAdmin:
///   [33] memberIdentityPub
///
/// 0x06 DemoteAdmin:
///   [33] memberIdentityPub
///
/// 0x07 RotateSenderKey:
///   [16] newDistributionId      (the rotator's NEW per-chain UUID;
///                                 the corresponding SKDM travels
///                                 separately as InnerEnvelopeKind 0x07)
/// ```
///
/// **Forward compatibility.** Future op kinds bump `op_version` rather
/// than overload existing kind bytes — receivers on old versions skip
/// unknown ops with a "needs-upgrade" warning instead of corrupting
/// their state. The codec is a hand-rolled binary format (matching
/// the rest of the codebase: `ContactCard.encoded`, the bundle/store
/// blobs in `crypto-core/src/store.rs`) rather than protobuf, to keep
/// the dependency surface minimal and the signed bytes deterministic.
struct GroupOp: Sendable, Equatable {
    let groupId: Data
    let epoch: UInt64
    let parentDigest: Data
    let operatorIdentity: Data
    let timestampMillis: UInt64
    /// Canonical hash of the member set the operator believed to be
    /// current at the moment they signed this op (USP #5). The
    /// receiver recomputes this from their own local view and
    /// rejects the op on mismatch — defeats the ghost-member
    /// equivocation attack where an admin silently adds a member
    /// only on their own device and uses the resulting "fork" to
    /// receive group traffic.
    ///
    /// Set to `ChatGroup.memberSetRoot(of: [])` for the Create op
    /// (no prior state to witness) — see `signed(...)`.
    let priorMemberSetRoot: Data
    let kind: GroupOpKind
    let signature: Data

    static let opVersion: UInt8 = 2
    static let parentDigestSize: Int = 32
    static let identityKeySize: Int = 33
    static let signatureSize: Int = 64
    static let distributionIdSize: Int = 16
    static let groupIdSize: Int = 16
    /// Width of the member-set-root field. Matches BLAKE3's 32-byte
    /// output; mirrored from `parentDigestSize` so the same constant
    /// drives both fixed-32 fields.
    static let memberSetRootSize: Int = 32
    /// All-zero parent digest used by the `Create` op. There is no
    /// prior signed op to chain to, so we anchor with zeros — the
    /// signed `Create` op's own digest becomes the parent for op #1.
    static let zeroParentDigest: Data = Data(repeating: 0, count: GroupOp.parentDigestSize)

    /// BLAKE3 digest of the signed wire bytes. Used as the
    /// `parentDigest` of the next op in the chain.
    func digest() throws -> Data {
        let signed = try encoded()
        return Blake3.hash(signed)
    }

    /// Verify the signature against the operator's identity-public.
    /// Stateless — does not require a `Session` because verification
    /// is a public-key operation. Returns `false` for a tampered or
    /// foreign-signed op; throws for malformed inputs.
    func verifySignature() throws -> Bool {
        let header = try encodedHeader()
        return try Session.verifyIdentitySignature(
            identityPub: operatorIdentity,
            message: header,
            signature: signature,
            contextTag: Session.SignatureContext.groupOp,
        )
    }

    /// Full signed wire bytes (header + signature).
    func encoded() throws -> Data {
        var out = try encodedHeader()
        guard signature.count == GroupOp.signatureSize else {
            throw GroupOpError.malformed("signature must be \(GroupOp.signatureSize) bytes")
        }
        out.append(signature)
        return out
    }

    /// Header bytes, i.e. the bytes the signature is computed over.
    /// Exposed so the operator can sign once and assemble the full
    /// op via `signed(header:signature:)`.
    func encodedHeader() throws -> Data {
        guard groupId.count == GroupOp.groupIdSize else {
            throw GroupOpError.malformed("groupId must be \(GroupOp.groupIdSize) bytes")
        }
        guard parentDigest.count == GroupOp.parentDigestSize else {
            throw GroupOpError.malformed("parentDigest must be \(GroupOp.parentDigestSize) bytes")
        }
        guard operatorIdentity.count == GroupOp.identityKeySize else {
            throw GroupOpError.malformed("operatorIdentity must be \(GroupOp.identityKeySize) bytes")
        }
        guard priorMemberSetRoot.count == GroupOp.memberSetRootSize else {
            throw GroupOpError.malformed("priorMemberSetRoot must be \(GroupOp.memberSetRootSize) bytes")
        }
        var out = Data(capacity: 256)
        out.append(GroupOp.opVersion)
        out.append(groupId)
        out.appendBigEndian(epoch)
        out.append(parentDigest)
        out.append(operatorIdentity)
        out.appendBigEndian(timestampMillis)
        out.append(priorMemberSetRoot)
        let payload = try kind.encodedPayload()
        out.append(kind.kindByte)
        out.appendBigEndian(UInt32(payload.count))
        out.append(payload)
        return out
    }

    /// Compose an op header with a freshly-computed signature. The
    /// caller computes the signature via `Session.identitySign(_:)` on
    /// the bytes of `encodedHeader()`; we just glue them together.
    static func signed(
        groupId: Data,
        epoch: UInt64,
        parentDigest: Data,
        operatorIdentity: Data,
        timestampMillis: UInt64,
        priorMemberSetRoot: Data,
        kind: GroupOpKind,
        signature: Data,
    ) -> GroupOp {
        GroupOp(
            groupId: groupId,
            epoch: epoch,
            parentDigest: parentDigest,
            operatorIdentity: operatorIdentity,
            timestampMillis: timestampMillis,
            priorMemberSetRoot: priorMemberSetRoot,
            kind: kind,
            signature: signature,
        )
    }

    /// Parse a signed op from wire bytes. Returns `nil` on a malformed
    /// blob; throws only for I/O-style failures (none today, kept for
    /// API symmetry with similar codecs).
    static func decode(_ bytes: Data) -> GroupOp? {
        var cursor = ByteCursor(bytes)
        guard let version: UInt8 = cursor.read(1)?.first else { return nil }
        guard version == GroupOp.opVersion else { return nil }
        guard let groupId = cursor.read(GroupOp.groupIdSize) else { return nil }
        guard let epoch: UInt64 = cursor.readBigEndian() else { return nil }
        guard let parentDigest = cursor.read(GroupOp.parentDigestSize) else { return nil }
        guard let operatorIdentity = cursor.read(GroupOp.identityKeySize) else { return nil }
        guard let timestampMillis: UInt64 = cursor.readBigEndian() else { return nil }
        guard let priorMemberSetRoot = cursor.read(GroupOp.memberSetRootSize) else { return nil }
        guard let kindByte: UInt8 = cursor.read(1)?.first else { return nil }
        guard let payloadLen: UInt32 = cursor.readBigEndian() else { return nil }
        guard let payload = cursor.read(Int(payloadLen)) else { return nil }
        guard let kind = GroupOpKind.decode(kindByte: kindByte, payload: payload) else { return nil }
        guard let signature = cursor.read(GroupOp.signatureSize) else { return nil }
        guard cursor.isExhausted else { return nil }
        return GroupOp(
            groupId: groupId,
            epoch: epoch,
            parentDigest: parentDigest,
            operatorIdentity: operatorIdentity,
            timestampMillis: timestampMillis,
            priorMemberSetRoot: priorMemberSetRoot,
            kind: kind,
            signature: signature,
        )
    }
}

/// Initial-member spec for `GroupOpKind.create`. Named struct rather
/// than a tuple so Swift can auto-synthesize `Equatable` on the
/// enclosing op kind (Swift does not auto-derive Equatable for enum
/// cases with tuple-typed associated values).
struct GroupOpInitialMember: Sendable, Equatable {
    let peerId: Data
    let role: GroupRole
    let displayName: String
}

enum GroupOpKind: Sendable, Equatable {
    case create(name: String, initialMembers: [GroupOpInitialMember])
    case addMember(peerId: Data, role: GroupRole, displayName: String)
    case removeMember(peerId: Data)
    case rename(newName: String)
    case promoteAdmin(peerId: Data)
    case demoteAdmin(peerId: Data)
    case rotateSenderKey(newDistributionId: UUID)

    var kindByte: UInt8 {
        switch self {
        case .create: 0x01
        case .addMember: 0x02
        case .removeMember: 0x03
        case .rename: 0x04
        case .promoteAdmin: 0x05
        case .demoteAdmin: 0x06
        case .rotateSenderKey: 0x07
        }
    }

    func encodedPayload() throws -> Data {
        var out = Data()
        switch self {
        case let .create(name, initialMembers):
            try writeUTF8U16LenBlob(&out, name)
            guard initialMembers.count <= ChatGroup.maxMembers else {
                throw GroupOpError.malformed("Create exceeds maxMembers (\(ChatGroup.maxMembers))")
            }
            out.append(UInt8(initialMembers.count))
            for member in initialMembers {
                guard member.peerId.count == GroupOp.identityKeySize else {
                    throw GroupOpError.malformed("member peerId must be \(GroupOp.identityKeySize) bytes")
                }
                out.append(member.peerId)
                out.append(member.role.wireByte)
                try writeUTF8U16LenBlob(&out, member.displayName)
            }
        case let .addMember(peerId, role, displayName):
            guard peerId.count == GroupOp.identityKeySize else {
                throw GroupOpError.malformed("peerId must be \(GroupOp.identityKeySize) bytes")
            }
            out.append(peerId)
            out.append(role.wireByte)
            try writeUTF8U16LenBlob(&out, displayName)
        case let .removeMember(peerId),
             let .promoteAdmin(peerId),
             let .demoteAdmin(peerId):
            guard peerId.count == GroupOp.identityKeySize else {
                throw GroupOpError.malformed("peerId must be \(GroupOp.identityKeySize) bytes")
            }
            out.append(peerId)
        case let .rename(newName):
            try writeUTF8U16LenBlob(&out, newName)
        case let .rotateSenderKey(newDistributionId):
            out.append(contentsOf: newDistributionId.dataBytes)
        }
        return out
    }

    static func decode(kindByte: UInt8, payload: Data) -> GroupOpKind? {
        var c = ByteCursor(payload)
        switch kindByte {
        case 0x01:
            guard let name = readUTF8U16LenBlob(&c) else { return nil }
            guard let count: UInt8 = c.read(1)?.first else { return nil }
            guard Int(count) <= ChatGroup.maxMembers else { return nil }
            var initialMembers: [GroupOpInitialMember] = []
            for _ in 0..<count {
                guard let peerId = c.read(GroupOp.identityKeySize) else { return nil }
                guard let roleByte: UInt8 = c.read(1)?.first else { return nil }
                guard let role = GroupRole(wireByte: roleByte) else { return nil }
                guard let display = readUTF8U16LenBlob(&c) else { return nil }
                initialMembers.append(GroupOpInitialMember(
                    peerId: peerId,
                    role: role,
                    displayName: display,
                ))
            }
            guard c.isExhausted else { return nil }
            return .create(name: name, initialMembers: initialMembers)
        case 0x02:
            guard let peerId = c.read(GroupOp.identityKeySize) else { return nil }
            guard let roleByte: UInt8 = c.read(1)?.first else { return nil }
            guard let role = GroupRole(wireByte: roleByte) else { return nil }
            guard let display = readUTF8U16LenBlob(&c) else { return nil }
            guard c.isExhausted else { return nil }
            return .addMember(peerId: peerId, role: role, displayName: display)
        case 0x03:
            guard let peerId = c.read(GroupOp.identityKeySize), c.isExhausted else { return nil }
            return .removeMember(peerId: peerId)
        case 0x04:
            guard let name = readUTF8U16LenBlob(&c), c.isExhausted else { return nil }
            return .rename(newName: name)
        case 0x05:
            guard let peerId = c.read(GroupOp.identityKeySize), c.isExhausted else { return nil }
            return .promoteAdmin(peerId: peerId)
        case 0x06:
            guard let peerId = c.read(GroupOp.identityKeySize), c.isExhausted else { return nil }
            return .demoteAdmin(peerId: peerId)
        case 0x07:
            guard let bytes = c.read(GroupOp.distributionIdSize), c.isExhausted else { return nil }
            return .rotateSenderKey(newDistributionId: UUID(dataBytes: bytes))
        default:
            return nil
        }
    }
}

enum GroupOpError: Error, Equatable, Sendable {
    case malformed(String)
}

// ─── Wire helpers ────────────────────────────────────────────────────

extension GroupRole {
    /// Canonical 1-byte encoding. Shared between the GroupOp wire
    /// format (`AddMember`/`Create` payloads) and the membership-root
    /// hash (`ChatGroup.memberSetRoot`). Single source of truth so a
    /// future schema change doesn't have to ripple through two
    /// independent encoders.
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
    /// Canonical 1-byte encoding for the membership-root hash. Only
    /// two states are *structurally* meaningful for group membership:
    /// the member is part of the group, or they have been removed.
    /// `pendingSKDM` is a transient local UI state (waiting for the
    /// SKDM round-trip) that resolves to `active` without any
    /// signed-op exchange — folding it to `active` here keeps the
    /// membership root deterministic across two devices that happen
    /// to be at slightly different points in the SKDM dance.
    var canonicalRootByte: UInt8 {
        switch self {
        case .removed: 0x00
        case .active, .pendingSKDM: 0x01
        }
    }
}

// File-internal in iOS, but exposed within the app module so the
// GroupBootstrap codec next door can reuse the cursor / int-write
// helpers without forking a duplicate copy.

extension UUID {
    init(dataBytes: Data) {
        precondition(dataBytes.count == 16)
        var bytes = uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        // `Data.copyBytes(to:)` returns the byte count; the closure
        // body's last expression therefore makes
        // `withUnsafeMutableBytes` return that `Int`. We don't need
        // it — explicit discard silences the unused-result warning.
        _ = withUnsafeMutableBytes(of: &bytes) { ptr in
            dataBytes.copyBytes(to: ptr.bindMemory(to: UInt8.self))
        }
        self.init(uuid: bytes)
    }

    var dataBytes: Data {
        var u = uuid
        return withUnsafeBytes(of: &u) { Data($0) }
    }
}

/// Append a UTF-8 string with a `UInt16` big-endian length prefix.
/// (The "U16" in the name refers to the length-prefix width — the
/// payload is plain UTF-8.)
func writeUTF8U16LenBlob(_ out: inout Data, _ s: String) throws {
    let utf8 = Data(s.utf8)
    guard utf8.count <= UInt16.max else {
        throw GroupOpError.malformed("string exceeds 65535 UTF-8 bytes")
    }
    out.appendBigEndian(UInt16(utf8.count))
    out.append(utf8)
}

/// Inverse of `writeUTF8U16LenBlob`. Returns nil on length overflow
/// or non-UTF-8 bytes.
func readUTF8U16LenBlob(_ c: inout ByteCursor) -> String? {
    guard let len: UInt16 = c.readBigEndian() else { return nil }
    guard let bytes = c.read(Int(len)) else { return nil }
    return String(data: bytes, encoding: .utf8)
}

extension Data {
    // `Swift.withUnsafeBytes(of:_:)` rather than the unqualified call —
    // inside an `extension Data` block, `withUnsafeBytes` resolves to
    // `Data.withUnsafeBytes` (single-argument) and shadows the
    // free-function form we need here.
    mutating func appendBigEndian(_ v: UInt16) {
        var be = v.bigEndian
        Swift.withUnsafeBytes(of: &be) { append(contentsOf: $0) }
    }

    mutating func appendBigEndian(_ v: UInt32) {
        var be = v.bigEndian
        Swift.withUnsafeBytes(of: &be) { append(contentsOf: $0) }
    }

    mutating func appendBigEndian(_ v: UInt64) {
        var be = v.bigEndian
        Swift.withUnsafeBytes(of: &be) { append(contentsOf: $0) }
    }
}

/// Minimal forward-only byte cursor. We hand-roll one rather than
/// reaching for `InputStream` so the parser stays allocation-free and
/// every read returns a sliced subrange of the input `Data` (zero-copy
/// on the read path).
struct ByteCursor {
    private let buffer: Data
    private var offset: Int

    init(_ data: Data) {
        self.buffer = data
        self.offset = 0
    }

    var isExhausted: Bool { offset == buffer.count }

    mutating func read(_ n: Int) -> Data? {
        guard n >= 0, offset + n <= buffer.count else { return nil }
        let lo = buffer.startIndex + offset
        let hi = lo + n
        offset += n
        return buffer[lo..<hi]
    }

    mutating func readBigEndian<T: FixedWidthInteger>() -> T? {
        guard let bytes = read(MemoryLayout<T>.size) else { return nil }
        var value: T = 0
        // Explicit discard: `Data.copyBytes(to:)` returns an `Int`
        // and propagates through `withUnsafeMutableBytes`.
        _ = withUnsafeMutableBytes(of: &value) { dst in
            bytes.copyBytes(to: dst.bindMemory(to: UInt8.self))
        }
        return T(bigEndian: value)
    }
}
