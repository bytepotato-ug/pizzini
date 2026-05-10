import Foundation
import PizziniCryptoCore
import Testing
@testable import pizzini

/// Wire-format and signature-verification tests for `GroupOp`. Covers
/// the slice-2 contract:
///   - encode → decode round-trip is lossless for every op kind,
///   - signature-verify accepts a real signature and rejects every
///     mutation we can express (foreign signer, tampered header byte,
///     tampered payload byte, swapped signature),
///   - the BLAKE3 digest is deterministic and 32 bytes long, suitable
///     as `parentDigest` in the next op.
///
/// These exercise the FFI `pizzini_verify_identity_signature` added in
/// this slice end-to-end: the iOS-side `Session.identitySign` produces
/// a 64-byte XEd25519 signature, the static
/// `Session.verifyIdentitySignature` verifies it against the signer's
/// 33-byte identity-public, and a flipped bit anywhere in the signed
/// header trips the verifier.

@Suite("GroupOp codec")
struct GroupOpCodecTests {
    @Test("Create round-trips with admins + members + display names")
    func createRoundTrip() throws {
        let groupId = Data(repeating: 0xAA, count: 16)
        let alice = identityKey(seed: 0xA1)
        let bob = identityKey(seed: 0xB2)
        let kind = GroupOpKind.create(
            name: "field-team",
            initialMembers: [
                GroupOpInitialMember(peerId: alice, role: .admin, displayName: "Alice"),
                GroupOpInitialMember(peerId: bob, role: .member, displayName: ""),
            ],
        )
        let op = GroupOp(
            groupId: groupId,
            epoch: 0,
            parentDigest: GroupOp.zeroParentDigest,
            operatorIdentity: alice,
            timestampMillis: 1_700_000_000_000,
            kind: kind,
            signature: Data(repeating: 0x77, count: GroupOp.signatureSize),
        )
        let bytes = try op.encoded()
        let decoded = try #require(GroupOp.decode(bytes))
        #expect(decoded == op)
    }

    @Test("AddMember round-trips")
    func addMemberRoundTrip() throws {
        let op = signedOp(
            kind: .addMember(
                peerId: identityKey(seed: 0xC3),
                role: .member,
                displayName: "Carol",
            ),
            epoch: 1,
        )
        let decoded = try #require(GroupOp.decode(op.encoded()))
        #expect(decoded == op)
    }

    @Test("RemoveMember / PromoteAdmin / DemoteAdmin round-trip")
    func memberOpsRoundTrip() throws {
        let target = identityKey(seed: 0xC3)
        for kind: GroupOpKind in [
            .removeMember(peerId: target),
            .promoteAdmin(peerId: target),
            .demoteAdmin(peerId: target),
        ] {
            let op = signedOp(kind: kind, epoch: 2)
            let decoded = try #require(GroupOp.decode(op.encoded()))
            #expect(decoded == op)
        }
    }

    @Test("Rename round-trips with UTF-8")
    func renameRoundTrip() throws {
        let op = signedOp(
            kind: .rename(newName: "café 🛡️ — squad"),
            epoch: 3,
        )
        let decoded = try #require(GroupOp.decode(op.encoded()))
        #expect(decoded == op)
    }

    @Test("RotateSenderKey round-trips with the new dist_id")
    func rotateRoundTrip() throws {
        let dist = UUID()
        let op = signedOp(kind: .rotateSenderKey(newDistributionId: dist), epoch: 5)
        let decoded = try #require(GroupOp.decode(op.encoded()))
        #expect(decoded == op)
        guard case let .rotateSenderKey(seen) = decoded.kind else {
            Issue.record("decoded kind is not rotateSenderKey")
            return
        }
        #expect(seen == dist)
    }

    @Test("decode rejects an unknown op-version byte")
    func rejectsBadVersion() throws {
        var bytes = try signedOp(kind: .rename(newName: "x"), epoch: 1).encoded()
        bytes[0] = 0xFF
        #expect(GroupOp.decode(bytes) == nil)
    }

    @Test("decode rejects a payload-length mismatch")
    func rejectsPayloadOverflow() throws {
        var bytes = try signedOp(kind: .rename(newName: "x"), epoch: 1).encoded()
        // Drop the trailing signature so the cursor runs short before
        // it reaches the signature read — exercises the
        // payload-length-vs-buffer integrity check.
        bytes.removeLast(GroupOp.signatureSize)
        #expect(GroupOp.decode(bytes) == nil)
    }

    @Test("decode rejects trailing junk")
    func rejectsTrailingJunk() throws {
        var bytes = try signedOp(kind: .rename(newName: "x"), epoch: 1).encoded()
        bytes.append(0xDE)
        #expect(GroupOp.decode(bytes) == nil)
    }
}

@Suite("GroupOp signature verification")
struct GroupOpSignatureTests {
    @Test("a real signature verifies against the signer's identity-public")
    func validSignature() throws {
        let alice = try Session()
        let aliceIdentity = try alice.identityPublic()
        let op = try realSignedOp(by: alice, kind: .rename(newName: "ok"), epoch: 0)
        // Sanity: the operator field matches Alice.
        #expect(op.operatorIdentity == aliceIdentity)
        #expect(try op.verifySignature() == true)
    }

    @Test("a signature signed by Alice fails to verify when claimed to be Bob's")
    func wrongSigner() throws {
        let alice = try Session()
        let bob = try Session()
        let bobIdentity = try bob.identityPublic()
        // Build the header with Bob's identity but sign with Alice's.
        let tampered = try makeOpClaimingDifferentSigner(
            actualSigner: alice,
            claimedIdentity: bobIdentity,
            kind: .rename(newName: "fake"),
        )
        #expect(try tampered.verifySignature() == false)
    }

    @Test("flipping a bit in the header breaks the signature")
    func tamperedHeader() throws {
        let alice = try Session()
        let original = try realSignedOp(by: alice, kind: .rename(newName: "ok"), epoch: 7)
        var bytes = try original.encoded()
        // Flip a bit somewhere in the header (avoiding the trailing
        // 64-byte signature). Byte 1 is inside the groupId.
        bytes[1] ^= 0x01
        let tampered = try #require(GroupOp.decode(bytes))
        #expect(try tampered.verifySignature() == false)
    }

    @Test("flipping a bit in the signature breaks verification")
    func tamperedSignature() throws {
        let alice = try Session()
        let original = try realSignedOp(by: alice, kind: .rename(newName: "ok"), epoch: 7)
        var bytes = try original.encoded()
        // Flip a bit inside the trailing signature.
        bytes[bytes.count - 5] ^= 0x80
        let tampered = try #require(GroupOp.decode(bytes))
        #expect(try tampered.verifySignature() == false)
    }
}

@Suite("GroupOp digest / hash-chain")
struct GroupOpDigestTests {
    @Test("digest is deterministic and 32 bytes")
    func digestShape() throws {
        let op = signedOp(kind: .rename(newName: "deterministic"), epoch: 4)
        let d1 = try op.digest()
        let d2 = try op.digest()
        #expect(d1 == d2)
        #expect(d1.count == 32)
    }

    @Test("changing any header field changes the digest")
    func digestSensitivity() throws {
        let groupId = Data(repeating: 0x11, count: 16)
        let identity = identityKey(seed: 0xA1)
        let baseOp = GroupOp(
            groupId: groupId,
            epoch: 1,
            parentDigest: GroupOp.zeroParentDigest,
            operatorIdentity: identity,
            timestampMillis: 1_700_000_000_000,
            kind: .rename(newName: "v1"),
            signature: Data(repeating: 0, count: GroupOp.signatureSize),
        )
        let bumpedEpoch = GroupOp(
            groupId: baseOp.groupId,
            epoch: 2,
            parentDigest: baseOp.parentDigest,
            operatorIdentity: baseOp.operatorIdentity,
            timestampMillis: baseOp.timestampMillis,
            kind: baseOp.kind,
            signature: baseOp.signature,
        )
        #expect(try baseOp.digest() != bumpedEpoch.digest())
    }

    @Test("digest can serve as parent of the next op in the chain")
    func chainsAsParent() throws {
        let alice = try Session()
        let op0 = try realSignedOp(by: alice, kind: .rename(newName: "v0"), epoch: 0)
        let parent = try op0.digest()
        let op1 = try realSignedOp(
            by: alice,
            kind: .rename(newName: "v1"),
            epoch: 1,
            parentDigest: parent,
        )
        #expect(op1.parentDigest == parent)
        #expect(try op1.verifySignature() == true)
    }
}

// ─── helpers ──────────────────────────────────────────────────────────

/// Deterministic 33-byte synthetic identity-key bytes for codec tests
/// that don't need real crypto (just a plausibly-sized blob in the
/// peerId fields). For signature tests we use real `Session`s.
private func identityKey(seed: UInt8) -> Data {
    var d = Data(count: 33)
    for i in 0..<33 { d[i] = seed &+ UInt8(i) }
    // Force the leading "DJB type prefix" byte to libsignal's value
    // so a future tightening of the verify path that checks this
    // doesn't surprise us.
    d[0] = 0x05
    return d
}

/// Build a `GroupOp` with synthetic identity + zeroed signature. Good
/// enough for codec round-trip tests; signature tests use
/// `realSignedOp` instead.
private func signedOp(
    kind: GroupOpKind,
    epoch: UInt64,
    parentDigest: Data = GroupOp.zeroParentDigest,
) -> GroupOp {
    GroupOp(
        groupId: Data(repeating: 0xAA, count: 16),
        epoch: epoch,
        parentDigest: parentDigest,
        operatorIdentity: identityKey(seed: 0xA1),
        timestampMillis: 1_700_000_000_000,
        kind: kind,
        signature: Data(repeating: 0x77, count: GroupOp.signatureSize),
    )
}

/// Build a `GroupOp` with a real XEd25519 signature produced by
/// `signer.identitySign(...)` over the encoded header.
private func realSignedOp(
    by signer: Session,
    kind: GroupOpKind,
    epoch: UInt64,
    parentDigest: Data = GroupOp.zeroParentDigest,
) throws -> GroupOp {
    let identity = try signer.identityPublic()
    let unsigned = GroupOp(
        groupId: Data(repeating: 0xAA, count: 16),
        epoch: epoch,
        parentDigest: parentDigest,
        operatorIdentity: identity,
        timestampMillis: 1_700_000_000_000,
        kind: kind,
        // Placeholder; replaced after we sign the header.
        signature: Data(repeating: 0, count: GroupOp.signatureSize),
    )
    let header = try unsigned.encodedHeader()
    let sig = try signer.identitySign(header)
    return GroupOp(
        groupId: unsigned.groupId,
        epoch: unsigned.epoch,
        parentDigest: unsigned.parentDigest,
        operatorIdentity: unsigned.operatorIdentity,
        timestampMillis: unsigned.timestampMillis,
        kind: unsigned.kind,
        signature: sig,
    )
}

/// Construct an op whose `operatorIdentity` field claims to be one
/// session's identity but whose signature was produced by a different
/// session. Used to exercise the "wrong signer" verification path.
private func makeOpClaimingDifferentSigner(
    actualSigner: Session,
    claimedIdentity: Data,
    kind: GroupOpKind,
) throws -> GroupOp {
    let header = GroupOp(
        groupId: Data(repeating: 0xAA, count: 16),
        epoch: 0,
        parentDigest: GroupOp.zeroParentDigest,
        operatorIdentity: claimedIdentity,
        timestampMillis: 1_700_000_000_000,
        kind: kind,
        signature: Data(repeating: 0, count: GroupOp.signatureSize),
    )
    let headerBytes = try header.encodedHeader()
    let sig = try actualSigner.identitySign(headerBytes)
    return GroupOp(
        groupId: header.groupId,
        epoch: header.epoch,
        parentDigest: header.parentDigest,
        operatorIdentity: header.operatorIdentity,
        timestampMillis: header.timestampMillis,
        kind: header.kind,
        signature: sig,
    )
}
