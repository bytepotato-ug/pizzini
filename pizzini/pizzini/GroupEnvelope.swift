import Foundation

/// Inner-envelope payload codec for the five group inner-kind bytes
/// added in slice 3, the audit-driven slice 4, and the post-audit
/// group-attachments wire ([RelayClient.swift:67](swift/Sources/PizziniCryptoCore/RelayClient.swift:67)):
///
///   0x06 groupChat            → `groupId(16) ‖ SenderKeyMessage`
///   0x07 groupKeyDistribution → `groupId(16) ‖ SenderKeyDistributionMessage`
///   0x08 groupOp              → signed `GroupOp` wire bytes (no extra wrap;
///                                groupId is part of the op header)
///   0x09 groupBootstrap       → `groupId(16) ‖ GroupBootstrap bytes`
///                                (audit fix HIGH-7 — signed snapshot
///                                so a newly-added member can build a
///                                local `ChatGroup` without replaying
///                                the entire op chain)
///   0x0A groupFileChunk       → `groupId(16) ‖ SenderKeyMessage`
///                                (the SenderKeyMessage encrypts a
///                                `FileChunkEnvelope` plaintext —
///                                same per-chunk codec as 1:1 so the
///                                AttachmentReassembler input is
///                                identical between the two paths)
///
/// The codecs sit between `ChatStore`'s receive-path dispatch and the
/// libsignal FFI so that the ChatStore switch-arm is one parse + one
/// FFI call deep, not three. They also pin the on-wire layout in one
/// place for both encode and decode paths — easier to keep the two
/// sides in sync than spread across send and receive code.
enum GroupEnvelope {
    static let groupIdSize: Int = 16

    /// Build the body of a `groupChat = 0x06` inner envelope.
    static func encodeGroupChat(groupId: Data, senderKeyMessage: Data) -> Data {
        var out = Data(capacity: groupIdSize + senderKeyMessage.count)
        out.append(groupId)
        out.append(senderKeyMessage)
        return out
    }

    /// Parse the body of a `groupChat = 0x06` inner envelope. The
    /// caller has already stripped the leading inner-kind byte (which
    /// is the responsibility of `ChatStore.handleSealedReceive`). nil
    /// for a payload too short to carry the 16-byte groupId prefix.
    static func decodeGroupChat(_ payload: Data) -> (groupId: Data, senderKeyMessage: Data)? {
        guard payload.count >= groupIdSize else { return nil }
        let lo = payload.startIndex
        let mid = lo + groupIdSize
        return (Data(payload[lo..<mid]), Data(payload[mid..<payload.endIndex]))
    }

    /// Build the body of a `groupKeyDistribution = 0x07` inner envelope.
    static func encodeKeyDistribution(groupId: Data, skdm: Data) -> Data {
        var out = Data(capacity: groupIdSize + skdm.count)
        out.append(groupId)
        out.append(skdm)
        return out
    }

    /// Parse the body of a `groupKeyDistribution = 0x07` inner envelope.
    static func decodeKeyDistribution(_ payload: Data) -> (groupId: Data, skdm: Data)? {
        guard payload.count >= groupIdSize else { return nil }
        let lo = payload.startIndex
        let mid = lo + groupIdSize
        return (Data(payload[lo..<mid]), Data(payload[mid..<payload.endIndex]))
    }

    /// Build the body of a `groupBootstrap = 0x09` inner envelope.
    /// `bootstrapBytes` is the output of `GroupBootstrap.encoded()` —
    /// already-signed, already-canonical.
    static func encodeBootstrap(groupId: Data, bootstrapBytes: Data) -> Data {
        var out = Data(capacity: groupIdSize + bootstrapBytes.count)
        out.append(groupId)
        out.append(bootstrapBytes)
        return out
    }

    /// Parse the body of a `groupBootstrap = 0x09` inner envelope.
    static func decodeBootstrap(_ payload: Data) -> (groupId: Data, bootstrapBytes: Data)? {
        guard payload.count >= groupIdSize else { return nil }
        let lo = payload.startIndex
        let mid = lo + groupIdSize
        return (Data(payload[lo..<mid]), Data(payload[mid..<payload.endIndex]))
    }

    // No `encodeGroupOp` / `decodeGroupOp` — the body of a 0x08
    // inner envelope is exactly `GroupOp.encoded()` and parsed by
    // `GroupOp.decode(_:)` already. Keeping them out of this file
    // avoids a redundant pass-through that could drift.

    /// Build the body of a `groupFileChunk = 0x0A` inner envelope.
    /// `senderKeyMessage` is the libsignal SenderKeyMessage produced
    /// by `Session.groupEncrypt` over a `FileChunkEnvelope.encode()`
    /// plaintext — identical layout to `groupChat` so the same FFI
    /// path applies on receive.
    static func encodeGroupFileChunk(groupId: Data, senderKeyMessage: Data) -> Data {
        var out = Data(capacity: groupIdSize + senderKeyMessage.count)
        out.append(groupId)
        out.append(senderKeyMessage)
        return out
    }

    /// Parse the body of a `groupFileChunk = 0x0A` inner envelope.
    /// nil for a payload too short to carry the 16-byte groupId
    /// prefix. The returned `senderKeyMessage` slice is fed straight
    /// to `Session.groupDecrypt`; the resulting plaintext is then
    /// decoded with `FileChunkEnvelope.decode(_:)` and submitted to
    /// the group reassembler.
    static func decodeGroupFileChunk(_ payload: Data) -> (groupId: Data, senderKeyMessage: Data)? {
        guard payload.count >= groupIdSize else { return nil }
        let lo = payload.startIndex
        let mid = lo + groupIdSize
        return (Data(payload[lo..<mid]), Data(payload[mid..<payload.endIndex]))
    }

    /// Extract the 16-byte `distribution_id` (a libsignal per-CHAIN
    /// identifier, surfaced as a `UUID`) from the header of a
    /// `SenderKeyMessage` — WITHOUT decrypting it.
    ///
    /// **Why this is needed.** `groupId` in the inner envelope is only
    /// a routing hint: `Session.groupDecrypt` looks the sender-key
    /// chain up by `(senderIdentity, distribution_id)`, where the
    /// `distribution_id` comes from the ciphertext header, not from
    /// `groupId`. A member who shares two groups with the victim can
    /// wrap a G2 ciphertext in a `groupChat` envelope labelled `G1`
    /// and — because the victim has installed that member's G2 chain
    /// — `groupDecrypt` happily decrypts it, splicing G2 plaintext
    /// into G1's transcript. The receive handlers defend against that
    /// by checking the extracted `distribution_id` against the one
    /// recorded for `(sender, group)` in
    /// `ChatGroup.memberDistributionIds` BEFORE rendering — but they
    /// need the ciphertext's `distribution_id` to do so, and the FFI
    /// `groupDecrypt` does not return it.
    ///
    /// **Wire format** (libsignal `SenderKeyMessage`, pinned at
    /// v0.93.2): `version(1 byte) || protobuf body || mac(8 bytes)`.
    /// The protobuf `SenderKeyMessage`'s field 1 is
    /// `distribution_uuid` (`bytes`), so the body begins with the
    /// protobuf tag `0x0a` (field 1, wire type 2 = length-delimited),
    /// a length byte `0x10` (16), then the 16 raw UUID bytes. Any
    /// deviation from that shape — too short, wrong tag, wrong length
    /// — yields nil, and the callers treat nil as a hard reject
    /// (fail-closed): a `SenderKeyMessage` whose header cannot be
    /// parsed is one we will not render.
    static func distributionId(fromSenderKeyMessage skm: Data) -> UUID? {
        // version(1) + tag(1) + len(1) + uuid(16) = 19 bytes minimum.
        guard skm.count >= 19 else { return nil }
        let base = skm.startIndex
        // skm[base] is the version byte — not validated here (libsignal
        // owns version handling on decrypt); we only need the header
        // shape to locate the UUID.
        guard skm[base + 1] == 0x0a, skm[base + 2] == 0x10 else { return nil }
        let uuidStart = base + 3
        let uuidBytes = skm[uuidStart..<(uuidStart + 16)]
        let b = Array(uuidBytes)
        return UUID(uuid: (
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
        ))
    }
}
