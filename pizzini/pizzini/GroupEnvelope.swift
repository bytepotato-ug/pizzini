import Foundation

/// Inner-envelope payload codec for the four group inner-kind bytes
/// added in slice 3 + the audit-driven slice 4 ([RelayClient.swift:67](swift/Sources/PizziniCryptoCore/RelayClient.swift:67)):
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
}
