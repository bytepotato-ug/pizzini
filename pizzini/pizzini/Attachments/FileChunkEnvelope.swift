import Foundation

/// Wire codec for the inner plaintext of a `.fileChunk` sealed envelope.
///
/// Wire layout (after the 1-byte InnerEnvelopeKind = 0x05 prefix that
/// every sealed envelope already carries):
///
/// ```
///   attachment_id    [16 bytes]
///   total_size       [u64 BE]   — full assembled byte length
///   chunk_index      [u32 BE]   — 0-based
///   chunk_count      [u32 BE]   — sender-asserted total
///   mime_len         [u16 BE]
///   mime             [utf8]     — informational (UTI / MIME)
///   filename_len     [u16 BE]
///   filename         [utf8]     — sender-asserted, RE-sanitized on receive
///   chunk_bytes      [rest]     — opaque payload bytes
/// ```
///
/// Self-describing per chunk (no separate manifest message). The cost is
/// ~50 bytes per chunk for repeating mime/filename, which is trivial
/// next to a 64 KB plaintext. The benefit is robustness: lose any chunk
/// and the surviving ones still tell the receiver what the attachment
/// is.
///
/// Caps below are **defensive**: a malicious peer could otherwise send
/// `chunk_count = u32::MAX` and pin gigabytes of reassembler memory,
/// or a 10 KB filename that breaks the renderer.
struct FileChunkEnvelope: Sendable, Equatable {
    let attachmentId: Data
    let totalSize: UInt64
    let chunkIndex: UInt32
    let chunkCount: UInt32
    let mime: String
    let filename: String
    let chunkBytes: Data

    /// Aim for the brief's "~64 KB plaintext, under the relay's per-
    /// frame budget after sealed envelope overhead". Sealed envelope
    /// adds ~300 B overhead (cert + ratchet header + USMC + sender-
    /// cert sig); SEND v2 wire frame adds another ~125 B (to + ttl +
    /// token). 64 KB plaintext + ~430 B overhead = ~65.4 KB on the
    /// wire — well below the 1 MB MAX_FRAME_BYTES at the relay.
    static let maxChunkPlaintextBytes: Int = 64 * 1024
    /// Cap chunk_count at 1024. Combined with maxChunkPlaintextBytes
    /// gives a per-attachment ceiling of 64 MB. F-203-style: a
    /// receiver-asserted bound, never trusts the sender's claim
    /// blindly.
    static let maxChunkCount: UInt32 = 1024
    /// Filename is post-sanitize ≤ 255 bytes (FilenameSanitizer.maxLength).
    /// We cap a bit higher on the wire to leave room for pre-sanitize
    /// names, but anything past 1024 is hostile.
    static let maxFilenameBytes = 1024
    /// MIME/UTI strings are short ASCII. 256 bytes is generous.
    static let maxMimeBytes = 256

    enum CodecError: Error, Equatable {
        case truncated
        case attachmentIdLength
        case oversizedChunkCount
        case oversizedFilename
        case oversizedMime
        case chunkIndexOutOfRange
        case oversizedChunk
    }

    /// Encode to wire-form plaintext. The caller prefixes the
    /// `InnerEnvelopeKind.fileChunk` byte before sealing.
    func encode() -> Data {
        var out = Data()
        out.reserveCapacity(16 + 8 + 4 + 4 + 2 + mime.utf8.count + 2 + filename.utf8.count + chunkBytes.count)
        out.append(attachmentId)
        var totalBE = totalSize.bigEndian
        withUnsafeBytes(of: &totalBE) { out.append(contentsOf: $0) }
        var idxBE = chunkIndex.bigEndian
        withUnsafeBytes(of: &idxBE) { out.append(contentsOf: $0) }
        var countBE = chunkCount.bigEndian
        withUnsafeBytes(of: &countBE) { out.append(contentsOf: $0) }
        let mimeBytes = Data(mime.utf8)
        var mimeLen = UInt16(mimeBytes.count).bigEndian
        withUnsafeBytes(of: &mimeLen) { out.append(contentsOf: $0) }
        out.append(mimeBytes)
        let filenameBytes = Data(filename.utf8)
        var fnLen = UInt16(filenameBytes.count).bigEndian
        withUnsafeBytes(of: &fnLen) { out.append(contentsOf: $0) }
        out.append(filenameBytes)
        out.append(chunkBytes)
        return out
    }

    /// Decode from wire-form plaintext (the byte-after-kind prefix).
    /// Throws on any structural violation; caller treats as a malformed
    /// frame from a paired peer, drops on the floor (the inner-envelope
    /// dispatch upstream will already have advanced the ratchet).
    static func decode(_ data: Data) throws -> FileChunkEnvelope {
        var c = Cursor(data)
        guard let aid = c.take(16) else { throw CodecError.truncated }
        if aid.count != 16 { throw CodecError.attachmentIdLength }
        guard let total = c.u64() else { throw CodecError.truncated }
        guard let idx = c.u32() else { throw CodecError.truncated }
        guard let count = c.u32() else { throw CodecError.truncated }
        if count == 0 || count > maxChunkCount {
            throw CodecError.oversizedChunkCount
        }
        if idx >= count { throw CodecError.chunkIndexOutOfRange }
        guard let mimeLen = c.u16() else { throw CodecError.truncated }
        if Int(mimeLen) > maxMimeBytes { throw CodecError.oversizedMime }
        guard let mimeBytes = c.take(Int(mimeLen)) else { throw CodecError.truncated }
        let mime = String(data: mimeBytes, encoding: .utf8) ?? ""
        guard let fnLen = c.u16() else { throw CodecError.truncated }
        if Int(fnLen) > maxFilenameBytes { throw CodecError.oversizedFilename }
        guard let fnBytes = c.take(Int(fnLen)) else { throw CodecError.truncated }
        let filename = String(data: fnBytes, encoding: .utf8) ?? ""
        let chunkBytes = c.rest()
        if chunkBytes.count > maxChunkPlaintextBytes {
            throw CodecError.oversizedChunk
        }
        return FileChunkEnvelope(
            attachmentId: aid,
            totalSize: total,
            chunkIndex: idx,
            chunkCount: count,
            mime: mime,
            filename: filename,
            chunkBytes: chunkBytes,
        )
    }
}

/// Tiny byte cursor — same shape as the one in RelayClient but we
/// keep it private to the iOS app rather than re-exporting from the
/// crypto-core Swift package (Cursor is non-public there).
private struct Cursor {
    var buf: Data
    init(_ buf: Data) { self.buf = buf }
    mutating func u16() -> UInt16? {
        guard buf.count >= 2 else { return nil }
        let v = buf.prefix(2).withUnsafeBytes { ptr in
            UInt16(bigEndian: ptr.loadUnaligned(as: UInt16.self))
        }
        buf = buf.dropFirst(2)
        return v
    }
    mutating func u32() -> UInt32? {
        guard buf.count >= 4 else { return nil }
        let v = buf.prefix(4).withUnsafeBytes { ptr in
            UInt32(bigEndian: ptr.loadUnaligned(as: UInt32.self))
        }
        buf = buf.dropFirst(4)
        return v
    }
    mutating func u64() -> UInt64? {
        guard buf.count >= 8 else { return nil }
        let v = buf.prefix(8).withUnsafeBytes { ptr in
            UInt64(bigEndian: ptr.loadUnaligned(as: UInt64.self))
        }
        buf = buf.dropFirst(8)
        return v
    }
    mutating func take(_ n: Int) -> Data? {
        guard buf.count >= n else { return nil }
        let blob = buf.prefix(n)
        buf = buf.dropFirst(n)
        return Data(blob)
    }
    mutating func rest() -> Data {
        let r = buf
        buf = Data()
        return r
    }
}
