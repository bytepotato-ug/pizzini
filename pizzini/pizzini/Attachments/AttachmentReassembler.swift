import Foundation

/// Receiver-side state machine for chunked file transfers.
///
/// Each (peer, attachmentId) pair gets one `Pending` entry; chunks
/// arrive in arbitrary order and we buffer them on disk under
/// `attachments/incoming/{aid}/chunk-{idx}.bin`. When the last expected
/// chunk lands, we concatenate into the final filename and hand the
/// URL back through `Result.complete`.
///
/// Disk-backed (not RAM-backed) for two reasons:
///   1. iOS suspending the app mid-receive shouldn't drop bytes the
///      relay is going to wash off its 24h queue.
///   2. Memory bound: a 64 MB attachment held in RAM during reassembly
///      meaningfully impacts memory pressure on older devices.
///
/// Adversarial bound: a malicious sender shipping `chunk_count = 1024`
/// followed by 1 chunk would otherwise pin the partial directory until
/// the user reset the app. `Pending.expiresAt` is set on first-chunk
/// arrival to `now + Self.partialTTL`; `staleEntries(now:)` flags
/// expired entries for cleanup.
@MainActor
final class AttachmentReassembler {
    /// Outcome of feeding a single chunk into the reassembler.
    enum FeedResult {
        /// Chunk accepted; not yet complete. `received` is the count
        /// across this attachment so far, `expected` is `chunk_count`.
        case progress(received: Int, expected: Int)
        /// All chunks present. Bytes assembled at `url`; the chat row
        /// can be inserted with this metadata.
        case complete(Completion)
        /// Chunk dropped — duplicate, claimed-vs-actual mismatch, or
        /// a hostile size assertion. Receiver should NOT advance UI;
        /// the inner-envelope ratchet step has already happened.
        case rejected(Reason)
    }

    enum Reason: Error, Equatable {
        case sizeMismatch     // sum-of-chunk-bytes != total_size
        case attachmentIdMismatch
        case duplicateChunk
        case oversizedChunk
        case writeFailed
    }

    struct Completion: Sendable {
        let attachmentId: Data
        let url: URL
        let sanitizedFilename: String
        let mime: String
        let totalSize: UInt64
        let tier: AttachmentTier
    }

    /// One per (peer, attachmentId). Persistent state lives on disk —
    /// this in-memory map exists for fast "have I already reassembled
    /// this?" lookups and for the staleness pass.
    private struct Pending {
        let attachmentId: Data
        let peer: Data
        let totalSize: UInt64
        let chunkCount: UInt32
        let claimedFilename: String
        let claimedMime: String
        var receivedIndices: Set<UInt32>
        var firstSeenAt: Date
        var expiresAt: Date
    }

    /// 24h cap on a partial reassembly. Matches the relay's max
    /// pending-frame TTL — anything that hasn't drained from the relay
    /// in 24h won't arrive after.
    static let partialTTL: TimeInterval = 24 * 60 * 60

    /// Per-peer cap on simultaneous in-flight attachments. A paired
    /// peer that opens N distinct attachmentIds and ships one chunk
    /// each could otherwise pin N directory inodes + chunk files on
    /// disk for 24 hours. The multi-select picker is hard-capped at
    /// 1 attachment per send (AttachmentPicker), so legitimate use
    /// never approaches this number; 32 is generous and bounds the
    /// damage to ~32 × 64 MiB worst-case per peer.
    static let perPeerPendingCap: Int = 32

    /// Receive-side memoisation of attachmentIds whose assembled file
    /// already exists on disk. Defends against the same-attachmentId-
    /// replay attack where a sender re-ships chunks under the same
    /// `attachmentId` after the receiver removed the pending entry on
    /// completion — without this guard the second transfer would
    /// truncate-overwrite the existing assembled file, swapping the
    /// bytes behind a chat row the user already accepted.
    private var completedAttachmentIds: Set<Data> = []

    /// Map key: `peer + attachmentId` (49 bytes for a libsignal IdentityKey).
    /// Don't key on attachmentId alone: a malicious paired peer A could
    /// otherwise try to confuse a separate peer B's reassembly by
    /// sending a chunk with the same attachment id (defeated by the
    /// peer-prefix; even ignoring sealed-sender's contact gate, the
    /// reassembler tables are partitioned per peer).
    private var pending: [Data: Pending] = [:]

    /// Feed one decoded `FileChunkEnvelope` from `peer`. Returns the
    /// outcome — caller observes `.complete` to insert a chat row.
    @discardableResult
    func feed(envelope: FileChunkEnvelope, fromPeer peer: Data) -> FeedResult {
        let key = peer + envelope.attachmentId

        // **Replay defense.** If we've previously
        // completed this attachmentId, reject every subsequent chunk
        // — the sender can't legitimately re-open the same id, and
        // accepting the chunk would truncate-overwrite the existing
        // assembled file on disk that an already-inserted chat row
        // points at. Bytes "behind" a row the user already accepted
        // would silently change.
        if completedAttachmentIds.contains(envelope.attachmentId) {
            return .rejected(.duplicateChunk)
        }

        // First-chunk-of-attachment: set up the disk dir + record.
        if pending[key] == nil {
            // **Per-peer in-flight cap.** Refuse to accept
            // a new attachmentId for this peer if they're already at
            // the cap. The reaper's 24h TTL will free slots; until
            // then a malicious sender can't pin unbounded disk by
            // opening millions of distinct one-chunk attachments.
            let inFlightForPeer = pending.values.filter { $0.peer == peer }.count
            if inFlightForPeer >= Self.perPeerPendingCap {
                return .rejected(.writeFailed)
            }
            let now = Date()
            let entry = Pending(
                attachmentId: envelope.attachmentId,
                peer: peer,
                totalSize: envelope.totalSize,
                chunkCount: envelope.chunkCount,
                claimedFilename: envelope.filename,
                claimedMime: envelope.mime,
                receivedIndices: [],
                firstSeenAt: now,
                expiresAt: now.addingTimeInterval(Self.partialTTL),
            )
            pending[key] = entry
            // Ensure the dir exists.
            _ = try? AttachmentSandbox.inboundDirectory(forAttachmentId: envelope.attachmentId)
        }

        guard var entry = pending[key] else {
            return .rejected(.attachmentIdMismatch)
        }
        // Per-attachment immutables: a sender can't change their mind
        // about total_size / chunk_count / filename mid-transfer.
        // Treat any divergence as hostile and drop.
        guard
            entry.totalSize == envelope.totalSize,
            entry.chunkCount == envelope.chunkCount,
            entry.claimedFilename == envelope.filename,
            entry.claimedMime == envelope.mime
        else {
            return .rejected(.attachmentIdMismatch)
        }
        if envelope.chunkIndex >= envelope.chunkCount {
            return .rejected(.attachmentIdMismatch)
        }
        if entry.receivedIndices.contains(envelope.chunkIndex) {
            // Dup at the reassembler layer. libsignal's seal_receive
            // already filtered ratchet-level dup; this triggers if the
            // sender re-encrypted the same chunk (e.g. their outbox
            // retried after we processed both). Safe to drop.
            return .rejected(.duplicateChunk)
        }

        // Defensive: the codec already capped chunk size, but check
        // again — a chunk that claims to fit but actually overruns
        // total_size when summed with prior chunks should bail before
        // we write garbage to disk.
        if UInt64(envelope.chunkBytes.count) > envelope.totalSize {
            return .rejected(.oversizedChunk)
        }

        // Persist this chunk to its index file.
        guard let chunkURL = chunkFileURL(
            attachmentId: envelope.attachmentId, index: envelope.chunkIndex
        ) else {
            return .rejected(.writeFailed)
        }
        do {
            try envelope.chunkBytes.write(
                to: chunkURL,
                options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication],
            )
        } catch {
            return .rejected(.writeFailed)
        }

        entry.receivedIndices.insert(envelope.chunkIndex)
        pending[key] = entry

        if entry.receivedIndices.count == Int(entry.chunkCount) {
            // All chunks present — assemble.
            switch finalize(entry) {
            case .success(let completion):
                pending.removeValue(forKey: key)
                // Mark this attachmentId as completed so a subsequent
                // re-send under the same id is rejected.
                // The 24h reaper clears stale entries; on a duress
                // wipe `AttachmentSandbox.eraseEverything()` clears
                // the on-disk files and a fresh ChatStore drops the
                // set with the rest of in-memory state.
                completedAttachmentIds.insert(completion.attachmentId)
                return .complete(completion)
            case .failure(let reason):
                // Cleanup partial state on a finalisation failure so
                // a re-send from the peer (rare, but a relay queue
                // re-drain could re-send) doesn't compound the issue.
                pending.removeValue(forKey: key)
                if let dir = try? AttachmentSandbox.inboundDirectory(
                    forAttachmentId: entry.attachmentId
                ) {
                    try? FileManager.default.removeItem(at: dir)
                }
                return .rejected(reason)
            }
        }
        return .progress(
            received: entry.receivedIndices.count,
            expected: Int(entry.chunkCount),
        )
    }

    /// Walk pending entries and return the attachment ids whose
    /// `expiresAt < now`. Caller is expected to call `discard(...)`
    /// on each. Pure read — no state mutation here so the caller can
    /// log / surface system messages before we wipe disk state.
    func staleEntries(now: Date) -> [(peer: Data, attachmentId: Data, claimedFilename: String)] {
        pending.values.compactMap {
            $0.expiresAt < now
                ? (peer: $0.peer, attachmentId: $0.attachmentId, claimedFilename: $0.claimedFilename)
                : nil
        }
    }

    /// Drop all in-memory + on-disk state for a (peer, attachment).
    func discard(peer: Data, attachmentId: Data) {
        let key = peer + attachmentId
        pending.removeValue(forKey: key)
        if let dir = try? AttachmentSandbox.inboundDirectory(forAttachmentId: attachmentId) {
            try? FileManager.default.removeItem(at: dir)
        }
    }

    // MARK: - Internals

    private func finalize(_ entry: Pending) -> Result<Completion, Reason> {
        let dir: URL
        do {
            dir = try AttachmentSandbox.inboundDirectory(forAttachmentId: entry.attachmentId)
        } catch {
            return .failure(.writeFailed)
        }

        // Re-sanitize the filename on the receive side: the sender's
        // claim is informational (sealed envelopes hide the filename
        // from the relay; only the sender wrote it). Re-running the
        // sanitiser here makes the receive path idempotent and defends
        // against a paired-peer threat model where the sender may
        // intentionally have skipped the sender-side sanitize.
        let safeName = FilenameSanitizer.sanitize(entry.claimedFilename)
        let tier = AttachmentTierClassifier.tier(forFilename: safeName)

        // Concatenate chunk-{i}.bin → {safeName}, byte-counted to
        // verify total_size.
        let outURL = dir.appending(path: safeName, directoryHint: .notDirectory)
        // Defense in depth on top of FilenameSanitizer: assert outURL
        // resolves inside `dir`. The sanitizer now refuses `.` / `..`
        // explicitly, but a future iOS version's URL standardization
        // could still produce surprising results — bail before we
        // create the file rather than after.
        do {
            try AttachmentSandbox.assertContained(url: outURL, in: dir)
        } catch {
            return .failure(.writeFailed)
        }
        FileManager.default.createFile(atPath: outURL.path, contents: nil, attributes: [
            .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
        ])
        guard let handle = try? FileHandle(forWritingTo: outURL) else {
            return .failure(.writeFailed)
        }
        defer { try? handle.close() }

        var written: UInt64 = 0
        for i in 0..<entry.chunkCount {
            guard let cu = chunkFileURL(attachmentId: entry.attachmentId, index: i) else {
                return .failure(.writeFailed)
            }
            do {
                let bytes = try Data(contentsOf: cu, options: [.mappedIfSafe])
                try handle.write(contentsOf: bytes)
                written += UInt64(bytes.count)
            } catch {
                return .failure(.writeFailed)
            }
        }
        if written != entry.totalSize {
            // Sender lied about total_size or a chunk got truncated
            // somehow. Don't surface a corrupt file to the user.
            return .failure(.sizeMismatch)
        }

        // Wipe the per-chunk staging files now that they're all
        // concatenated. The assembled file stays.
        for i in 0..<entry.chunkCount {
            if let cu = chunkFileURL(attachmentId: entry.attachmentId, index: i) {
                try? FileManager.default.removeItem(at: cu)
            }
        }

        return .success(Completion(
            attachmentId: entry.attachmentId,
            url: outURL,
            sanitizedFilename: safeName,
            mime: entry.claimedMime,
            totalSize: entry.totalSize,
            tier: tier,
        ))
    }

    private func chunkFileURL(attachmentId: Data, index: UInt32) -> URL? {
        guard let dir = try? AttachmentSandbox.inboundDirectory(forAttachmentId: attachmentId)
        else { return nil }
        return dir.appending(
            path: String(format: "chunk-%05u.bin", index),
            directoryHint: .notDirectory,
        )
    }
}
