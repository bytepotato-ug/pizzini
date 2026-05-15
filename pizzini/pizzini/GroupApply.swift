import Foundation
import PizziniCryptoCore

/// Apply state machine for `ChatGroup`. Receivers call `apply(_:)` on
/// every signed `GroupOp` they receive; the call mutates the group's
/// membership / name / role / dist-id state in-place if the op is the
/// next one in the chain, queues it on `pendingOps` if there's an
/// epoch gap, and returns a structured outcome the host surfaces to
/// the user (e.g. equivocation warnings) or to logs (e.g. dropped
/// signatures).
///
/// The state machine is deliberately small — one entry point — so
/// every op flows through the exact same signature/epoch/parent
/// checks before any mutation. The Create op is NOT applied via this
/// path: `ChatGroup.create(fromCreate:signedBytes:localIdentityPub:)`
/// is the bootstrap constructor because there is no prior `ChatGroup`
/// to mutate.
extension ChatGroup {
    /// Outcome of a single apply attempt. The applied/queued cases
    /// carry the op's epoch so callers can wire up UI affordances
    /// (e.g. "5 ops queued, oldest at epoch 7").
    enum ApplyOutcome: Sendable, Equatable {
        case applied(epoch: UInt64)
        /// Op's epoch is beyond `currentEpoch + 1`. Stored on
        /// `pendingOps` and reattempted after subsequent successful
        /// applies via `replayPending()`.
        case queued(epoch: UInt64)
        /// We already applied this exact op (idempotent re-receive
        /// from a relay retry / sealed-sender redelivery). No-op.
        case rejectedDuplicate
        /// Two divergent ops have been observed at the same epoch.
        /// Either:
        ///   - We applied a different op at this epoch already (the
        ///     incoming op's digest does not match the one in
        ///     `recentOpDigests`), or
        ///   - The op is the next-in-chain (`epoch == currentEpoch + 1`)
        ///     but its `parentDigest` does not chain to our
        ///     `lastOpDigest` — the operator is forking the log.
        /// Both cases mean an admin equivocated; the host surfaces a
        /// "group integrity warning" to the user.
        case rejectedEquivocation(epoch: UInt64)
        /// Signature failed to verify against `operatorIdentity`.
        case rejectedSignature
        /// Operator is not authorised to perform this op (admin-only
        /// rules, or operator is no longer a member). Drop silently —
        /// a stale op from a removed member is the common cause and
        /// is not worth surfacing.
        case rejectedAuthorization
        /// Op is structurally malformed (e.g. payload references a
        /// peer not in the group, group is at member cap, would brick
        /// the group by removing the last admin). The string is for
        /// developer logs; the host surfaces a generic "operation
        /// failed" if anything user-facing is needed.
        case rejectedMalformed(String)
        /// Op's `priorMemberSetRoot` does not match the
        /// receiver's locally-computed canonical root over the
        /// current member set. The operator either:
        ///   - Forked the membership (silently added a ghost member
        ///     visible only on their side), OR
        ///   - Operated on stale state (didn't see a peer's removal
        ///     before issuing this op).
        /// Either way the apply is unsafe — surfaces a stronger
        /// "group integrity warning" than the equivocation case,
        /// because the operator's signature is valid but the state
        /// they witnessed disagrees with ours. Carries both digests
        /// for the diagnostic UI / dev logs.
        case rejectedMemberSetMismatch(local: Data, claimed: Data)
        /// Past-epoch op for an epoch BEFORE the local user joined the
        /// group. A member bootstrapped via `GroupBootstrap` seeds
        /// `recentOpDigests` with a single entry, so for any epoch
        /// below the bootstrap epoch the equivocation check has no
        /// cached digest to compare against and would silently
        /// classify a divergent op as `.rejectedDuplicate`. That
        /// would let an inviting admin equivocate undetectably on
        /// every pre-join epoch. We instead surface this distinct
        /// outcome: the receiver genuinely cannot verify history from
        /// before they joined, and the host shows a "cannot verify
        /// history before you joined" state rather than a misleading
        /// silent duplicate-drop.
        case rejectedPreJoinHistory(epoch: UInt64)
    }

    /// Side effects accumulated during `apply(_:sideEffects:)`. The host
    /// (`ChatStoreGroups`) consults these to decide whether to ship our
    /// SKDM to a freshly-active member, schedule our own chain
    /// rotation in response to a member-remove, or surface a UI
    /// notification. The struct intentionally has no `Date` /
    /// counter / op-payload fields — anything time-sensitive lives in
    /// the persisted `ChatGroup` proper.
    struct ApplySideEffects: Sendable {
        /// Peers who became active members in this apply (or in any
        /// queue-drained op chained from it). Drives the bidirectional
        /// SKDM exchange: for every entry, the host broadcasts its
        /// current SKDM to that peer if it hasn't already done so
        /// since the last rotation. Audit fix HIGH-2.
        var newActiveMembers: Set<Data> = []

        /// True when an inbound `RemoveMember` op landed where the
        /// target is NOT the local user. Per design point 5 (audit
        /// HIGH-1), every remaining active member rotates their own
        /// chain on a member-remove so the removed member can no
        /// longer decrypt subsequent messages from anyone — not just
        /// the admin who issued the remove.
        var requestSelfRotation: Bool = false

        /// True when the local user is the target of an inbound
        /// `RemoveMember` op. The host clears self's chain state
        /// (myCurrentDistributionId, mySkdmRecipients,
        /// sentSinceRotation) and refuses subsequent
        /// `sendGroupMessage` calls. Audit fix HIGH-3 / MEDIUM-5.
        var requestSelfChainClear: Bool = false

        /// Equivocation epoch when the apply produced
        /// `.rejectedEquivocation` and the host should surface a
        /// system row. Mirrored from the outcome for callers that
        /// want a single inspection point post-apply.
        var equivocationEpoch: UInt64? = nil

        /// True when this apply lowered or raised an admin slot. The
        /// host can use this to refresh any cached `isAdmin` state.
        /// Currently informational only.
        var rolesChanged: Bool = false

        /// Identity-pub of the local user, captured at the start of
        /// `apply(_:sideEffects:)` so post-mutation predicates
        /// (`requestSelfChainClear`, `newActiveMembers`-not-self) can
        /// run without re-threading the value. Set by the convenience
        /// overload from the host's `myCard.peerId`.
        fileprivate var localIdentityPub: Data?

        public init(localIdentityPub: Data? = nil) {
            self.localIdentityPub = localIdentityPub
        }
    }

    /// Apply a signed op. Mutates `members`, `displayName`,
    /// `currentEpoch`, `lastOpDigest`, `memberDistributionIds`,
    /// `pendingOps`, and `recentOpDigests`. Replays the pending queue
    /// after a successful apply.
    @discardableResult
    mutating func apply(_ op: GroupOp) -> ApplyOutcome {
        var sx = ApplySideEffects()
        return apply(op, sideEffects: &sx)
    }

    /// Side-effect-aware overload. The host passes a `sideEffects`
    /// accumulator that the state machine populates; the host then
    /// inspects it after the call to decide whether to broadcast
    /// SKDMs, rotate chains, surface UI rows, etc.
    @discardableResult
    mutating func apply(_ op: GroupOp, sideEffects sx: inout ApplySideEffects) -> ApplyOutcome {
        // Phase 1: structural sanity — wrong group ID is the easy
        // way to catch a misrouted op (e.g. host applied to the
        // wrong ChatGroup).
        guard op.groupId == self.id else {
            return .rejectedMalformed("groupId mismatch")
        }

        // Compute the op's digest once; we need it for both
        // equivocation detection (at this-or-prior epoch) and the
        // hash-chain update (after a successful apply). Failure here
        // would mean the op didn't survive a re-encode — either
        // malformed or codec broken. Either way: reject as malformed,
        // don't crash. Bound to a local variable name that doesn't
        // shadow `digest(forEpoch:)`.
        guard let signedBytes = try? op.encoded() else {
            return .rejectedMalformed("could not encode op")
        }
        let opDigest = Blake3.hash(signedBytes)

        // Phase 2: signature. We do this BEFORE epoch checks so a
        // malicious peer can't probe our state by sending unsigned
        // future-epoch ops to learn our `currentEpoch` from queue
        // behaviour.
        guard let valid = try? op.verifySignature(), valid else {
            return .rejectedSignature
        }

        // Phase 3: epoch ordering.
        let expectedEpoch = currentEpoch + 1
        if op.epoch < expectedEpoch {
            // Past-epoch op for an epoch BEFORE the local user joined:
            // we have no cached digest for that epoch (a bootstrapped
            // member's `recentOpDigests` starts with a single entry at
            // the bootstrap epoch), so the equivocation check below
            // cannot fire and would mislabel a divergent op as a
            // benign `.rejectedDuplicate`. Surface it as explicitly
            // out-of-scope instead — the receiver cannot verify
            // history from before their join, and the host shows that
            // state rather than silently swallowing the op.
            if let localId = sx.localIdentityPub,
               let localJoinedAt = members.first(where: { $0.peerId == localId })?.joinedAtEpoch,
               op.epoch < localJoinedAt {
                return .rejectedPreJoinHistory(epoch: op.epoch)
            }
            // Past-epoch op at or after our join epoch. Distinguish
            // equivocation from idempotent re-receive via the cached
            // digest at that epoch.
            if let known = digest(forEpoch: op.epoch), known != opDigest {
                sx.equivocationEpoch = op.epoch
                return .rejectedEquivocation(epoch: op.epoch)
            }
            return .rejectedDuplicate
        }
        if op.epoch > expectedEpoch {
            // Future-epoch op. Park it; `replayPending()` will retry
            // after the missing parents arrive.
            queuePending(signedBytes: signedBytes)
            return .queued(epoch: op.epoch)
        }

        // Phase 4: parent hash chain. The op's `parentDigest` must
        // match the digest of our most-recently-applied op, otherwise
        // the operator is forking the chain.
        if op.parentDigest != lastOpDigest {
            sx.equivocationEpoch = op.epoch
            return .rejectedEquivocation(epoch: op.epoch)
        }

        // Phase 5: authorisation.
        guard isAuthorised(operatorIdentity: op.operatorIdentity, kind: op.kind) else {
            return .rejectedAuthorization
        }

        // Phase 5.5: Verifiable group membership.
        //
        // The operator stamped this op with a canonical hash of the
        // member set they believed to be current at signing time.
        // Recompute against our local view; mismatch means our two
        // views of "who is in this group" differ — either someone
        // added a ghost member on one side and not the other, or an
        // earlier op didn't propagate, or somebody is operating on
        // stale state. None of those are safe to apply: the
        // resulting state would diverge from every other honest
        // member's view, and a malicious admin would be able to
        // inject ghost members the rest of us never authorised.
        //
        // Two-byte equality compare via the Data == implementation,
        // which is constant-time enough for a 32-byte BLAKE3 digest
        // — there is no secret on either side anyway (both digests
        // are derived from public membership state).
        let localRoot = self.memberSetRoot
        if op.priorMemberSetRoot != localRoot {
            return .rejectedMemberSetMismatch(local: localRoot, claimed: op.priorMemberSetRoot)
        }

        // Phase 6: domain mutation.
        switch executeMutation(op: op, sideEffects: &sx) {
        case .ok:
            currentEpoch = op.epoch
            lastOpDigest = opDigest
            recordDigest(opDigest, atEpoch: op.epoch)
            replayPending(sideEffects: &sx)
            return .applied(epoch: op.epoch)
        case let .rejected(reason):
            return .rejectedMalformed(reason)
        }
    }

    /// Drain any queued ops whose `epoch == currentEpoch + 1` after a
    /// successful apply. A single landed op can unblock a long chain
    /// of queued descendants; we sort by epoch ascending and walk
    /// forward, applying each next-epoch op until the chain breaks
    /// again. Idempotent.
    ///
    /// Sorting + index-based walk gives us O(N log N) up front then
    /// O(N) drain, vs. the previous O(N²) "scan-and-restart" pattern
    /// which a malicious admin could weaponise into multi-second main-
    /// thread pins by shipping a queue-filling reverse-order chain
    /// (audit HIGH-6).
    mutating func replayPending() {
        var sx = ApplySideEffects()
        replayPending(sideEffects: &sx)
    }

    /// Side-effect-aware drain. Side effects accumulate across all
    /// applied ops, so the host sees the union of (e.g.) "new active
    /// members" from a chain of AddMembers that drained at once.
    mutating func replayPending(sideEffects sx: inout ApplySideEffects) {
        guard !pendingOps.isEmpty else { return }

        // Decode + sort once so the drain is monotonic. Ops we can't
        // decode are dropped here rather than surviving the queue.
        //
        // retention is enforced at queue-INSERT time via
        // `queuePending`'s per-operator cap rather than as a
        // timestamp filter here. The audit's original suggestion
        // ("drop ops whose claimed timestamp is > 30d old") is
        // attractive but `timestampMillis` is operator-chosen — a
        // malicious admin can claim any value. The per-operator cap
        // is the architectural fix: one bad admin can occupy at
        // most `pendingOpsPerOperatorCap` slots regardless of what
        // they sign or when. A future-claimed timestamp doesn't
        // change the queue-fill math.
        var decoded: [(epoch: UInt64, bytes: Data, op: GroupOp)] = []
        decoded.reserveCapacity(pendingOps.count)
        for bytes in pendingOps {
            guard let op = GroupOp.decode(bytes) else { continue }
            decoded.append((op.epoch, bytes, op))
        }
        decoded.sort { $0.epoch < $1.epoch }

        var keptBytes: [Data] = []
        keptBytes.reserveCapacity(decoded.count)

        var idx = 0
        while idx < decoded.count {
            let entry = decoded[idx]
            if entry.epoch <= currentEpoch {
                // Already-superseded queued op. Drop.
                idx += 1
                continue
            }
            if entry.epoch == currentEpoch + 1 {
                // Apply this op. If it succeeds, currentEpoch
                // advances and the same loop pass picks up the next
                // entry (now at the new currentEpoch + 1).
                let outcome = applyAlreadyParked(entry.op, signedBytes: entry.bytes, sideEffects: &sx)
                if case .applied = outcome {
                    idx += 1
                    continue
                }
                // Apply failed (e.g. signature or auth). Drop this op
                // and continue — no point re-applying a known-bad op.
                idx += 1
                continue
            }
            // Epoch is strictly in the future relative to currentEpoch
            // (gap not yet closed). Keep for later.
            keptBytes.append(entry.bytes)
            idx += 1
        }

        pendingOps = keptBytes
    }

    // ─── helpers ────────────────────────────────────────────────────

    private mutating func queuePending(signedBytes: Data) {
        if pendingOps.count >= ChatGroup.pendingOpsCap { return }
        if pendingOps.contains(signedBytes) { return }
        // Per-operator sub-cap. Without this, one
        // compromised admin can sign `pendingOpsCap` future-epoch ops
        // and pin the entire queue, silently dropping every other
        // admin's legitimate future ops. With it, the worst-case
        // impact of a single bad admin is bounded to their own
        // `pendingOpsPerOperatorCap` slots.
        if let incoming = GroupOp.decode(signedBytes) {
            let ownedByThisOperator = pendingOps.reduce(0) { acc, bytes in
                guard let op = GroupOp.decode(bytes) else { return acc }
                return op.operatorIdentity == incoming.operatorIdentity ? acc + 1 : acc
            }
            if ownedByThisOperator >= ChatGroup.pendingOpsPerOperatorCap {
                return
            }
        }
        pendingOps.append(signedBytes)
    }

    /// Same path as `apply(_:)` but skips the queue check — invoked
    /// from `replayPending(sideEffects:)` when we know the op is at
    /// the next-epoch boundary. Re-runs signature/parent checks
    /// because they're cheap and the queue may have been re-ordered
    /// relative to the signing time. Defensive guard: refuse to apply
    /// anything not at `currentEpoch + 1` even though the caller
    /// promises this — audit LOW-1.
    private mutating func applyAlreadyParked(
        _ op: GroupOp,
        signedBytes: Data,
        sideEffects sx: inout ApplySideEffects,
    ) -> ApplyOutcome {
        guard op.epoch == currentEpoch + 1 else {
            return .rejectedMalformed("applyAlreadyParked invariant: epoch != currentEpoch + 1")
        }
        let opDigest = Blake3.hash(signedBytes)
        guard let valid = try? op.verifySignature(), valid else {
            return .rejectedSignature
        }
        if op.parentDigest != lastOpDigest {
            sx.equivocationEpoch = op.epoch
            return .rejectedEquivocation(epoch: op.epoch)
        }
        guard isAuthorised(operatorIdentity: op.operatorIdentity, kind: op.kind) else {
            return .rejectedAuthorization
        }
        switch executeMutation(op: op, sideEffects: &sx) {
        case .ok:
            currentEpoch = op.epoch
            lastOpDigest = opDigest
            recordDigest(opDigest, atEpoch: op.epoch)
            return .applied(epoch: op.epoch)
        case let .rejected(reason):
            return .rejectedMalformed(reason)
        }
    }

    private func isAuthorised(operatorIdentity opId: Data, kind: GroupOpKind) -> Bool {
        switch kind {
        case .rotateSenderKey:
            // Any active member may rotate their own chain.
            return members.contains { $0.peerId == opId && $0.status != .removed }
        case .create:
            // Create is not applied through this state machine — see
            // `ChatGroup.create(fromCreate:signedBytes:localIdentityPub:)`.
            // If a Create op slips into apply(), we've messed up
            // somewhere; reject defensively.
            return false
        default:
            // Admin-only mutations: AddMember, RemoveMember, Rename,
            // PromoteAdmin, DemoteAdmin.
            return members.contains {
                $0.peerId == opId && $0.role == .admin && $0.status != .removed
            }
        }
    }

    private mutating func executeMutation(
        op: GroupOp,
        sideEffects sx: inout ApplySideEffects,
    ) -> MutationOutcome {
        switch op.kind {
        case .create:
            // Caught by `isAuthorised` above; defensive duplicate.
            return .rejected("Create must use ChatGroup.create(fromCreate:...)")
        case let .addMember(peerId, role, displayName):
            return mutateAddMember(
                peerId: peerId,
                role: role,
                displayName: displayName,
                addedBy: op.operatorIdentity,
                atEpoch: op.epoch,
                sideEffects: &sx,
            )
        case let .removeMember(peerId):
            return mutateRemoveMember(peerId: peerId, sideEffects: &sx)
        case let .rename(newName):
            displayName = newName
            return .ok
        case let .promoteAdmin(peerId):
            sx.rolesChanged = true
            return mutatePromoteAdmin(peerId: peerId)
        case let .demoteAdmin(peerId):
            sx.rolesChanged = true
            return mutateDemoteAdmin(peerId: peerId)
        case let .rotateSenderKey(newDistributionId):
            // Updates only the operator's chain — other members'
            // entries are untouched. The local user's
            // `myCurrentDistributionId` is set by the host at
            // SKDM-create time; this branch never overwrites it,
            // even when the op is our own (the host calls apply on
            // its own freshly-signed RotateSenderKey op).
            memberDistributionIds[op.operatorIdentity] = newDistributionId
            return .ok
        }
    }

    private mutating func mutateAddMember(
        peerId: Data,
        role: GroupRole,
        displayName: String,
        addedBy: Data,
        atEpoch epoch: UInt64,
        sideEffects sx: inout ApplySideEffects,
    ) -> MutationOutcome {
        guard peerId.count == GroupOp.identityKeySize else {
            return .rejected("invalid peerId length")
        }

        // Re-add of a previously-removed peer: replace the row in
        // place rather than appending so member-history-order stays
        // consistent across the op log replay. Audit fix HIGH-4: the
        // member cap must apply on this branch too — otherwise
        // remove-then-readd cycles the cap upward without bound.
        if let idx = members.firstIndex(where: { $0.peerId == peerId }) {
            if members[idx].status != .removed {
                return .rejected("member already active in group")
            }
            // Re-add bumps activeMembers by 1; reject if it would
            // cross the hard cap.
            if activeMembers.count >= ChatGroup.maxMembers {
                return .rejected("group at member cap")
            }
            members[idx] = GroupMember(
                peerId: peerId,
                displayName: displayName,
                role: role,
                joinedAtEpoch: epoch,
                status: .pendingSKDM,
                addedBy: addedBy,
            )
            // Drop any lingering dist-id binding from before the
            // remove so the next SKDM cleanly installs the fresh chain.
            memberDistributionIds.removeValue(forKey: peerId)
            if peerId != sx.localIdentityPub {
                sx.newActiveMembers.insert(peerId)
            }
            return .ok
        }

        if activeMembers.count >= ChatGroup.maxMembers {
            return .rejected("group at member cap")
        }
        members.append(GroupMember(
            peerId: peerId,
            displayName: displayName,
            role: role,
            joinedAtEpoch: epoch,
            status: .pendingSKDM,
            addedBy: addedBy,
        ))
        if peerId != sx.localIdentityPub {
            sx.newActiveMembers.insert(peerId)
        }
        return .ok
    }

    private mutating func mutateRemoveMember(
        peerId: Data,
        sideEffects sx: inout ApplySideEffects,
    ) -> MutationOutcome {
        guard let idx = members.firstIndex(where: {
            $0.peerId == peerId && $0.status != .removed
        }) else {
            return .rejected("member not in group")
        }
        // Last-admin protection: removing the only remaining admin
        // would brick the group. Reject — admins must be replaced
        // before being removed.
        let activeAdmins = activeMembers.filter { $0.role == .admin }
        if activeAdmins.count == 1, activeAdmins[0].peerId == peerId {
            return .rejected("cannot remove the last admin")
        }
        members[idx].status = .removed
        // Drop the removed member's dist_id binding so we don't
        // accidentally reuse a stale chain if the same peerId is
        // later re-added at a fresh dist_id.
        memberDistributionIds.removeValue(forKey: peerId)
        // Drop them from the "we've shipped our SKDM" set so a
        // subsequent re-add gets a fresh broadcast.
        mySkdmRecipients.remove(peerId)

        if let me = sx.localIdentityPub, peerId == me {
            // We're the target. Host will clear our own chain state.
            sx.requestSelfChainClear = true
        } else if let me = sx.localIdentityPub,
                  members.contains(where: { $0.peerId == me && $0.status != .removed }) {
            // We're still active — design point 5 mandates we rotate
            // our own chain so the removed peer can't decrypt our
            // future messages. Audit fix HIGH-1.
            sx.requestSelfRotation = true
        }
        return .ok
    }

    private mutating func mutatePromoteAdmin(peerId: Data) -> MutationOutcome {
        guard let idx = members.firstIndex(where: {
            $0.peerId == peerId && $0.status != .removed
        }) else {
            return .rejected("target not in group")
        }
        members[idx].role = .admin
        return .ok
    }

    private mutating func mutateDemoteAdmin(peerId: Data) -> MutationOutcome {
        guard let idx = members.firstIndex(where: {
            $0.peerId == peerId && $0.status != .removed
        }) else {
            return .rejected("target not in group")
        }
        let activeAdmins = activeMembers.filter { $0.role == .admin }
        if activeAdmins.count == 1, activeAdmins[0].peerId == peerId {
            return .rejected("cannot demote the last admin")
        }
        members[idx].role = .member
        return .ok
    }

    private enum MutationOutcome {
        case ok
        case rejected(String)
    }
}

extension ChatGroup {
    /// Construct a fresh `ChatGroup` from a freshly-received (or
    /// just-signed) `Create` op. The caller must verify the op's
    /// signature *before* invoking this — at the bootstrap moment we
    /// have no prior `ChatGroup` state and no membership chain to
    /// authorise against, so the trust anchor for accepting the
    /// Create comes one layer up: post-audit, the host MUST also
    /// verify (a) the immediate sender of the inner-envelope IS the
    /// operator of the Create op (no forwarding), and (b) the
    /// operator is in the local user's 1:1 contacts. See
    /// `handleGroupOp` in `ChatStoreGroups.swift` for both checks.
    /// Returns nil for a structurally-invalid Create.
    ///
    /// `localIdentityPub` is currently unused at construction time —
    /// kept in the signature for symmetry with future paths that
    /// derive the local user's initial `MemberStatus` (e.g. `.active`
    /// if we are the creator, `.pendingSKDM` otherwise).
    static func create(
        fromCreate op: GroupOp,
        signedBytes: Data,
        localIdentityPub _: Data,
    ) -> ChatGroup? {
        guard case let .create(name, initialMembers) = op.kind else { return nil }
        guard op.epoch == 0 else { return nil }
        guard op.parentDigest == GroupOp.zeroParentDigest else { return nil }
        guard op.groupId.count == GroupOp.groupIdSize else { return nil }
        guard initialMembers.count <= ChatGroup.maxMembers else { return nil }
        // Operator must be in the initial member list. Their declared
        // role is overridden to .admin so a malformed Create that
        // tries to bootstrap with a non-admin operator can't brick
        // the group with no admins.
        guard initialMembers.contains(where: { $0.peerId == op.operatorIdentity }) else {
            return nil
        }
        // Members can't appear twice in the initial list.
        let unique = Set(initialMembers.map { $0.peerId })
        guard unique.count == initialMembers.count else { return nil }

        let members = initialMembers.map { spec -> GroupMember in
            GroupMember(
                peerId: spec.peerId,
                displayName: spec.displayName,
                role: spec.peerId == op.operatorIdentity ? .admin : spec.role,
                joinedAtEpoch: 0,
                status: .pendingSKDM,
                // Every initial member was introduced by the creator —
                // including the creator themselves (self-introduced).
                addedBy: op.operatorIdentity,
            )
        }

        let opDigest = Blake3.hash(signedBytes)
        let createdAt = Date(
            timeIntervalSince1970: TimeInterval(op.timestampMillis) / 1000,
        )
        return ChatGroup(
            id: op.groupId,
            displayName: name,
            members: members,
            createdAt: createdAt,
            currentEpoch: 0,
            lastOpDigest: opDigest,
            pendingOps: [],
            log: [],
            lastSeenAt: nil,
            lastMessageAt: nil,
            myCurrentDistributionId: nil,
            memberDistributionIds: [:],
            sentSinceRotation: 0,
            lastRotatedAt: createdAt,
            mySkdmRecipients: [],
            recentOpDigests: [String(0): opDigest],
            // Receive-side bootstrap: the user must accept the
            // invitation before we enrol our chain or render
            // messages. The host (`createGroup`) flips this back to
            // false because the creator has already implicitly
            // accepted by initiating.
            pendingInvitation: true,
        )
    }
}
