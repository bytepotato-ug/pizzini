import Foundation
import PizziniCryptoCore
import UniformTypeIdentifiers

/// Group-chat surface on `ChatStore`. Lives in its own file to keep
/// ChatStore.swift's 1.5K-line core legible while still piggybacking
/// on its `state`, `session`, `relay`, and outbox plumbing.
///
/// Trust gates (audit fixes):
///
/// * `handleGroupOp` for `Create` requires the sender to BE the
///   operator (no forwarding) AND the operator to be in our 1:1
///   contacts. Same gate applied to `handleGroupBootstrap`.
///   (CRITICAL-1.)
/// * `handleGroupChat` decrypts only when the sender is an active
///   member of the named group. (CRITICAL-2.)
/// * `handleGroupKeyDistribution` installs a peer's chain only when
///   the group exists locally AND the peer is an active member of it.
///   (CRITICAL-3.)
///
/// Bidirectional SKDM exchange (HIGH-2): every time the group's
/// member set or our chain changes, the host calls
/// `ensureMySKDMReachesActiveMembers` to ship our current SKDM to any
/// active member who hasn't yet received it. The set of recipients
/// we've already shipped to lives on `ChatGroup.mySkdmRecipients` and
/// resets on rotation.
///
/// Mandatory rotation on remove (HIGH-1): every remaining active
/// member rotates their own chain when a `RemoveMember` op lands —
/// not just the admin who issued it. The state machine sets a
/// `requestSelfRotation` flag in `ApplySideEffects`; the host fires
/// one `rotateMyGroupChain` per call (coalesced regardless of how
/// many removes arrived in the same drain).
///
/// Wiring summary:
///
/// **Outbound** (this file):
///   - `createGroup`     — mint groupId, sign Create op, generate
///                         local sender-key, broadcast op + SKDM to
///                         every invitee.
///   - `inviteToGroup`   — admin-only; build AddMember op, ship a
///                         signed `GroupBootstrap` to the newcomer
///                         (so they can build local state without an
///                         op-chain replay), broadcast the AddMember
///                         to all current members, ship our current
///                         SKDM to the newcomer.
///   - `removeFromGroup` — admin-only; build RemoveMember op,
///                         broadcast, mark our local row as removed,
///                         then rotate our own chain so the removed
///                         member can no longer decrypt.
///   - `renameGroup`     — admin-only; signed Rename op.
///   - `promoteAdmin` / `demoteAdmin` — admin-only role flips with
///                         last-admin protection.
///   - `sendGroupMessage` — encrypt once with our chain, fan out N
///                          sealed-sender envelopes (one per active
///                          member except self).
///   - `rotateMyGroupChain` — mint a fresh dist_id, sign a
///                            RotateSenderKey op, broadcast op + new
///                            SKDM to every active member.
///
/// **Inbound** (this file too): handlers for the four group inner-
/// envelope kinds — `handleGroupOp(...)`,
/// `handleGroupKeyDistribution(...)`, `handleGroupChat(...)`,
/// `handleGroupBootstrap(...)`.
extension ChatStore {
    // ─── Outbound: create / invite / remove / rename / roles ────────

    /// Create a new group with `name` and the given `initialContacts`
    /// as additional members. The local user is auto-included as the
    /// admin; `initialContacts` MUST be 1:1-paired contacts (the
    /// design rule: "you can only be added by someone who has already
    /// QR-paired with you in person"). Returns the new `ChatGroup.id`,
    /// or nil if a precondition failed (no session, name empty,
    /// initialContacts not all paired, or the group would exceed
    /// `ChatGroup.maxMembers`).
    @discardableResult
    func createGroup(name: String, initialContacts: [Contact]) -> Data? {
        guard let session, let myCard, let relay else { return nil }
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else { return nil }
        // Cap is N = local + invitees.
        guard initialContacts.count + 1 <= ChatGroup.maxMembers else { return nil }
        // Every invitee must be 1:1-paired. The admin can't bootstrap
        // a group with someone they've never verified — that's the
        // load-bearing trust property documented in `Group.swift`.
        let allPaired = initialContacts.allSatisfy { c in
            state.contacts.contains(where: { $0.identityPub == c.identityPub })
        }
        guard allPaired else { return nil }
        // No duplicate invitees.
        let unique = Set(initialContacts.map(\.identityPub))
        guard unique.count == initialContacts.count else { return nil }

        // 16-byte random group id.
        var gidBytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &gidBytes)
        let groupId = Data(gidBytes)

        // Build the Create op header. Operator = self; initial
        // members = [self.admin] + invitees.member.
        // Self's displayName isn't sent on the wire as the user-
        // visible label — `memberDisplayName` overrides at render
        // time. Keep it empty so a recipient who somehow ends up in
        // the bake-fallback path (peerId not in their contacts) sees
        // the fingerprint shorthand rather than the misleading "you"
        // (audit MEDIUM-8).
        var members: [GroupOpInitialMember] = [
            GroupOpInitialMember(
                peerId: myCard.peerId,
                role: .admin,
                displayName: "",
            ),
        ]
        for c in initialContacts {
            members.append(GroupOpInitialMember(
                peerId: c.identityPub,
                role: .member,
                displayName: c.displayName,
            ))
        }
        let kind = GroupOpKind.create(name: trimmedName, initialMembers: members)
        guard let signedOp = signOp(
            session: session,
            groupId: groupId,
            epoch: 0,
            parent: GroupOp.zeroParentDigest,
            operatorIdentity: myCard.peerId,
            kind: kind,
        ) else { return nil }

        // Construct local state from the freshly-signed Create op.
        guard let signedBytes = try? signedOp.encoded() else { return nil }
        guard var group = ChatGroup.create(
            fromCreate: signedOp,
            signedBytes: signedBytes,
            localIdentityPub: myCard.peerId,
        ) else { return nil }
        // Creator implicitly accepted by tapping Create — clear the
        // invitation flag that `ChatGroup.create` defaults to true
        // for the receive-side bootstrap path.
        group.pendingInvitation = false

        // Mint our local sender-key chain. Failures here would mean
        // libsignal-state corruption — surface as nil so the UI can
        // bail out cleanly.
        let myDist = UUID()
        guard let mySKDM = try? session.senderKeyDistributionCreate(distributionId: myDist) else {
            return nil
        }
        group.myCurrentDistributionId = myDist
        group.memberDistributionIds[myCard.peerId] = myDist
        // The creator's own row goes straight to .active (we have our
        // own SKDM right here; no exchange needed for ourselves).
        if let idx = group.members.firstIndex(where: { $0.peerId == myCard.peerId }) {
            group.members[idx].status = .active
        }
        // Persist the libsignal sender-key state to disk.
        persistSession()

        state.groups.append(group)
        let gIdx = state.groups.count - 1
        Storage.persist(appState: state)

        diagLog("group", "createGroup \(short(groupId)) name=\"\(trimmedName)\""
            + " admin=\(short(myCard.peerId)) inviting \(initialContacts.count) member(s):"
            + " " + initialContacts.map { short($0.identityPub) }.joined(separator: ", "))
        // Broadcast: every invitee gets the signed Create op (0x08)
        // AND the creator's SKDM (0x07). Order matters only loosely
        // — both are independent inner envelopes, and the receiver
        // can apply them in either order (apply Create first, then
        // process SKDM; or process SKDM first, then apply Create —
        // libsignal doesn't care).
        //
        // Fan-out timing leak (audit LOW-5): N pairwise sends back-
        // to-back let the relay correlate "one fan-out, group of
        // size N" by burst timing. Tor's circuit-isolation defaults
        // and per-recipient delivery jitter are the v2 mitigation.
        for c in initialContacts {
            broadcastGroupOp(signedBytes, toPeer: c.identityPub, session: session, relay: relay)
            broadcastSenderKeyDistribution(
                groupId: groupId,
                skdm: mySKDM,
                toPeer: c.identityPub,
                session: session,
                relay: relay,
                groupAt: gIdx,
            )
        }
        Storage.persist(appState: state)
        return groupId
    }

    /// Admin-only: add a 1:1-paired contact to an existing group.
    /// Builds an `AddMember` op chained from the group's current
    /// `lastOpDigest`, ships a signed `GroupBootstrap` of the
    /// post-AddMember state to the newcomer (so they can build local
    /// state from a single envelope without replaying our op chain),
    /// broadcasts the op to every active member + the newcomer, and
    /// ships our current SKDM to the newcomer.
    @discardableResult
    func inviteToGroup(groupId: Data, contact: Contact) -> Bool {
        guard let session, let myCard, let relay,
              let gIdx = groupIndex(forId: groupId)
        else { return false }
        guard state.groups[gIdx].role(of: myCard.peerId) == .admin else { return false }
        // Must be 1:1-paired.
        guard state.contacts.contains(where: { $0.identityPub == contact.identityPub }) else {
            return false
        }
        // Cap.
        guard state.groups[gIdx].activeMembers.count + 1 <= ChatGroup.maxMembers else { return false }
        // Already in?
        if state.groups[gIdx].members.contains(where: {
            $0.peerId == contact.identityPub && $0.status != .removed
        }) { return false }

        let kind = GroupOpKind.addMember(
            peerId: contact.identityPub,
            role: .member,
            displayName: contact.displayName,
        )
        guard let signedOp = signOp(
            session: session,
            groupId: groupId,
            epoch: state.groups[gIdx].currentEpoch + 1,
            parent: state.groups[gIdx].lastOpDigest,
            operatorIdentity: myCard.peerId,
            kind: kind,
        ) else { return false }

        // Apply locally first so our own state advances even if a
        // broadcast fails partway through. Capture side effects so
        // the post-apply hook can ship our SKDM to the newcomer (the
        // newcomer is now in `newActiveMembers`).
        var sx = ChatGroup.ApplySideEffects(localIdentityPub: myCard.peerId)
        if case .applied = state.groups[gIdx].apply(signedOp, sideEffects: &sx) {} else {
            return false
        }

        guard let signedBytes = try? signedOp.encoded() else { return false }

        // Ship the GroupBootstrap to the newcomer FIRST so they can
        // construct a local ChatGroup before any AddMember/SKDM
        // arrives. This closes audit HIGH-7 (the AddMember-without-
        // local-group drop path).
        if let bootstrap = signBootstrap(session: session, group: state.groups[gIdx], operatorIdentity: myCard.peerId) {
            broadcastGroupBootstrap(
                bootstrap: bootstrap,
                toPeer: contact.identityPub,
                session: session,
                relay: relay,
            )
        }

        // Broadcast the AddMember op to every current active member
        // (other than us) AND the newcomer.
        let recipients = state.groups[gIdx].activeMembers
            .map(\.peerId)
            .filter { $0 != myCard.peerId }
        for peer in recipients {
            broadcastGroupOp(signedBytes, toPeer: peer, session: session, relay: relay)
        }

        // Reciprocal SKDM exchange (HIGH-2): ship our current SKDM to
        // the newcomer (and any other active member who hasn't yet
        // received it). The hook also covers the case where the
        // newcomer is reached via a state mutation we didn't
        // initiate.
        applyPostMutationSideEffects(groupAt: gIdx, sideEffects: sx, session: session, relay: relay)
        Storage.persist(appState: state)
        return true
    }

    /// Admin-only: remove a member from a group. Local state advances
    /// immediately; remaining members receive the `RemoveMember` op
    /// and apply it; the local user then rotates their sender-key
    /// chain so the removed member can no longer decrypt subsequent
    /// messages from us. Other remaining members rotate independently
    /// when they apply the same op (audit fix HIGH-1).
    @discardableResult
    func removeFromGroup(groupId: Data, peerIdentity: Data) -> Bool {
        guard let session, let myCard, let relay,
              let gIdx = groupIndex(forId: groupId)
        else { return false }
        guard state.groups[gIdx].role(of: myCard.peerId) == .admin else { return false }
        guard state.groups[gIdx].members.contains(where: {
            $0.peerId == peerIdentity && $0.status != .removed
        }) else { return false }

        let kind = GroupOpKind.removeMember(peerId: peerIdentity)
        guard let signedOp = signOp(
            session: session,
            groupId: groupId,
            epoch: state.groups[gIdx].currentEpoch + 1,
            parent: state.groups[gIdx].lastOpDigest,
            operatorIdentity: myCard.peerId,
            kind: kind,
        ) else { return false }

        var sx = ChatGroup.ApplySideEffects(localIdentityPub: myCard.peerId)
        if case let .rejectedMalformed(reason) = state.groups[gIdx].apply(signedOp, sideEffects: &sx) {
            // Last-admin protection (or any other reject) surfaces
            // here; tell the user instead of silently failing
            // (audit MEDIUM-4).
            appendGroupSystem(groupAt: gIdx, "Could not remove member: \(reason).")
            Storage.persist(appState: state)
            return false
        }

        guard let signedBytes = try? signedOp.encoded() else { return false }
        for member in state.groups[gIdx].activeMembers
            where member.peerId != myCard.peerId {
            broadcastGroupOp(signedBytes, toPeer: member.peerId, session: session, relay: relay)
        }
        // Mandatory rotation post-remove (slice 4d / audit HIGH-1).
        // The state machine flagged `requestSelfRotation` if we are
        // still active; the post-mutation hook fires a single
        // rotation regardless of how many remove ops applied in this
        // call.
        applyPostMutationSideEffects(groupAt: gIdx, sideEffects: sx, session: session, relay: relay)
        Storage.persist(appState: state)
        return true
    }

    /// Admin-only: rename the group. Surfaces inline errors via a
    /// system row when the apply rejects (e.g. authorization).
    @discardableResult
    func renameGroup(groupId: Data, newName: String) -> Bool {
        guard let session, let myCard, let relay,
              let gIdx = groupIndex(forId: groupId)
        else { return false }
        let trimmed = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        guard state.groups[gIdx].role(of: myCard.peerId) == .admin else { return false }
        guard state.groups[gIdx].displayName != trimmed else { return false }

        let kind = GroupOpKind.rename(newName: trimmed)
        guard let signedOp = signOp(
            session: session,
            groupId: groupId,
            epoch: state.groups[gIdx].currentEpoch + 1,
            parent: state.groups[gIdx].lastOpDigest,
            operatorIdentity: myCard.peerId,
            kind: kind,
        ) else { return false }

        var sx = ChatGroup.ApplySideEffects(localIdentityPub: myCard.peerId)
        if case .applied = state.groups[gIdx].apply(signedOp, sideEffects: &sx) {} else {
            return false
        }
        guard let signedBytes = try? signedOp.encoded() else { return false }
        for member in state.groups[gIdx].activeMembers
            where member.peerId != myCard.peerId {
            broadcastGroupOp(signedBytes, toPeer: member.peerId, session: session, relay: relay)
        }
        applyPostMutationSideEffects(groupAt: gIdx, sideEffects: sx, session: session, relay: relay)
        Storage.persist(appState: state)
        return true
    }

    /// Admin-only: promote a member to admin.
    @discardableResult
    func promoteToAdmin(groupId: Data, peerIdentity: Data) -> Bool {
        signAndBroadcastRoleOp(
            groupId: groupId,
            peerIdentity: peerIdentity,
            kind: .promoteAdmin(peerId: peerIdentity),
        )
    }

    /// Admin-only: demote an admin back to member, with last-admin
    /// protection (apply rejects if it would brick the group).
    @discardableResult
    func demoteFromAdmin(groupId: Data, peerIdentity: Data) -> Bool {
        signAndBroadcastRoleOp(
            groupId: groupId,
            peerIdentity: peerIdentity,
            kind: .demoteAdmin(peerId: peerIdentity),
        )
    }

    private func signAndBroadcastRoleOp(
        groupId: Data,
        peerIdentity: Data,
        kind: GroupOpKind,
    ) -> Bool {
        guard let session, let myCard, let relay,
              let gIdx = groupIndex(forId: groupId)
        else { return false }
        guard state.groups[gIdx].role(of: myCard.peerId) == .admin else { return false }
        guard state.groups[gIdx].members.contains(where: {
            $0.peerId == peerIdentity && $0.status != .removed
        }) else { return false }

        guard let signedOp = signOp(
            session: session,
            groupId: groupId,
            epoch: state.groups[gIdx].currentEpoch + 1,
            parent: state.groups[gIdx].lastOpDigest,
            operatorIdentity: myCard.peerId,
            kind: kind,
        ) else { return false }

        var sx = ChatGroup.ApplySideEffects(localIdentityPub: myCard.peerId)
        switch state.groups[gIdx].apply(signedOp, sideEffects: &sx) {
        case .applied:
            break
        case let .rejectedMalformed(reason):
            appendGroupSystem(groupAt: gIdx, "Role change failed: \(reason).")
            Storage.persist(appState: state)
            return false
        default:
            // Auth/duplicate/equiv/sig: silent — these mean our own
            // local view drifted from the canonical chain, which
            // shouldn't be possible for an op we just signed.
            return false
        }
        guard let signedBytes = try? signedOp.encoded() else { return false }
        for member in state.groups[gIdx].activeMembers
            where member.peerId != myCard.peerId {
            broadcastGroupOp(signedBytes, toPeer: member.peerId, session: session, relay: relay)
        }
        applyPostMutationSideEffects(groupAt: gIdx, sideEffects: sx, session: session, relay: relay)
        Storage.persist(appState: state)
        return true
    }

    // ─── Outbound: invitation accept / decline ──────────────────────

    /// Accept a pending group invitation: clear the
    /// `pendingInvitation` flag, mint our local sender-key chain,
    /// and broadcast our SKDM to every active member. From this
    /// moment on, peers can decrypt our messages and our composer
    /// is unlocked. No-op if the group isn't pending.
    @discardableResult
    func acceptGroupInvitation(groupId: Data) -> Bool {
        guard let session, let myCard, let relay,
              let gIdx = groupIndex(forId: groupId)
        else { return false }
        guard state.groups[gIdx].pendingInvitation else { return false }
        // Refuse if the admin already removed us while pending —
        // the invitation was withdrawn before we accepted.
        guard state.groups[gIdx].activeMembers.contains(where: { $0.peerId == myCard.peerId }) else {
            return false
        }
        state.groups[gIdx].pendingInvitation = false
        NSLog(
            "[pizzini.group] accept \(short(groupId)):"
                + " enrolling local chain and broadcasting SKDM",
        )
        enrolMyChainOnFirstJoin(groupAt: gIdx, session: session, relay: relay)
        Storage.persist(appState: state)
        return true
    }

    /// Decline a pending group invitation: drop the local group
    /// state. We never enrolled a chain so there's nothing to
    /// rotate; remaining members keep showing us as `.pendingSKDM`
    /// until they manually rotate or remove us — the same honesty
    /// constraint as `leaveGroup` (peer-to-peer can't enforce
    /// removal at the other end). No-op if the group isn't pending.
    @discardableResult
    func declineGroupInvitation(groupId: Data) -> Bool {
        guard let gIdx = groupIndex(forId: groupId) else { return false }
        guard state.groups[gIdx].pendingInvitation else { return false }
        NSLog("[pizzini.group] decline \(short(groupId)): removing local group state")
        state.groups.remove(at: gIdx)
        Storage.persist(appState: state)
        return true
    }

    /// Counterpart to 1:1 `markRead(contactID:)` for groups: stamp
    /// `lastSeenAt` (drives the unread-count badge), refresh the app
    /// badge, and emit a 0x04 readReceipt to every active member who
    /// has authored at least one inbound row in this group's log
    /// AND for whom we've toggled read-receipts ON in their 1:1
    /// chat. Each per-sender receipt covers the highest pairwise
    /// `messageId` they sent us, so the sender's outbox can mark
    /// every leg of every group message at-or-below that as `readAt`
    /// (Phase 7 rollup picks it up from there).
    ///
    /// The receipt rides each member's existing pairwise sealed-
    /// sender channel — no new wire kind. F-405 symmetric drop on
    /// the receiver: even with our emit, a member who has toggled
    /// receipts OFF for us simply drops the claim.
    func markGroupRead(groupID: Data) {
        guard let gIdx = groupIndex(forId: groupID) else { return }
        state.groups[gIdx].lastSeenAt = Date()
        Storage.persist(appState: state)
        refreshAppBadge()
        // Per-sender highest-messageId scan over the group log.
        var highestPerSender: [Data: (messageId: Data, timestamp: Date)] = [:]
        for row in state.groups[gIdx].log
            where row.side == .peer && row.kind != .system {
            guard let senderPeerId = row.senderPeerId,
                  let mid = row.messageId
            else { continue }
            if let existing = highestPerSender[senderPeerId],
               row.timestamp <= existing.timestamp {
                continue
            }
            highestPerSender[senderPeerId] = (mid, row.timestamp)
        }
        for (sender, info) in highestPerSender {
            guard let cIdx = state.contacts.firstIndex(where: { $0.identityPub == sender }) else {
                // Member who isn't a 1:1 contact of ours — we have
                // no pairwise channel to ship the receipt over.
                // (Practically rare: group invitees must be 1:1-paired
                // by an admin, but a contact-deletion since join could
                // strand a row here.)
                continue
            }
            emitReadReceipt(forContactAt: cIdx, highestMessageId: info.messageId)
        }
    }

    /// Panic-mode counterpart to 1:1 `deleteChat(_:)`: wipe the
    /// group's local log but keep the user's membership and chain
    /// state intact. Mirrors the activist threat model — instant
    /// cleanup of visible content without changing what the rest
    /// of the group sees about us. To actually leave the group the
    /// user goes through `leaveGroup(_:)` (which rotates the chain
    /// and removes the local row); panic intentionally stops short
    /// of that so a recovery from a bad triple-tap is just "you'll
    /// have to scroll up — your participation is unchanged."
    func deleteGroupChat(groupId: Data) {
        guard let gIdx = groupIndex(forId: groupId) else { return }
        state.groups[gIdx].log.removeAll()
        state.groups[gIdx].lastMessageAt = nil
        state.groups[gIdx].lastSeenAt = Date()
        Storage.persist(appState: state)
    }

    /// Local-only leave: drop the group from this device. We rotate
    /// our chain first so remaining members can no longer decrypt
    /// our future messages with the chain we abandoned (audit fix
    /// LOW-4) — the rotation broadcast doubles as a courtesy "this
    /// chain is dead" signal even though the group state on remote
    /// peers still lists us as a member.
    ///
    /// To "leave properly" so other members stop sending: ask an
    /// admin to remove you. This action is the security-conscious
    /// fallback when that's not possible (e.g. compromised admin,
    /// urgency, ghosting).
    @discardableResult
    func leaveGroup(groupId: Data) -> Bool {
        guard let gIdx = groupIndex(forId: groupId) else { return false }
        // Best-effort rotation before we drop the group. If we have
        // no chain yet (never sent a message) the rotation is a
        // no-op.
        if state.groups[gIdx].myCurrentDistributionId != nil {
            rotateMyGroupChain(groupId: groupId)
        }
        // Re-lookup; rotateMyGroupChain may have mutated the array.
        guard let gIdx2 = groupIndex(forId: groupId) else { return true }
        state.groups.remove(at: gIdx2)
        Storage.persist(appState: state)
        return true
    }

    // ─── Outbound: send + rotate ────────────────────────────────────

    /// Encrypt `text` with our group sender-key chain and fan out
    /// sealed-sender envelopes to every active member except self.
    /// Skips recipients we have no delivery token for (logged as a
    /// system row on the local group log; outbox+retry pending v2).
    /// Refuses to send if the local user is no longer an active
    /// member of the group (audit fix HIGH-3).
    @discardableResult
    func sendGroupMessage(groupId: Data, text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        guard let session, let myCard, let relay,
              let gIdx = groupIndex(forId: groupId)
        else { return false }

        // HIGH-3: refuse if we're not an active member of the group.
        // The chain may still be installed in libsignal's store but a
        // removed member must not be able to keep posting.
        guard state.groups[gIdx].activeMembers.contains(where: { $0.peerId == myCard.peerId }) else {
            appendGroupSystem(groupAt: gIdx, "You are no longer a member of this group.")
            Storage.persist(appState: state)
            return false
        }
        // Refuse while the invitation is pending — the user hasn't
        // tapped Join yet, so no chain has been minted and no SKDM
        // has been broadcast. The composer in `GroupChatView` is
        // also disabled in this state; this guard is the runtime
        // backstop.
        guard !state.groups[gIdx].pendingInvitation else {
            return false
        }

        // Periodic-rotation gate.
        if shouldRotateBeforeSend(groupAt: gIdx) {
            rotateMyGroupChain(groupId: groupId)
        }
        guard let myDist = state.groups[gIdx].myCurrentDistributionId else {
            appendGroupSystem(groupAt: gIdx, "Group encryption not yet ready — waiting for SKDM exchange.")
            Storage.persist(appState: state)
            return false
        }
        let plaintext = Data(trimmed.utf8)
        guard let ciphertext = try? session.groupEncrypt(distributionId: myDist, plaintext: plaintext) else {
            appendGroupSystem(groupAt: gIdx, "Encrypt failed.")
            Storage.persist(appState: state)
            return false
        }
        persistSession()
        let body = GroupEnvelope.encodeGroupChat(groupId: groupId, senderKeyMessage: ciphertext)
        var inner = Data([RelayClient.InnerEnvelopeKind.groupChat.rawValue])
        inner.append(body)
        let recipients = state.groups[gIdx].activeMembers
            .map(\.peerId)
            .filter { $0 != myCard.peerId }
        NSLog(
            "[pizzini.group] sendGroupMessage \(short(groupId)):"
                + " \(plaintext.count) B plaintext, ciphertext \(ciphertext.count) B,"
                + " fanning out to \(recipients.count) member(s):"
                + " " + recipients.map { short($0) }.joined(separator: ", "),
        )
        var skipped: [String] = []
        // Stable per-logical-message id stamped on every pairwise leg
        // so the chat row can roll up status across the fan-out via
        // `OutboxStore.groupMessageStatus(forId:)`.
        let groupMessageId = ChatStore.makeGroupMessageId()
        let now = Date()
        // Fan-out timing leak (audit LOW-5): tight loop; relay can
        // correlate. Documented limitation; jitter is v2 work.
        for recipient in recipients {
            guard let cIdx = state.contacts.firstIndex(where: { $0.identityPub == recipient }),
                  let token = popDeliveryTokenPublic(forContactAt: cIdx)
            else {
                skipped.append(short(recipient))
                continue
            }
            let messageId = ChatStore.makeGroupMessageId()
            let ttl = state.contacts[cIdx].ttlSeconds
            do {
                let sealed = try session.encryptSealed(
                    peer: recipient,
                    messageId: messageId,
                    plaintext: inner,
                )
                // Persist the outbox entry BEFORE the relay handoff —
                // a force-quit between encryptSealed and persist would
                // otherwise lose the entry and the row would render as
                // "no status" forever even though the bytes were sent.
                var entry = OutboxEntry(
                    messageId: messageId,
                    recipientPeerId: recipient,
                    sealedCiphertext: sealed,
                    token: token,
                    ttl: TimeInterval(ttl),
                    sentAt: now,
                    retries: 0,
                    deliveredAt: nil,
                    failedAt: nil,
                    relayedAt: nil,
                    groupMessageId: groupMessageId,
                )
                outbox.entries[messageId] = entry
                Storage.upsertOutboxEntry(entry)
                relay.sendSealed(
                    toPeer: recipient,
                    sealedCiphertext: sealed,
                    ttlSeconds: ttl,
                    token: token,
                )
                entry.relayedAt = now
                entry.token = Data() // F-505: scrub once relayed
                outbox.entries[messageId] = entry
                Storage.upsertOutboxEntry(entry)
            } catch {
                NSLog("[pizzini] group fan-out failed for \(short(recipient)): \(error)")
            }
        }
        // Append our own log row. Self-attributed messages render
        // without the "Name: " prefix in the chat view. The
        // `groupMessageId` stamp lets the bubble render-time lookup
        // fan in the per-recipient outbox status to a single icon.
        state.groups[gIdx].log.append(PersistedMessage(
            side: .me,
            text: trimmed,
            kind: .whisper,
            bytes: ciphertext.count,
            groupMessageId: groupMessageId,
        ))
        state.groups[gIdx].lastMessageAt = Date()
        state.groups[gIdx].sentSinceRotation &+= 1
        if !skipped.isEmpty {
            appendGroupSystem(
                groupAt: gIdx,
                "Sent to \(recipients.count - skipped.count)/\(recipients.count) members. "
                    + "No delivery tokens for: \(skipped.joined(separator: ", ")).",
            )
        }
        Storage.persist(appState: state)
        return true
    }

    /// Send a chunked file attachment to the named group. Mirrors
    /// `sendGroupMessage` for the gate / rotation / fan-out pattern
    /// and `sendFile` for the off-main strip + chunk pass:
    ///
    /// 1. Send-side trust gates (mirror `sendGroupMessage`): refuse
    ///    if the local user is no longer an active member or the
    ///    invitation is still pending. Audit HIGH-3.
    /// 2. Periodic-rotation hygiene: if `shouldRotateBeforeSend`,
    ///    rotate the chain BEFORE the off-main pass so all chunks
    ///    of this attachment ride the post-rotation chain.
    /// 3. Off-main: read bytes, sanitize filename, classify tier,
    ///    metadata-strip (Tier-3 strip on a 4K video can take
    ///    seconds), and slice into ≤64 KB plaintext chunks.
    /// 4. Main hop: for each chunk, `groupEncrypt` once with our
    ///    chain, wrap in the `groupFileChunk = 0x0A` inner envelope,
    ///    fan out to every active member except self as N
    ///    independent pairwise sealed-sender envelopes. Per-recipient
    ///    delivery-token depletion is silently skipped (mirrors
    ///    `sendGroupMessage`'s skipped-member handling); recipient
    ///    sees a partial transfer that times out at the 24h
    ///    reassembler TTL — no user-visible "out of tokens" dialog.
    /// 5. Append a single `.attachment` `PersistedMessage` to the
    ///    group log. Outbox+retry is deferred to v2 (the brief is
    ///    explicit: each chunk is fire-and-forget at the sender).
    func sendGroupAttachment(groupId: Data, attachmentURL: URL, caption: String?) {
        // Precondition: session + relay must exist so the off-main
        // strip pass isn't wasted; we re-resolve both inside
        // `shipPreparedGroupAttachment` after the hop because those
        // properties are mutable across foreground re-arms.
        guard session != nil, let myCard, relay != nil,
              let gIdx = groupIndex(forId: groupId)
        else { return }
        // HIGH-3: refuse if we're no longer an active member.
        guard state.groups[gIdx].activeMembers.contains(where: { $0.peerId == myCard.peerId }) else {
            appendGroupSystem(groupAt: gIdx, "You are no longer a member of this group.")
            Storage.persist(appState: state)
            return
        }
        // Refuse while pending — composer is also disabled in this
        // state, this is the runtime backstop.
        guard !state.groups[gIdx].pendingInvitation else { return }

        // Sanitize filename at the boundary; the receiver re-sanitizes
        // (defence in depth) but the sender side gets a clean
        // rendering immediately and the wire bytes can never carry an
        // RTL-override / path-separator name.
        let rawFilename = attachmentURL.lastPathComponent
        let safeName = FilenameSanitizer.sanitize(rawFilename)
        if AttachmentTierClassifier.isBlockedAtSend(filename: safeName) {
            appendGroupSystem(
                groupAt: gIdx,
                "Can't send \(safeName): files of this type can run when tapped on iOS. Pizzini blocks them at send.",
            )
            Storage.persist(appState: state)
            return
        }
        let mime = mimeTypeForFilename(safeName)
        let tier = AttachmentTierClassifier.tier(forFilename: safeName)
        let captionText = caption?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        // Periodic-rotation gate. Rotate BEFORE the off-main pass so
        // every chunk of this attachment uses the same (post-rotation)
        // chain. A rotation mid-attachment would force the receiver
        // to install a fresh chain partway through, which the
        // groupDecrypt path can handle but is needlessly noisy.
        if shouldRotateBeforeSend(groupAt: gIdx) {
            rotateMyGroupChain(groupId: groupId)
        }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            // Off-main: read + (optionally) strip metadata.
            let raw: Data
            do {
                raw = try Data(contentsOf: attachmentURL, options: [.mappedIfSafe])
            } catch {
                Task { @MainActor [weak self] in
                    self?.appendGroupSystem(groupId: groupId, text: "Couldn't read \(safeName): \(error)")
                }
                return
            }
            let bytes: Data
            do {
                bytes = try MetadataStripper.stripped(
                    raw, filename: safeName, mimeType: mime
                )
            } catch {
                Task { @MainActor [weak self] in
                    self?.appendGroupSystem(groupId: groupId, text: "Strip failed for \(safeName): \(error)")
                }
                return
            }
            var aidBytes = [UInt8](repeating: 0, count: 16)
            _ = aidBytes.withUnsafeMutableBufferPointer { ptr in
                SecRandomCopyBytes(kSecRandomDefault, ptr.count, ptr.baseAddress!)
            }
            let attachmentId = Data(aidBytes)
            let chunkSize = FileChunkEnvelope.maxChunkPlaintextBytes
            let totalSize = bytes.count
            let chunkCount = max(1, (totalSize + chunkSize - 1) / chunkSize)
            if UInt32(chunkCount) > FileChunkEnvelope.maxChunkCount {
                Task { @MainActor [weak self] in
                    self?.appendGroupSystem(
                        groupId: groupId,
                        text: "\(safeName) is too large (\(totalSize) bytes; max \(FileChunkEnvelope.maxChunkPlaintextBytes * Int(FileChunkEnvelope.maxChunkCount))).",
                    )
                }
                return
            }
            var working: [Data] = []
            working.reserveCapacity(chunkCount)
            for i in 0..<chunkCount {
                let start = i * chunkSize
                let end = min(start + chunkSize, totalSize)
                working.append(bytes.subdata(in: start..<end))
            }
            // Stage a sender-side sandbox copy so the local row can
            // present Save-to-Files / Preview after send. Subject to
            // the 7d sandbox TTL like inbound attachments — chat row
            // stays past that, just without the bytes.
            let outboundRelPath: String? = {
                guard let dir = try? AttachmentSandbox.outboundDirectory(
                    forAttachmentId: attachmentId,
                ) else { return nil }
                let url = dir.appending(path: safeName, directoryHint: .notDirectory)
                do {
                    try bytes.write(
                        to: url,
                        options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication],
                    )
                } catch {
                    NSLog("[pizzini] outbound sandbox write failed: \(error)")
                    return nil
                }
                guard let root = try? AttachmentSandbox.root() else { return nil }
                let rootPath = root.path.hasSuffix("/") ? root.path : root.path + "/"
                return url.path.hasPrefix(rootPath)
                    ? String(url.path.dropFirst(rootPath.count))
                    : nil
            }()
            let preparedChunks = working
            Task { @MainActor [weak self] in
                self?.shipPreparedGroupAttachment(
                    groupId: groupId,
                    attachmentId: attachmentId,
                    sanitizedFilename: safeName,
                    mime: mime,
                    tier: tier,
                    chunks: preparedChunks,
                    totalSize: UInt64(totalSize),
                    captionText: captionText,
                    sandboxRelPath: outboundRelPath,
                )
            }
        }
    }

    /// Main-actor continuation of `sendGroupAttachment`. For each
    /// chunk: `groupEncrypt` once → wrap in `groupFileChunk` →
    /// fan out per active member as a 1:1 sealed envelope.
    @MainActor
    private func shipPreparedGroupAttachment(
        groupId: Data,
        attachmentId: Data,
        sanitizedFilename: String,
        mime: String,
        tier: AttachmentTier,
        chunks: [Data],
        totalSize: UInt64,
        captionText: String,
        sandboxRelPath: String?,
    ) {
        guard let session, let myCard, let relay,
              let gIdx = groupIndex(forId: groupId)
        else { return }
        // Re-check gates after the off-main hop: state may have
        // mutated (e.g. a RemoveMember-self landed while we were
        // stripping). HIGH-3 still applies.
        guard state.groups[gIdx].activeMembers.contains(where: { $0.peerId == myCard.peerId }) else {
            appendGroupSystem(groupAt: gIdx, "You are no longer a member of this group.")
            Storage.persist(appState: state)
            return
        }
        guard !state.groups[gIdx].pendingInvitation else { return }
        guard let myDist = state.groups[gIdx].myCurrentDistributionId else {
            appendGroupSystem(groupAt: gIdx, "Group encryption not yet ready — waiting for SKDM exchange.")
            Storage.persist(appState: state)
            return
        }

        let chunkCountU32 = UInt32(chunks.count)
        let recipients = state.groups[gIdx].activeMembers
            .map(\.peerId)
            .filter { $0 != myCard.peerId }
        // Stable id for the whole logical group attachment. Every
        // outbox leg (chunkCount × recipients legs total) shares it
        // so the chat row can roll up status across the entire fan-
        // out via `OutboxStore.groupMessageStatus(forId:)`.
        let groupMessageId = ChatStore.makeGroupMessageId()
        let now = Date()
        diagLog("group", "sendGroupAttachment \(short(groupId)):"
            + " aid=\(short(attachmentId)) filename=\"\(sanitizedFilename)\""
            + " size=\(totalSize) chunks=\(chunkCountU32) tier=\(tier.rawValue)"
            + " fan-out=\(recipients.count) member(s)")

        var perRecipientSkippedChunks: [Data: Int] = [:]
        for i in 0..<chunks.count {
            let envelope = FileChunkEnvelope(
                attachmentId: attachmentId,
                totalSize: totalSize,
                chunkIndex: UInt32(i),
                chunkCount: chunkCountU32,
                mime: mime,
                filename: sanitizedFilename,
                chunkBytes: chunks[i],
            )
            let plaintext = envelope.encode()
            let ciphertext: Data
            do {
                ciphertext = try session.groupEncrypt(distributionId: myDist, plaintext: plaintext)
            } catch {
                appendGroupSystem(groupAt: gIdx, "Encrypt failed at chunk \(i)/\(chunks.count): \(error)")
                Storage.persist(appState: state)
                return
            }
            // Persist the chain advance immediately. A force-quit
            // between groupEncrypt and persist would otherwise roll
            // back the on-disk chain by one step, and the next
            // outbound chunk would reuse a chain key the receiver
            // has already consumed.
            persistSession()
            let body = GroupEnvelope.encodeGroupFileChunk(
                groupId: groupId, senderKeyMessage: ciphertext)
            var inner = Data([RelayClient.InnerEnvelopeKind.groupFileChunk.rawValue])
            inner.append(body)
            // Per-recipient pairwise wrap + send.
            for recipient in recipients {
                guard let cIdx = state.contacts.firstIndex(where: { $0.identityPub == recipient }) else {
                    perRecipientSkippedChunks[recipient, default: 0] += 1
                    continue
                }
                guard let token = popDeliveryTokenPublic(forContactAt: cIdx) else {
                    // Silent-drop per the brief. The diagLog buffer in
                    // Settings → Diagnostics surfaces it for users
                    // debugging "why did Bob's screen show a partial
                    // attachment?" without a user-visible quota dialog.
                    perRecipientSkippedChunks[recipient, default: 0] += 1
                    continue
                }
                let messageId = ChatStore.makeGroupMessageId()
                let ttl = state.contacts[cIdx].ttlSeconds
                do {
                    let sealed = try session.encryptSealed(
                        peer: recipient,
                        messageId: messageId,
                        plaintext: inner,
                    )
                    var entry = OutboxEntry(
                        messageId: messageId,
                        recipientPeerId: recipient,
                        sealedCiphertext: sealed,
                        token: token,
                        ttl: TimeInterval(ttl),
                        sentAt: now,
                        retries: 0,
                        deliveredAt: nil,
                        failedAt: nil,
                        relayedAt: nil,
                        attachmentId: attachmentId,
                        chunkIndex: UInt32(i),
                        chunkCount: chunkCountU32,
                        groupMessageId: groupMessageId,
                    )
                    outbox.entries[messageId] = entry
                    Storage.upsertOutboxEntry(entry)
                    relay.sendSealed(
                        toPeer: recipient,
                        sealedCiphertext: sealed,
                        ttlSeconds: ttl,
                        token: token,
                    )
                    entry.relayedAt = now
                    entry.token = Data() // F-505 scrub-on-relay
                    outbox.entries[messageId] = entry
                    Storage.upsertOutboxEntry(entry)
                } catch {
                    NSLog(
                        "[pizzini] group attachment fan-out failed for \(short(recipient))"
                            + " chunk \(i)/\(chunks.count): \(error)",
                    )
                    perRecipientSkippedChunks[recipient, default: 0] += 1
                }
            }
            // Persist again after the per-chunk fan-out: each
            // `encryptSealed` advanced a 1:1 ratchet that must hit
            // disk before we move on to the next chunk.
            persistSession()
        }
        if !perRecipientSkippedChunks.isEmpty {
            // Diagnostic-only: surface in the in-app Diagnostics
            // ring buffer so users can see why a recipient saw a
            // partial transfer. No system row in the chat — silent
            // drop matches the 1:1 attachment behaviour today.
            for (peer, dropped) in perRecipientSkippedChunks {
                diagLog("group", "sendGroupAttachment \(short(groupId)):"
                    + " \(short(peer)) dropped \(dropped)/\(chunkCountU32) chunk(s)"
                    + " (out of delivery tokens or unpaired)")
            }
        }
        // Single `.attachment` chat row for the sender — captions
        // (if any) ride on the row text the same way 1:1 sendFile
        // surfaces them locally. Receivers see the attachment row
        // without the caption (parity with 1:1; lifting the caption
        // into a paired text envelope is future work).
        let info = AttachmentInfo(
            attachmentId: attachmentId,
            filename: sanitizedFilename,
            byteSize: totalSize,
            mime: mime,
            tier: tier,
            sandboxRelativePath: sandboxRelPath,
            isInbound: false,
        )
        let row = PersistedMessage(
            side: .me,
            text: captionText,
            kind: .attachment,
            bytes: Int(totalSize),
            attachment: info,
            groupMessageId: groupMessageId,
        )
        state.groups[gIdx].log.append(row)
        state.groups[gIdx].lastMessageAt = row.timestamp
        // sendGroupMessage bumps `sentSinceRotation` per send. Bump
        // by chunkCount here so the periodic-rotation threshold
        // (`ChatGroup.rotationMessageThreshold`) is reached at the
        // intuitive cadence regardless of attachment vs text mix.
        state.groups[gIdx].sentSinceRotation &+= chunkCountU32
        Storage.persist(appState: state)
    }

    /// Process an inbound `groupFileChunk = 0x0A` envelope. Same
    /// trust ladder as `handleGroupChat`:
    ///
    /// 1. Decode body → `(groupId, ciphertext)`.
    /// 2. Resolve local `ChatGroup` for the named groupId — drop if
    ///    we don't have one.
    /// 3. CRITICAL-2 membership gate: drop if sender is not an
    ///    active (non-removed) member. Any 1:1-paired peer who has
    ///    previously installed a chain with us could otherwise
    ///    inject content into a group log they know the ID of.
    /// 4. `pendingInvitation` gate: still call `groupDecrypt` to
    ///    keep the sender's chain in sync with us, but DROP the
    ///    plaintext without rendering. Mirrors `handleGroupChat`'s
    ///    accept-later-no-backlog behaviour.
    /// 5. Decrypt, parse `FileChunkEnvelope`, feed
    ///    `groupReassembler`. Capture `(peer, attachmentId) →
    ///    groupId` on first chunk and verify on every subsequent
    ///    chunk so a sender flipping the groupId mid-transfer is
    ///    treated as hostile.
    /// 6. On `.complete`, append a single `.attachment`
    ///    `PersistedMessage` to the group log via
    ///    `ChatGroup.appendIncomingAttachment` — `senderPeerId`
    ///    populated so the group view's render-time member-name
    ///    resolution (`memberDisplayName`) works.
    func handleGroupFileChunk(payload: Data, fromPeer sender: Data) {
        guard let session else { return }
        guard let parsed = GroupEnvelope.decodeGroupFileChunk(payload) else {
            NSLog("[pizzini.group] groupFileChunk ← \(short(sender)): malformed body")
            return
        }
        let (groupId, ciphertext) = parsed
        guard let gIdx = groupIndex(forId: groupId) else {
            NSLog(
                "[pizzini.group] groupFileChunk ← \(short(sender)):"
                    + " unknown group \(short(groupId)), dropping",
            )
            return
        }
        // CRITICAL-2 membership gate.
        guard state.groups[gIdx].acceptsIncomingMessage(from: sender) else {
            NSLog(
                "[pizzini.group] groupFileChunk ← \(short(sender)) for \(short(groupId)):"
                    + " DROPPED — sender is not an active member",
            )
            return
        }
        // pendingInvitation: advance chain but drop without rendering.
        if state.groups[gIdx].pendingInvitation {
            NSLog(
                "[pizzini.group] groupFileChunk ← \(short(sender)) for \(short(groupId)):"
                    + " group is pendingInvitation — chunk dropped without rendering",
            )
            _ = try? session.groupDecrypt(senderIdentity: sender, ciphertext: ciphertext)
            persistSession()
            return
        }
        let plaintext: Data
        do {
            plaintext = try session.groupDecrypt(senderIdentity: sender, ciphertext: ciphertext)
        } catch {
            diagLog("group", "groupFileChunk ← \(short(sender)) for \(short(groupId)):"
                + " DECRYPT FAILED — \(error). Likely cause: SKDM never arrived from this sender.")
            surfaceUndecryptable(groupAt: gIdx, sender: sender, error: error)
            return
        }
        persistSession()
        let envelope: FileChunkEnvelope
        do {
            envelope = try FileChunkEnvelope.decode(plaintext)
        } catch {
            NSLog(
                "[pizzini.group] groupFileChunk ← \(short(sender)) for \(short(groupId)):"
                    + " malformed FileChunkEnvelope — \(error). Dropped.",
            )
            return
        }
        // First-chunk capture / subsequent-chunk verify of
        // `(peer, attachmentId) → groupId`. A sender who flips the
        // groupId mid-transfer is hostile (or buggy); drop the chunk
        // and the prior reassembly state to fail the transfer cleanly.
        let routingKey = sender + envelope.attachmentId
        if let prior = groupAttachmentRouting[routingKey] {
            if prior != groupId {
                NSLog(
                    "[pizzini.group] groupFileChunk ← \(short(sender)):"
                        + " groupId flip mid-attachment for aid=\(short(envelope.attachmentId))"
                        + " (prior=\(short(prior)) new=\(short(groupId))) — discarding partial",
                )
                groupReassembler.discard(peer: sender, attachmentId: envelope.attachmentId)
                groupAttachmentRouting.removeValue(forKey: routingKey)
                return
            }
        } else {
            groupAttachmentRouting[routingKey] = groupId
        }
        let outcome = groupReassembler.feed(envelope: envelope, fromPeer: sender)
        switch outcome {
        case .progress:
            // Mid-attachment — quiet. The completion arm renders the
            // single chat row when every chunk has landed.
            break
        case .complete(let completion):
            groupAttachmentRouting.removeValue(forKey: routingKey)
            let safeName = completion.sanitizedFilename
            let relPath = sandboxRelativePath(forURL: completion.url)
            state.groups[gIdx].appendIncomingAttachment(
                attachmentId: completion.attachmentId,
                filename: safeName,
                byteSize: completion.totalSize,
                mime: completion.mime,
                tier: completion.tier,
                sandboxRelativePath: relPath,
                senderPeerId: sender,
            )
            Storage.persist(appState: state)
            maybeFireBackgroundHaptic(forIncoming: .group(groupId: groupId))
            NSLog(
                "[pizzini.group] received attachment \(safeName) (\(completion.totalSize) bytes,"
                    + " tier=\(completion.tier.rawValue)) for group \(short(groupId)) from \(short(sender))",
            )
        case .rejected(let reason):
            NSLog("[pizzini.group] group reassembler rejected chunk: \(reason)")
        }
    }

    /// Generate a fresh sender-key chain, broadcast a
    /// `RotateSenderKey` op + the new SKDM to every active member.
    /// Idempotent — a no-op if the local user isn't an active group
    /// member (e.g. they've been removed). Resets
    /// `mySkdmRecipients` so the bidirectional-SKDM hook re-ships to
    /// everyone.
    func rotateMyGroupChain(groupId: Data) {
        guard let session, let myCard, let relay,
              let gIdx = groupIndex(forId: groupId)
        else { return }
        guard state.groups[gIdx].activeMembers.contains(where: { $0.peerId == myCard.peerId }) else {
            return
        }
        let newDist = UUID()
        guard let newSKDM = try? session.senderKeyDistributionCreate(distributionId: newDist) else {
            return
        }
        let kind = GroupOpKind.rotateSenderKey(newDistributionId: newDist)
        guard let signedOp = signOp(
            session: session,
            groupId: groupId,
            epoch: state.groups[gIdx].currentEpoch + 1,
            parent: state.groups[gIdx].lastOpDigest,
            operatorIdentity: myCard.peerId,
            kind: kind,
        ) else { return }
        var sx = ChatGroup.ApplySideEffects(localIdentityPub: myCard.peerId)
        if case .applied = state.groups[gIdx].apply(signedOp, sideEffects: &sx) {} else {
            return
        }
        // Update local sender-key state alongside the op apply.
        state.groups[gIdx].myCurrentDistributionId = newDist
        state.groups[gIdx].memberDistributionIds[myCard.peerId] = newDist
        state.groups[gIdx].sentSinceRotation = 0
        state.groups[gIdx].lastRotatedAt = Date()
        // Reset the "we shipped our SKDM" set — every active member
        // must re-receive the new SKDM.
        state.groups[gIdx].mySkdmRecipients = []
        persistSession()

        // Broadcast the op + the SKDM to every remaining member.
        guard let signedBytes = try? signedOp.encoded() else {
            Storage.persist(appState: state)
            return
        }
        for member in state.groups[gIdx].activeMembers
            where member.peerId != myCard.peerId {
            broadcastGroupOp(signedBytes, toPeer: member.peerId, session: session, relay: relay)
            broadcastSenderKeyDistribution(
                groupId: groupId,
                skdm: newSKDM,
                toPeer: member.peerId,
                session: session,
                relay: relay,
                groupAt: gIdx,
            )
        }
        Storage.persist(appState: state)
    }

    /// Re-broadcast our CURRENT sender-key chain to every active
    /// member, regardless of whether `mySkdmRecipients` says we
    /// already shipped it. Recovery action when a peer's row is
    /// stuck on `.pendingSKDM` after our own join — it almost
    /// always means the original SKDM frame got dropped on the way
    /// (delivery-token depletion, app backgrounding mid-broadcast,
    /// dev-relay queue eviction). Differs from
    /// `rotateMyGroupChain` in that it does NOT mint a fresh
    /// chain — that would invalidate every peer's installed
    /// state. Idempotent and safe to call repeatedly.
    @discardableResult
    func resendMyKeys(groupId: Data) -> Bool {
        guard let session, let myCard, let relay,
              let gIdx = groupIndex(forId: groupId)
        else { return false }
        guard let myDist = state.groups[gIdx].myCurrentDistributionId else {
            // No chain to resend — user hasn't enrolled yet.
            return false
        }
        guard !state.groups[gIdx].pendingInvitation else { return false }
        let skdm: Data
        do {
            skdm = try session.senderKeyDistributionCreate(distributionId: myDist)
        } catch {
            NSLog("[pizzini.group] resendMyKeys \(short(groupId)): mint failed — \(error)")
            return false
        }
        persistSession()
        let recipients = state.groups[gIdx].activeMembers
            .map(\.peerId)
            .filter { $0 != myCard.peerId }
        // Wipe the "already shipped" set so every active member is
        // re-attempted regardless of prior success.
        state.groups[gIdx].mySkdmRecipients = []
        NSLog(
            "[pizzini.group] resendMyKeys \(short(groupId)):"
                + " re-broadcasting current SKDM (\(skdm.count) B)"
                + " to \(recipients.count) member(s)",
        )
        for recipient in recipients {
            broadcastSenderKeyDistribution(
                groupId: groupId,
                skdm: skdm,
                toPeer: recipient,
                session: session,
                relay: relay,
                groupAt: gIdx,
            )
        }
        Storage.persist(appState: state)
        return true
    }

    private func shouldRotateBeforeSend(groupAt gIdx: Int) -> Bool {
        let g = state.groups[gIdx]
        if g.sentSinceRotation >= ChatGroup.rotationMessageThreshold { return true }
        if Date().timeIntervalSince(g.lastRotatedAt) >= ChatGroup.rotationTimeThreshold {
            return true
        }
        return false
    }

    // ─── Inbound handlers (called from ChatStore receive dispatch) ──

    /// Apply a signed `GroupOp`. Bootstraps a fresh `ChatGroup` from
    /// a `Create` op (with full trust-anchor checks — audit
    /// CRITICAL-1), otherwise calls into the apply state machine and
    /// fires the bidirectional-SKDM / mandatory-rotation post-apply
    /// hooks.
    func handleGroupOp(payload: Data, fromPeer sender: Data) {
        guard let session, let myCard, let relay else { return }
        guard let op = GroupOp.decode(payload) else {
            diagLog("group", "groupOp ← \(short(sender)): malformed signed bytes")
            return
        }
        diagLog("group", "groupOp ← \(short(sender)): kind=\(opKindLabel(op.kind))"
            + " group=\(short(op.groupId)) epoch=\(op.epoch)"
            + " operator=\(short(op.operatorIdentity))")

        if case .create = op.kind {
            // Bootstrap path. Audit CRITICAL-1: the trust anchor for
            // a Create is "the operator is in our 1:1 contacts AND
            // the immediate sender is the operator" — anything else
            // and we'd be accepting groups from unverified
            // identities.
            guard sender == op.operatorIdentity else {
                diagLog("group", "Create REJECTED — sender \(short(sender))"
                    + " forwarding on behalf of \(short(op.operatorIdentity))"
                    + " (forwarding not allowed for Create)")
                return
            }
            guard state.contacts.contains(where: { $0.identityPub == op.operatorIdentity }) else {
                diagLog("group", "Create REJECTED — operator \(short(op.operatorIdentity))"
                    + " is not in our 1:1 contacts")
                return
            }
            if groupIndex(forId: op.groupId) != nil {
                diagLog("group", "Create for existing group \(short(op.groupId)) — ignoring")
                return
            }
            // Verify the signature before constructing — Create
            // bypasses the apply state machine's verification path.
            guard (try? op.verifySignature()) == true else {
                diagLog("group", "Create signature INVALID, dropping")
                return
            }
            // The Create payload must include US in the initial
            // member list — otherwise we have no business being
            // bootstrapped into the group.
            guard case let .create(_, initialMembers) = op.kind,
                  initialMembers.contains(where: { $0.peerId == myCard.peerId })
            else {
                diagLog("group", "Create REJECTED — local user not in initialMembers")
                return
            }
            guard let signedBytes = try? op.encoded(),
                  let group = ChatGroup.create(
                      fromCreate: op,
                      signedBytes: signedBytes,
                      localIdentityPub: myCard.peerId,
                  )
            else {
                diagLog("group", "Create REJECTED (structural) for group \(short(op.groupId))")
                return
            }
            state.groups.append(group)
            diagLog("group", "invitation received for \(short(op.groupId))"
                + " with \(group.members.count) member(s)"
                + " — awaiting user accept/decline")
            // Receive-side bootstrap is now an INVITATION. We don't
            // enrol our chain or broadcast SKDMs until the user taps
            // Join — `enrolMyChainOnFirstJoin` is fired from
            // `acceptGroupInvitation` instead. We DO leave the group
            // row in `state.groups` (with `pendingInvitation = true`)
            // so subsequent op/SKDM frames from the admin can apply
            // and install chains — accepting later then plugs into a
            // already-up-to-date snapshot.
            Storage.persist(appState: state)
            return
        }

        guard let gIdx = groupIndex(forId: op.groupId) else {
            // Non-Create op for a group we don't have. Common case:
            // an AddMember-self op arrives slightly before the
            // GroupBootstrap that's supposed to set up our local
            // state. Drop silently — the bootstrap will arrive and
            // include this op's effects already (the snapshot
            // reflects post-AddMember state). For ops we genuinely
            // miss, slice 5 will own a per-group catch-up handshake.
            NSLog(
                "[pizzini.group] groupOp ← \(short(sender)):"
                    + " dropped (no local ChatGroup for \(short(op.groupId)))",
            )
            return
        }
        // Defensive: log if the op's operator isn't the sender.
        // Forwarding non-Create ops is legitimate (it's how AddMember
        // ops reach members who weren't added by us).
        if op.operatorIdentity != sender {
            NSLog(
                "[pizzini.group] groupOp ← \(short(sender)):"
                    + " forwarding on behalf of \(short(op.operatorIdentity))",
            )
        }
        var sx = ChatGroup.ApplySideEffects(localIdentityPub: myCard.peerId)
        let outcome = state.groups[gIdx].apply(op, sideEffects: &sx)

        switch outcome {
        case let .applied(epoch):
            NSLog(
                "[pizzini.group] groupOp ← \(short(sender)):"
                    + " APPLIED \(opKindLabel(op.kind)) at epoch \(epoch),"
                    + " group now has \(state.groups[gIdx].activeMembers.count) active member(s)",
            )
            applyPostMutationSideEffects(groupAt: gIdx, sideEffects: sx, session: session, relay: relay)
        case let .queued(epoch):
            NSLog(
                "[pizzini.group] groupOp ← \(short(sender)):"
                    + " queued (epoch \(epoch) > expected \(state.groups[gIdx].currentEpoch + 1))",
            )
        case .rejectedDuplicate:
            NSLog(
                "[pizzini.group] groupOp ← \(short(sender)):"
                    + " duplicate, ignored",
            )
        case let .rejectedEquivocation(epoch):
            NSLog(
                "[pizzini.group] groupOp ← \(short(sender)):"
                    + " EQUIVOCATION at epoch \(epoch)",
            )
            appendGroupSystem(
                groupAt: gIdx,
                "Group integrity warning: divergent op observed at epoch \(epoch).",
            )
        case .rejectedSignature:
            NSLog("[pizzini.group] groupOp ← \(short(sender)): signature rejected")
        case .rejectedAuthorization:
            NSLog("[pizzini.group] groupOp ← \(short(sender)): unauthorised operator")
        case let .rejectedMalformed(reason):
            NSLog("[pizzini.group] groupOp ← \(short(sender)): malformed — \(reason)")
        }
        Storage.persist(appState: state)
    }

    private func opKindLabel(_ kind: GroupOpKind) -> String {
        switch kind {
        case .create: "Create"
        case .addMember: "AddMember"
        case .removeMember: "RemoveMember"
        case .rename: "Rename"
        case .promoteAdmin: "PromoteAdmin"
        case .demoteAdmin: "DemoteAdmin"
        case .rotateSenderKey: "RotateSenderKey"
        }
    }

    /// Process a signed `GroupBootstrap` (0x09) inner envelope. This
    /// is how a newly-added member acquires local `ChatGroup` state
    /// when an `AddMember` op alone leaves them stranded (audit fix
    /// HIGH-7). Trust gate: same as Create — sender must be the
    /// operator AND the operator must be in our 1:1 contacts.
    /// Bootstrapped groups land with `pendingInvitation = true`; the
    /// local user must tap Join before the chain is enrolled.
    func handleGroupBootstrap(payload: Data, fromPeer sender: Data) {
        guard let myCard else { return }
        guard let parsed = GroupEnvelope.decodeBootstrap(payload) else {
            NSLog("[pizzini.group] bootstrap ← \(short(sender)): malformed body")
            return
        }
        let (envelopeGroupId, bootstrapBytes) = parsed
        guard let bootstrap = GroupBootstrap.decode(bootstrapBytes) else {
            NSLog("[pizzini.group] bootstrap ← \(short(sender)): malformed bootstrap blob")
            return
        }
        // Body's groupId-prefix MUST match the snapshot's own groupId
        // — defence against a relay corruption / accidental code mix-up.
        guard envelopeGroupId == bootstrap.groupId else {
            NSLog("[pizzini.group] bootstrap ← \(short(sender)): groupId prefix mismatch")
            return
        }
        // Trust anchor #1: forwarding is not allowed for bootstraps.
        // Trust anchor #2: the issuing operator must be in our 1:1
        // contacts.
        guard sender == bootstrap.operatorIdentity else {
            NSLog(
                "[pizzini.group] bootstrap ← \(short(sender)):"
                    + " rejected — sender \(short(sender)) forwarding on behalf of \(short(bootstrap.operatorIdentity))",
            )
            return
        }
        guard state.contacts.contains(where: { $0.identityPub == bootstrap.operatorIdentity }) else {
            NSLog(
                "[pizzini.group] bootstrap ← \(short(sender)):"
                    + " rejected — operator \(short(bootstrap.operatorIdentity)) not in 1:1 contacts",
            )
            return
        }
        guard (try? bootstrap.verifySignature()) == true else {
            NSLog("[pizzini.group] bootstrap ← \(short(sender)): signature INVALID")
            return
        }
        // The issuing operator must be an active admin in their own
        // snapshot — otherwise they had no business signing it.
        guard bootstrap.members.contains(where: {
            $0.peerId == bootstrap.operatorIdentity
                && $0.role == .admin && $0.status != .removed
        }) else {
            NSLog("[pizzini.group] bootstrap ← \(short(sender)): operator not an active admin in snapshot")
            return
        }
        // We must be in the snapshot's member list.
        guard bootstrap.members.contains(where: { $0.peerId == myCard.peerId }) else {
            NSLog("[pizzini.group] bootstrap ← \(short(sender)): local user not in snapshot")
            return
        }
        // If we already have the group, this is a no-op. Future-work:
        // diff the snapshot against local state and surface
        // discrepancies; for now we trust our existing op-chain
        // state.
        if let existing = groupIndex(forId: bootstrap.groupId) {
            NSLog(
                "[pizzini.group] bootstrap ← \(short(sender)):"
                    + " already have group \(short(bootstrap.groupId))"
                    + " (currentEpoch=\(state.groups[existing].currentEpoch),"
                    + " snapshot currentEpoch=\(bootstrap.currentEpoch))"
                    + " — ignoring",
            )
            return
        }
        guard let group = bootstrap.intoChatGroup(localIdentityPub: myCard.peerId) else {
            NSLog("[pizzini.group] bootstrap ← \(short(sender)): structural rejection")
            return
        }
        state.groups.append(group)
        NSLog(
            "[pizzini.group] bootstrap ← \(short(sender)):"
                + " invitation received for \(short(bootstrap.groupId))"
                + " at epoch \(bootstrap.currentEpoch)"
                + " with \(group.members.count) member(s) — awaiting user accept/decline",
        )
        // Same flow as handleGroupOp Create: do NOT enrol our chain
        // or broadcast SKDMs until the user taps Join. Subsequent
        // op/SKDM frames apply against the pending group; on
        // acceptance the host calls `enrolMyChainOnFirstJoin`.
        Storage.persist(appState: state)
    }

    /// Process a peer's incoming `groupKeyDistribution` (0x07) inner
    /// envelope. Audit fix CRITICAL-3: only install the chain if we
    /// have a local `ChatGroup` for the named groupId AND the sender
    /// is an active member of that group. Otherwise drop silently —
    /// installing chains for arbitrary groupId/sender pairs widens
    /// the libsignal store and lets non-members pre-position chains
    /// for the message-injection attack documented in CRITICAL-2.
    func handleGroupKeyDistribution(payload: Data, fromPeer sender: Data) {
        guard let session, let relay else { return }
        guard let parsed = GroupEnvelope.decodeKeyDistribution(payload) else {
            NSLog("[pizzini.group] SKDM ← \(short(sender)): malformed body")
            return
        }
        let (groupId, skdm) = parsed
        guard let gIdx = groupIndex(forId: groupId) else {
            NSLog(
                "[pizzini.group] SKDM ← \(short(sender)):"
                    + " dropped — no local ChatGroup for \(short(groupId))"
                    + " (CRITICAL-3 gate)",
            )
            return
        }
        guard state.groups[gIdx].members.contains(where: {
            $0.peerId == sender && $0.status != .removed
        }) else {
            NSLog(
                "[pizzini.group] SKDM ← \(short(sender)):"
                    + " dropped — sender is not an active member of \(short(groupId))"
                    + " (CRITICAL-3 gate)",
            )
            return
        }
        NSLog(
            "[pizzini.group] SKDM ← \(short(sender)):"
                + " group=\(short(groupId)) bytes=\(skdm.count)",
        )
        let dist: UUID
        do {
            dist = try session.senderKeyDistributionProcess(
                senderIdentity: sender,
                skdm: skdm,
            )
        } catch {
            NSLog(
                "[pizzini.group] SKDM ← \(short(sender)):"
                    + " install FAILED for \(short(groupId)) — \(error)",
            )
            return
        }
        persistSession()
        state.groups[gIdx].memberDistributionIds[sender] = dist
        // Mark the sender as .active now that we can decrypt them.
        if let mIdx = state.groups[gIdx].members.firstIndex(where: {
            $0.peerId == sender && $0.status == .pendingSKDM
        }) {
            state.groups[gIdx].members[mIdx].status = .active
            NSLog(
                "[pizzini.group] SKDM ← \(short(sender)):"
                    + " installed, member flipped to .active in \(short(groupId))",
            )
        }
        // Reciprocal SKDM exchange (audit HIGH-2): if we are an
        // active member of this group, ensure the sender has our
        // current SKDM so they can decrypt our messages too.
        let mySxStub = ChatGroup.ApplySideEffects(localIdentityPub: myCard?.peerId)
        applyPostMutationSideEffects(groupAt: gIdx, sideEffects: mySxStub, session: session, relay: relay)
        Storage.persist(appState: state)
    }

    /// Decrypt a `groupChat` (0x06) inner envelope and append to the
    /// group log. Audit fix CRITICAL-2: only accept messages from
    /// active members of the named group. Decryption bytes from a
    /// non-member are dropped — without this gate, any 1:1-paired
    /// peer who has previously installed a chain with us could
    /// inject content into any group log they know the ID of.
    func handleGroupChat(payload: Data, fromPeer sender: Data, pairwiseMessageId: Data) {
        guard let session else { return }
        guard let parsed = GroupEnvelope.decodeGroupChat(payload) else {
            NSLog("[pizzini.group] groupChat ← \(short(sender)): malformed body")
            return
        }
        let (groupId, ciphertext) = parsed
        guard let gIdx = groupIndex(forId: groupId) else {
            NSLog(
                "[pizzini.group] groupChat ← \(short(sender)):"
                    + " unknown group \(short(groupId)), dropping",
            )
            return
        }
        // CRITICAL-2 membership gate.
        guard state.groups[gIdx].members.contains(where: {
            $0.peerId == sender && $0.status != .removed
        }) else {
            NSLog(
                "[pizzini.group] groupChat ← \(short(sender)) for \(short(groupId)):"
                    + " DROPPED — sender is not an active member",
            )
            return
        }
        // Don't render messages while the user hasn't accepted the
        // invitation. We still consume the ratchet step on
        // libsignal's side (groupDecrypt advances the chain), but
        // we drop the plaintext rather than appending it to the
        // log — accepting later doesn't surface a backlog of
        // messages from before the user joined.
        if state.groups[gIdx].pendingInvitation {
            NSLog(
                "[pizzini.group] groupChat ← \(short(sender)) for \(short(groupId)):"
                    + " group is pendingInvitation — message dropped without rendering",
            )
            // Still call decrypt to keep our chain state in sync
            // with the sender's, otherwise a later accept wouldn't
            // be able to decrypt subsequent messages.
            _ = try? session.groupDecrypt(senderIdentity: sender, ciphertext: ciphertext)
            persistSession()
            return
        }
        let plaintext: Data
        do {
            plaintext = try session.groupDecrypt(senderIdentity: sender, ciphertext: ciphertext)
        } catch {
            diagLog("group", "groupChat ← \(short(sender)) for \(short(groupId)):"
                + " DECRYPT FAILED — \(error). Likely cause: SKDM never arrived from this sender.")
            surfaceUndecryptable(groupAt: gIdx, sender: sender, error: error)
            return
        }
        NSLog(
            "[pizzini.group] groupChat ← \(short(sender)) for \(short(groupId)):"
                + " decrypted \(plaintext.count) B",
        )
        persistSession()
        let text = String(data: plaintext, encoding: .utf8)
            ?? "<\(plaintext.count) non-utf8 bytes>"
        // Render-time member-name resolution (audit MEDIUM-7): store
        // the sender's peerId on the row so `GroupChatView` resolves
        // the display name dynamically (rename of a 1:1 contact
        // propagates to every historical row immediately).
        // The pairwise sealed-sender messageId rides along too so
        // `markGroupRead` can later emit a 0x04 readReceipt covering
        // this row — same shape as 1:1 read receipts, scoped to the
        // sender's pairwise channel.
        let row = PersistedMessage(
            side: .peer,
            text: text,
            kind: .whisper,
            bytes: ciphertext.count,
            messageId: pairwiseMessageId,
            senderPeerId: sender,
        )
        state.groups[gIdx].log.append(row)
        state.groups[gIdx].lastMessageAt = Date()
        Storage.persist(appState: state)
        // Same deterministic mark-read shortcut as 1:1: if the user
        // is provably in this group, fire `markGroupRead`
        // synchronously instead of relying on SwiftUI's
        // `.onChange(of: group.log.count)` propagation in
        // `GroupChatView`. Removes the receipt-drop race during a
        // relay-state flap.
        if activeSurface == .group(groupId: groupId) {
            markGroupRead(groupID: groupId)
        }
        maybeFireBackgroundHaptic(forIncoming: .group(groupId: groupId))
    }

    // ─── Utilities ──────────────────────────────────────────────────

    func groupIndex(forId groupId: Data) -> Int? {
        state.groups.firstIndex(where: { $0.id == groupId })
    }

    /// Resolve a member's display name with the local user's
    /// preferred labelling, NOT the name baked into the original
    /// `GroupOp` payload.
    ///
    /// 1. If `peerId == my own identity-pub` → `"you"`.
    /// 2. Else if `peerId` is in our 1:1 contacts → that contact's
    ///    `displayName` (so renames in the contacts list propagate
    ///    to every group view automatically).
    /// 3. Else fall back to whatever name the op carried, then the
    ///    4-byte fingerprint shorthand if that is empty.
    ///
    /// All group-rendering surfaces (`GroupChatView`,
    /// `GroupSettingsView`, `GroupRow`, the inbound `groupChat`
    /// system-row prefix) route through this so a single edit to a
    /// 1:1 contact's name updates everywhere.
    func memberDisplayName(_ peerId: Data, in group: ChatGroup) -> String {
        if let myCard, peerId == myCard.peerId { return "you" }
        if let contact = state.contacts.first(where: { $0.identityPub == peerId }) {
            return contact.displayName
        }
        if let baked = group.members.first(where: { $0.peerId == peerId })?.displayName,
           !baked.isEmpty {
            return baked
        }
        return short(peerId)
    }

    private func enrolMyChainOnFirstJoin(
        groupAt gIdx: Int,
        session: Session,
        relay: RelayClient,
    ) {
        guard let myCard else { return }
        // Idempotent — only enrol if we haven't already.
        if state.groups[gIdx].myCurrentDistributionId != nil {
            NSLog("[pizzini.group] enrol \(short(state.groups[gIdx].id)): already enrolled, skipping")
            return
        }
        let groupId = state.groups[gIdx].id
        let dist = UUID()
        let skdm: Data
        do {
            skdm = try session.senderKeyDistributionCreate(distributionId: dist)
        } catch {
            NSLog("[pizzini.group] enrol \(short(groupId)): SKDM mint failed — \(error)")
            return
        }
        state.groups[gIdx].myCurrentDistributionId = dist
        state.groups[gIdx].memberDistributionIds[myCard.peerId] = dist
        if let idx = state.groups[gIdx].members.firstIndex(where: { $0.peerId == myCard.peerId }) {
            state.groups[gIdx].members[idx].status = .active
        }
        // Fresh chain → no recipients yet.
        state.groups[gIdx].mySkdmRecipients = []
        persistSession()
        let recipients = state.groups[gIdx].activeMembers
            .filter { $0.peerId != myCard.peerId }
        NSLog(
            "[pizzini.group] enrol \(short(groupId)): minted dist, broadcasting SKDM (\(skdm.count) B)"
                + " to \(recipients.count) member(s): "
                + recipients.map { short($0.peerId) }.joined(separator: ", "),
        )
        for member in recipients {
            broadcastSenderKeyDistribution(
                groupId: groupId,
                skdm: skdm,
                toPeer: member.peerId,
                session: session,
                relay: relay,
                groupAt: gIdx,
            )
        }
    }

    /// Post-apply hook: ship our SKDM to any new active members and
    /// fire a self-rotation if the apply requested one. Coalesces
    /// requests across queue-drained cascades — calling this once
    /// per outer apply call is correct even when many ops drained.
    private func applyPostMutationSideEffects(
        groupAt gIdx: Int,
        sideEffects sx: ChatGroup.ApplySideEffects,
        session: Session,
        relay: RelayClient,
    ) {
        // Self-chain clear (we got removed).
        if sx.requestSelfChainClear {
            state.groups[gIdx].myCurrentDistributionId = nil
            state.groups[gIdx].mySkdmRecipients = []
            state.groups[gIdx].sentSinceRotation = 0
            // libsignal's store keeps our chain — no FFI to forget
            // it. Cosmetic; we won't use it again because
            // sendGroupMessage gates on activeMember-self.
            return
        }
        // Pending invitations don't enrol or broadcast anything
        // until the user taps Join — silently skip the SKDM /
        // rotation hooks. The state machine still applies the op
        // (so the snapshot stays in sync with the admin's view of
        // the group); we just don't act on it crypto-wise.
        if state.groups[gIdx].pendingInvitation {
            return
        }
        // Mandatory rotation on member-remove (HIGH-1).
        if sx.requestSelfRotation {
            let groupId = state.groups[gIdx].id
            rotateMyGroupChain(groupId: groupId)
            // rotateMyGroupChain handles its own SKDM broadcast + set
            // population, so we don't double-broadcast below.
            return
        }
        // Bidirectional SKDM (HIGH-2).
        ensureMySKDMReachesActiveMembers(groupAt: gIdx, session: session, relay: relay)
    }

    /// For every active member who isn't us and isn't yet in
    /// `mySkdmRecipients`, ship our current SKDM. Builds the SKDM
    /// once, broadcasts, and updates the recipients set. No-op when
    /// we have no chain (haven't enrolled yet) or no active members
    /// to ship to.
    private func ensureMySKDMReachesActiveMembers(
        groupAt gIdx: Int,
        session: Session,
        relay: RelayClient,
    ) {
        guard let myCard else { return }
        guard let myDist = state.groups[gIdx].myCurrentDistributionId else { return }
        let groupId = state.groups[gIdx].id
        let needs: [Data] = state.groups[gIdx].activeMembers
            .map(\.peerId)
            .filter { $0 != myCard.peerId && !state.groups[gIdx].mySkdmRecipients.contains($0) }
        guard !needs.isEmpty else { return }

        let skdm: Data
        do {
            skdm = try session.senderKeyDistributionCreate(distributionId: myDist)
        } catch {
            NSLog(
                "[pizzini.group] reciprocal SKDM \(short(groupId)):"
                    + " SKDM mint failed — \(error)",
            )
            return
        }
        persistSession()
        for peer in needs {
            broadcastSenderKeyDistribution(
                groupId: groupId,
                skdm: skdm,
                toPeer: peer,
                session: session,
                relay: relay,
                groupAt: gIdx,
            )
        }
    }

    private func signOp(
        session: Session,
        groupId: Data,
        epoch: UInt64,
        parent: Data,
        operatorIdentity: Data,
        kind: GroupOpKind,
    ) -> GroupOp? {
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        let unsigned = GroupOp(
            groupId: groupId,
            epoch: epoch,
            parentDigest: parent,
            operatorIdentity: operatorIdentity,
            timestampMillis: now,
            kind: kind,
            signature: Data(repeating: 0, count: GroupOp.signatureSize),
        )
        guard let header = try? unsigned.encodedHeader(),
              let sig = try? session.identitySign(header)
        else { return nil }
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

    /// Sign a snapshot of the current group state. Returns nil if
    /// the encode/sign path fails (libsignal-state corruption).
    private func signBootstrap(
        session: Session,
        group: ChatGroup,
        operatorIdentity: Data,
    ) -> GroupBootstrap? {
        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        let unsigned = GroupBootstrap(
            groupId: group.id,
            displayName: group.displayName,
            members: group.members,
            currentEpoch: group.currentEpoch,
            lastOpDigest: group.lastOpDigest,
            operatorIdentity: operatorIdentity,
            timestampMillis: now,
            signature: Data(repeating: 0, count: GroupOp.signatureSize),
        )
        guard let header = try? unsigned.encodedHeader(),
              let sig = try? session.identitySign(header)
        else { return nil }
        return GroupBootstrap(
            groupId: unsigned.groupId,
            displayName: unsigned.displayName,
            members: unsigned.members,
            currentEpoch: unsigned.currentEpoch,
            lastOpDigest: unsigned.lastOpDigest,
            operatorIdentity: unsigned.operatorIdentity,
            timestampMillis: unsigned.timestampMillis,
            signature: sig,
        )
    }

    private func broadcastGroupOp(
        _ signedBytes: Data,
        toPeer recipient: Data,
        session: Session,
        relay: RelayClient,
    ) {
        guard let cIdx = state.contacts.firstIndex(where: { $0.identityPub == recipient }) else {
            diagLog("group", "groupOp → \(short(recipient)): NO CONTACT (1:1 unpaired)")
            return
        }
        guard let token = popDeliveryTokenPublic(forContactAt: cIdx) else {
            diagLog("group", "groupOp → \(short(recipient)): NO DELIVERY TOKEN"
                + " (stash empty for this peer); op dropped — outbox+retry pending v2")
            return
        }
        var inner = Data([RelayClient.InnerEnvelopeKind.groupOp.rawValue])
        inner.append(signedBytes)
        let messageId = ChatStore.makeGroupMessageId()
        do {
            let sealed = try session.encryptSealed(
                peer: recipient,
                messageId: messageId,
                plaintext: inner,
            )
            relay.sendSealed(
                toPeer: recipient,
                sealedCiphertext: sealed,
                ttlSeconds: state.contacts[cIdx].ttlSeconds,
                token: token,
            )
            diagLog("group", "groupOp → \(short(recipient)): sealed=\(sealed.count) B, sent")
        } catch {
            diagLog("group", "groupOp → \(short(recipient)): seal failed — \(error)")
        }
    }

    /// Broadcast our SKDM for `groupId` to one peer and record it in
    /// `mySkdmRecipients` on success so the bidirectional-SKDM hook
    /// doesn't re-send. `groupAt` is the array index of the group; we
    /// pass it explicitly to avoid an extra `firstIndex` lookup.
    private func broadcastSenderKeyDistribution(
        groupId: Data,
        skdm: Data,
        toPeer recipient: Data,
        session: Session,
        relay: RelayClient,
        groupAt gIdx: Int,
    ) {
        guard let cIdx = state.contacts.firstIndex(where: { $0.identityPub == recipient }) else {
            diagLog("group", "SKDM \(short(groupId)) → \(short(recipient)):"
                + " NO CONTACT (1:1 unpaired) — recipient cannot decrypt our messages")
            return
        }
        guard let token = popDeliveryTokenPublic(forContactAt: cIdx) else {
            diagLog("group", "SKDM \(short(groupId)) → \(short(recipient)):"
                + " NO DELIVERY TOKEN (stash empty for this peer);"
                + " SKDM dropped, recipient cannot decrypt")
            return
        }
        var inner = Data([RelayClient.InnerEnvelopeKind.groupKeyDistribution.rawValue])
        inner.append(GroupEnvelope.encodeKeyDistribution(groupId: groupId, skdm: skdm))
        let messageId = ChatStore.makeGroupMessageId()
        do {
            let sealed = try session.encryptSealed(
                peer: recipient,
                messageId: messageId,
                plaintext: inner,
            )
            relay.sendSealed(
                toPeer: recipient,
                sealedCiphertext: sealed,
                ttlSeconds: state.contacts[cIdx].ttlSeconds,
                token: token,
            )
            // Successful seal → record so the bidirectional hook
            // doesn't re-fire for this peer until next rotation.
            state.groups[gIdx].mySkdmRecipients.insert(recipient)
            diagLog("group", "SKDM \(short(groupId)) → \(short(recipient)):"
                + " sealed=\(sealed.count) B, sent")
        } catch {
            diagLog("group", "SKDM \(short(groupId)) → \(short(recipient)):"
                + " seal failed — \(error)")
        }
    }

    private func broadcastGroupBootstrap(
        bootstrap: GroupBootstrap,
        toPeer recipient: Data,
        session: Session,
        relay: RelayClient,
    ) {
        guard let bytes = try? bootstrap.encoded() else {
            NSLog("[pizzini.group] bootstrap → \(short(recipient)): encode failed")
            return
        }
        guard let cIdx = state.contacts.firstIndex(where: { $0.identityPub == recipient }) else {
            NSLog("[pizzini.group] bootstrap → \(short(recipient)): no contact")
            return
        }
        guard let token = popDeliveryTokenPublic(forContactAt: cIdx) else {
            NSLog("[pizzini.group] bootstrap → \(short(recipient)): no delivery token")
            return
        }
        var inner = Data([RelayClient.InnerEnvelopeKind.groupBootstrap.rawValue])
        inner.append(GroupEnvelope.encodeBootstrap(groupId: bootstrap.groupId, bootstrapBytes: bytes))
        let messageId = ChatStore.makeGroupMessageId()
        do {
            let sealed = try session.encryptSealed(
                peer: recipient,
                messageId: messageId,
                plaintext: inner,
            )
            relay.sendSealed(
                toPeer: recipient,
                sealedCiphertext: sealed,
                ttlSeconds: state.contacts[cIdx].ttlSeconds,
                token: token,
            )
            NSLog("[pizzini.group] bootstrap → \(short(recipient)): sealed=\(sealed.count) B, sent")
        } catch {
            NSLog("[pizzini.group] bootstrap → \(short(recipient)): seal failed — \(error)")
        }
    }

    private func appendGroupSystem(groupAt gIdx: Int, _ text: String) {
        state.groups[gIdx].log.append(
            PersistedMessage(side: .me, text: text, kind: .system, bytes: 0),
        )
    }

    /// `groupId`-keyed variant for call sites that hop back from a
    /// background queue and don't have the array index in hand.
    /// Silent no-op if the group has been removed since the hop —
    /// e.g. the user tapped Leave during the off-main strip pass.
    fileprivate func appendGroupSystem(groupId: Data, text: String) {
        guard let gIdx = groupIndex(forId: groupId) else { return }
        appendGroupSystem(groupAt: gIdx, text)
        Storage.persist(appState: state)
    }

    /// Surface an in-chat system row when `groupDecrypt` fails so the
    /// user knows a peer's message arrived but couldn't be read —
    /// previously this was NSLog-only and the message just vanished.
    /// Most common root cause is that the sender's SKDM never reached
    /// us (delivery-token depletion, app backgrounded mid-broadcast,
    /// dev-relay queue eviction); the recovery action is the
    /// "Resend my keys" button on the *sender's* Group Settings.
    ///
    /// Dedups against the immediately-previous log row so a malicious
    /// peer (or a stuck SKDM that's failing on every retry) can't
    /// flood the log with system rows. After any other row interleaves
    /// — a successful decrypt from this or another member, an op
    /// apply system row — the next failure surfaces a fresh banner.
    private func surfaceUndecryptable(groupAt gIdx: Int, sender: Data, error: Error) {
        let name = memberDisplayName(sender, in: state.groups[gIdx])
        let body = "Couldn't decrypt a message from \(name)."
            + " They may need to tap 'Resend my keys' in Group Settings."
        if let last = state.groups[gIdx].log.last,
           last.kind == .system,
           last.text == body {
            // Run-of-failures dedup. The chain still advances on
            // every undecryptable; we just don't repaint the same
            // banner.
            return
        }
        appendGroupSystem(groupAt: gIdx, body)
        Storage.persist(appState: state)
    }

    private static func makeGroupMessageId() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &bytes)
        return Data(bytes)
    }
}
