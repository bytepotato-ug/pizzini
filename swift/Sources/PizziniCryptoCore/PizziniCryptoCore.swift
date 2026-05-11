// Idiomatic Swift wrapper over the Rust crypto-core C ABI.
//
// All cryptographic state lives on the Rust side; Swift only marshals bytes
// across the FFI boundary.

import Foundation
import PizziniCryptoCoreFFI

public enum PizziniCryptoCore {
    /// The native crypto-core library version, read across the FFI bridge.
    public static var version: String {
        guard let cString = pizzini_crypto_core_version() else { return "" }
        return String(cString: cString)
    }
}

// MARK: - Identity

/// A long-term identity keypair, in libsignal's serialized form.
public struct IdentityKeyPair: Sendable {
    public let bytes: Data

    public init(bytes: Data) {
        self.bytes = bytes
    }

    /// Generate a fresh identity keypair using the OS CSPRNG.
    public static func generate() throws -> IdentityKeyPair {
        var buffer = [UInt8](repeating: 0, count: 256)
        var len: UInt = 0
        let rc = buffer.withUnsafeMutableBufferPointer { ptr in
            pizzini_identity_keypair_generate(ptr.baseAddress, UInt(ptr.count), &len)
        }
        switch rc {
        case PIZZINI_OK:
            return IdentityKeyPair(bytes: Data(buffer.prefix(Int(len))))
        case PIZZINI_ERR_BUFFER_TOO_SMALL:
            throw CryptoCoreError.bufferTooSmall(required: Int(len))
        case PIZZINI_ERR_INVALID_ARG:
            throw CryptoCoreError.invalidArgument
        default:
            throw CryptoCoreError.unknown(code: rc)
        }
    }
}

// MARK: - Per-device session store

/// Owns one libsignal `InMemSignalProtocolStore` on the Rust side. Use this
/// for real two-device messaging: each device has one Session, peers exchange
/// PreKey bundles out-of-band, then encrypt / decrypt via wire bytes.
public final class Session: @unchecked Sendable {
    public enum MessageType: Sendable {
        case preKey
        case whisper
    }

    public struct EncryptResult: Sendable {
        public let ciphertext: Data
        public let messageType: MessageType
    }

    private var handle: OpaquePointer?

    /// Create a session for a brand-new identity (fresh keypair, fresh
    /// registration id). Persist `identityKeypairBytes` in Keychain to
    /// rehydrate the same identity later.
    public init() throws {
        guard let h = pizzini_store_new(nil, 0) else {
            throw CryptoCoreError.internalError
        }
        self.handle = h
    }

    /// Rehydrate identity only. Loses session/prekey state — for full
    /// continuity (sessions, ratchet) use `init(serialized:)` instead.
    public init(identitySeed seed: Data) throws {
        let h = seed.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> OpaquePointer? in
            pizzini_store_new(ptr.bindMemory(to: UInt8.self).baseAddress, UInt(seed.count))
        }
        guard let h else { throw CryptoCoreError.internalError }
        self.handle = h
    }

    /// Rehydrate the full store (identity + prekeys + per-peer sessions)
    /// from the bytes returned by `serialize()`. Pair every meaningful
    /// state change in the host with a fresh `serialize()` to keep on-disk
    /// state in sync.
    public init(serialized blob: Data) throws {
        let h = blob.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> OpaquePointer? in
            pizzini_store_new_from_serialized(
                ptr.bindMemory(to: UInt8.self).baseAddress, UInt(blob.count)
            )
        }
        guard let h else { throw CryptoCoreError.internalError }
        self.handle = h
    }

    deinit {
        if let h = handle {
            pizzini_store_free(h)
        }
    }

    /// Bytes to persist in Keychain — opaque libsignal IdentityKeyPair.
    public func identityKeypairBytes() throws -> Data {
        try readBlob { handle, buf, cap, len in
            pizzini_store_identity_keypair(handle, buf, cap, len)
        }
    }

    /// Routing peer-id: 33-byte serialized public IdentityKey. Pass this to
    /// the relay and to peers as your address.
    public func identityPublic() throws -> Data {
        try readBlob { handle, buf, cap, len in
            pizzini_store_identity_public(handle, buf, cap, len)
        }
    }

    /// Generate a fresh PreKey bundle (rotates one-time / signed / Kyber
    /// pre-keys), persist them in the store, and return the wire bytes.
    public func publishBundle() throws -> Data {
        try readBlob(initialCap: 4096) { handle, buf, cap, len in
            pizzini_store_publish_bundle(handle, buf, cap, len)
        }
    }

    /// Snapshot the full store (identity, prekeys, sessions) for persisting
    /// to Keychain. Pair with `init(serialized:)` on the next launch.
    public func serialize() throws -> Data {
        try readBlob(initialCap: 16384) { handle, buf, cap, len in
            pizzini_store_serialize(handle, buf, cap, len)
        }
    }

    /// Idempotently track a peer in the persisted index. Call right after
    /// adding a contact (e.g. after a QR scan), before the actual handshake
    /// — so the peer survives `serialize` even if no session exists yet.
    public func registerPeer(peerIdentity: Data) throws {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        let rc = peerIdentity.withUnsafeBytes { ptr in
            pizzini_store_register_peer(
                handle,
                ptr.bindMemory(to: UInt8.self).baseAddress, UInt(peerIdentity.count)
            )
        }
        try mapRC(rc)
    }

    /// Drop a peer's session and remove from the persisted index. Future
    /// messages to or from this identity require a fresh PQXDH handshake.
    public func forgetPeer(peerIdentity: Data) throws {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        let rc = peerIdentity.withUnsafeBytes { ptr in
            pizzini_store_forget_peer(
                handle,
                ptr.bindMemory(to: UInt8.self).baseAddress, UInt(peerIdentity.count)
            )
        }
        try mapRC(rc)
    }

    /// Run PQXDH against a peer's bundle. After this, `encrypt`/`decrypt`
    /// against `peerIdentity` will produce / accept real ciphertexts.
    public func initiateSession(peerIdentity: Data, bundle: Data) throws {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        let rc = peerIdentity.withUnsafeBytes { peerPtr in
            bundle.withUnsafeBytes { bundlePtr in
                pizzini_store_initiate_session(
                    handle,
                    peerPtr.bindMemory(to: UInt8.self).baseAddress, UInt(peerIdentity.count),
                    bundlePtr.bindMemory(to: UInt8.self).baseAddress, UInt(bundle.count)
                )
            }
        }
        try mapRC(rc)
    }

    public func encrypt(peerIdentity: Data, plaintext: Data) throws -> EncryptResult {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        var ct = [UInt8](repeating: 0, count: max(plaintext.count + 256, 4096))
        var ctLen: UInt = 0
        var msgType: UInt32 = 0
        let rc = peerIdentity.withUnsafeBytes { peerPtr -> Int32 in
            plaintext.withUnsafeBytes { plainPtr -> Int32 in
                ct.withUnsafeMutableBufferPointer { ctPtr in
                    pizzini_store_encrypt(
                        handle,
                        peerPtr.bindMemory(to: UInt8.self).baseAddress, UInt(peerIdentity.count),
                        plainPtr.bindMemory(to: UInt8.self).baseAddress, UInt(plaintext.count),
                        ctPtr.baseAddress, UInt(ctPtr.count), &ctLen,
                        &msgType
                    )
                }
            }
        }
        try mapRC(rc)
        let mt: MessageType = (msgType == UInt32(PIZZINI_MSG_TYPE_PREKEY)) ? .preKey : .whisper
        return EncryptResult(ciphertext: Data(ct.prefix(Int(ctLen))), messageType: mt)
    }

    public func decrypt(peerIdentity: Data, ciphertext: Data, isPreKey: Bool) throws -> Data {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        var pt = [UInt8](repeating: 0, count: max(ciphertext.count + 256, 1024))
        var ptLen: UInt = 0
        let rc = peerIdentity.withUnsafeBytes { peerPtr -> Int32 in
            ciphertext.withUnsafeBytes { ctPtr -> Int32 in
                pt.withUnsafeMutableBufferPointer { ptPtr in
                    pizzini_store_decrypt(
                        handle,
                        peerPtr.bindMemory(to: UInt8.self).baseAddress, UInt(peerIdentity.count),
                        ctPtr.bindMemory(to: UInt8.self).baseAddress, UInt(ciphertext.count),
                        isPreKey ? 1 : 0,
                        ptPtr.baseAddress, UInt(ptPtr.count), &ptLen
                    )
                }
            }
        }
        try mapRC(rc)
        return Data(pt.prefix(Int(ptLen)))
    }

    /// Mint a single delivery token (84 bytes). Each is one-use against
    /// the relay's per-recipient replay set. Phase 3 hands out a stash
    /// of 1024 to each newly-paired contact.
    public func mintDeliveryToken() throws -> Data {
        try readBlob(initialCap: 128) { handle, buf, cap, len in
            pizzini_store_mint_delivery_token(handle, buf, cap, len)
        }
    }

    /// Recipient's published delivery-token verify key (33 bytes —
    /// libsignal-native PublicKey serialize() form). Deterministic per
    /// IdentityKeyPair via HKDF, so a Keychain restore reconstructs it
    /// without a separate signing-key backup. The relay's per-recipient
    /// table maps peer-id → verify-key from each HELLO frame.
    public func deliveryTokenVerifyKey() throws -> Data {
        try readBlob(initialCap: 64) { handle, buf, cap, len in
            pizzini_store_delivery_token_verify_key(handle, buf, cap, len)
        }
    }

    /// Sign `payload` with the local IdentityKey's private half,
    /// domain-separated by `contextTag`.
    ///
    /// **F-NEW-101**: the tag is MANDATORY and non-empty. The signed
    /// bytes are `u16_be(tag.count) || tag || payload` — a verifier
    /// reconstructing the same bytes can confirm the signature was
    /// produced for that specific context. A caller that passes a
    /// tag different from the verifier's would get a verify failure
    /// rather than a cross-context-reusable signature.
    ///
    /// Returns the 64-byte Ed25519 signature.
    public func identitySign(_ payload: Data, contextTag: Data) throws -> Data {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        guard !contextTag.isEmpty else { throw CryptoCoreError.invalidArgument }
        var buf = [UInt8](repeating: 0, count: 128)
        var len: UInt = 0
        var rc = contextTag.withUnsafeBytes { tPtr -> Int32 in
            payload.withUnsafeBytes { pPtr -> Int32 in
                buf.withUnsafeMutableBufferPointer { outPtr in
                    pizzini_store_identity_sign_v2(
                        handle,
                        tPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        UInt(contextTag.count),
                        pPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        UInt(payload.count),
                        outPtr.baseAddress,
                        UInt(outPtr.count),
                        &len,
                    )
                }
            }
        }
        if rc == PIZZINI_ERR_BUFFER_TOO_SMALL {
            buf = [UInt8](repeating: 0, count: Int(len))
            rc = contextTag.withUnsafeBytes { tPtr -> Int32 in
                payload.withUnsafeBytes { pPtr -> Int32 in
                    buf.withUnsafeMutableBufferPointer { outPtr in
                        pizzini_store_identity_sign_v2(
                            handle,
                            tPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            UInt(contextTag.count),
                            pPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            UInt(payload.count),
                            outPtr.baseAddress,
                            UInt(outPtr.count),
                            &len,
                        )
                    }
                }
            }
        }
        guard rc == PIZZINI_OK else {
            if rc == PIZZINI_ERR_INVALID_ARG { throw CryptoCoreError.invalidArgument }
            throw CryptoCoreError.internalError
        }
        return Data(buf.prefix(Int(len)))
    }

    /// Pull the issuer's `delivery_token_verify_key` (33 bytes) out of a
    /// BUNDLE_RESPONSE payload without consuming the bundle. Used by iOS
    /// to stash the peer's key on the Contact at pair time so subsequent
    /// TOKEN_ISSUE batches can be authenticated end-to-end via
    /// `verifyDeliveryToken`. F-202/F-401.
    public static func extractBundleVerifyKey(_ bundle: Data) throws -> Data {
        let initialCap = 64
        var buf = [UInt8](repeating: 0, count: initialCap)
        var len: UInt = 0
        var rc = bundle.withUnsafeBytes { bPtr -> Int32 in
            buf.withUnsafeMutableBufferPointer { outPtr in
                pizzini_bundle_extract_verify_key(
                    bPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    UInt(bundle.count),
                    outPtr.baseAddress,
                    UInt(outPtr.count),
                    &len,
                )
            }
        }
        if rc == PIZZINI_ERR_BUFFER_TOO_SMALL {
            buf = [UInt8](repeating: 0, count: Int(len))
            rc = bundle.withUnsafeBytes { bPtr -> Int32 in
                buf.withUnsafeMutableBufferPointer { outPtr in
                    pizzini_bundle_extract_verify_key(
                        bPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        UInt(bundle.count),
                        outPtr.baseAddress,
                        UInt(outPtr.count),
                        &len,
                    )
                }
            }
        }
        guard rc == PIZZINI_OK else { throw CryptoCoreError.internalError }
        return Data(buf.prefix(Int(len)))
    }

    /// Verify a delivery token's XEd25519 signature against an issuer's
    /// bundle-published verify key. F-202/F-401: the iOS receiver of a
    /// TOKEN_ISSUE batch authenticates each token end-to-end before
    /// adding it to the per-contact stash, defeating relay swap.
    ///
    /// `verifyKey` is the 33-byte bundle field; `token` is the 84-byte
    /// `nonce16 || expiry_be_u32 || sig64`. Returns `true` on a valid
    /// signature, `false` if the signature does not match. Throws
    /// `CryptoCoreError.invalidArgument` for length/null mismatches.
    public static func verifyDeliveryToken(verifyKey: Data, token: Data) throws -> Bool {
        let rc = verifyKey.withUnsafeBytes { vkPtr -> Int32 in
            token.withUnsafeBytes { tokPtr -> Int32 in
                pizzini_verify_delivery_token(
                    vkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    UInt(verifyKey.count),
                    tokPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    UInt(token.count),
                )
            }
        }
        switch rc {
        case PIZZINI_OK:
            return true
        case PIZZINI_ERR_BAD_SIGNATURE:
            return false
        case PIZZINI_ERR_INVALID_ARG:
            throw CryptoCoreError.invalidArgument
        default:
            throw CryptoCoreError.internalError
        }
    }

    /// Verify an XEd25519 signature `sig` over `message`, claimed to
    /// have been produced by the `IdentityKey` whose 33-byte serialized
    /// public half is `identityPub`. Returns `true` on a valid
    /// signature, `false` if the signature does not match. Throws
    /// `CryptoCoreError.invalidArgument` for length / null mismatches.
    ///
    /// Used by the Swift host to authenticate signed `GroupOp` log
    /// entries: the operator's identity-public is embedded in the op
    /// header and the recipient verifies the signature before applying
    /// the op or persisting it. Stateless — does not require a live
    /// `Session` because verification is a public-key operation.
    public static func verifyIdentitySignature(
        identityPub: Data,
        message: Data,
        signature: Data,
        contextTag: Data,
    ) throws -> Bool {
        guard !contextTag.isEmpty else { throw CryptoCoreError.invalidArgument }
        let rc = identityPub.withUnsafeBytes { idPtr -> Int32 in
            contextTag.withUnsafeBytes { tagPtr -> Int32 in
                message.withUnsafeBytes { msgPtr -> Int32 in
                    signature.withUnsafeBytes { sigPtr -> Int32 in
                        pizzini_verify_identity_signature_v2(
                            idPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            UInt(identityPub.count),
                            tagPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            UInt(contextTag.count),
                            msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            UInt(message.count),
                            sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            UInt(signature.count),
                        )
                    }
                }
            }
        }
        switch rc {
        case PIZZINI_OK:
            return true
        case PIZZINI_ERR_BAD_SIGNATURE:
            return false
        case PIZZINI_ERR_INVALID_ARG:
            throw CryptoCoreError.invalidArgument
        default:
            throw CryptoCoreError.internalError
        }
    }

    /// Canonical domain-separation tags. Adding a new use-site MUST
    /// add a new tag here rather than reusing an existing one — that
    /// is the entire point of the F-NEW-101 fix.
    public enum SignatureContext {
        /// HELLO possession proof — included for completeness even
        /// though `RelayClient` constructs the literal directly.
        public static let hello: Data = Data("pizzini.hello.v3".utf8)
        /// `GroupOp` signature (Create / AddMember / RemoveMember /
        /// RotateSenderKey / GroupChat / Rename).
        // v2: GroupOp wire format gained the 32-byte
        // `priorMemberSetRoot` field (USP #5: verifiable group
        // membership). Bumping the tag in lockstep with the wire
        // bump ensures any in-flight v1 signature fails verification
        // under v2 — no downgrade-attack path that lets a v1 op
        // slip through a v2 verifier.
        public static let groupOp: Data = Data("pizzini.group.op.v2".utf8)
        /// `GroupBootstrap` snapshot signature.
        // v2: GroupBootstrap wire format gained the 32-byte
        // `memberSetRoot` field (USP #5: self-consistency check the
        // joiner runs against the admin's `members[]` list).
        // Lockstep bump with the v1 → v2 wire change ensures
        // pre-v2 snapshots fail signature verification on a v2
        // joiner — closes the downgrade path.
        public static let groupBootstrap: Data = Data("pizzini.group.bootstrap.v2".utf8)
        /// Device-rekey ed25519 signature used by `ChatStore.requestBundleWithHashcash`.
        public static let deviceRekey: Data = Data("pizzini.device.rekey.v1".utf8)
    }

    /// Mints (or refreshes) the cached SenderCertificate. Production
    /// callers don't need this — `encryptSealed` calls it implicitly —
    /// but it's handy for diagnostics ("can my store actually issue a
    /// cert?") during onboarding.
    @discardableResult
    public func ensureSenderCertificate() throws -> Data {
        try readBlob(initialCap: 1024) { handle, buf, cap, len in
            pizzini_store_ensure_sender_certificate(handle, buf, cap, len)
        }
    }

    /// Sealed-sender SEND. Wraps `plaintext` for `peer`, prefixes the
    /// 16-byte `messageId` and the ratchet's PreKey/Whisper tag at the
    /// USMC layer, and seals the whole thing to the recipient's identity
    /// key. The relay forwards the returned bytes as the SEND v2
    /// payload — `from_id` and `is_prekey` no longer ride at the wire
    /// level.
    public func encryptSealed(peer: Data, messageId: Data, plaintext: Data) throws -> Data {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        guard messageId.count == 16 else { throw CryptoCoreError.invalidArgument }
        var sealed = [UInt8](repeating: 0, count: max(plaintext.count + 1024, 4096))
        var sealedLen: UInt = 0
        var rc = peer.withUnsafeBytes { peerPtr -> Int32 in
            messageId.withUnsafeBytes { idPtr -> Int32 in
                plaintext.withUnsafeBytes { ptPtr -> Int32 in
                    sealed.withUnsafeMutableBufferPointer { outPtr in
                        pizzini_store_seal_send(
                            handle,
                            peerPtr.bindMemory(to: UInt8.self).baseAddress, UInt(peer.count),
                            idPtr.bindMemory(to: UInt8.self).baseAddress,
                            ptPtr.bindMemory(to: UInt8.self).baseAddress, UInt(plaintext.count),
                            outPtr.baseAddress, UInt(outPtr.count), &sealedLen
                        )
                    }
                }
            }
        }
        if rc == PIZZINI_ERR_BUFFER_TOO_SMALL {
            sealed = [UInt8](repeating: 0, count: Int(sealedLen))
            rc = peer.withUnsafeBytes { peerPtr -> Int32 in
                messageId.withUnsafeBytes { idPtr -> Int32 in
                    plaintext.withUnsafeBytes { ptPtr -> Int32 in
                        sealed.withUnsafeMutableBufferPointer { outPtr in
                            pizzini_store_seal_send(
                                handle,
                                peerPtr.bindMemory(to: UInt8.self).baseAddress, UInt(peer.count),
                                idPtr.bindMemory(to: UInt8.self).baseAddress,
                                ptPtr.bindMemory(to: UInt8.self).baseAddress, UInt(plaintext.count),
                                outPtr.baseAddress, UInt(outPtr.count), &sealedLen
                            )
                        }
                    }
                }
            }
        }
        try mapRC(rc)
        return Data(sealed.prefix(Int(sealedLen)))
    }

    /// Sealed-sender RECEIVE result: the verified sender, the 16-byte
    /// message id (caller owns dedup), and the inner plaintext.
    ///
    /// `isDuplicate == true` means libsignal's ratchet rejected the
    /// inner ciphertext as already-consumed (a retry of a SEND we
    /// already processed). `plaintext` is empty in that case; sender
    /// + messageId are still populated so the host can re-emit a
    /// fresh ACK and shut down the sender's retry loop.
    public struct SealedReceived: Sendable {
        public let peer: Data
        public let messageId: Data
        public let plaintext: Data
        public let isDuplicate: Bool
    }

    /// Sealed-sender RECEIVE. Validates the embedded cert against the
    /// claimed sender's identity_pub (which must be a contact already in
    /// the store's peers list) and decrypts the inner ratchet ciphertext.
    /// Throws `internalError` on either validation failure or unknown
    /// sender — both surfaces are deliberately indistinguishable.
    public func decryptSealed(_ sealed: Data) throws -> SealedReceived {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        var sender = [UInt8](repeating: 0, count: 64)
        var senderLen: UInt = 0
        var msgId = [UInt8](repeating: 0, count: 16)
        var plaintext = [UInt8](repeating: 0, count: max(sealed.count + 256, 1024))
        var plaintextLen: UInt = 0
        var isDuplicate: UInt8 = 0
        var rc = sealed.withUnsafeBytes { sealedPtr -> Int32 in
            sender.withUnsafeMutableBufferPointer { sPtr in
                msgId.withUnsafeMutableBufferPointer { mPtr in
                    plaintext.withUnsafeMutableBufferPointer { pPtr in
                        pizzini_store_seal_receive(
                            handle,
                            sealedPtr.bindMemory(to: UInt8.self).baseAddress, UInt(sealed.count),
                            sPtr.baseAddress, UInt(sPtr.count), &senderLen,
                            mPtr.baseAddress,
                            pPtr.baseAddress, UInt(pPtr.count), &plaintextLen,
                            &isDuplicate
                        )
                    }
                }
            }
        }
        if rc == PIZZINI_ERR_BUFFER_TOO_SMALL {
            // Grow both buffers per the lengths reported on the failed
            // call. The decrypt is idempotent at the libsignal layer
            // *only because the FFI returns INTERNAL before advancing
            // the ratchet on a buffer-too-small*; otherwise we'd have
            // already consumed the prekey. Retrying with bigger buffers
            // is safe.
            sender = [UInt8](repeating: 0, count: Int(senderLen))
            plaintext = [UInt8](repeating: 0, count: Int(plaintextLen))
            rc = sealed.withUnsafeBytes { sealedPtr -> Int32 in
                sender.withUnsafeMutableBufferPointer { sPtr in
                    msgId.withUnsafeMutableBufferPointer { mPtr in
                        plaintext.withUnsafeMutableBufferPointer { pPtr in
                            pizzini_store_seal_receive(
                                handle,
                                sealedPtr.bindMemory(to: UInt8.self).baseAddress, UInt(sealed.count),
                                sPtr.baseAddress, UInt(sPtr.count), &senderLen,
                                mPtr.baseAddress,
                                pPtr.baseAddress, UInt(pPtr.count), &plaintextLen,
                                &isDuplicate
                            )
                        }
                    }
                }
            }
        }
        try mapRC(rc)
        return SealedReceived(
            peer: Data(sender.prefix(Int(senderLen))),
            messageId: Data(msgId),
            plaintext: Data(plaintext.prefix(Int(plaintextLen))),
            isDuplicate: isDuplicate != 0
        )
    }

    private func readBlob(
        initialCap: Int = 256,
        _ body: (OpaquePointer, UnsafeMutablePointer<UInt8>, UInt, UnsafeMutablePointer<UInt>) -> Int32
    ) throws -> Data {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        var buf = [UInt8](repeating: 0, count: initialCap)
        var len: UInt = 0
        var rc = buf.withUnsafeMutableBufferPointer { ptr in
            body(handle, ptr.baseAddress!, UInt(ptr.count), &len)
        }
        if rc == PIZZINI_ERR_BUFFER_TOO_SMALL {
            buf = [UInt8](repeating: 0, count: Int(len))
            rc = buf.withUnsafeMutableBufferPointer { ptr in
                body(handle, ptr.baseAddress!, UInt(ptr.count), &len)
            }
        }
        try mapRC(rc)
        return Data(buf.prefix(Int(len)))
    }

    // ─── Group cipher (libsignal Sender Keys) ────────────────────────
    //
    // Wrappers around the four `pizzini_store_*` exports added in
    // slice 1. Caller responsibilities:
    //
    //   1. The `distributionId` is libsignal's per-CHAIN identifier,
    //      not the public group ID. Each rotation = pick a fresh
    //      `UUID()`. Old chains stay in the store so late-arriving
    //      ciphertext still decrypts.
    //   2. `senderIdentity` is the 33-byte identity-public verified
    //      via the sealed-sender unwrap. Passing the wrong identity
    //      surfaces as a generic `internalError` rather than a
    //      specific signature-mismatch error — the FFI error path
    //      collapses libsignal's distinctions to keep the surface
    //      narrow.
    //   3. The plaintext / ciphertext blobs are the bytes that ride
    //      INSIDE the `groupChat = 0x06` / `groupKeyDistribution =
    //      0x07` inner envelopes; the outer sealed-sender wrap is
    //      handled elsewhere.
    //
    // See `crypto-core/tests/group_cipher.rs` for the wire-level
    // round-trip and persistence tests; the Swift-side tests in
    // `swift/Tests/PizziniCryptoCoreTests/PizziniCryptoCoreTests.swift`
    // exercise the same paths through this bridge.

    /// Generate (or recover) the SKDM bytes for our local sender-key
    /// chain at `distributionId`. Calling twice with the same
    /// `distributionId` reuses the existing chain — rotation is
    /// "pick a fresh `UUID` and call again."
    public func senderKeyDistributionCreate(distributionId: UUID) throws -> Data {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        var distBytes = distributionId.distributionIdBytes
        return try readBlob(initialCap: 256) { handle, buf, cap, len in
            distBytes.withUnsafeBufferPointer { distPtr in
                pizzini_store_sender_key_distribution_create(
                    handle,
                    distPtr.baseAddress,
                    buf, cap, len,
                )
            }
        }
    }

    /// Process a peer's incoming SKDM. `senderIdentity` is the verified
    /// 33-byte identity-public from the sealed-sender unwrap. Returns
    /// the `UUID` (distribution_id) embedded in the SKDM so the caller
    /// can update its `ChatGroup.memberDistributionIds` in lockstep.
    @discardableResult
    public func senderKeyDistributionProcess(
        senderIdentity: Data,
        skdm: Data,
    ) throws -> UUID {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        var distBytes = [UInt8](repeating: 0, count: 16)
        let rc = senderIdentity.withUnsafeBytes { senderPtr -> Int32 in
            skdm.withUnsafeBytes { skdmPtr -> Int32 in
                distBytes.withUnsafeMutableBufferPointer { distPtr in
                    pizzini_store_sender_key_distribution_process(
                        handle,
                        senderPtr.bindMemory(to: UInt8.self).baseAddress,
                        UInt(senderIdentity.count),
                        skdmPtr.bindMemory(to: UInt8.self).baseAddress,
                        UInt(skdm.count),
                        distPtr.baseAddress,
                    )
                }
            }
        }
        try mapRC(rc)
        return UUID(distributionIdBytes: distBytes)
    }

    /// Encrypt `plaintext` for the chain identified by `distributionId`.
    /// Caller must have called `senderKeyDistributionCreate(distributionId:)`
    /// first; otherwise libsignal returns `NoSenderKeyState` (mapped to
    /// `internalError`). The output is the `SenderKeyMessage` body of a
    /// `groupChat = 0x06` inner envelope — caller prepends the 16-byte
    /// `groupId` and wraps the result in N pairwise sealed-sender
    /// envelopes for fan-out.
    public func groupEncrypt(distributionId: UUID, plaintext: Data) throws -> Data {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        var distBytes = distributionId.distributionIdBytes
        let initial = max(plaintext.count + 256, 1024)
        return try readBlob(initialCap: initial) { handle, buf, cap, len in
            distBytes.withUnsafeBufferPointer { distPtr in
                plaintext.withUnsafeBytes { ptPtr -> Int32 in
                    pizzini_store_group_encrypt(
                        handle,
                        distPtr.baseAddress,
                        ptPtr.bindMemory(to: UInt8.self).baseAddress,
                        UInt(plaintext.count),
                        buf, cap, len,
                    )
                }
            }
        }
    }

    /// Decrypt a `SenderKeyMessage` from `senderIdentity`. The
    /// distribution_id is encoded in the ciphertext header and looked
    /// up against the SKDM previously processed via
    /// `senderKeyDistributionProcess(senderIdentity:skdm:)`. Throws
    /// `internalError` if the chain isn't installed (the host should
    /// trigger an SKDM exchange) or the signature fails.
    public func groupDecrypt(senderIdentity: Data, ciphertext: Data) throws -> Data {
        guard let handle else { throw CryptoCoreError.invalidArgument }
        let initial = max(ciphertext.count + 256, 1024)
        return try readBlob(initialCap: initial) { handle, buf, cap, len in
            senderIdentity.withUnsafeBytes { senderPtr -> Int32 in
                ciphertext.withUnsafeBytes { ctPtr -> Int32 in
                    pizzini_store_group_decrypt(
                        handle,
                        senderPtr.bindMemory(to: UInt8.self).baseAddress,
                        UInt(senderIdentity.count),
                        ctPtr.bindMemory(to: UInt8.self).baseAddress,
                        UInt(ciphertext.count),
                        buf, cap, len,
                    )
                }
            }
        }
    }

    private func mapRC(_ rc: Int32) throws {
        switch rc {
        case PIZZINI_OK: return
        case PIZZINI_ERR_INVALID_ARG: throw CryptoCoreError.invalidArgument
        case PIZZINI_ERR_BUFFER_TOO_SMALL: throw CryptoCoreError.bufferTooSmall(required: 0)
        case PIZZINI_ERR_INTERNAL: throw CryptoCoreError.internalError
        default: throw CryptoCoreError.unknown(code: rc)
        }
    }
}

private extension UUID {
    /// 16 raw bytes in libsignal's expected order (the `Uuid::from_bytes`
    /// input). Foundation's `UUID.uuid` gives us a `uuid_t` tuple in
    /// the same order, so this is a direct copy.
    var distributionIdBytes: [UInt8] {
        let u = self.uuid
        return [
            u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7,
            u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15,
        ]
    }

    init(distributionIdBytes b: [UInt8]) {
        precondition(b.count == 16)
        self.init(uuid: (
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        ))
    }
}

/// BLAKE3-256 hash. Re-exposed across the FFI bridge because CryptoKit
/// doesn't ship BLAKE3 — and the relay's hashcash verifier hashes the
/// same way, so the iOS challenge derivation MUST match bit-for-bit.
public enum Blake3 {
    public static func hash(_ input: Data) -> Data {
        var out = [UInt8](repeating: 0, count: 32)
        let rc = input.withUnsafeBytes { ptr -> Int32 in
            out.withUnsafeMutableBufferPointer { o in
                pizzini_blake3_hash(
                    ptr.bindMemory(to: UInt8.self).baseAddress,
                    UInt(input.count),
                    o.baseAddress
                )
            }
        }
        precondition(rc == PIZZINI_OK, "pizzini_blake3_hash never fails with valid args")
        return Data(out)
    }
}

/// Symmetric, human-comparable "safety number" derived from two
/// IdentityKey publics. Both peers see the same 60-digit code when
/// no MITM is in their session; substitution of either identity by
/// a network attacker changes the digits.
///
/// Compared out of band (voice call, in person) once after pairing to
/// promote a contact from `addedVia` (medium/low trust) to verified.
/// Derivation lives in the Rust core — see `pizzini_safety_number_derive`
/// for the exact domain-separated BLAKE3 input — so the iOS host
/// cannot disagree with itself across builds, and a future Rust-side
/// change to the SAS format requires a domain-tag bump.
public enum SafetyNumber {
    /// Length of one IdentityKey public in bytes (DJB prefix + 32-byte
    /// point). The derivation FFI rejects any other size, so we
    /// mirror the constant Swift-side to catch caller mistakes
    /// (truncated peer ids, raw 32-byte points) at the call site.
    public static let identityLength = 33
    /// Number of decimal digits in a rendered safety number, before
    /// any formatting / grouping is applied.
    public static let digitCount = 60
    /// Display layout: twelve groups of five digits, single-space
    /// separated. Matches the screen reader rhythm of "five-five-five".
    public static let groupSize = 5

    /// Derives the 60-digit safety number for the pair
    /// `(localIdentity, peerIdentity)`. Order is normalised in the
    /// core; either argument order produces identical output. The
    /// returned string is the grouped display form
    /// (`"XXXXX XXXXX … XXXXX"`, 12 groups of 5).
    public static func derive(localIdentity: Data, peerIdentity: Data) -> String {
        precondition(
            localIdentity.count == identityLength && peerIdentity.count == identityLength,
            "safety number requires 33-byte serialized IdentityKey publics on both sides"
        )
        var out = [UInt8](repeating: 0, count: digitCount)
        let rc: Int32 = localIdentity.withUnsafeBytes { aRaw in
            peerIdentity.withUnsafeBytes { bRaw in
                out.withUnsafeMutableBufferPointer { o in
                    pizzini_safety_number_derive(
                        aRaw.bindMemory(to: UInt8.self).baseAddress,
                        UInt(localIdentity.count),
                        bRaw.bindMemory(to: UInt8.self).baseAddress,
                        UInt(peerIdentity.count),
                        o.baseAddress,
                        UInt(o.count)
                    )
                }
            }
        }
        precondition(
            rc == PIZZINI_OK,
            "pizzini_safety_number_derive never fails when args meet the precondition above"
        )
        let digits = String(decoding: Data(out), as: UTF8.self)
        var formatted = ""
        formatted.reserveCapacity(digitCount + (digitCount / groupSize) - 1)
        var idx = digits.startIndex
        var first = true
        while idx < digits.endIndex {
            if !first { formatted.append(" ") }
            first = false
            let end = digits.index(idx, offsetBy: groupSize)
            formatted.append(contentsOf: digits[idx..<end])
            idx = end
        }
        return formatted
    }
}

/// BLAKE3 hashcash prover — used for first-contact BUNDLE_REQUEST anti-DoS.
///
/// The relay's challenge layout is
/// `BLAKE3(recipient_peer_id || floor(unix_time / 3600))`. Caller derives
/// that, hands it to `compute`, gets a u64 nonce that satisfies the
/// `defaultBits` difficulty target. Cost ~16s on a modern phone at 22
/// bits.
///
/// **MUST stay in sync with the relay's `HASHCASH_BITS` constant in
/// `relay/src/main.rs` and the Rust crate's `HASHCASH_DEFAULT_BITS` in
/// `crypto-core/src/hashcash.rs`.** A drift here (e.g. iOS at 18 while
/// the relay enforces 22, the F-NEW-209 bump) causes every iOS
/// BUNDLE_REQUEST to be rejected by the relay with `invalid hashcash`
/// and no peer can ever complete the PreKey handshake. The pairing UI
/// stalls indefinitely on "Waiting for handshake".
public enum Hashcash {
    public static let defaultBits: UInt32 = 22

    public static func compute(challenge: Data, bits: UInt32 = defaultBits) -> UInt64 {
        var nonce: UInt64 = 0
        let rc = challenge.withUnsafeBytes { ptr -> Int32 in
            pizzini_hashcash_compute(
                ptr.bindMemory(to: UInt8.self).baseAddress,
                UInt(challenge.count),
                bits,
                &nonce
            )
        }
        precondition(rc == PIZZINI_OK, "hashcash_compute should never fail with valid args")
        return nonce
    }
}

/// Argon2id KDF — used by the SQLCipher storage layer to stretch a
/// Secure-Enclave-unwrapped seed into the database key. Implemented
/// in `crypto-core/src/lib.rs` (Rust, RustCrypto's `argon2` crate)
/// and exposed across the FFI rather than re-implemented Swift-side:
/// CryptoKit doesn't ship Argon2 and the only pure-Swift options
/// (CryptoSwift) are an order of magnitude slower than RustCrypto.
public enum Argon2id {
    /// Parameter set passed to Argon2id. Stored alongside the database
    /// so we can bump the cost on newer hardware without breaking
    /// existing installs (the meta row persists what the current
    /// database was keyed with; a future migration can re-derive
    /// under stronger params and re-key with `PRAGMA rekey`).
    public struct Params: Sendable, Equatable {
        /// Memory cost in KiB.
        public let memoryKiB: UInt32
        /// Time / iteration cost.
        public let timeIterations: UInt32
        /// Degree of parallelism.
        public let parallelism: UInt32

        public init(memoryKiB: UInt32, timeIterations: UInt32, parallelism: UInt32) {
            self.memoryKiB = memoryKiB
            self.timeIterations = timeIterations
            self.parallelism = parallelism
        }

        /// Production parameters — OWASP 2025 mobile-app
        /// recommendation. ~250 ms on iPhone 12 / ~80 ms on iPhone
        /// 15 Pro. Paid once per cold launch when the database
        /// opens.
        public static let production = Params(
            memoryKiB: 64 * 1024,
            timeIterations: 3,
            parallelism: 1,
        )
    }

    /// Derive `outputLength` bytes from `passphrase` + `salt` under
    /// `params`. Throws on FFI errors (bad parameters, salt too short,
    /// etc). The successful path is the common case and writes a
    /// fresh deterministic key.
    public static func derive(
        passphrase: Data,
        salt: Data,
        params: Params,
        outputLength: Int = 32,
    ) throws -> Data {
        var out = [UInt8](repeating: 0, count: outputLength)
        let rc: Int32 = salt.withUnsafeBytes { saltPtr in
            passphrase.withUnsafeBytes { passPtr in
                out.withUnsafeMutableBufferPointer { outBuf in
                    pizzini_argon2id_derive(
                        saltPtr.bindMemory(to: UInt8.self).baseAddress,
                        UInt(salt.count),
                        passPtr.bindMemory(to: UInt8.self).baseAddress,
                        UInt(passphrase.count),
                        params.memoryKiB,
                        params.timeIterations,
                        params.parallelism,
                        outBuf.baseAddress,
                        UInt(outputLength),
                    )
                }
            }
        }
        switch rc {
        case PIZZINI_OK:
            return Data(out)
        case PIZZINI_ERR_INVALID_ARG:
            throw CryptoCoreError.invalidArgument
        case PIZZINI_ERR_INTERNAL:
            throw CryptoCoreError.internalError
        default:
            throw CryptoCoreError.unknown(code: rc)
        }
    }
}

public enum CryptoCoreError: Error, Sendable {
    case invalidArgument
    case bufferTooSmall(required: Int)
    case internalError
    case unknown(code: Int32)
}
