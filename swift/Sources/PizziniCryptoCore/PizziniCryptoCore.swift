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
    public struct SealedReceived: Sendable {
        public let peer: Data
        public let messageId: Data
        public let plaintext: Data
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
        var rc = sealed.withUnsafeBytes { sealedPtr -> Int32 in
            sender.withUnsafeMutableBufferPointer { sPtr in
                msgId.withUnsafeMutableBufferPointer { mPtr in
                    plaintext.withUnsafeMutableBufferPointer { pPtr in
                        pizzini_store_seal_receive(
                            handle,
                            sealedPtr.bindMemory(to: UInt8.self).baseAddress, UInt(sealed.count),
                            sPtr.baseAddress, UInt(sPtr.count), &senderLen,
                            mPtr.baseAddress,
                            pPtr.baseAddress, UInt(pPtr.count), &plaintextLen
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
                                pPtr.baseAddress, UInt(pPtr.count), &plaintextLen
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
            plaintext: Data(plaintext.prefix(Int(plaintextLen)))
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

public enum CryptoCoreError: Error, Sendable {
    case invalidArgument
    case bufferTooSmall(required: Int)
    case internalError
    case unknown(code: Int32)
}
