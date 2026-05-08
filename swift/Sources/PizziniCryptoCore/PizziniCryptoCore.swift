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
