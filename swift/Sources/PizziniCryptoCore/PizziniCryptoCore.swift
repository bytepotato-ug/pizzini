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

// MARK: - Loopback session

/// In-process Alice ↔ Bob session for demoing the full PQXDH + ratchet stack.
/// Holds a Rust-allocated handle and frees it on deinit.
public final class LoopbackSession: @unchecked Sendable {
    public enum MessageType: Sendable {
        case preKey
        case whisper
    }

    public struct SendResult: Sendable {
        public let ciphertext: Data
        public let decrypted: Data
        public let messageType: MessageType
    }

    private var handle: OpaquePointer?

    public init() throws {
        guard let h = pizzini_loopback_new() else {
            throw CryptoCoreError.internalError
        }
        // cbindgen forward-declares `struct LoopbackState`, so Swift bridges
        // pointers to it as OpaquePointer directly — no cast needed.
        self.handle = h
    }

    deinit {
        if let h = handle {
            pizzini_loopback_free(h)
        }
    }

    /// Sends a message from Alice to Bob, returning the wire ciphertext and
    /// Bob's recovered plaintext.
    public func aliceSend(_ plaintext: String) throws -> SendResult {
        try send(plaintext, sender: .alice)
    }

    /// Mirror of `aliceSend` for the other direction.
    public func bobSend(_ plaintext: String) throws -> SendResult {
        try send(plaintext, sender: .bob)
    }

    private enum Sender { case alice, bob }

    private func send(_ plaintext: String, sender: Sender) throws -> SendResult {
        guard let handle = handle else { throw CryptoCoreError.invalidArgument }
        let plainBytes = Array(plaintext.utf8)

        // Caps from the FFI doc: ciphertext up to 4 KB (Kyber1024 PreKey),
        // decrypted up to plaintext + 256.
        var ciphertext = [UInt8](repeating: 0, count: 4096)
        var ctLen: UInt = 0
        var decrypted = [UInt8](repeating: 0, count: plainBytes.count + 256)
        var ptLen: UInt = 0
        var msgType: UInt32 = 0

        let rc = plainBytes.withUnsafeBufferPointer { plainPtr -> Int32 in
            ciphertext.withUnsafeMutableBufferPointer { ctPtr in
                decrypted.withUnsafeMutableBufferPointer { ptPtr in
                    switch sender {
                    case .alice:
                        return pizzini_loopback_alice_send(
                            handle,
                            plainPtr.baseAddress, UInt(plainPtr.count),
                            ctPtr.baseAddress, UInt(ctPtr.count), &ctLen,
                            ptPtr.baseAddress, UInt(ptPtr.count), &ptLen,
                            &msgType
                        )
                    case .bob:
                        return pizzini_loopback_bob_send(
                            handle,
                            plainPtr.baseAddress, UInt(plainPtr.count),
                            ctPtr.baseAddress, UInt(ctPtr.count), &ctLen,
                            ptPtr.baseAddress, UInt(ptPtr.count), &ptLen,
                            &msgType
                        )
                    }
                }
            }
        }

        switch rc {
        case PIZZINI_OK:
            let type: MessageType = (msgType == UInt32(PIZZINI_MSG_TYPE_PREKEY)) ? .preKey : .whisper
            return SendResult(
                ciphertext: Data(ciphertext.prefix(Int(ctLen))),
                decrypted: Data(decrypted.prefix(Int(ptLen))),
                messageType: type
            )
        case PIZZINI_ERR_BUFFER_TOO_SMALL:
            // ctLen or ptLen will hold the required size (whichever overflowed).
            throw CryptoCoreError.bufferTooSmall(required: Int(max(ctLen, ptLen)))
        case PIZZINI_ERR_INVALID_ARG:
            throw CryptoCoreError.invalidArgument
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
