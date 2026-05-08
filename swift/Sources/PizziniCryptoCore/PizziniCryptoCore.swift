// Idiomatic Swift wrapper over the Rust crypto-core C ABI.
//
// All cryptographic state lives on the Rust side; Swift only marshals bytes
// across the FFI boundary. Anything sensitive (keys, plaintext) handled here
// should be wrapped in `Data` (with explicit clearing) or returned as opaque
// handles when we add session/encrypt/decrypt later.

import Foundation
import PizziniCryptoCoreFFI

public enum PizziniCryptoCore {
    /// The native crypto-core library version, read across the FFI bridge.
    /// Useful for confirming the Swift target linked the library it expects.
    public static var version: String {
        guard let cString = pizzini_crypto_core_version() else { return "" }
        return String(cString: cString)
    }
}

/// A long-term identity keypair, in libsignal's serialized form.
/// The bytes are the only canonical representation; do not parse them in Swift.
public struct IdentityKeyPair: Sendable {
    public let bytes: Data

    /// Generate a fresh identity keypair using the OS CSPRNG.
    public static func generate() throws -> IdentityKeyPair {
        // 256 is comfortably above libsignal's serialized identity size; if
        // that ever grows we'll get PIZZINI_ERR_BUFFER_TOO_SMALL with the
        // required size in `len`, and can retry. Hardcoded for now since the
        // wire format is stable.
        // size_t in C → UInt in Swift via cbindgen's uintptr_t mapping.
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

public enum CryptoCoreError: Error, Sendable {
    case invalidArgument
    case bufferTooSmall(required: Int)
    case unknown(code: Int32)
}
