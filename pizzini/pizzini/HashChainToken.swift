import CryptoKit
import Foundation

/// Hash-chained delivery tokens (v2). Replaces the per-message
/// Ed25519-signed token model.
///
/// **Why this exists.** Today every SEND carries one signed token from
/// a finite stash. The stash drains, the refill request itself spends
/// a token, and a user who runs out has no recovery short of a fresh
/// `BUNDLE_REQUEST`. Hash chains collapse "the stash" into a single
/// 32-byte seed: the sender derives token N from the seed in
/// constant-on-disk space, the relay validates each in O(Δi) hashes
/// against the last one it saw, and the chain only needs rotating
/// after its `length` is exhausted (months at typical chat volume).
///
/// **Construction.** Recipient picks a random seed `s`. Computes the
/// forward chain `s_0 = s`, `s_1 = H(s_0)`, …, `s_n = H(s_{n-1})`.
/// `s_n` is the chain *root*, registered with the relay (and bound to
/// recipient's peer_id). Recipient ships `(chainId, seed, length)`
/// to the sender via the sealed-sender channel.
///
/// **Token reveal order is reversed.** Token at sender-side index `i`
/// (1-indexed) is the chain value at position `n − i`. So `token[1] =
/// s_{n−1}`, `token[2] = s_{n−2}`, …, `token[n] = s_0 = seed`. The key
/// algebraic property: `H(token[i+1]) == token[i]`. The relay holds
/// `(root, lastIndex, lastToken)`. To validate a presented
/// `(index, token)`: apply `H` `(index − lastIndex)` times to `token`
/// and check it equals `lastToken`. On success, advance the state.
///
/// **Privacy.** The relay only knows `(recipient, chainId)` →
/// `(root, lastIndex, lastToken)`. Sender identity is never bound to
/// the chain on the relay side; sealed-sender survives. The recipient
/// MAY hold multiple chains (one per sender) and the relay tries each
/// of recipient's chains in turn — N=50 contacts × 1 chain each = 50
/// SHA-256 ops per validation, well under a millisecond.
enum HashChainToken {
    /// Master cutover flag. Currently ON: the v2 hash-chained token
    /// model is the single path on the sender side, in lockstep with
    /// the relay's `chain_validator_store` which accepts v2 SENDs as
    /// of the stage-3b/2 commit. The v1 Ed25519-signed-token code is
    /// retained behind the `else` branches one release for paranoia /
    /// rollback (set this to `false` to revert without deploying a
    /// new build); a follow-up commit will excise it once v2 has
    /// soaked in production.
    ///
    /// Operational requirement before this flip reaches users: the
    /// updated relay binary (including `FRAME_TYPE_REGISTER_CHAIN`,
    /// `chain_validator_store`, and the 52-byte v2 dispatch in
    /// `check_delivery_token`) must be deployed on EVERY seed in
    /// `chainparams` before this build is published. See
    /// `docs/delivery-token-v2-rollout.md`.
    static let cutoverEnabled = true

    static let hashSize = 32
    static let chainIDSize = 16
    /// Default chain length. 2^14 tokens at one-per-message ≈ 5 months
    /// of usage at 100 messages/day. Rotation kicks in well before
    /// exhaustion (see `Chain.shouldRotate`). Tuned for a balance
    /// between rotation cadence and the upfront cost the sender pays
    /// to derive late tokens: token `i` requires `length − i` hashes
    /// to derive from the seed, which at 2^14 = ~0.3 ms worst-case on
    /// a modern phone.
    static let defaultLength = 16384

    /// Sender-side chain state. Holds the seed + the next index to
    /// reveal; persisted per (sender peer_id, recipient peer_id).
    /// `Codable` so the chain rides through SQLCipher with the
    /// existing per-contact persistence path.
    struct Chain: Codable, Sendable, Equatable {
        let chainID: Data
        let seed: Data
        let length: Int
        let root: Data
        /// 1-indexed next-token cursor. Starts at 1 (token[0] is
        /// reserved — the relay never validates index 0).
        var nextIndex: Int

        /// Heuristic: rotate when more than 80% of the chain has been
        /// minted. `nextIndex - 1` is the count of tokens revealed so
        /// far; comparing it to `length * 4 / 5` is "I've used more
        /// than 80%." Gives the recipient a comfortable window to
        /// ship a fresh seed over the sealed channel before the
        /// current chain runs dry.
        var shouldRotate: Bool { (nextIndex - 1) > (length * 4) / 5 }

        /// True once the chain has been fully spent. Further calls to
        /// `nextToken` return nil.
        var isExhausted: Bool { nextIndex > length }
    }

    /// Fixed-size binary encoding of a `Chain` for SQLCipher
    /// persistence and for the `chainSeedDelivery` sealed-envelope
    /// payload. Layout: `chainID(16) ‖ seed(32) ‖ root(32) ‖ length(4 BE)
    /// ‖ nextIndex(4 BE)` = 88 bytes. Stable across Swift / Rust ports.
    static let chainWireSize = chainIDSize + hashSize + hashSize + 4 + 4

    static func encodeChain(_ chain: Chain) -> Data {
        precondition(chain.chainID.count == chainIDSize, "chain id must be \(chainIDSize) bytes")
        precondition(chain.seed.count == hashSize, "chain seed must be \(hashSize) bytes")
        precondition(chain.root.count == hashSize, "chain root must be \(hashSize) bytes")
        var out = Data(capacity: chainWireSize)
        out.append(chain.chainID)
        out.append(chain.seed)
        out.append(chain.root)
        var lengthBE = UInt32(chain.length).bigEndian
        withUnsafeBytes(of: &lengthBE) { out.append(contentsOf: $0) }
        var nextBE = UInt32(chain.nextIndex).bigEndian
        withUnsafeBytes(of: &nextBE) { out.append(contentsOf: $0) }
        return out
    }

    static func decodeChain(_ wire: Data) -> Chain? {
        guard wire.count == chainWireSize else { return nil }
        var cursor = wire.startIndex
        let chainID = wire.subdata(in: cursor ..< cursor + chainIDSize)
        cursor += chainIDSize
        let seed = wire.subdata(in: cursor ..< cursor + hashSize)
        cursor += hashSize
        let root = wire.subdata(in: cursor ..< cursor + hashSize)
        cursor += hashSize
        let lengthBytes = wire.subdata(in: cursor ..< cursor + 4)
        cursor += 4
        let nextBytes = wire.subdata(in: cursor ..< cursor + 4)
        let length = Int(lengthBytes.withUnsafeBytes { ptr -> UInt32 in
            ptr.loadUnaligned(as: UInt32.self).bigEndian
        })
        let nextIndex = Int(nextBytes.withUnsafeBytes { ptr -> UInt32 in
            ptr.loadUnaligned(as: UInt32.self).bigEndian
        })
        // Sanity guards: length must be positive; nextIndex must be in
        // [1, length+1]; binary garbage from disk shouldn't blow up
        // the chat list. Root is intentionally NOT re-verified here
        // (would cost `length` hashes per load); the relay-side
        // validator is the trust boundary for chain integrity.
        guard length > 0, nextIndex >= 1, nextIndex <= length + 1 else { return nil }
        return Chain(
            chainID: chainID,
            seed: seed,
            length: length,
            root: root,
            nextIndex: nextIndex,
        )
    }

    /// Sealed-envelope body for `InnerEnvelopeKind.chainSeedDelivery`.
    /// Carries one freshly-minted chain from the recipient (who owns
    /// the chain root, registered with the relay) to the sender (who
    /// uses it to derive tokens for messages to the recipient).
    /// Identical wire shape as `encodeChain`, so it ships and parses
    /// through the same 88-byte codec.
    static func encodeSeedDelivery(_ chain: Chain) -> Data {
        encodeChain(chain)
    }

    static func decodeSeedDelivery(_ wire: Data) -> Chain? {
        guard let chain = decodeChain(wire) else { return nil }
        // A fresh seed-delivery payload MUST present an unused chain.
        // A peer that ships `nextIndex > 1` is either confused or
        // hostile — refuse rather than silently start mid-chain.
        guard chain.nextIndex == 1 else { return nil }
        return chain
    }

    /// One on-wire token presentation: chain identifier + cursor +
    /// the 32-byte chain value. The recipient (and ultimately the
    /// relay) validate this against the chain's stored state.
    struct Token: Sendable, Equatable, Hashable {
        let chainID: Data
        let index: Int
        let value: Data
    }

    /// Exact wire size of an encoded v2 token: 16 (chainID) + 4
    /// (index, big-endian u32) + 32 (value) = 52 bytes. The relay
    /// distinguishes v1 (84 B) from v2 (52 B) purely by `token` field
    /// length on the SEND frame — no version byte, no protocol break.
    static let wireSize = chainIDSize + 4 + hashSize

    /// Encode a token for the SEND frame's `token` blob.
    /// Layout: `chainID(16) ‖ index(4 BE) ‖ value(32)`.
    static func encode(_ token: Token) -> Data {
        precondition(token.chainID.count == chainIDSize, "chain id must be \(chainIDSize) bytes")
        precondition(token.value.count == hashSize, "token value must be \(hashSize) bytes")
        precondition(token.index >= 0, "token index must be non-negative")
        var out = Data(capacity: wireSize)
        out.append(token.chainID)
        var indexBE = UInt32(token.index).bigEndian
        withUnsafeBytes(of: &indexBE) { out.append(contentsOf: $0) }
        out.append(token.value)
        return out
    }

    /// Decode a 52-byte SEND-frame token blob back into the struct.
    /// Returns nil on any size or shape mismatch — the caller falls
    /// back to v1-token parsing.
    static func decode(_ wire: Data) -> Token? {
        guard wire.count == wireSize else { return nil }
        let chainID = wire.subdata(in: wire.startIndex ..< wire.startIndex + chainIDSize)
        let indexStart = wire.startIndex + chainIDSize
        let indexBytes = wire.subdata(in: indexStart ..< indexStart + 4)
        let valueStart = indexStart + 4
        let value = wire.subdata(in: valueStart ..< valueStart + hashSize)
        let index = indexBytes.withUnsafeBytes { ptr -> UInt32 in
            ptr.loadUnaligned(as: UInt32.self).bigEndian
        }
        return Token(chainID: chainID, index: Int(index), value: value)
    }

    /// Recipient-side primitive: mint a fresh chain. The seed is 32
    /// random bytes from `SecRandomCopyBytes`; the chain root is the
    /// `length`-fold SHA-256 of the seed. The recipient registers
    /// `root` with the relay and ships `(chainID, seed, length)` to
    /// the sender.
    static func mintChain(length: Int = defaultLength) -> Chain {
        precondition(length > 0, "chain length must be positive")
        var seedBytes = [UInt8](repeating: 0, count: hashSize)
        let seedRC = SecRandomCopyBytes(kSecRandomDefault, seedBytes.count, &seedBytes)
        precondition(seedRC == errSecSuccess, "SecRandom must succeed for chain seed")
        var idBytes = [UInt8](repeating: 0, count: chainIDSize)
        let idRC = SecRandomCopyBytes(kSecRandomDefault, idBytes.count, &idBytes)
        precondition(idRC == errSecSuccess, "SecRandom must succeed for chain id")
        let seed = Data(seedBytes)
        let root = applyHash(seed, times: length)
        return Chain(
            chainID: Data(idBytes),
            seed: seed,
            length: length,
            root: root,
            nextIndex: 1,
        )
    }

    /// Sender-side primitive: produce the next token in the chain and
    /// advance the cursor. Returns nil when the chain is exhausted.
    static func nextToken(in chain: inout Chain) -> Token? {
        guard !chain.isExhausted else { return nil }
        let index = chain.nextIndex
        let value = applyHash(chain.seed, times: chain.length - index)
        chain.nextIndex = index + 1
        return Token(chainID: chain.chainID, index: index, value: value)
    }

    /// Stateless cold-path validator: hash the presented token forward
    /// `index` times and check it matches the registered root. Useful
    /// for first-token validation, recovery from lost relay state, and
    /// tests. The relay's hot path uses `validate(_:against:)` against
    /// the last-seen state, which is O(Δi) instead of O(index).
    ///
    /// Math: `token[i] == H^(length − i)(seed)` and `root ==
    /// H^length(seed)`, so applying `H` exactly `i` more times to the
    /// token recovers the root.
    static func verify(_ token: Token, againstRoot root: Data, length: Int) -> Bool {
        guard token.value.count == hashSize else { return false }
        guard token.index >= 1, token.index <= length else { return false }
        let derived = applyHash(token.value, times: token.index)
        return constantTimeEquals(derived, root)
    }

    /// Relay-style replay-protected state. Each `(recipient, chainID)`
    /// maps to one of these. Held in Swift for tests + to mirror what
    /// the Rust relay will hold once Stage 3 lands.
    struct Validator: Sendable {
        let chainID: Data
        let root: Data
        let length: Int
        /// Last successfully-validated index. 0 means "no tokens
        /// validated yet" and `lastValue == root`.
        var lastIndex: Int
        /// The chain value at position `length − lastIndex`. Used to
        /// validate the next presentation in O(Δi).
        var lastValue: Data

        init(chainID: Data, root: Data, length: Int) {
            self.chainID = chainID
            self.root = root
            self.length = length
            self.lastIndex = 0
            self.lastValue = root
        }
    }

    /// Replay-protected validate. Returns true and advances the
    /// validator iff the presentation is fresh and chains correctly.
    /// Replays (`index <= lastIndex`), out-of-chain values, and
    /// out-of-range indices all return false without state mutation.
    static func validate(_ token: Token, against state: inout Validator) -> Bool {
        guard token.chainID == state.chainID else { return false }
        guard token.value.count == hashSize else { return false }
        guard token.index > state.lastIndex, token.index <= state.length else {
            return false
        }
        let derived = applyHash(token.value, times: token.index - state.lastIndex)
        guard constantTimeEquals(derived, state.lastValue) else { return false }
        state.lastIndex = token.index
        state.lastValue = token.value
        return true
    }

    // MARK: - Internal helpers

    /// Apply SHA-256 `n` times. `n == 0` returns the input unchanged.
    static func applyHash(_ input: Data, times n: Int) -> Data {
        precondition(n >= 0, "hash iteration count must be non-negative")
        var current = input
        for _ in 0..<n {
            current = Data(SHA256.hash(data: current))
        }
        return current
    }

    /// Constant-time comparison for the two 32-byte hash outputs.
    /// Defends against the (low-likelihood) timing channel where a
    /// relay implementation under attacker observation reveals the
    /// number of matching prefix bytes via response latency.
    private static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count {
            diff |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return diff == 0
    }
}
