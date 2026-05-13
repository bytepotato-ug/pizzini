import CryptoKit
import Foundation
import Testing
@testable import pizzini

/// Stage-0 coverage for the v2 hash-chained delivery-token primitive.
/// The relay-side validator + wire format land in later stages — this
/// file pins the cryptographic invariants the rest of the migration
/// will ride on.
@Suite("HashChainToken primitive")
struct HashChainTokenTests {
    // MARK: - Mint / shape

    @Test("minted chain has correct shapes")
    func mintShape() {
        let chain = HashChainToken.mintChain(length: 256)
        #expect(chain.chainID.count == HashChainToken.chainIDSize)
        #expect(chain.seed.count == HashChainToken.hashSize)
        #expect(chain.root.count == HashChainToken.hashSize)
        #expect(chain.length == 256)
        #expect(chain.nextIndex == 1)
        #expect(!chain.isExhausted)
        #expect(!chain.shouldRotate)
    }

    @Test("root equals SHA-256 iterated `length` times over the seed")
    func rootMatchesIteratedHash() {
        let chain = HashChainToken.mintChain(length: 128)
        let recomputed = HashChainToken.applyHash(chain.seed, times: chain.length)
        #expect(recomputed == chain.root)
    }

    @Test("two fresh chains are independent")
    func mintEntropy() {
        let a = HashChainToken.mintChain(length: 64)
        let b = HashChainToken.mintChain(length: 64)
        #expect(a.chainID != b.chainID)
        #expect(a.seed != b.seed)
        #expect(a.root != b.root)
    }

    // MARK: - Cold-path verify

    @Test("first token verifies against root")
    func firstTokenVerifies() {
        var chain = HashChainToken.mintChain(length: 64)
        let t = HashChainToken.nextToken(in: &chain)
        #expect(t != nil)
        if let t {
            #expect(HashChainToken.verify(t, againstRoot: chain.root, length: chain.length))
        }
    }

    @Test("token index is monotonically incremented across reveals")
    func tokensAdvanceIndex() {
        var chain = HashChainToken.mintChain(length: 8)
        let tokens = (0..<8).compactMap { _ in HashChainToken.nextToken(in: &chain) }
        #expect(tokens.count == 8)
        #expect(tokens.map(\.index) == Array(1...8))
        for t in tokens {
            #expect(HashChainToken.verify(t, againstRoot: chain.root, length: chain.length))
        }
    }

    @Test("each subsequent token hashes to the previous one")
    func chainAlgebra() {
        var chain = HashChainToken.mintChain(length: 16)
        var prior: Data?
        for _ in 0..<5 {
            guard let token = HashChainToken.nextToken(in: &chain) else {
                Issue.record("unexpected exhaustion")
                return
            }
            if let prior {
                let next = Data(SHA256.hash(data: token.value))
                #expect(next == prior, "H(token[i+1]) must equal token[i]")
            }
            prior = token.value
        }
    }

    @Test("verify rejects an index outside [1, length]")
    func verifyRejectsBadIndex() {
        let chain = HashChainToken.mintChain(length: 32)
        let dummy = HashChainToken.Token(
            chainID: chain.chainID,
            index: 0,
            value: Data(repeating: 0xAB, count: HashChainToken.hashSize),
        )
        #expect(!HashChainToken.verify(dummy, againstRoot: chain.root, length: chain.length))
        let oversize = HashChainToken.Token(
            chainID: chain.chainID,
            index: chain.length + 1,
            value: Data(repeating: 0xCD, count: HashChainToken.hashSize),
        )
        #expect(!HashChainToken.verify(oversize, againstRoot: chain.root, length: chain.length))
    }

    @Test("verify rejects a tampered value")
    func verifyRejectsTamperedValue() {
        var chain = HashChainToken.mintChain(length: 32)
        guard let real = HashChainToken.nextToken(in: &chain) else {
            Issue.record("unexpected exhaustion")
            return
        }
        var bytes = real.value
        bytes[0] ^= 0x01
        let tampered = HashChainToken.Token(
            chainID: real.chainID,
            index: real.index,
            value: bytes,
        )
        #expect(!HashChainToken.verify(tampered, againstRoot: chain.root, length: chain.length))
    }

    @Test("verify rejects wrong-length token value")
    func verifyRejectsShortValue() {
        let chain = HashChainToken.mintChain(length: 8)
        let bad = HashChainToken.Token(
            chainID: chain.chainID,
            index: 1,
            value: Data(repeating: 0x00, count: HashChainToken.hashSize - 1),
        )
        #expect(!HashChainToken.verify(bad, againstRoot: chain.root, length: chain.length))
    }

    // MARK: - Exhaustion / rotation

    @Test("nextToken returns nil once the chain is fully spent")
    func chainExhausts() {
        var chain = HashChainToken.mintChain(length: 4)
        for _ in 0..<4 { _ = HashChainToken.nextToken(in: &chain) }
        #expect(chain.isExhausted)
        #expect(HashChainToken.nextToken(in: &chain) == nil)
    }

    @Test("shouldRotate flips at the 80% high-water mark")
    func rotationHysteresis() {
        var chain = HashChainToken.mintChain(length: 100)
        // length * 4 / 5 = 80. Until nextIndex > 80, no rotation.
        for _ in 0..<80 { _ = HashChainToken.nextToken(in: &chain) }
        #expect(!chain.shouldRotate)
        _ = HashChainToken.nextToken(in: &chain)
        #expect(chain.shouldRotate)
    }

    // MARK: - Replay-protected validator (relay-side simulation)

    @Test("validator accepts every token of an in-order presentation")
    func validatorAcceptsInOrder() {
        var chain = HashChainToken.mintChain(length: 12)
        var v = HashChainToken.Validator(
            chainID: chain.chainID,
            root: chain.root,
            length: chain.length,
        )
        for _ in 0..<12 {
            guard let token = HashChainToken.nextToken(in: &chain) else {
                Issue.record("unexpected exhaustion mid-test")
                return
            }
            #expect(HashChainToken.validate(token, against: &v))
        }
        #expect(v.lastIndex == 12)
    }

    @Test("validator rejects a replayed token")
    func validatorRejectsReplay() {
        var chain = HashChainToken.mintChain(length: 8)
        var v = HashChainToken.Validator(
            chainID: chain.chainID,
            root: chain.root,
            length: chain.length,
        )
        guard let t = HashChainToken.nextToken(in: &chain) else { return }
        #expect(HashChainToken.validate(t, against: &v))
        #expect(!HashChainToken.validate(t, against: &v))
        #expect(v.lastIndex == 1, "state must not advance on replay")
    }

    @Test("validator rejects out-of-order (lower-index) presentation")
    func validatorRejectsOutOfOrder() {
        var chain = HashChainToken.mintChain(length: 8)
        var v = HashChainToken.Validator(
            chainID: chain.chainID,
            root: chain.root,
            length: chain.length,
        )
        let t1 = HashChainToken.nextToken(in: &chain)!
        let t2 = HashChainToken.nextToken(in: &chain)!
        #expect(HashChainToken.validate(t2, against: &v))
        #expect(!HashChainToken.validate(t1, against: &v))
    }

    @Test("validator tolerates a gap and still verifies via the chain")
    func validatorAcceptsGap() {
        // A real network can drop or re-order a SEND. The relay only
        // logs the highest valid index it has seen; a later token from
        // the same chain must still verify against `lastValue` via the
        // (index − lastIndex) hash iterations. This guards the path
        // where one of the chunks of a multi-chunk attachment lands
        // before an earlier chunk.
        var chain = HashChainToken.mintChain(length: 16)
        var v = HashChainToken.Validator(
            chainID: chain.chainID,
            root: chain.root,
            length: chain.length,
        )
        _ = HashChainToken.nextToken(in: &chain)
        _ = HashChainToken.nextToken(in: &chain)
        let t3 = HashChainToken.nextToken(in: &chain)!
        _ = HashChainToken.nextToken(in: &chain)
        let t5 = HashChainToken.nextToken(in: &chain)!
        #expect(HashChainToken.validate(t3, against: &v))
        #expect(HashChainToken.validate(t5, against: &v))
        #expect(v.lastIndex == 5)
    }

    // MARK: - Wire format

    @Test("wire encode/decode round-trips a token")
    func wireRoundTrip() {
        var chain = HashChainToken.mintChain(length: 16)
        let original = HashChainToken.nextToken(in: &chain)!
        let wire = HashChainToken.encode(original)
        #expect(wire.count == HashChainToken.wireSize)
        guard let decoded = HashChainToken.decode(wire) else {
            Issue.record("decode returned nil for a freshly-encoded token")
            return
        }
        #expect(decoded == original)
    }

    @Test("wire size matches the v2 spec: 52 bytes")
    func wireSizeIs52() {
        #expect(HashChainToken.wireSize == 52)
    }

    @Test("decode rejects v1-shaped (84 B) tokens")
    func decodeRejectsV1Length() {
        // 84 = 16 nonce + 4 expiry + 64 sig — the relay's v1 token
        // shape. A v1 blob arriving at a v2 decoder must return nil
        // so the caller falls back to v1 parsing.
        let v1Shape = Data(repeating: 0xAA, count: 84)
        #expect(HashChainToken.decode(v1Shape) == nil)
    }

    @Test("decode rejects empty + arbitrary lengths")
    func decodeRejectsBadLengths() {
        #expect(HashChainToken.decode(Data()) == nil)
        #expect(HashChainToken.decode(Data(repeating: 0, count: 51)) == nil)
        #expect(HashChainToken.decode(Data(repeating: 0, count: 53)) == nil)
    }

    @Test("wire encoding preserves big-endian index")
    func wireIndexIsBigEndian() {
        // Index 0x01020304 should encode as bytes 01 02 03 04 at
        // offset chainIDSize. Tests the BE invariant the relay-side
        // Rust parser will rely on.
        let token = HashChainToken.Token(
            chainID: Data(repeating: 0x11, count: HashChainToken.chainIDSize),
            index: 0x01020304,
            value: Data(repeating: 0x22, count: HashChainToken.hashSize),
        )
        let wire = HashChainToken.encode(token)
        let idx = HashChainToken.chainIDSize
        #expect(wire[idx] == 0x01)
        #expect(wire[idx + 1] == 0x02)
        #expect(wire[idx + 2] == 0x03)
        #expect(wire[idx + 3] == 0x04)
    }

    // MARK: - Chain wire codec (persistence + seed delivery)

    @Test("chain binary codec round-trips a fresh chain")
    func chainCodecRoundTripFresh() {
        let original = HashChainToken.mintChain(length: 1024)
        let wire = HashChainToken.encodeChain(original)
        #expect(wire.count == HashChainToken.chainWireSize)
        let back = HashChainToken.decodeChain(wire)
        #expect(back == original)
    }

    @Test("chain binary codec preserves advanced nextIndex")
    func chainCodecRoundTripAdvanced() {
        var chain = HashChainToken.mintChain(length: 64)
        for _ in 0..<7 { _ = HashChainToken.nextToken(in: &chain) }
        let wire = HashChainToken.encodeChain(chain)
        let back = HashChainToken.decodeChain(wire)
        #expect(back == chain)
        #expect(back?.nextIndex == 8)
    }

    @Test("decodeChain rejects truncated or oversize blobs")
    func chainCodecRejectsBadSize() {
        let chain = HashChainToken.mintChain(length: 8)
        let valid = HashChainToken.encodeChain(chain)
        #expect(HashChainToken.decodeChain(valid.dropLast()) == nil)
        #expect(HashChainToken.decodeChain(valid + Data([0xFF])) == nil)
        #expect(HashChainToken.decodeChain(Data()) == nil)
    }

    @Test("decodeSeedDelivery rejects a mid-chain (nextIndex > 1) payload")
    func seedDeliveryRejectsAdvancedChain() {
        var chain = HashChainToken.mintChain(length: 32)
        _ = HashChainToken.nextToken(in: &chain)
        let wire = HashChainToken.encodeSeedDelivery(chain)
        // The codec emits same wire, but the seed-delivery decoder
        // refuses anything other than a fresh `nextIndex == 1` chain.
        #expect(HashChainToken.decodeSeedDelivery(wire) == nil)
    }

    @Test("cutover flag is shippable in either state (no dual-path guard fails)")
    func cutoverFlagIsShippable() {
        // We allow the flag to be either true or false at compile
        // time — the production rollout flips it from false to true
        // in a dedicated commit after the relay-side validator is
        // deployed. The test simply pins that the constant exists
        // and is reachable so a future refactor that renames it
        // breaks visibly here rather than silently disabling v2.
        let _ = HashChainToken.cutoverEnabled
    }

    @Test("decodeSeedDelivery accepts a fresh chain")
    func seedDeliveryAcceptsFreshChain() {
        let chain = HashChainToken.mintChain(length: 32)
        let wire = HashChainToken.encodeSeedDelivery(chain)
        #expect(HashChainToken.decodeSeedDelivery(wire) == chain)
    }

    @Test("validator rejects a token from a different chain ID")
    func validatorRejectsWrongChain() {
        var chainA = HashChainToken.mintChain(length: 8)
        let chainB = HashChainToken.mintChain(length: 8)
        var v = HashChainToken.Validator(
            chainID: chainA.chainID,
            root: chainA.root,
            length: chainA.length,
        )
        let mixed = HashChainToken.Token(
            chainID: chainB.chainID,
            index: 1,
            value: HashChainToken.nextToken(in: &chainA)!.value,
        )
        #expect(!HashChainToken.validate(mixed, against: &v))
    }
}
