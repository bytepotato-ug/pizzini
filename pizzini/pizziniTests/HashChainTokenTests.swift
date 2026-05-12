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
