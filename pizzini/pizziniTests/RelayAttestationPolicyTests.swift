import Testing
@testable import pizzini

@Suite("Relay attestation outbound policy")
struct RelayAttestationPolicyTests {
    @Test("bundled relay mismatch blocks outbound traffic")
    func bundledMismatchBlocksOutbound() {
        #expect(!ChatStore.shouldUseRelayForOutbound(
            isBundledRelay: true,
            verdict: .mismatch,
        ))
    }

    @Test("unverifiable bundled relay remains warn-only")
    func bundledUnverifiableRemainsUsable() {
        #expect(ChatStore.shouldUseRelayForOutbound(
            isBundledRelay: true,
            verdict: .unverifiable,
        ))
    }

    @Test("custom relay mismatch remains warn-only")
    func customMismatchRemainsUsable() {
        #expect(ChatStore.shouldUseRelayForOutbound(
            isBundledRelay: false,
            verdict: .mismatch,
        ))
    }

    // F-TL-01: a bundled relay that never answers STATUS_REQUEST keeps the
    // default `.notEvaluated` verdict; it must NOT be usable for outbound, or
    // a tampered relay could dodge the attestation gate just by staying
    // silent. STATUS_REQUEST is sent on connect, so a well-behaved relay
    // leaves `.notEvaluated` within ~1 RTT.
    @Test("bundled relay not-yet-evaluated is blocked from outbound")
    func bundledNotEvaluatedBlocksOutbound() {
        #expect(!ChatStore.shouldUseRelayForOutbound(
            isBundledRelay: true,
            verdict: .notEvaluated,
        ))
    }

    // A user's own custom relay is not subject to the bundled-fleet gate, so
    // its attestation state never blocks their own traffic.
    @Test("custom relay not-yet-evaluated remains usable")
    func customNotEvaluatedRemainsUsable() {
        #expect(ChatStore.shouldUseRelayForOutbound(
            isBundledRelay: false,
            verdict: .notEvaluated,
        ))
    }

    @Test("bundled relay verified is usable")
    func bundledVerifiedIsUsable() {
        #expect(ChatStore.shouldUseRelayForOutbound(
            isBundledRelay: true,
            verdict: .verified,
        ))
    }
}
