import Foundation
import PizziniCryptoCore
import Testing
@testable import pizzini

/// Audit M1: tests that pin the two distinct cooldowns on the
/// chain-serve path — the bundle-coupled 6 h and the proactive-
/// refresh 30 min — and the inner-kind raw value for the new
/// sealed envelope. The end-to-end refresh round-trip lives in
/// the integration / sim flow; these unit tests pin the
/// invariants that would silently desync the two cooldown paths
/// or the wire enum if a future refactor touched them.
@Suite("Chain refresh cooldown (audit M1)")
struct ChainRefreshCooldownTests {

    /// The two cooldown constants must be distinct AND the refresh
    /// cooldown must be strictly shorter than the bundle-coupled
    /// one. If a future change accidentally collapsed them, the
    /// proactive-refresh path would inherit the 6 h cap and
    /// re-introduce the deadlock that the reverted commit 62dcc54
    /// caused.
    @Test("chainRefreshCooldown is strictly shorter than chainServeCooldown")
    func refreshCooldownIsShorter() {
        #expect(Contact.chainRefreshCooldown < Contact.chainServeCooldown)
        #expect(Contact.chainRefreshCooldown > 0)
        #expect(Contact.chainServeCooldown > Contact.chainRefreshCooldown)
    }

    /// The production refresh cooldown is 30 min — short enough that
    /// proactive rotation never hits the cap in normal use, tight
    /// enough to bound a flooding paired peer.
    @Test("chainRefreshCooldown is 30 minutes")
    func refreshCooldownIs30Min() {
        #expect(Contact.chainRefreshCooldown == 30 * 60)
    }

    /// The chainRefreshRequest inner kind sits at slot 0x0C, the
    /// next slot after chainSeedDelivery (0x0B). Pin the raw value
    /// so a future enum-reorder doesn't silently change the wire
    /// byte. Sealed inner kinds are part of the wire surface —
    /// shifting them is a forward-incompat protocol break.
    @Test("chainRefreshRequest raw value pinned at 0x0C")
    func chainRefreshRequestRawValue() {
        #expect(RelayClient.InnerEnvelopeKind.chainRefreshRequest.rawValue == 0x0C)
        #expect(RelayClient.InnerEnvelopeKind.chainSeedDelivery.rawValue == 0x0B)
        // Pre-existing slot pins guard against an accidental
        // enum-reorder that would shift the refresh-request byte.
        #expect(RelayClient.InnerEnvelopeKind.chat.rawValue == 0x01)
        #expect(RelayClient.InnerEnvelopeKind.ack.rawValue == 0x02)
        #expect(RelayClient.InnerEnvelopeKind.readReceipt.rawValue == 0x04)
    }

    /// chainRefreshRequest must decode cleanly from its raw byte —
    /// a sealed envelope arriving with 0x0C must reach the
    /// `case .chainRefreshRequest` dispatch arm, not the "unknown
    /// envelope" fallback.
    @Test("chainRefreshRequest round-trips through the InnerEnvelopeKind initializer")
    func chainRefreshRequestRoundTrip() {
        let kind = RelayClient.InnerEnvelopeKind(rawValue: 0x0C)
        #expect(kind == .chainRefreshRequest)
    }
}
