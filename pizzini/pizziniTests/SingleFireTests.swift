//  SingleFireTests.swift
//  pizziniTests
//
//  Regression pin for F-tor-02: the NEWNYM ack-and-grace path in
//  `TorController.sendNewnymSignalAndWait` resumes its continuation
//  via a `SingleFire` atomic claim — whichever of (tor's `250` ack)
//  or (the grace-period timeout) arrives first wins, and the other
//  one is a no-op. Without the SingleFire gate, the continuation
//  could resume twice and crash the process.
//
//  This test pins the primitive directly. If anyone replaces or
//  rewrites SingleFire without preserving the "first claim wins,
//  every other claim is a no-op" semantic, the path-change rotation
//  starts double-resuming a continuation and the runtime aborts.

import Foundation
import PizziniTor
import Testing

@Suite("TorController.SingleFire atomic-claim invariants (F-tor-02)")
struct SingleFireTests {

    /// The first claim wins; every subsequent claim returns false.
    /// This is the literal `CheckedContinuation`-guard contract.
    @Test func firstClaimWinsRestLose() {
        let single = TorController.SingleFire()
        #expect(single.claim() == true)
        #expect(single.claim() == false)
        #expect(single.claim() == false)
    }

    /// Two threads racing the same SingleFire — exactly one of them
    /// must see `true`, the other must see `false`. Pinned with
    /// 100 trials so a stochastic regression doesn't pass on the
    /// happy path.
    @Test func concurrentRaceProducesExactlyOneWinner() async {
        for _ in 0..<100 {
            let single = TorController.SingleFire()
            async let a: Bool = Task.detached { single.claim() }.value
            async let b: Bool = Task.detached { single.claim() }.value
            let (ra, rb) = await (a, b)
            #expect(ra != rb, "exactly one of the two concurrent claims must win — got a=\(ra), b=\(rb)")
        }
    }
}
