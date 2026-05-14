import Foundation
import PizziniCryptoCore
import Testing
@testable import pizzini

/// Boundary tests for `DBKey.paramsFailMinimumStrength`.
///
/// The predicate gates `loadStoredParams` so that an attacker who
/// pre-plants a tampered `Argon2id.Params` row in the shared Keychain
/// (e.g. a profile-installed enterprise app, a Cellebrite staging
/// attack against an unlocked device, or a malicious sibling app
/// sharing an access group) cannot downgrade the at-rest key
/// derivation. See the comment block above `paramsFailMinimumStrength`
/// in `DBKey.swift` for the threat model in detail.
///
/// **Policy: exact-match allowlist, not an open floor.** The predicate
/// used to accept anything above a `M ≥ 32 MiB, T ≥ 2` floor — which
/// let an attacker key the DB at any work factor above the floor
/// (e.g. half production). It now accepts ONLY params equal to a
/// code-known shipped preset (`DBKey.acceptedParamPresets`, today just
/// `.production`). These tests pin that allowlist so a future change
/// that re-opens an `>=` range — or accidentally drops `.production`
/// from the list — breaks here loudly.
@Suite("DBKey.paramsFailMinimumStrength")
struct DBKeyParamsFloorTests {

    /// Production params (M = 64 MiB, T = 3, P = 1) must pass —
    /// they're what the legitimate first-launch path writes and the
    /// only preset that has ever shipped.
    @Test func productionPasses() {
        #expect(!DBKey.paramsFailMinimumStrength(.production))
    }

    /// Every entry in the accepted-preset allowlist must pass — the
    /// allowlist IS the policy, so a preset on it that the predicate
    /// rejects would be a self-contradiction.
    @Test func everyAcceptedPresetPasses() {
        for preset in DBKey.acceptedParamPresets {
            #expect(!DBKey.paramsFailMinimumStrength(preset))
        }
    }

    /// The old "exactly at the floor" shape — M = 32 MiB, T = 2 — is
    /// now REJECTED. Under the open-floor predicate this passed
    /// (roughly half the production work factor); the allowlist
    /// closes that gap because it is not a shipped preset.
    @Test func oldFloorShapeNowRejected() {
        let p = Argon2id.Params(
            memoryKiB: 32 * 1024,
            timeIterations: 2,
            parallelism: 1,
        )
        #expect(DBKey.paramsFailMinimumStrength(p))
    }

    /// One KiB below production memory → rejected. Not on the
    /// allowlist; catches an attacker writing a params row that
    /// looks plausible on a quick `grep` but is not the exact
    /// shipped shape.
    @Test func oneKiBBelowProductionMemoryFails() {
        let p = Argon2id.Params(
            memoryKiB: 64 * 1024 - 1,
            timeIterations: 3,
            parallelism: 1,
        )
        #expect(DBKey.paramsFailMinimumStrength(p))
    }

    /// Fewer iterations than production → rejected.
    @Test func fewerIterationsThanProductionFails() {
        let p = Argon2id.Params(
            memoryKiB: 64 * 1024,
            timeIterations: 2,
            parallelism: 1,
        )
        #expect(DBKey.paramsFailMinimumStrength(p))
    }

    /// One iteration → rejected. A single Argon2id pass is the
    /// canonical "fast crack" parameter shape.
    @Test func oneIterationFails() {
        let p = Argon2id.Params(
            memoryKiB: 64 * 1024,
            timeIterations: 1,
            parallelism: 1,
        )
        #expect(DBKey.paramsFailMinimumStrength(p))
    }

    /// Zero iterations → rejected. Defensive: the libargon2 binding
    /// would refuse this at derive() time, but we don't want the
    /// allowlist predicate to be the weak link if that ever changed.
    @Test func zeroIterationsFails() {
        let p = Argon2id.Params(
            memoryKiB: 64 * 1024,
            timeIterations: 0,
            parallelism: 1,
        )
        #expect(DBKey.paramsFailMinimumStrength(p))
    }

    /// Cellebrite-shape weakening: tiny memory, single iteration.
    /// The headline case the threat-model comment names.
    @Test func obviouslyWeakFails() {
        let p = Argon2id.Params(
            memoryKiB: 8,        // 8 KiB — orders of magnitude under production
            timeIterations: 1,
            parallelism: 1,
        )
        #expect(DBKey.paramsFailMinimumStrength(p))
    }

    /// Memory well ABOVE production is now also rejected — the policy
    /// is exact-match, not "at least as strong as production." A
    /// stronger-than-production row is not what any shipped build
    /// keyed a DB under, so accepting it would mean the open path
    /// trusts an attacker-reachable Keychain row to define the work
    /// factor. If a heavier preset is ever genuinely shipped, it is
    /// appended to `DBKey.acceptedParamPresets` (an explicit code-side
    /// allowlist entry), not silently admitted by an `>=` comparison.
    @Test func aboveProductionMemoryRejected() {
        let p = Argon2id.Params(
            memoryKiB: 256 * 1024, // 256 MiB
            timeIterations: 3,
            parallelism: 1,
        )
        #expect(DBKey.paramsFailMinimumStrength(p))
    }

    /// A params row that matches production on memory + iterations
    /// but differs in parallelism is rejected — the allowlist match
    /// is over ALL three fields (`Argon2id.Params` `Equatable`), so
    /// parallelism is part of the gated shape, not a free knob.
    @Test func differingParallelismRejected() {
        let p = Argon2id.Params(
            memoryKiB: Argon2id.Params.production.memoryKiB,
            timeIterations: Argon2id.Params.production.timeIterations,
            parallelism: Argon2id.Params.production.parallelism &+ 1,
        )
        #expect(DBKey.paramsFailMinimumStrength(p))
    }
}
