import Foundation
import PizziniCryptoCore
import Testing
@testable import pizzini

/// Boundary tests for `DBKey.paramsFailMinimumStrength`.
///
/// The predicate gates `loadStoredParams` so that an attacker who
/// pre-plants a weak `Argon2id.Params` row in the shared Keychain
/// (e.g. a profile-installed enterprise app, a Cellebrite staging
/// attack against an unlocked device, or a malicious sibling app
/// sharing an access group) cannot downgrade the at-rest key
/// derivation to something brute-forceable. See the comment block
/// above `paramsFailMinimumStrength` in `DBKey.swift` for the
/// threat model in detail.
///
/// These tests pin the policy boundary so a future tweak that
/// silently widens the floor (or, worse, accidentally weakens it)
/// breaks here loudly.
@Suite("DBKey.paramsFailMinimumStrength")
struct DBKeyParamsFloorTests {

    /// Production params (M = 64 MiB, T = 3, P = 1) must pass —
    /// they're what the legitimate first-launch path writes.
    @Test func productionPasses() {
        #expect(!DBKey.paramsFailMinimumStrength(.production))
    }

    /// Exactly at the floor: M = 32 MiB, T = 2 → still acceptable.
    /// The floor is "< 32 MiB" and "< 2 iterations", so the floor
    /// values themselves must NOT be rejected. This pins the
    /// inclusive vs. exclusive boundary.
    @Test func atTheFloorPasses() {
        let p = Argon2id.Params(
            memoryKiB: 32 * 1024,
            timeIterations: 2,
            parallelism: 1,
        )
        #expect(!DBKey.paramsFailMinimumStrength(p))
    }

    /// One KiB below the memory floor → rejected. Catches an
    /// attacker writing `M = 32 MiB - 1 KiB, T = 3, P = 1` which
    /// looks plausible on a quick `grep` but lands a measurable
    /// brute-force speedup.
    @Test func oneKiBBelowMemoryFloorFails() {
        let p = Argon2id.Params(
            memoryKiB: 32 * 1024 - 1,
            timeIterations: 3,
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
    /// floor predicate to be the weak link if that ever changed.
    @Test func zeroIterationsFails() {
        let p = Argon2id.Params(
            memoryKiB: 64 * 1024,
            timeIterations: 0,
            parallelism: 1,
        )
        #expect(DBKey.paramsFailMinimumStrength(p))
    }

    /// Cellebrite-shape weakening: tiny memory, single iteration.
    /// The headline case the threat-model comment names. Both
    /// dimensions fail; either alone is enough to trigger.
    @Test func obviouslyWeakFails() {
        let p = Argon2id.Params(
            memoryKiB: 8,        // 8 KiB — orders of magnitude under floor
            timeIterations: 1,
            parallelism: 1,
        )
        #expect(DBKey.paramsFailMinimumStrength(p))
    }

    /// Memory well above floor + iterations at floor → passes.
    /// Confirms the predicate is a strict OR across dimensions
    /// rather than a stricter AND that would refuse legitimate
    /// "heavy memory, low iters" tradeoffs.
    @Test func aboveMemoryAtIterFloorPasses() {
        let p = Argon2id.Params(
            memoryKiB: 256 * 1024, // 256 MiB
            timeIterations: 2,
            parallelism: 1,
        )
        #expect(!DBKey.paramsFailMinimumStrength(p))
    }

    /// Above floor on both dimensions but unusual parallelism →
    /// the predicate ignores parallelism. Documents the policy:
    /// parallelism is treated as a non-security-critical knob
    /// (Argon2id parallelism doesn't materially affect cracking
    /// resistance for the memory/time budget Pizzini uses).
    @Test func parallelismIsNotGated() {
        let p = Argon2id.Params(
            memoryKiB: 64 * 1024,
            timeIterations: 3,
            parallelism: 8,
        )
        #expect(!DBKey.paramsFailMinimumStrength(p))
    }
}
