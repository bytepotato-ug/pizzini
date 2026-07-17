import Foundation
import Testing
@testable import pizzini

/// PZ-H7 / F-DUR-02 — a freshly minted database (first install OR the
/// post-duress re-bootstrap) already has a fresh `SecRandom` salt, so
/// `SQLiteStorage.bootstrap` now seeds the rotation clock to "now"
/// instead of letting the absent-slot case force an immediate,
/// pointless key rotation (Argon2id + rekey + VACUUM). On the duress
/// path that forced rotation inflated submit→unlock latency enough to
/// leak "a wipe just happened."
///
/// These exercise the pure, Keychain-free `rotationDue(lastRotationEpoch:
/// now:)` core (the Keychain/SE path is entitlement-gated and gives
/// false reds on the simulator). They pin that (a) seeding the clock to
/// `now` suppresses the immediate rotation, (b) an absent slot still
/// means "due" for every other path, and (c) the periodic rotation
/// still fires once the interval actually elapses.
@Suite("DBKey — PZ-H7 rotation-clock seeding")
struct DBKeyRotationClockTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    @Test("absent slot is treated as due (unchanged for non-fresh paths)")
    func absentSlotIsDue() {
        #expect(DBKey.rotationDue(lastRotationEpoch: nil, now: now) == true)
    }

    @Test("seeding the clock to now suppresses the redundant immediate rotation")
    func seededNowIsNotDue() {
        let epoch = UInt64(now.timeIntervalSince1970)
        #expect(DBKey.rotationDue(lastRotationEpoch: epoch, now: now) == false)
    }

    @Test("a clock just under the interval is not yet due")
    func justUnderIntervalNotDue() {
        let epoch = UInt64(now.addingTimeInterval(-(DBKey.rotationInterval - 60)).timeIntervalSince1970)
        #expect(DBKey.rotationDue(lastRotationEpoch: epoch, now: now) == false)
    }

    @Test("the periodic rotation still fires once the interval has elapsed")
    func pastIntervalIsDue() {
        let epoch = UInt64(now.addingTimeInterval(-(DBKey.rotationInterval + 60)).timeIntervalSince1970)
        #expect(DBKey.rotationDue(lastRotationEpoch: epoch, now: now) == true)
    }
}
