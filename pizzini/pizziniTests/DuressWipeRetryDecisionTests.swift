import Foundation
import Testing
@testable import pizzini

/// PZ-M13: an interrupted duress wipe (key erase not confirmed) is
/// retried on the next unlocked foreground — but only while the device
/// is still in the uncommitted post-wipe state. Once a new identity has
/// been committed (onboarding completed), the fixed-name Keychain slots
/// hold THAT identity's keys, so re-erasing would destroy live data; the
/// flag is cleared without erasing instead. `duressWipeRetryAction` is
/// the pure, `nonisolated` decision point — no Keychain — so it runs on
/// the simulator. (The live erase + persistence is device-checklist.)
@Suite("PZ-M13 incomplete-wipe retry decision")
struct DuressWipeRetryDecisionTests {
    @Test("no recorded incompleteness → do nothing")
    func notIncompleteIsNoRetry() {
        #expect(
            ChatStore.duressWipeRetryAction(incomplete: false, onboardingCompleted: false)
                == .noRetry
        )
        #expect(
            ChatStore.duressWipeRetryAction(incomplete: false, onboardingCompleted: true)
                == .noRetry
        )
    }

    @Test("incomplete + still onboarding → finish the erase")
    func incompleteUncommittedRetries() {
        #expect(
            ChatStore.duressWipeRetryAction(incomplete: true, onboardingCompleted: false)
                == .retryErase
        )
    }

    @Test("incomplete + onboarding committed → clear flag, never erase (data-loss guard)")
    func incompleteCommittedClearsWithoutErase() {
        #expect(
            ChatStore.duressWipeRetryAction(incomplete: true, onboardingCompleted: true)
                == .clearWithoutErase
        )
    }
}
