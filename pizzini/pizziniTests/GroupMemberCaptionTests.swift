import Foundation
import Testing
@testable import pizzini

/// PZ-H9: the group member list must never assert "verified 1:1" for a
/// contact that was only scanned or pasted but never verified out of
/// band. The previous code returned "verified 1:1" for ANY contact in
/// the local list, manufacturing trust the user never established.
@Suite("Group member verification caption (PZ-H9)")
struct GroupMemberCaptionTests {

    @Test
    func verifiedContactShowsVerified1to1() {
        #expect(
            GroupInvitationView.memberVerificationCaption(state: .verified, inserterName: nil)
                == "verified 1:1"
        )
        // A verified contact stays verified even if an inserter is known.
        #expect(
            GroupInvitationView.memberVerificationCaption(state: .verified, inserterName: "Alice")
                == "verified 1:1"
        )
    }

    @Test
    func scannedButUnverifiedContactIsNotClaimedVerified() {
        let caption = GroupInvitationView.memberVerificationCaption(
            state: .scannedUnverified, inserterName: nil
        )
        #expect(caption != "verified 1:1")
        #expect(caption?.localizedCaseInsensitiveContains("not verified") == true)
    }

    @Test
    func pastedContactIsNotClaimedVerified() {
        let caption = GroupInvitationView.memberVerificationCaption(
            state: .pastedUnverified, inserterName: nil
        )
        #expect(caption != "verified 1:1")
        #expect(caption?.localizedCaseInsensitiveContains("not verified") == true)
    }

    @Test
    func nonContactFallsBackToInserterProvenance() {
        #expect(
            GroupInvitationView.memberVerificationCaption(state: nil, inserterName: "you")
                == "added by you — not verified in person"
        )
        #expect(
            GroupInvitationView.memberVerificationCaption(state: nil, inserterName: nil)
                == "not verified in person"
        )
    }

    /// Core safety invariant: "verified 1:1" is produced for, and only
    /// for, a `.verified` contact — no other state may claim it.
    @Test
    func verifiedLabelOnlyForVerifiedState() {
        let states: [ContactVerificationState?] = [
            .verified, .scannedUnverified, .pastedUnverified, nil,
        ]
        for state in states {
            let caption = GroupInvitationView.memberVerificationCaption(
                state: state, inserterName: nil
            )
            if state == .verified {
                #expect(caption == "verified 1:1")
            } else {
                #expect(caption != "verified 1:1")
            }
        }
    }
}
