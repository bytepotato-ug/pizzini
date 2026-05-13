import Foundation
import PizziniTor
import Testing

/// Tests for `TorController.userFacingPhase(forTag:)`.
///
/// The mapping is the contract between tor's BOOTSTRAP `TAG=` strings
/// and the short, user-facing copy ContactsListView shows next to the
/// connection spinner. It is intentionally lossy — tor walks through
/// ~20 internal tags during a cold start, and surfacing all of them
/// reads as flickering rather than progress. These tests pin the
/// contract so a future copy edit can't silently re-introduce the
/// flicker.
@Suite("TorController.userFacingPhase(forTag:)")
struct BootstrapPhaseLabelTests {

    @Test func startingTag() {
        #expect(TorController.userFacingPhase(forTag: "starting") == "Starting")
    }

    @Test func connTagsAllMapToFindingRoute() {
        for tag in [
            "conn_pt", "conn_done_pt",
            "conn_proxy", "conn_done_proxy",
            "conn", "conn_done",
        ] {
            #expect(
                TorController.userFacingPhase(forTag: tag) == "Finding a route",
                "tag=\(tag)",
            )
        }
    }

    @Test func handshakeTagsAllMapToBuildingCircuit() {
        for tag in ["handshake", "handshake_done", "onehop_create"] {
            #expect(
                TorController.userFacingPhase(forTag: tag) == "Building circuit",
                "tag=\(tag)",
            )
        }
    }

    @Test func directoryTagsAllMapToLoadingDirectory() {
        for tag in [
            "requesting_status", "loading_status",
            "loading_keys",
            "requesting_descriptors", "loading_descriptors",
            "enough_dirinfo",
        ] {
            #expect(
                TorController.userFacingPhase(forTag: tag) == "Loading directory",
                "tag=\(tag)",
            )
        }
    }

    @Test func apCircuitTagsAllMapToConnectingToRelay() {
        for tag in [
            "ap_conn", "ap_conn_done",
            "ap_handshake", "ap_handshake_done",
            "circuit_create",
        ] {
            #expect(
                TorController.userFacingPhase(forTag: tag) == "Connecting to relay",
                "tag=\(tag)",
            )
        }
    }

    @Test func doneTagMapsToConnected() {
        #expect(TorController.userFacingPhase(forTag: "done") == "Connected")
    }

    /// Unknown tag → nil so the observer leaves the previous label
    /// in place rather than flicker to an empty string. This is the
    /// load-bearing flicker-defence test.
    @Test func unknownTagReturnsNil() {
        #expect(TorController.userFacingPhase(forTag: "totally_made_up_tag") == nil)
        #expect(TorController.userFacingPhase(forTag: "") == nil)
        // Case sensitivity matters — tor emits lowercase tags, and a
        // future case-insensitive matcher could let a stray uppercase
        // string slip past without a label. Pin the literal-match
        // contract.
        #expect(TorController.userFacingPhase(forTag: "CONN") == nil)
    }
}
