import Foundation
import Testing
@testable import pizzini

/// PZ-M20: the transparency-log URL gate must allow `http://` ONLY for
/// `.onion` hosts (Tor gives transport confidentiality + the onion is a
/// self-authenticating address), so the fetch can move onto an operator
/// onion mirror — while clearnet `http://` stays rejected.
@Suite("Transparency log URL scheme gate (PZ-M20)")
struct TransparencyLogURLSchemeTests {

    @Test
    func httpsAcceptedForAnyHost() {
        #expect(TransparencyLogConfig.urlSchemeIsAcceptable(
            URL(string: "https://raw.githubusercontent.com/x/y/main/transparency-log.ndjson")!))
        #expect(TransparencyLogConfig.urlSchemeIsAcceptable(
            URL(string: "https://pizzini2rblrswjmq7axintrq55lhnqwudf7vawckrt3toqps26vxxyd.onion/log")!))
    }

    @Test
    func httpAcceptedOnlyForOnion() {
        #expect(TransparencyLogConfig.urlSchemeIsAcceptable(
            URL(string: "http://pizzini2rblrswjmq7axintrq55lhnqwudf7vawckrt3toqps26vxxyd.onion/transparency-log.ndjson")!))
        // Clearnet http:// must stay rejected — an active network attacker
        // could substitute the response body there.
        #expect(!TransparencyLogConfig.urlSchemeIsAcceptable(URL(string: "http://evil.example.com/log")!))
        #expect(!TransparencyLogConfig.urlSchemeIsAcceptable(URL(string: "http://example.com/log")!))
    }

    @Test
    func otherSchemesRejected() {
        #expect(!TransparencyLogConfig.urlSchemeIsAcceptable(URL(string: "ftp://example.com/log")!))
        #expect(!TransparencyLogConfig.urlSchemeIsAcceptable(URL(string: "file:///etc/passwd")!))
    }

    /// The shipped default stays on the clearnet GitHub mirror over HTTPS
    /// until the operator's onion mirror is live, so the gate must accept
    /// it (no accidental breakage from the relaxation).
    @Test
    func shippedDefaultURLIsAccepted() {
        #expect(TransparencyLogConfig.logURL != nil)
    }
}
