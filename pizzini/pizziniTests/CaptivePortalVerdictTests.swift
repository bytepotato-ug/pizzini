import Foundation
import Testing
@testable import pizzini

/// Tests for `captivePortalVerdict(response:body:)`.
///
/// The function is the pure half of the captive-portal probe: given
/// an HTTPURLResponse + body data (or nil for a request error), it
/// returns the user-facing verdict that drives the banner copy.
/// All the side effects (URLSession, banner state) live in the
/// caller; the policy lives here so we can pin every branch.
///
/// The probe runs only after Tor's bootstrap stalls below 50% for
/// >30 s — the verdict drives the banner that turns an otherwise-
/// opaque "Connecting…" pill into an actionable "this WiFi needs a
/// sign-in page" / "no internet" message. Misclassifying a portal
/// as `.none` would leave the user staring at a spinner with no idea
/// the network is intercepting traffic; misclassifying a clean
/// network as `.portal` would tell them to chase a portal that
/// doesn't exist. The strictness of the body match is intentional.
@Suite("captivePortalVerdict")
struct CaptivePortalVerdictTests {

    private static let okURL = URL(string: "http://captive.apple.com/")!

    private static func make(status: Int) -> HTTPURLResponse {
        HTTPURLResponse(
            url: okURL,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: nil,
        )!
    }

    /// Apple's open-network response: 200 with the literal body
    /// "Success". No portal — Tor is just slow on this network; no
    /// banner change. The strict match (not "Success" as a
    /// substring, not "<HTML>…Success…</HTML>") is the contract;
    /// loosening it would silently classify a portal that *also*
    /// emits the word "Success" somewhere in its login page as a
    /// clean network.
    @Test func successBodyReturnsNone() {
        let response = Self.make(status: 200)
        let body = Data("Success".utf8)
        #expect(captivePortalVerdict(response: response, body: body) == .none)
    }

    /// 200 but the body isn't "Success" — a captive portal that
    /// proxied the request and rewrote the response to its own
    /// login page. The 200 status is the giveaway that the network
    /// is up; the body proves it isn't the network we asked for.
    @Test func twoHundredWithUnexpectedBodyIsPortal() {
        let response = Self.make(status: 200)
        let body = Data("<html><body>Login required</body></html>".utf8)
        #expect(captivePortalVerdict(response: response, body: body) == .portal)
    }

    /// 200 with an empty body — corner case, technically not the
    /// "Success" literal so classified as portal. A portal that
    /// returns 200 with no body to dodge content-based detection
    /// still trips this branch, which is the right outcome.
    @Test func twoHundredWithEmptyBodyIsPortal() {
        let response = Self.make(status: 200)
        let body = Data()
        #expect(captivePortalVerdict(response: response, body: body) == .portal)
    }

    /// 200 with a nil body — the URLSession data callback shouldn't
    /// usually produce this, but the type system allows it; defensive
    /// branch falls into `.portal` because we can't confirm
    /// "Success".
    @Test func twoHundredWithNilBodyIsPortal() {
        let response = Self.make(status: 200)
        #expect(captivePortalVerdict(response: response, body: nil) == .portal)
    }

    /// 302 / 303 — the classic captive-portal redirect to the
    /// sign-in page. Any non-200 is interpreted as portal because
    /// `captive.apple.com/` is documented to return 200/"Success"
    /// when unintercepted.
    @Test func redirectIsPortal() {
        let response = Self.make(status: 302)
        let body = Data()
        #expect(captivePortalVerdict(response: response, body: body) == .portal)
    }

    /// 503 / 502 — the network is broken but reachable, often the
    /// portal's own backend faulting. Treat as portal: the only
    /// recovery path is the user switching networks or completing
    /// a portal flow, and "no internet" would be a confusing label
    /// when the HTTP layer did reply.
    @Test func serverErrorIsPortal() {
        let response = Self.make(status: 503)
        let body = Data("gateway down".utf8)
        #expect(captivePortalVerdict(response: response, body: body) == .portal)
    }

    /// 401 / 403 — common captive-portal challenge code on some
    /// hotel networks. Portal.
    @Test func authChallengeIsPortal() {
        let response = Self.make(status: 401)
        let body = Data()
        #expect(captivePortalVerdict(response: response, body: body) == .portal)
    }

    /// nil HTTPURLResponse — the dataTask itself errored out
    /// (timeout, DNS failure, no route). The device has no working
    /// connectivity at all; portal would be the wrong label
    /// because there's nothing to authenticate against.
    @Test func nilResponseIsNetworkDown() {
        #expect(captivePortalVerdict(response: nil, body: nil) == .networkDown)
    }

    /// nil response with a body present — defensive case (the data
    /// callback wouldn't usually deliver bytes without a response).
    /// Still treat as network-down: the absence of the response is
    /// the load-bearing signal.
    @Test func nilResponseWithSpuriousBodyIsNetworkDown() {
        let body = Data("Success".utf8)
        #expect(captivePortalVerdict(response: nil, body: body) == .networkDown)
    }

    /// Body is bytes that are not valid UTF-8 — invalid encoding
    /// is, again, not the open-network response. Portal.
    @Test func invalidUtf8BodyIsPortal() {
        let response = Self.make(status: 200)
        let body = Data([0xFF, 0xFE, 0xFD])
        #expect(captivePortalVerdict(response: response, body: body) == .portal)
    }
}
