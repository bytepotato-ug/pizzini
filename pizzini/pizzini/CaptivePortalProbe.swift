import Foundation

/// Verdict from a single probe to Apple's captive-portal detection
/// endpoint. Drives the user-facing banner copy when a Tor bootstrap
/// stalls — the user needs to know *why* (sign-in page hijack vs
/// genuinely no network) to act, and the bootstrap UI alone can't
/// distinguish them.
public enum CaptivePortalVerdict: Equatable, Sendable {
    /// The endpoint replied 200 with the expected body. The network
    /// is open; Tor is just slow on this connection. No banner.
    case none
    /// Non-200 reply, redirect, or unexpected body. A captive portal
    /// is intercepting HTTP, and the user needs to open Safari to
    /// complete the sign-in flow before Tor can dial.
    case portal
    /// The probe itself failed (timeout, no route, DNS error). Not a
    /// portal — the device has no working internet at all.
    case networkDown
}

/// Pure verdict function. Encapsulates the policy for interpreting
/// Apple's captive-portal endpoint so it can be exercised in unit
/// tests without round-tripping a real request.
///
/// The endpoint contract (documented by Apple in the Captive Network
/// Assistant flow): a network with no portal returns the exact body
/// `"Success"`; anything else — non-200, redirect, mangled body — is
/// a portal injecting its own response. We treat a nil response as a
/// network-down signal (the call site only passes nil when the
/// `URLSessionDataTask` itself errored).
public func captivePortalVerdict(
    response: HTTPURLResponse?,
    body: Data?,
) -> CaptivePortalVerdict {
    guard let response else { return .networkDown }
    guard response.statusCode == 200 else { return .portal }
    guard let body, let text = String(data: body, encoding: .utf8) else {
        return .portal
    }
    return text == "Success" ? .none : .portal
}

/// Networking helper that runs the probe. Kept thin — the
/// load-bearing logic lives in `captivePortalVerdict`. The probe URL
/// is the only documented clearnet exception added by this code; see
/// `docs/threat-model.md` for the policy.
///
/// `URLSession.shared` honours the same Tor-bypass posture as the
/// transparency-log fetch — both are explicit clearnet calls because
/// neither can ride Tor by definition (the portal probe IS the test
/// for whether the network is intercepting clearnet; if it could
/// ride Tor we wouldn't be probing).
enum CaptivePortalProbe {
    /// Apple's HTTP captive-portal detection endpoint. Stable since
    /// the early-2010s iOS Captive Network Assistant launch.
    static let probeURL = URL(string: "http://captive.apple.com/")!

    /// Returns the verdict for a single probe round-trip. `timeout`
    /// is short on purpose — a stalled tor bootstrap has been
    /// happening for >30 s before we even consider probing, so the
    /// probe itself must not extend the user's "Connecting…" state
    /// by another long wait.
    static func run(timeout: TimeInterval = 5) async -> CaptivePortalVerdict {
        var request = URLRequest(url: probeURL)
        request.httpMethod = "GET"
        request.timeoutInterval = timeout
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            return captivePortalVerdict(
                response: response as? HTTPURLResponse,
                body: data,
            )
        } catch {
            return .networkDown
        }
    }
}
