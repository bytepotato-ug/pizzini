import Foundation

/// Factory for the *isolated* clearnet sessions used by the two
/// documented Tor-bypass exceptions: the captive-portal probe
/// (`CaptivePortalProbe`) and the GitHub-hosted transparency-log fetch
/// (`TransparencyLog`). Each call site builds its own session from this
/// configuration — never `URLSession.shared` — so a cookie or cache
/// validator planted by one clearnet endpoint cannot ride to the other.
/// The two exceptions stay mutually unlinkable beyond the device IP
/// (F-TOR-02). Mirrors the isolation of `TransparencyLog.torSession()`,
/// minus the SOCKS proxy (these calls are clearnet by definition).
enum ClearnetSession {
    /// An ephemeral, cookie-less, cache-less configuration.
    static func isolatedConfiguration(timeout: TimeInterval = 30) -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieAcceptPolicy = .never
        config.httpCookieStorage = nil
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.timeoutIntervalForRequest = timeout
        return config
    }

    /// A fresh isolated session. Built per call (never shared) so no
    /// cross-request state survives between the two clearnet exceptions.
    static func make(timeout: TimeInterval = 30) -> URLSession {
        URLSession(configuration: isolatedConfiguration(timeout: timeout))
    }
}
