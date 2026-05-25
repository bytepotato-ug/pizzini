import Foundation
import Testing
@testable import pizzini

/// F-TOR-02: the two clearnet exceptions (captive-portal probe and
/// transparency-log fetch) must each use their own cookie-less,
/// cache-less session so an endpoint-set cookie can't link them.
@Suite("Clearnet session isolation")
struct ClearnetSessionIsolationTests {
    @Test("isolated configuration disables cookies and cache")
    func configurationIsIsolated() {
        let c = ClearnetSession.isolatedConfiguration()
        #expect(c.httpCookieAcceptPolicy == .never)
        #expect(c.httpCookieStorage == nil)
        #expect(c.urlCache == nil)
        #expect(c.requestCachePolicy == .reloadIgnoringLocalAndRemoteCacheData)
    }

    @Test("each session is distinct and carries no cookie store")
    func sessionsAreDistinctAndCookieless() {
        let a = ClearnetSession.make()
        let b = ClearnetSession.make()
        #expect(a !== b)
        #expect(a.configuration.httpCookieStorage == nil)
        #expect(b.configuration.httpCookieStorage == nil)
        // And neither is the process-wide shared jar.
        #expect(a.configuration.httpCookieStorage !== URLSession.shared.configuration.httpCookieStorage)
    }
}
