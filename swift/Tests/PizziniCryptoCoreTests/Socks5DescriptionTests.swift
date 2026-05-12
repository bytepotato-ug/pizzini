// Tests for the human-readable description of `Socks5.FrameError`.
// The previous default Swift stringification produced `rejected(5)`
// for any REP code; RFC 1928 §6 codes 0x01–0x08 now decode to their
// canonical names so the Settings → Relays diagnostic row reads
// "SOCKS5 host unreachable" instead of "rejected(4)".

import Foundation
import Testing
@testable import PizziniCryptoCore

@Suite("Socks5 FrameError description")
struct Socks5DescriptionTests {
    @Test("REP=0x05 decodes to 'connection refused'")
    func rep05Refused() {
        let s = String(describing: Socks5.FrameError.rejected(0x05))
        #expect(s.contains("connection refused"))
        #expect(s.contains("REP=0x05"))
    }

    @Test("REP=0x04 decodes to 'host unreachable'")
    func rep04HostUnreachable() {
        let s = String(describing: Socks5.FrameError.rejected(0x04))
        #expect(s.contains("host unreachable"))
        #expect(s.contains("REP=0x04"))
    }

    @Test("REP=0x06 decodes to 'TTL expired' — tor's descriptor-lookup-timeout signal")
    func rep06TTLExpired() {
        let s = String(describing: Socks5.FrameError.rejected(0x06))
        #expect(s.contains("TTL expired"))
    }

    @Test("REP outside §6 (0xFF) surfaces 'rejected' + raw hex")
    func repUnknownFallsBack() {
        let s = String(describing: Socks5.FrameError.rejected(0xFF))
        #expect(s.contains("rejected"))
        #expect(s.contains("REP=0xff"))
    }

    @Test("badVersion includes the offending byte")
    func badVersionFormatted() {
        let s = String(describing: Socks5.FrameError.badVersion(0x04))
        #expect(s.contains("0x04"))
        #expect(s.contains("0x05"))  // expected
    }

    @Test("noAcceptableMethods has a human form")
    func noAcceptableMethods() {
        let s = String(describing: Socks5.FrameError.noAcceptableMethods)
        #expect(s.contains("NO-AUTH"))
    }

    @Test("shortRead has a human form")
    func shortRead() {
        let s = String(describing: Socks5.FrameError.shortRead)
        #expect(s.contains("short read") || s.contains("incomplete"))
    }

    @Test("unsupportedReplyAddressType includes the offending byte")
    func unsupportedAtyp() {
        let s = String(describing: Socks5.FrameError.unsupportedReplyAddressType(0x05))
        #expect(s.contains("0x05"))
    }
}
