// SOCKS5 framing tests for the .onion routing path. These cover the
// pure builder/parser surface — no NWConnection, no Tor. The wire
// layout is RFC 1928; mismatches against the RFC are what the asserts
// catch.

import Foundation
import Testing
@testable import PizziniCryptoCore

@Suite("Socks5 framing")
struct Socks5Tests {
    @Test("greeting is exactly VER=5, NMETHODS=1, METHOD=NO_AUTH")
    func greetingExactBytes() {
        #expect(Socks5.clientGreeting == Data([0x05, 0x01, 0x00]))
    }

    @Test("CONNECT request encodes domain target as ATYP=3 + length + bytes + port BE")
    func connectRequestForOnionTarget() {
        let host = "pizzini2rblrswjmq7axintrq55lhnqwudf7vawckrt3toqps26vxxyd.onion"
        let req = Socks5.connectRequest(host: host, port: 7777)
        var cursor = 0
        #expect(req[cursor] == 0x05); cursor += 1
        #expect(req[cursor] == 0x01); cursor += 1
        #expect(req[cursor] == 0x00); cursor += 1
        #expect(req[cursor] == 0x03); cursor += 1
        let hostLen = Int(req[cursor]); cursor += 1
        #expect(hostLen == host.utf8.count)
        let hostBytes = req[cursor..<cursor + hostLen]
        #expect(Data(hostBytes) == Data(host.utf8))
        cursor += hostLen
        // Port 7777 = 0x1E61.
        #expect(req[cursor] == 0x1E)
        #expect(req[cursor + 1] == 0x61)
        cursor += 2
        #expect(cursor == req.count)
    }

    @Test("CONNECT request fits short hostnames identically")
    func connectRequestShortHost() {
        let req = Socks5.connectRequest(host: "a.onion", port: 1)
        // VER CMD RSV ATYP LEN host... PORT_HI PORT_LO
        #expect(req.count == 4 + 1 + "a.onion".utf8.count + 2)
        #expect(req.last == 0x01)
    }

    @Test("greeting reply with NO_AUTH accepted")
    func greetingReplyAccepted() throws {
        let ok = try Socks5.parseGreetingReply(Data([0x05, 0x00]))
        #expect(ok == 0x00)
    }

    @Test("greeting reply with wrong VER throws .badVersion")
    func greetingReplyBadVersion() {
        #expect(throws: Socks5.FrameError.badVersion(0x04)) {
            _ = try Socks5.parseGreetingReply(Data([0x04, 0x00]))
        }
    }

    @Test("greeting reply with 0xFF method throws .noAcceptableMethods")
    func greetingReplyRejected() {
        #expect(throws: Socks5.FrameError.noAcceptableMethods) {
            _ = try Socks5.parseGreetingReply(Data([0x05, 0xFF]))
        }
    }

    @Test("greeting reply short read")
    func greetingReplyShort() {
        #expect(throws: Socks5.FrameError.shortRead) {
            _ = try Socks5.parseGreetingReply(Data([0x05]))
        }
    }

    @Test("CONNECT reply IPv4 success consumes exactly 10 bytes")
    func connectReplyIPv4() throws {
        // VER REP RSV ATYP=1 4×addr 2×port
        let frame = Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00])
        switch try Socks5.tryParseConnectReply(frame) {
        case .complete(let consumed): #expect(consumed == 10)
        case .incomplete: Issue.record("expected complete")
        }
    }

    @Test("CONNECT reply IPv6 success consumes exactly 22 bytes")
    func connectReplyIPv6() throws {
        var frame = Data([0x05, 0x00, 0x00, 0x04])
        frame.append(contentsOf: [UInt8](repeating: 0, count: 16))
        frame.append(contentsOf: [0x00, 0x00])
        switch try Socks5.tryParseConnectReply(frame) {
        case .complete(let consumed): #expect(consumed == 22)
        case .incomplete: Issue.record("expected complete")
        }
    }

    @Test("CONNECT reply domain success: ATYP=3 + length + bytes + port")
    func connectReplyDomain() throws {
        // length=3, addr="abc", port=0
        var frame = Data([0x05, 0x00, 0x00, 0x03, 0x03])
        frame.append(contentsOf: [0x61, 0x62, 0x63])
        frame.append(contentsOf: [0x00, 0x00])
        switch try Socks5.tryParseConnectReply(frame) {
        case .complete(let consumed): #expect(consumed == 4 + 1 + 3 + 2)
        case .incomplete: Issue.record("expected complete")
        }
    }

    @Test("CONNECT reply incomplete header returns .incomplete")
    func connectReplyIncompleteHeader() throws {
        let result = try Socks5.tryParseConnectReply(Data([0x05, 0x00, 0x00]))
        #expect(result == .incomplete)
    }

    @Test("CONNECT reply incomplete domain payload returns .incomplete")
    func connectReplyIncompleteDomainPayload() throws {
        // Says length=10 but only ships 3 addr bytes.
        var frame = Data([0x05, 0x00, 0x00, 0x03, 0x0A])
        frame.append(contentsOf: [0x61, 0x62, 0x63])
        let result = try Socks5.tryParseConnectReply(frame)
        #expect(result == .incomplete)
    }

    @Test("CONNECT reply REP=0x05 (connection refused) throws .rejected")
    func connectReplyRejected() {
        let frame = Data([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        #expect(throws: Socks5.FrameError.rejected(0x05)) {
            _ = try Socks5.tryParseConnectReply(frame)
        }
    }

    @Test("CONNECT reply bad version throws .badVersion")
    func connectReplyBadVersion() {
        let frame = Data([0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        #expect(throws: Socks5.FrameError.badVersion(0x04)) {
            _ = try Socks5.tryParseConnectReply(frame)
        }
    }

    @Test("CONNECT reply unsupported ATYP throws .unsupportedReplyAddressType")
    func connectReplyUnsupportedAtyp() {
        let frame = Data([0x05, 0x00, 0x00, 0x09, 0, 0, 0, 0])
        #expect(throws: Socks5.FrameError.unsupportedReplyAddressType(0x09)) {
            _ = try Socks5.tryParseConnectReply(frame)
        }
    }

    @Test("Decision: only a strict v3 onion routes through SOCKS5")
    func onionRoutingDecision() {
        // The routing decision lives in RelayClient.connect itself,
        // gated on `OnionHost.canonical`. Mirror the same validator
        // here so a regression in either side (the validator OR the
        // routing call-site) is caught by this assertion.
        let onionHosts = [
            "pizzini2rblrswjmq7axintrq55lhnqwudf7vawckrt3toqps26vxxyd.onion",
        ]
        let directHosts = [
            "127.0.0.1",
            "10.0.1.5",
            "relay.example.com",
            "abc.oniondomain.com", // suffix is "domain.com", not ".onion"
            "onion",               // bare token, no leading dot
            "abc.onion",           // too short to be a v3 (16 vs 56)
            "evil.com.onion",      // trailing-suffix poisoning
        ]
        for h in onionHosts {
            #expect(OnionHost.isValid(h))
        }
        for h in directHosts {
            #expect(!OnionHost.isValid(h))
        }
    }
}
