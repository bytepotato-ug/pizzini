// SOCKS5 frame builders + parsers for the .onion routing path in
// RelayClient. Plain RFC 1928 framing, NO_AUTH method only — the proxy
// is our own embedded tor running on 127.0.0.1, so an extra auth
// handshake would buy nothing.
//
// We do SOCKS5 by hand on the NWConnection rather than rely on
// NWParameters.proxyConfiguration: that API silently fails to route
// .onion hostnames on iOS 18 (it tries to DNS-resolve the hostname
// locally first, which can't succeed for a v3 onion address). Speaking
// the protocol explicitly is ~50 lines of bytecode and avoids the
// silent-fall-back-to-direct trap entirely.
//
// All helpers here are pure: no I/O, no shared state. Tests in
// PizziniCryptoCoreTests/Socks5Tests.swift cover the frame shape +
// error paths.

import Foundation

enum Socks5 {
    /// RFC 1928 §3 greeting: VER 0x05, NMETHODS 0x01, single method byte
    /// 0x00 (NO AUTH). Tor's SOCKS implementation always accepts NO AUTH
    /// for loopback clients.
    static let clientGreeting = Data([0x05, 0x01, 0x00])

    /// Build the SOCKS5 CONNECT request for a domain-name target
    /// (ATYP 0x03). We always use domain ATYP — for .onion targets,
    /// the hostname is the authoritative identifier and DNS resolution
    /// is meaningless. Tor parses the domain bytes directly.
    ///
    /// `host` is the bare target hostname (e.g. `"pizzini2…onion"`).
    /// `port` is the destination TCP port the proxy should dial.
    static func connectRequest(host: String, port: UInt16) -> Data {
        // RFC 1928 caps DST.ADDR for domain targets at 255 bytes (it's
        // a single-byte length prefix). Onion v3 hostnames are 62
        // chars; nothing realistic gets close to the limit.
        let hostBytes = Data(host.utf8)
        precondition(hostBytes.count <= 255, "SOCKS5 domain target exceeds 255 bytes")

        var out = Data(capacity: 4 + 1 + hostBytes.count + 2)
        out.append(0x05)                       // VER
        out.append(0x01)                       // CMD = CONNECT
        out.append(0x00)                       // RSV
        out.append(0x03)                       // ATYP = DOMAINNAME
        out.append(UInt8(hostBytes.count))     // length prefix
        out.append(hostBytes)
        var portBE = port.bigEndian
        withUnsafeBytes(of: &portBE) { out.append(contentsOf: $0) }
        return out
    }

    /// Errors surfaced from the parsers. Mapped to RelayClient.State
    /// failures by the caller.
    enum FrameError: Error, Equatable, Sendable, CustomStringConvertible {
        case shortRead
        case badVersion(UInt8)
        case noAcceptableMethods
        /// CONNECT request rejected by the proxy. Code values are
        /// RFC 1928 §6: 0x01 general failure, 0x02 not allowed by
        /// ruleset, 0x03 net unreachable, 0x04 host unreachable, 0x05
        /// connection refused, 0x06 TTL expired, 0x07 cmd not
        /// supported, 0x08 atyp not supported. Tor maps onion-specific
        /// failures into these too (e.g. 0x06 for descriptor lookup
        /// timeout).
        case rejected(UInt8)
        /// ATYP byte in the server's reply wasn't one of the three
        /// supported types (IPv4 / IPv6 / DOMAINNAME). Either a
        /// non-SOCKS proxy got in our way or the response is corrupt.
        case unsupportedReplyAddressType(UInt8)

        /// Human-readable description used by `RelayClient` when it
        /// strings-formats the error into the user-visible
        /// `.failed(reason)` state. The default Swift `\(error)`
        /// for an associated-value enum is `rejected(5)` — which
        /// surfaces verbatim in the Settings → Relays diagnostic
        /// row. Decode REP codes into the names that match RFC 1928
        /// §6 so the user (and the support inbox) can tell apart
        /// "host unreachable" from "TTL expired" without a hex
        /// table.
        var description: String {
            switch self {
            case .shortRead:
                return "incomplete SOCKS5 reply (short read)"
            case .badVersion(let v):
                return String(format: "SOCKS5 version mismatch (got 0x%02x, expected 0x05)", v)
            case .noAcceptableMethods:
                return "SOCKS5 proxy rejected NO-AUTH method"
            case .rejected(let code):
                return "SOCKS5 \(Self.repName(code)) (REP=0x\(String(format: "%02x", code)))"
            case .unsupportedReplyAddressType(let t):
                return String(format: "SOCKS5 reply ATYP unsupported (0x%02x)", t)
            }
        }

        /// RFC 1928 §6 REP-code names. Unknown codes are surfaced
        /// as their hex value alone — the description above adds
        /// the `REP=` prefix so a future tor extension code stays
        /// recognisable.
        private static func repName(_ code: UInt8) -> String {
            switch code {
            case 0x01: return "general SOCKS server failure"
            case 0x02: return "connection not allowed by ruleset"
            case 0x03: return "network unreachable"
            case 0x04: return "host unreachable"
            case 0x05: return "connection refused"
            case 0x06: return "TTL expired"
            case 0x07: return "command not supported"
            case 0x08: return "address type not supported"
            default:   return "rejected"
            }
        }
    }

    /// Parse the 2-byte greeting reply.
    /// Returns the negotiated method byte (always 0x00 in practice).
    /// Throws `.shortRead` if fewer than 2 bytes are available — the
    /// caller should accumulate more bytes and retry.
    static func parseGreetingReply(_ data: Data) throws -> UInt8 {
        guard data.count >= 2 else { throw FrameError.shortRead }
        let bytes = Array(data.prefix(2))
        guard bytes[0] == 0x05 else { throw FrameError.badVersion(bytes[0]) }
        guard bytes[1] == 0x00 else { throw FrameError.noAcceptableMethods }
        return bytes[1]
    }

    /// Result of a partial CONNECT-reply parse.
    /// - `.complete(consumed)`: full reply has arrived; `consumed`
    ///   bytes should be removed from the read buffer before the
    ///   normal relay framing begins.
    /// - `.incomplete`: not enough bytes yet; keep reading.
    enum ConnectParseResult: Equatable, Sendable {
        case complete(consumed: Int)
        case incomplete
    }

    /// Try to parse a SOCKS5 CONNECT reply out of `data`. The reply
    /// shape is `VER REP RSV ATYP BND.ADDR BND.PORT`, where BND.ADDR's
    /// length depends on ATYP:
    ///   - 0x01 IPv4:    4 bytes
    ///   - 0x04 IPv6:   16 bytes
    ///   - 0x03 domain: 1-byte length + N bytes
    /// Plus 2 bytes for BND.PORT at the tail. The minimum reply size
    /// is 10 bytes (IPv4 reply with zero-padding); the maximum is
    /// 4 + 1 + 255 + 2 = 262 bytes for a max-length domain reply.
    static func tryParseConnectReply(_ data: Data) throws -> ConnectParseResult {
        guard data.count >= 4 else { return .incomplete }
        let bytes = Array(data.prefix(4))
        guard bytes[0] == 0x05 else { throw FrameError.badVersion(bytes[0]) }
        guard bytes[1] == 0x00 else { throw FrameError.rejected(bytes[1]) }
        // bytes[2] is RSV, ignored per RFC.
        let atyp = bytes[3]

        let addrLen: Int
        switch atyp {
        case 0x01: addrLen = 4
        case 0x04: addrLen = 16
        case 0x03:
            guard data.count >= 5 else { return .incomplete }
            addrLen = 1 + Int(data[data.startIndex.advanced(by: 4)])
        default:
            throw FrameError.unsupportedReplyAddressType(atyp)
        }
        let total = 4 + addrLen + 2 // header + BND.ADDR + BND.PORT
        if data.count < total {
            return .incomplete
        }
        return .complete(consumed: total)
    }
}
