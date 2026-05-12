import CoreImage.CIFilterBuiltins
import Foundation
import SwiftUI
import UIKit

/// Wire payload encoded into the discovery QR. Tiny: peer-id + relay
/// host. The bundle itself rides over the relay (BUNDLE_REQUEST /
/// BUNDLE_RESPONSE) — see relay/src/main.rs.
///
/// Format: `pizzini1://<peerIdHex>@<host>:<port>`. URL-shaped so iOS QR
/// scanners and other tooling can recognise it, but parsing is hand-rolled.
struct ContactCard: Equatable, Identifiable {
    let peerId: Data
    let host: String
    let port: UInt16

    /// peerId is unique per identity, so it doubles as the SwiftUI id.
    var id: Data { peerId }

    var encoded: String {
        let hex = peerId.map { String(format: "%02x", $0) }.joined()
        return "pizzini1://\(hex)@\(host):\(port)"
    }

    var fingerprintShort: String {
        let head = peerId.prefix(4).map { String(format: "%02x", $0) }.joined()
        let tail = peerId.suffix(2).map { String(format: "%02x", $0) }.joined()
        return "\(head)…\(tail)"
    }

    /// Best-effort parse for callers that don't care about WHY a decode
    /// failed (legacy call sites, tests, the QR-decoder hot path).
    /// Returns nil on any rejection. New code that has a user-visible
    /// surface should prefer `validate(_:)` so it can show the specific
    /// reason.
    static func decode(_ s: String) -> ContactCard? {
        try? validate(s)
    }

    /// Strict, error-typed contact-card parser. The single source of
    /// truth for "is this string a Pizzini contact card?" Used by both
    /// the QR-scan and clipboard-paste paths.
    ///
    /// Rules, every one of which yields a distinct `reason` so the UI
    /// can tell the user exactly what's wrong:
    ///
    ///   1. **Bounded input.** A card is ~80 ASCII bytes; reject any
    ///      paste >4 KiB. Defends against a clipboard accident (a
    ///      multi-MB blob of text) AND a deliberate DoS via paste of
    ///      a huge synthetic string designed to slow the decode loop.
    ///
    ///   2. **Trim whitespace.** Tap-paste on iOS often appends a
    ///      trailing newline; macOS handoff occasionally prepends one.
    ///      Both are benign; strip them up front.
    ///
    ///   3. **NFKC + printable-ASCII.** Mirrors `OnionHost.canonical`:
    ///      reject anything where the NFKC normalisation differs from
    ///      the input, OR contains codepoints outside `0x20..=0x7E`.
    ///      Defeats Unicode look-alikes where a glyph rendering as
    ///      `pizzini1://` actually contains an ideographic stop or
    ///      look-alike `1`.
    ///
    ///   4. **Scheme.** Must start with the literal ASCII prefix
    ///      `pizzini1://`. No other schemes recognised.
    ///
    ///   5. **Body shape.** Exactly one `@` separator, exactly one
    ///      trailing `:` for the port. Reject `host` that contains
    ///      additional `@` or `:` (defends against `evil@:7777@…`
    ///      style smuggling).
    ///
    ///   6. **peerId.** Exactly 66 lowercase hex characters. That's
    ///      libsignal's `IdentityKey` wire form (1 type byte + 32
    ///      Ed25519 point bytes). Anything else means the card was
    ///      truncated, expanded, or for a different protocol.
    ///
    ///   7. **peerId entropy floor.** Reject all-zero or all-same-byte
    ///      keys — those are placeholder/test patterns, not real
    ///      identities, and pairing with them is always a bug.
    ///
    ///   8. **Port.** Must be a valid 1-65535 UInt16. Port 0 isn't a
    ///      real listener; reject it explicitly so a malformed `:0`
    ///      doesn't silently parse.
    static func validate(_ raw: String) throws(ContactCardDecodeError) -> ContactCard {
        // 1. Bounded input.
        guard raw.utf8.count <= 4096 else {
            throw ContactCardDecodeError(
                reason: "The pasted text is too long for a contact card. A real card is short and starts with pizzini1://."
            )
        }
        // 2. Trim.
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw ContactCardDecodeError(reason: "Your clipboard is empty.")
        }
        // 3. NFKC + printable-ASCII gate.
        let nfkc = trimmed.precomposedStringWithCompatibilityMapping
        guard nfkc == trimmed else {
            throw ContactCardDecodeError(
                reason: "The pasted text contains non-standard characters (possibly a look-alike). It is not a Pizzini contact card."
            )
        }
        for scalar in trimmed.unicodeScalars {
            let v = scalar.value
            if v < 0x20 || v > 0x7E {
                throw ContactCardDecodeError(
                    reason: "The pasted text contains characters that don't belong in a contact card."
                )
            }
        }
        // 4. Scheme.
        let prefix = "pizzini1://"
        guard trimmed.hasPrefix(prefix) else {
            throw ContactCardDecodeError(
                reason: "This is not a Pizzini contact card. Cards start with pizzini1://."
            )
        }
        let body = trimmed.dropFirst(prefix.count)
        // 5. Body shape: exactly one `@`, exactly one `:` in host:port.
        guard let at = body.firstIndex(of: "@") else {
            throw ContactCardDecodeError(reason: "The contact card is malformed (missing @ separator).")
        }
        guard body[body.index(after: at)...].firstIndex(of: "@") == nil else {
            throw ContactCardDecodeError(reason: "The contact card has too many @ separators.")
        }
        let hex = String(body[body.startIndex..<at])
        let hostPort = body[body.index(after: at)...]
        guard let colon = hostPort.lastIndex(of: ":") else {
            throw ContactCardDecodeError(reason: "The contact card is missing the :port suffix.")
        }
        let host = String(hostPort[hostPort.startIndex..<colon])
        let portStr = String(hostPort[hostPort.index(after: colon)...])
        guard !host.contains(":") else {
            throw ContactCardDecodeError(reason: "The contact card has too many : separators.")
        }
        // 6. peerId: exactly 66 lowercase hex chars.
        let hexLower = hex.lowercased()
        guard hexLower.count == 66 else {
            throw ContactCardDecodeError(
                reason: "The contact card's identity is the wrong length (expected 66 hex characters, got \(hex.count))."
            )
        }
        guard hexLower == hex || hex.allSatisfy({ "0123456789abcdefABCDEF".contains($0) }) else {
            throw ContactCardDecodeError(reason: "The contact card's identity contains non-hex characters.")
        }
        var bytes = Data(capacity: 33)
        var idx = hexLower.startIndex
        while idx < hexLower.endIndex {
            let next = hexLower.index(idx, offsetBy: 2)
            guard let byte = UInt8(hexLower[idx..<next], radix: 16) else {
                throw ContactCardDecodeError(reason: "The contact card's identity contains non-hex characters.")
            }
            bytes.append(byte)
            idx = next
        }
        // 7. peerId entropy floor.
        if bytes.allSatisfy({ $0 == 0 }) {
            throw ContactCardDecodeError(reason: "The contact card's identity is all zeros — not a real identity.")
        }
        if let first = bytes.first, bytes.allSatisfy({ $0 == first }) {
            throw ContactCardDecodeError(reason: "The contact card's identity has no entropy — likely a test or corrupted card.")
        }
        // 8. Port.
        guard let port = UInt16(portStr), port > 0 else {
            throw ContactCardDecodeError(
                reason: "The contact card has an invalid port (\(portStr.isEmpty ? "missing" : portStr))."
            )
        }
        return ContactCard(peerId: bytes, host: host, port: port)
    }
}

/// Thrown by `ContactCard.validate(_:)`. The `reason` is a single-
/// sentence, plain-language string suitable for an alert body — no
/// stack traces, no internal field names. Adding a new failure mode
/// to `validate` means adding a new reason string here (the rules are
/// in `validate`'s doc comment for a reason: keep them grep-able).
struct ContactCardDecodeError: Error, Equatable, Sendable {
    let reason: String
}

/// Pure QR-image renderer. Used by `MyQRSheet`'s reveal/hide states —
/// the surrounding chrome (warning, hide-toggle, details disclosure)
/// lives in `MyQRSheet` so this stays reusable.
///
/// Default `sideLength = 180pt` is deliberately conservative: pairing
/// happens hand-to-hand (≈30 cm apart), and at that range a 180pt QR
/// is comfortably scannable. A photographer 2 m+ away — security
/// camera, someone behind a window, a shoulder surfer with their own
/// phone — gets a postage-stamp image whose modules don't resolve
/// cleanly. The previous 280pt code was scannable from across the
/// room, which is exactly the threat the warning above the QR is
/// asking the user to defend against. Smaller code, smaller blast
/// radius if a stray photo gets taken.
struct ContactQRImage: View {
    let card: ContactCard
    var sideLength: CGFloat = 180

    var body: some View {
        if let image = qrImage(for: card.encoded) {
            Image(uiImage: image)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: sideLength, maxHeight: sideLength)
                .padding(8)
                .background(Color.white)
                .cornerRadius(12)
                .accessibilityLabel("Pizzini contact QR")
        } else {
            Text("(could not render QR)")
                .foregroundStyle(.red)
        }
    }

    private func qrImage(for text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        let context = CIContext()
        guard let cg = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}

/// Compact "host:port · fingerprint" line for power-users who want to
/// double-check what's encoded in the QR. Hidden behind a disclosure in
/// `MyQRSheet`; non-technical users never see it.
struct ContactCardDetails: View {
    let card: ContactCard

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            row(label: "Relay", value: "\(card.host):\(card.port)")
            row(label: "Fingerprint", value: card.fingerprintShort)
        }
        .font(.caption.monospaced())
    }

    private func row(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .foregroundStyle(.primary)
        }
    }
}
