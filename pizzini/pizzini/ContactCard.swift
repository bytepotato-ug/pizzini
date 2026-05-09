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

    static func decode(_ s: String) -> ContactCard? {
        let prefix = "pizzini1://"
        guard s.hasPrefix(prefix) else { return nil }
        let body = s.dropFirst(prefix.count)
        guard let at = body.firstIndex(of: "@") else { return nil }
        let hex = String(body[body.startIndex..<at])
        let hostPort = String(body[body.index(after: at)...])
        guard hex.count.isMultiple(of: 2) else { return nil }
        var bytes = Data(capacity: hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let byte = UInt8(hex[idx..<next], radix: 16) else { return nil }
            bytes.append(byte)
            idx = next
        }
        guard let colon = hostPort.lastIndex(of: ":") else { return nil }
        let host = String(hostPort[hostPort.startIndex..<colon])
        let portStr = String(hostPort[hostPort.index(after: colon)...])
        guard let port = UInt16(portStr) else { return nil }
        return ContactCard(peerId: bytes, host: host, port: port)
    }
}

/// Pure QR-image renderer. Used by `MyQRSheet`'s reveal/hide states —
/// the surrounding chrome (warning, hide-toggle, details disclosure)
/// lives in `MyQRSheet` so this stays reusable.
struct ContactQRImage: View {
    let card: ContactCard
    var sideLength: CGFloat = 280

    var body: some View {
        if let image = qrImage(for: card.encoded) {
            Image(uiImage: image)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: sideLength, maxHeight: sideLength)
                .padding(12)
                .background(Color.white)
                .cornerRadius(16)
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
