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
struct ContactCard: Equatable {
    let peerId: Data
    let host: String
    let port: UInt16

    var encoded: String {
        let hex = peerId.map { String(format: "%02x", $0) }.joined()
        return "pizzini1://\(hex)@\(host):\(port)"
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

struct ContactCardView: View {
    let card: ContactCard

    var body: some View {
        VStack(spacing: 12) {
            if let image = qrImage(for: card.encoded) {
                Image(uiImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 280, maxHeight: 280)
                    .padding(8)
                    .background(Color.white)
                    .cornerRadius(12)
                    .accessibilityLabel("Pizzini contact QR")
            } else {
                Text("(could not render QR)")
                    .foregroundStyle(.red)
            }
            Text(card.host + ":" + String(card.port))
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
            Text(fingerprint(card.peerId))
                .font(.caption2.monospaced())
                .foregroundStyle(.tertiary)
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

    private func fingerprint(_ data: Data) -> String {
        let bytes = Array(data)
        let head = bytes.prefix(4).map { String(format: "%02x", $0) }.joined()
        let tail = bytes.suffix(4).map { String(format: "%02x", $0) }.joined()
        return "\(head)…\(tail)  (\(bytes.count) B)"
    }
}
