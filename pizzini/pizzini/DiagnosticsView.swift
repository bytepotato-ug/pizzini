import SwiftUI
import PizziniCryptoCore
import UIKit

/// In-app diagnostic view for debugging the group-chat plumbing
/// without wiring up Console.app. Surfaces:
///
///   * Relay connection state and identity-pub fingerprint.
///   * Contact and group counts (incl. pending invitations).
///   * Per-contact delivery-token stash level — depleted stashes
///     are the most common cause of dropped group ops / SKDMs
///     (the design's outbox+retry is deferred to v2).
///   * The most recent 200 group-flow events from
///     `ChatStore.diagEvents`, newest at the top, with category
///     coloring so receive failures stand out.
///   * DEBUG builds only: an "Export QA log" section that hands
///     the persistent `qa.log` file (capturing every diagLog +
///     pzLog event across the test session, including across
///     launches and force-quits) to the iOS share sheet.
///
/// Reached from `Settings → Diagnostics`. The in-memory event
/// buffer resets on app launch; the file-backed QA log does NOT
/// (it persists across launches until the operator taps "Clear
/// QA log").
struct DiagnosticsView: View {
    @Bindable var store: ChatStore

    /// `.sheet(item:)` driver for the UIActivityViewController
    /// share sheet — holds the URL(s) of the log file(s) being
    /// exported. `nil` = sheet not presented.
    @State private var exportTargets: ExportTargets?

    /// Driver for the "are you sure you want to clear the QA log?"
    /// confirmation dialog. iOS-26 destructive button conventions
    /// — the operator should never lose a session's log by
    /// fat-fingering a tap.
    @State private var showClearConfirm = false

    var body: some View {
        Form {
            Section("Identity") {
                if let myCard = store.myCard {
                    LabeledContent("Peer ID", value: short(myCard.peerId))
                } else {
                    LabeledContent("Peer ID", value: "(no card)")
                }
                LabeledContent("Relay", value: store.state.relayHost)
                LabeledContent("Connection", value: connectionLabel)
            }

            Section("Counts") {
                LabeledContent("Contacts", value: "\(store.state.contacts.count)")
                LabeledContent("Groups (joined)",
                               value: "\(store.state.groups.filter { !$0.pendingInvitation }.count)")
                LabeledContent("Pending invitations",
                               value: "\(store.state.groups.filter { $0.pendingInvitation }.count)")
            }

            Section {
                if store.state.contacts.isEmpty {
                    Text("No contacts yet.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(store.state.contacts) { contact in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(contact.displayName)
                                    .font(.body.weight(.medium))
                                Spacer()
                                chainBadge(contact.outboundTokenChain)
                            }
                            Text("\(short(contact.identityPub)) • session: \(contact.sessionEstablished ? "ok" : "pending")")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("Contacts (delivery-token chain)")
            } footer: {
                Text("Each SEND derives one token from this contact's outbound hash chain (peer-minted at pair time; sealed `chainSeedDelivery`). The badge shows tokens remaining; once it reaches 0 we auto-fetch a fresh chain via BUNDLE_REQUEST on the next send. \"none\" means the chain hasn't arrived yet.")
            }

            Section {
                if store.diagEvents.isEmpty {
                    Text("No events captured this session.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(store.diagEvents.reversed()) { event in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(alignment: .firstTextBaseline, spacing: 6) {
                                Text(category(event.category))
                                    .font(.caption2.weight(.semibold).monospaced())
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1)
                                    .background(Capsule().fill(categoryColor(event.category).opacity(0.18)))
                                    .foregroundStyle(categoryColor(event.category))
                                Text(timestamp(event.timestamp))
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(.secondary)
                                Spacer()
                            }
                            Text(event.message)
                                .font(.caption.monospaced())
                                .foregroundStyle(.primary)
                                .textSelection(.enabled)
                        }
                        .padding(.vertical, 2)
                    }
                }
            } header: {
                Text("Recent events (newest first)")
            } footer: {
                Text("Last \(store.diagEvents.count) events captured this session. Lines with REJECTED, NO CONTACT, NO DELIVERY TOKEN, or DROPPED tell you why a group invitation didn't reach the other device.")
            }

            #if DEBUG
            Section {
                if let active = QALog.currentLogFileURL() {
                    HStack {
                        Image(systemName: "doc.text")
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 1) {
                            Text("qa.log")
                                .font(.body.monospaced())
                            Text(fileSizeLabel(active))
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                    if let rotated = QALog.rotatedLogFileURL() {
                        HStack {
                            Image(systemName: "doc.text.below.ecg")
                                .foregroundStyle(.secondary)
                            VStack(alignment: .leading, spacing: 1) {
                                Text("qa.log.1 (previous)")
                                    .font(.body.monospaced())
                                Text(fileSizeLabel(rotated))
                                    .font(.caption2.monospaced())
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    Button {
                        var urls: [URL] = [active]
                        if let rotated = QALog.rotatedLogFileURL() {
                            urls.append(rotated)
                        }
                        exportTargets = ExportTargets(urls: urls)
                    } label: {
                        Label("Share via system share sheet", systemImage: "square.and.arrow.up")
                    }
                    Button(role: .destructive) {
                        showClearConfirm = true
                    } label: {
                        Label("Clear QA log", systemImage: "trash")
                    }
                } else {
                    Text("QA-log file not available (no DEBUG build, or first event hasn't fired yet).")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("QA debug log (DEBUG build only)")
            } footer: {
                Text("DEBUG builds persist every diagLog + pzLog line to qa.log under Application Support/qa-debug/, rotated at 10 MB. Survives app force-quit. File is iCloud-backup-excluded and FileProtectionType.completeUntilFirstUserAuthentication. Production / TestFlight builds compile this section out entirely.")
            }
            #endif
        }
        .navigationTitle("Diagnostics")
        .navigationBarTitleDisplayMode(.inline)
        #if DEBUG
        .sheet(item: $exportTargets) { targets in
            ActivityShareSheet(urls: targets.urls)
        }
        .confirmationDialog(
            "Clear QA log?",
            isPresented: $showClearConfirm,
            titleVisibility: .visible,
        ) {
            Button("Clear", role: .destructive) {
                QALog.clear()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Deletes qa.log (and qa.log.1 if present). New events from after this point will start a fresh file.")
        }
        #endif
    }

    // ─── helpers ────────────────────────────────────────────────────

    private func short(_ data: Data) -> String {
        let head = data.prefix(4).map { String(format: "%02x", $0) }.joined()
        let tail = data.suffix(2).map { String(format: "%02x", $0) }.joined()
        return "\(head)…\(tail)"
    }

    private var connectionLabel: String {
        switch store.relayState {
        case .idle: return "idle"
        case let .connectingToTor(progress): return "connecting to Tor… \(progress)%"
        case .connecting: return "connecting…"
        case .connected: return "connected"
        case let .failed(msg): return "failed: \(msg)"
        }
    }

    private func category(_ raw: String) -> String {
        raw.uppercased()
    }

    private func categoryColor(_ raw: String) -> Color {
        switch raw {
        case "group": return .blue
        case "relay": return .red
        case "pair":  return .green
        default:       return .secondary
        }
    }

    private func timestamp(_ d: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter.string(from: d)
    }

    @ViewBuilder
    private func chainBadge(_ chain: HashChainToken.Chain?) -> some View {
        if let chain {
            let remaining = chain.length - (chain.nextIndex - 1)
            Text("\(remaining) / \(chain.length)")
                .font(.caption2.monospaced().weight(.medium))
                .padding(.horizontal, 6)
                .padding(.vertical, 1)
                .background(Capsule().fill(chainColor(remaining, total: chain.length).opacity(0.18)))
                .foregroundStyle(chainColor(remaining, total: chain.length))
        } else {
            Text("none")
                .font(.caption2.monospaced().weight(.medium))
                .padding(.horizontal, 6)
                .padding(.vertical, 1)
                .background(Capsule().fill(Color.red.opacity(0.18)))
                .foregroundStyle(.red)
        }
    }

    private func chainColor(_ remaining: Int, total: Int) -> Color {
        if remaining == 0 { return .red }
        // Same threshold as `Chain.shouldRotate`: 20% remaining flips
        // to orange so an operator can see the rotation cycle.
        if remaining * 5 < total { return .orange }
        return .green
    }

    #if DEBUG
    /// Human-readable file size for the QA-log row. iOS-native
    /// formatter so the unit matches Files / Mail conventions.
    private func fileSizeLabel(_ url: URL) -> String {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        let bytes = (attrs?[.size] as? UInt64) ?? 0
        return ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }
    #endif
}

#if DEBUG
/// `.sheet(item:)` driver — `Identifiable` so SwiftUI can present
/// the share sheet when the binding flips non-nil and tear it down
/// on dismiss.
private struct ExportTargets: Identifiable {
    let id = UUID()
    let urls: [URL]
}

/// Minimal SwiftUI wrapper around `UIActivityViewController`. The
/// system share sheet handles every share target (AirDrop, Mail,
/// Files, Messages, third-party apps) without us having to spell
/// any of them out. The `.completionWithItemsHandler` is left nil
/// — there's no post-share state we need to mutate locally.
private struct ActivityShareSheet: UIViewControllerRepresentable {
    let urls: [URL]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: urls, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
#endif
