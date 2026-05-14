import PizziniCryptoCore
import SwiftUI

/// USP #1: shows the running relay's self-attestation (binary
/// SHA-256, git commit SHA, dirty bit, crate version) so users
/// can verify which build is actually serving them.
///
/// The trust chain works like this:
///
///   1. The relay code is open (this repo).
///   2. A reproducible-build script (`scripts/build-relay-release.sh`)
///      compiles a deterministic binary from a clean git checkout
///      and prints its SHA-256 + commit SHA.
///   3. The operator publishes that pair in a signed transparency
///      log entry alongside every deploy.
///   4. The relay computes its own SHA-256 at startup (over the
///      bytes of `/proc/self/exe`) and returns it via the
///      STATUS_RESPONSE frame.
///   5. This view shows the relay's reported values; the user (or
///      an auditor) compares them against the operator-published
///      log entry. Mismatch → either a stale published entry
///      (operator missed a redeploy) or a tampered binary.
///
/// Step 5 is the user-facing side; the in-band comparison against
/// a fetched transparency log is on the roadmap.
struct RelayAttestationView: View {
    @Bindable var store: ChatStore

    var body: some View {
        List {
            switch store.relayState {
            case .connected:
                if let status = store.relayStatus {
                    statusSection(status)
                } else {
                    Section {
                        loadingRow
                    } footer: {
                        Text("The relay hasn't responded to our STATUS_REQUEST yet. This usually resolves within a few seconds of connecting.")
                    }
                }
            case let .connectingToTor(progress):
                Section {
                    Label("Connecting to Tor… \(progress)%", systemImage: "hourglass")
                        .foregroundStyle(.secondary)
                }
            case .connecting:
                Section {
                    Label("Connecting to relay…", systemImage: "hourglass")
                        .foregroundStyle(.secondary)
                }
            case .idle, .failed:
                Section {
                    Label("Relay is offline", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                } footer: {
                    Text("Attestation information is only available while the app is connected to the relay.")
                }
            }
            explainerSection
        }
        .navigationTitle("Relay attestation")
        .navigationBarTitleDisplayMode(.inline)
    }

    @ViewBuilder
    private func statusSection(_ status: RelayStatus) -> some View {
        Section {
            attestRow(label: "Crate version", value: status.crateVersion)
            attestRow(label: "Protocol", value: "v\(status.protocolVersion)")
            attestRow(label: "Build state", value: buildStateLabel(status.gitDirty))
        } header: {
            Text("Running build")
        }

        Section {
            attestRow(label: "Commit", value: status.gitSha, copyable: true)
        } header: {
            Text("Source commit")
        } footer: {
            Text("Compare this SHA against the git tag in the transparency log for the operator's last announced deploy.")
        }

        Section {
            attestRow(label: "SHA-256", value: hex(status.binarySha256), copyable: true, monospaced: true)
        } header: {
            Text("Binary digest")
        } footer: {
            Text("Should match the value `sha256sum` reports for the operator-published `pizzini-relay` artifact. A mismatch means the running binary differs from any audited build.")
        }

        transparencyLogSection(reportedSha256: hex(status.binarySha256))
    }

    /// USP #1 second half UI: green/red badge for "running binary
    /// SHA appears in the operator-signed transparency log,"
    /// plus a manual refresh button + last-fetched timestamp +
    /// error surfacing.
    @ViewBuilder
    private func transparencyLogSection(reportedSha256 sha: String) -> some View {
        let keyConfigured = TransparencyLogConfig.operatorVerifyKey != nil
        let urlConfigured = TransparencyLogConfig.logURL != nil

        if !keyConfigured {
            Section {
                HStack(spacing: 10) {
                    Image(systemName: "questionmark.circle")
                        .foregroundStyle(.secondary)
                    Text("Transparency log not configured for this build.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("Verified against transparency log")
            } footer: {
                Text("This build of the iOS app doesn't include an operator verify key, so the binary digest above is informational only. Re-flash with TransparencyLogConfig.operatorVerifyKeyBase64 set to enable in-band verification.")
            }
        } else {
            Section {
                statusRow(reportedSha256: sha)
                if urlConfigured {
                    refreshControlRow
                }
                if let err = store.transparencyLogError {
                    errorRow(err)
                }
            } header: {
                Text("Verified against transparency log")
            } footer: {
                statusFooter(reportedSha256: sha, urlConfigured: urlConfigured)
            }
        }
    }

    /// The single primary line, driven by the connection-layer
    /// `relayAttestationVerdict` (computed on every reconnect, not
    /// lazily here). Four states — and crucially "could not verify"
    /// is amber+warning, NOT a neutral grey "not loaded yet": an
    /// adversary who simply blocks the log fetch must not be able to
    /// present an unverifiable relay as if it were merely awaiting a
    /// first fetch. The amber state is coupled to the same
    /// `.unverifiable` verdict that feeds the (decision-gated)
    /// enforcement path in `ChatStore.didReceiveStatus`.
    @ViewBuilder
    private func statusRow(reportedSha256 sha: String) -> some View {
        switch store.relayAttestationVerdict {
        case .verified:
            HStack(spacing: 10) {
                Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                Text("This relay matches a signed operator log entry.")
                    .font(.caption)
            }
        case .mismatch:
            HStack(spacing: 10) {
                Image(systemName: "exclamationmark.shield.fill").foregroundStyle(.red)
                Text("This relay is NOT in any signed log entry.")
                    .font(.caption.weight(.semibold))
            }
        case .unverifiable:
            HStack(spacing: 10) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text("Could not verify this relay — the transparency log is unavailable.")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.orange)
            }
        case .notEvaluated:
            HStack(spacing: 10) {
                Image(systemName: "hourglass").foregroundStyle(.secondary)
                Text("Verifying this relay against the transparency log…")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    /// Manual refresh + last-fetched timestamp. Single row so the
    /// section stays compact.
    private var refreshControlRow: some View {
        HStack(spacing: 10) {
            Button {
                store.refreshTransparencyLog()
            } label: {
                Label("Refresh log", systemImage: "arrow.clockwise")
                    .font(.caption)
            }
            .buttonStyle(.plain)
            Spacer(minLength: 0)
            if let last = store.transparencyLogLastFetched {
                Text("Fetched \(Self.relativeTime.localizedString(for: last, relativeTo: Date()))")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// One-line summary of the latest fetch error. Uses
    /// `caption2` so the error doesn't dominate the section.
    private func errorRow(_ err: TransparencyLog.FetchError) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(.orange)
            Text(Self.errorMessage(err))
                .font(.caption2)
                .foregroundStyle(.orange)
        }
    }

    private func statusFooter(reportedSha256 sha: String, urlConfigured: Bool) -> Text {
        switch store.relayAttestationVerdict {
        case .verified:
            return Text("The running binary's SHA-256 was signed by the operator into the public transparency log. The relay is running an audited build.")
        case .mismatch:
            return Text("The running binary's SHA-256 does not appear in the operator's signed transparency log. Possible causes: a brand-new deploy the operator hasn't announced yet, a stale log on your device, or a tampered binary on the server. Do not send sensitive messages until the operator publishes a matching entry.")
        case .unverifiable:
            if urlConfigured {
                return Text("The transparency log could not be verified — the fetch failed, was blocked, or returned no signed entries. Until it loads, this relay's binary cannot be checked against any audited build. Tap Refresh log to retry.")
            } else {
                return Text("No log URL configured. Set TransparencyLogConfig.logURLString to enable automatic fetching. Without it, this relay's binary cannot be verified.")
            }
        case .notEvaluated:
            return Text("Verification runs automatically on every reconnect. Each log entry's signature is checked against the operator's pinned public key.")
        }
    }

    /// Human-readable message for each fetch-error case. Kept
    /// short so the inline `caption2` row stays readable on the
    /// narrowest iPhone width.
    private static func errorMessage(_ err: TransparencyLog.FetchError) -> String {
        switch err {
        case .urlNotConfigured: return "Log URL not configured."
        case .http(let detail): return "Fetch failed: \(detail)."
        case .empty: return "Fetched log was empty or had no valid entries."
        case .rollback: return "Fetched log is older than the cached one — refusing (possible attack)."
        case .cache(let detail): return "Cache write failed: \(detail)."
        }
    }

    private static let relativeTime: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f
    }()

    private func buildStateLabel(_ dirty: UInt8) -> String {
        switch dirty {
        case 0: return "Clean (reproducible-build eligible)"
        case 1: return "Dirty (dev build — do not deploy)"
        case 2: return "Unknown (built outside a git checkout)"
        default: return "Unrecognized (\(dirty))"
        }
    }

    private var loadingRow: some View {
        HStack(spacing: 10) {
            ProgressView()
            Text("Requesting attestation…")
                .foregroundStyle(.secondary)
        }
    }

    private var explainerSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                Text("How this works")
                    .font(.subheadline.weight(.semibold))
                Text(
                    """
                    The relay reports the SHA-256 of its own binary every time \
                    this app connects. The operator publishes a signed log of \
                    every deploy listing the matching SHA. If the relay's \
                    reported SHA isn't in that log, the binary on the server \
                    differs from any source you can audit.
                    """
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
    }

    private func attestRow(
        label: String,
        value: String,
        copyable: Bool = false,
        monospaced: Bool = false,
    ) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(minWidth: 90, alignment: .leading)
            Text(value)
                .font(monospaced ? .caption.monospaced() : .body)
                .multilineTextAlignment(.leading)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            if copyable {
                Button {
                    UIPasteboard.general.setItems(
                        [[UIPasteboard.typeAutomatic: value]],
                        options: [
                            .localOnly: true,
                            .expirationDate: Date().addingTimeInterval(60),
                        ],
                    )
                } label: {
                    Image(systemName: "doc.on.doc")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Copy \(label)")
            }
        }
        .padding(.vertical, 2)
    }

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
