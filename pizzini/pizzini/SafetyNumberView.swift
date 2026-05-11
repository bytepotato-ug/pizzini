import PizziniCryptoCore
import SwiftUI

/// Out-of-band verification screen for a 1:1 contact's safety number.
///
/// The 60-digit symmetric code shown here is derived from both
/// identity public keys in the Rust core
/// (`pizzini_safety_number_derive`). It is the user-visible answer to
/// the "what if someone copies their identity into WhatsApp" attack:
/// if a network-positioned attacker substitutes either side's
/// identity bytes in transit, Alice's screen and Bob's screen show
/// different digits. Read aloud over a voice call or compared in
/// person, the mismatch surfaces the MITM before the chat starts to
/// be useful.
///
/// The view is presented as a sheet from `ChatView`'s ⋯ menu. It
/// reads + mutates only one row of `ChatStore.state.contacts` (the
/// chat being verified). Re-rendering on every `verifiedAt` change is
/// intentional — the user pressing "matches" must flip the banner
/// without dismissing the sheet, so they can immediately see they're
/// in the green state.
struct SafetyNumberView: View {
    @Bindable var store: ChatStore
    let contactID: UUID
    @Environment(\.dismiss) private var dismiss

    private var contact: Contact? {
        store.state.contacts.first { $0.id == contactID }
    }

    var body: some View {
        NavigationStack {
            if let contact, let sas = store.safetyNumber(for: contact) {
                content(contact: contact, safetyNumber: sas)
            } else {
                missingState
            }
        }
    }

    private func content(contact: Contact, safetyNumber: String) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                stateBanner(for: contact)
                explanation(for: contact)
                codeBlock(safetyNumber)
                instructions(for: contact)
                actions(for: contact)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle("Safety number")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Done") { dismiss() }
            }
        }
    }

    // MARK: - Sections

    /// Top-of-sheet status pill. Mirrors the three-state
    /// `ContactVerificationState` from `Models.swift` — colour is the
    /// load-bearing cue for users skimming the screen.
    @ViewBuilder
    private func stateBanner(for contact: Contact) -> some View {
        let (icon, title, subtitle, tint): (String, String, String, Color) = {
            switch contact.verificationState {
            case .verified:
                let when = contact.verifiedAt.map { Self.dateFormatter.string(from: $0) } ?? "earlier"
                return (
                    "checkmark.seal.fill",
                    "Verified",
                    "You confirmed this safety number with \(contact.displayName) on \(when).",
                    .green
                )
            case .scannedUnverified:
                return (
                    "qrcode.viewfinder",
                    "Scanned in person",
                    "You scanned \(contact.displayName)'s QR code on this device. Compare the safety number to upgrade to full trust.",
                    .orange
                )
            case .pastedUnverified:
                return (
                    "exclamationmark.triangle.fill",
                    "Pasted — not yet verified",
                    "This identity was pasted from another app. Anything could have edited the bytes in transit. Compare the safety number with \(contact.displayName) before sharing anything sensitive.",
                    .red
                )
            }
        }()
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(.white)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.subheadline.weight(.semibold)).foregroundStyle(.white)
                Text(subtitle).font(.caption).foregroundStyle(.white.opacity(0.95))
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12).fill(tint))
    }

    private func explanation(for contact: Contact) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Why this matters")
                .font(.subheadline.weight(.semibold))
            Text(
                """
                The 60 digits below are computed from your identity and \
                \(contact.displayName)'s. Both phones show the same digits \
                when nothing is wrong. If someone replaced an identity \
                while you were sharing them — through SMS, another \
                messenger, or a photo of a QR — the digits won't match.
                """
            )
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    private func codeBlock(_ sas: String) -> some View {
        let groups = sas.split(separator: " ").map(String.init)
        // Two columns of six groups feels tighter for hand-to-hand
        // reading than a single 12-row column, and stays inside the
        // narrow iPhone safe area without the digits shrinking below
        // accessible size at the default Dynamic Type setting.
        let columns = [GridItem(.flexible(), spacing: 16), GridItem(.flexible(), spacing: 16)]
        return VStack(alignment: .leading, spacing: 8) {
            Text("Compare these digits")
                .font(.subheadline.weight(.semibold))
            LazyVGrid(columns: columns, alignment: .leading, spacing: 8) {
                ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                    Text(group)
                        .font(.system(.title3, design: .monospaced).weight(.medium))
                        .accessibilityLabel(Self.accessibilityReading(of: group))
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 12).fill(Color(.secondarySystemBackground)))
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Safety number: \(Self.accessibilityReading(of: sas))")
        }
    }

    private func instructions(for contact: Contact) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("How to compare")
                .font(.subheadline.weight(.semibold))
            Text("1. Call \(contact.displayName) — voice or video, not a messenger they could have lost.")
            Text("2. Read the digits to each other group by group.")
            Text("3. If every group matches, tap \"They match\". If even one differs, tap \"They don't match\" and reach out by another channel — do not send anything sensitive.")
        }
        .font(.caption)
        .foregroundStyle(.secondary)
    }

    @ViewBuilder
    private func actions(for contact: Contact) -> some View {
        VStack(spacing: 8) {
            if contact.verifiedAt == nil {
                Button {
                    store.markVerified(contactId: contact.id)
                } label: {
                    Label("They match — mark as verified", systemImage: "checkmark.seal.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                Button(role: .destructive) {
                    store.clearVerification(contactId: contact.id)
                    // Leave the sheet open so the user can re-check the
                    // digits and pivot — closing it would hide the very
                    // information they need to debug "wait, is this the
                    // right person?"
                } label: {
                    Label("They don't match", systemImage: "exclamationmark.triangle")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
            } else {
                Button(role: .destructive) {
                    store.clearVerification(contactId: contact.id)
                } label: {
                    Label("Mark as not verified", systemImage: "arrow.uturn.backward")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(.top, 8)
    }

    private var missingState: some View {
        VStack(spacing: 12) {
            Image(systemName: "questionmark.app.dashed")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text("Safety number unavailable")
                .font(.headline)
            Text("Pizzini is still loading your identity. Try again in a moment.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Button("Close") { dismiss() }
                .buttonStyle(.bordered)
                .padding(.top, 8)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("Safety number")
        .navigationBarTitleDisplayMode(.inline)
    }

    // MARK: - Helpers

    /// Space-separates each digit so VoiceOver reads "one two three"
    /// instead of pronouncing "12345" as twelve-thousand-three-hundred-
    /// forty-five. Critical for users who actually rely on assistive
    /// tech to perform the comparison.
    private static func accessibilityReading(of digits: String) -> String {
        digits.map { c in c == " " ? "," : String(c) }.joined(separator: " ")
    }

    private static let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()
}

/// Inline strip rendered above the chat composer when the contact
/// hasn't been SAS-verified yet. Tap → opens `SafetyNumberView`.
/// Hidden the moment `verifiedAt` is set, even mid-session.
struct VerificationBanner: View {
    let contact: Contact
    let onVerify: () -> Void

    var body: some View {
        let (icon, headline, tint): (String, String, Color) = {
            switch contact.verificationState {
            case .verified:
                return ("checkmark.seal.fill", "", .clear) // hidden
            case .scannedUnverified:
                return ("qrcode.viewfinder", "Compare safety number to fully verify", .orange)
            case .pastedUnverified:
                return ("exclamationmark.triangle.fill", "Identity was pasted — verify safety number before sharing", .red)
            }
        }()
        if contact.verificationState != .verified {
            Button(action: onVerify) {
                HStack(spacing: 10) {
                    Image(systemName: icon)
                        .foregroundStyle(.white)
                    Text(headline)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.white)
                        .multilineTextAlignment(.leading)
                    Spacer(minLength: 0)
                    Image(systemName: "chevron.right")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.white)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(tint)
            }
            .buttonStyle(.plain)
            .accessibilityHint("Opens the safety-number comparison screen")
        }
    }
}
