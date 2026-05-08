//
//  ContentView.swift
//  pizzini
//
//  Created by username on 08.05.26.
//

import SwiftUI
import PizziniCryptoCore

struct ContentView: View {
    @State private var store = ChatStore()
    @State private var draft: String = ""
    @State private var showScanner = false
    @State private var showRelaySheet = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if let err = store.initError {
                errorState(err)
            } else if store.peer == nil {
                pairingView
            } else {
                chatView
            }
        }
        .sheet(isPresented: $showScanner) {
            QRScannerView(
                onScanned: { value in
                    showScanner = false
                    store.acceptScannedCard(value)
                },
                onCancel: { showScanner = false }
            )
        }
        .sheet(isPresented: $showRelaySheet) {
            RelaySettingsSheet(
                host: store.relayHost,
                onSave: { newHost in
                    store.setRelayHost(newHost)
                    showRelaySheet = false
                },
                onCancel: { showRelaySheet = false }
            )
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: "lock.shield")
                    .foregroundStyle(.tint)
                Text("Pizzini")
                    .font(.headline)
                Spacer()
                Text(PizziniCryptoCore.version)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 8) {
                relayBadge
                Spacer()
                Menu {
                    Button {
                        showRelaySheet = true
                    } label: {
                        Label("Relay host (\(store.relayHost))", systemImage: "antenna.radiowaves.left.and.right")
                    }
                    Button(role: .destructive) {
                        store.resetIdentity()
                    } label: {
                        Label("Reset identity", systemImage: "arrow.counterclockwise")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                        .font(.caption)
                }
            }
        }
        .padding()
    }

    private var relayBadge: some View {
        let (text, color): (String, Color) = {
            switch store.relayState {
            case .idle:        return ("idle", .gray)
            case .connecting:  return ("connecting", .orange)
            case .connected:   return ("connected", .green)
            case .failed(let m): return ("failed: \(m)", .red)
            }
        }()
        return HStack(spacing: 4) {
            Circle().frame(width: 6, height: 6).foregroundStyle(color)
            Text("relay \(text)")
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
        }
    }

    private var pairingView: some View {
        ScrollView {
            VStack(spacing: 24) {
                if let card = store.myCard {
                    Text("your contact card")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    ContactCardView(card: card)
                }
                Button {
                    showScanner = true
                } label: {
                    Label("Scan a contact's QR", systemImage: "qrcode.viewfinder")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .padding(.horizontal)

                HStack(spacing: 12) {
                    Button {
                        if let card = store.myCard {
                            UIPasteboard.general.string = card.encoded
                        }
                    } label: {
                        Label("Copy mine", systemImage: "doc.on.doc")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    Button {
                        if let s = UIPasteboard.general.string {
                            store.acceptScannedCard(s)
                        }
                    } label: {
                        Label("Paste theirs", systemImage: "doc.on.clipboard")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }
                .padding(.horizontal)

                Text("Both peers must be online on the same relay. After scan/paste, Pizzini fetches the peer's PreKey bundle over the relay, runs PQXDH, and you can chat. Clipboard fallback is for sims (no camera).")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
            .padding(.top, 24)
        }
    }

    private var chatView: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 12) {
                        if store.log.isEmpty {
                            Text("Say hi.")
                                .foregroundStyle(.secondary)
                                .padding(.top, 48)
                        }
                        ForEach(store.log) { entry in
                            ChatRow(entry: entry).id(entry.id)
                        }
                    }
                    .padding(.horizontal)
                    .padding(.vertical, 12)
                }
                .onChange(of: store.log.count) { _, _ in
                    if let last = store.log.last {
                        withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
                .scrollDismissesKeyboard(.interactively)
            }
            Divider()
            HStack {
                TextField("type a message", text: $draft)
                    .textFieldStyle(.roundedBorder)
                    .submitLabel(.send)
                    .onSubmit { sendDraft() }
                Button {
                    sendDraft()
                } label: {
                    Image(systemName: "paperplane.fill")
                        .padding(.horizontal, 4)
                }
                .buttonStyle(.borderedProminent)
                .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding()
        }
    }

    private func sendDraft() {
        store.send(draft)
        draft = ""
    }

    private func errorState(_ msg: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.largeTitle)
                .foregroundStyle(.red)
            Text("init failed")
                .font(.headline)
            Text(msg)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Chat row

struct ChatRow: View {
    let entry: ChatLogEntry

    var body: some View {
        HStack(alignment: .bottom) {
            if entry.side == .peer { Spacer(minLength: 32) }
            VStack(alignment: entry.side == .me ? .leading : .trailing, spacing: 4) {
                Text(entry.text)
                    .font(.body)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(bubbleColor)
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                metadata
            }
            if entry.side == .me { Spacer(minLength: 32) }
        }
    }

    private var bubbleColor: Color {
        switch entry.kind {
        case .system: return Color.gray.opacity(0.15)
        case .preKey, .whisper:
            return entry.side == .me
                ? Color.blue.opacity(0.18)
                : Color.green.opacity(0.18)
        }
    }

    private var metadata: some View {
        HStack(spacing: 6) {
            Text(entry.side == .me ? "me" : "peer")
                .foregroundStyle(.secondary)
            if entry.kind != .system {
                Text("·").foregroundStyle(.tertiary)
                Text(entry.kind == .preKey ? "PreKey" : "Whisper")
                    .foregroundStyle(entry.kind == .preKey ? .orange : .green)
                Text("·").foregroundStyle(.tertiary)
                Text("\(entry.bytes) B").foregroundStyle(.secondary)
            }
        }
        .font(.caption2.monospaced())
    }
}

// MARK: - Relay settings

private struct RelaySettingsSheet: View {
    @State var host: String
    let onSave: (String) -> Void
    let onCancel: () -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("host (e.g. 192.168.x.x)", text: $host)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                } header: {
                    Text("relay host")
                } footer: {
                    Text("Both peers connect to the same relay. Sim → 127.0.0.1; phone → the Mac's LAN IP. Port is fixed at 7777.")
                }
            }
            .navigationTitle("Relay")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { onSave(host) }
                }
            }
        }
    }
}

#Preview {
    ContentView()
}
