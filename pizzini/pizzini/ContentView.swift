//
//  ContentView.swift
//  pizzini
//
//  Created by username on 08.05.26.
//

import SwiftUI
import PizziniCryptoCore

struct ContentView: View {
    @State private var store = ChatStore.shared
    @State private var showScanner = false
    @State private var showMyQR = false
    @State private var showRelaySheet = false
    @State private var confirmDeleteAllChats = false
    @State private var confirmReset = false

    var body: some View {
        Group {
            if let err = store.initError {
                errorState(err)
            } else {
                NavigationStack {
                    ContactsListView(
                        store: store,
                        showScanner: $showScanner,
                        showMyQR: $showMyQR,
                        showRelaySheet: $showRelaySheet,
                        confirmDeleteAllChats: $confirmDeleteAllChats,
                        confirmReset: $confirmReset
                    )
                }
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
        .sheet(isPresented: $showMyQR) {
            MyQRSheet(card: store.myCard, onDone: { showMyQR = false })
        }
        .sheet(isPresented: $showRelaySheet) {
            RelaySettingsSheet(
                host: store.state.relayHost,
                onSave: { newHost in
                    store.setRelayHost(newHost)
                    showRelaySheet = false
                },
                onCancel: { showRelaySheet = false }
            )
        }
        .confirmationDialog(
            "Delete all chats? Contacts and sessions stay; only message logs are wiped.",
            isPresented: $confirmDeleteAllChats,
            titleVisibility: .visible
        ) {
            Button("Delete all chats", role: .destructive) {
                store.deleteAllChats()
            }
            Button("Cancel", role: .cancel) {}
        }
        .confirmationDialog(
            "Reset identity? This wipes contacts, sessions, and your keypair. Peers will need to rescan you.",
            isPresented: $confirmReset,
            titleVisibility: .visible
        ) {
            Button("Reset identity", role: .destructive) {
                store.resetIdentity()
            }
            Button("Cancel", role: .cancel) {}
        }
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

private struct MyQRSheet: View {
    let card: ContactCard?
    let onDone: () -> Void

    var body: some View {
        NavigationStack {
            VStack(spacing: 18) {
                if let card {
                    ContactCardView(card: card)
                    Button {
                        UIPasteboard.general.string = card.encoded
                    } label: {
                        Label("Copy contact string", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.bordered)
                } else {
                    ProgressView("preparing identity…")
                }
                Text("Show this to a peer in person and have them scan it. They show theirs back to you. After both scans, chat unlocks.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
                Spacer()
            }
            .padding(.top, 24)
            .navigationTitle("Your QR")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done", action: onDone)
                }
            }
        }
    }
}

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
