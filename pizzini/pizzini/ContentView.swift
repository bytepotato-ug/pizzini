//
//  ContentView.swift
//  pizzini
//
//  Created by username on 08.05.26.
//

import SwiftUI
import UIKit
import PizziniCryptoCore

struct ContentView: View {
    @State private var store = ChatStore.shared
    @State private var lockManager = LockManager.shared
    @State private var showScanner = false
    @State private var showMyQR = false
    @State private var showRelaySheet = false
    @State private var showSecuritySheet = false
    @State private var confirmDeleteAllChats = false
    @State private var confirmReset = false
    @State private var pendingCard: ContactCard?
    @State private var pendingName: String = ""

    var body: some View {
        // The body deliberately does NOT depend on `Environment(\.scenePhase)`
        // — see LockManager's header doc for why. Privacy shielding and
        // the lock overlay are driven exclusively by `lockManager.isShielded`
        // / `lockManager.isLocked`, which are mutated by the four
        // `.onReceive` hooks below at exactly the right lifecycle points.
        // Animations are intentionally absent: a fade would let chat
        // content peek through during the transition.
        ZStack {
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
                            showSecuritySheet: $showSecuritySheet,
                            confirmDeleteAllChats: $confirmDeleteAllChats,
                            confirmReset: $confirmReset,
                            onPasteContact: promptForName(decoding:)
                        )
                    }
                }
            }

            // Lock overlay covers the chat UI when the app is locked. By
            // the time `isLocked` flips to true on a foreground transition,
            // `isShielded` is also still true (cleared only after this),
            // so any frame in between renders the shield, not the chat.
            if lockManager.isLocked {
                LockOverlayView(lockManager: lockManager)
            }

            // Privacy shield. Set on `willDeactivate` so it's already in
            // place by the time iOS captures the multitasking snapshot;
            // cleared on `didActivate` after the lock decision has run.
            if lockManager.isShielded {
                PrivacyShieldView()
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScene.willDeactivateNotification)) { _ in
            lockManager.handleWillDeactivate()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScene.didEnterBackgroundNotification)) { _ in
            lockManager.handleDidEnterBackground()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScene.willEnterForegroundNotification)) { _ in
            lockManager.handleWillEnterForeground()
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScene.didActivateNotification)) { _ in
            lockManager.handleDidActivate()
        }
        .fullScreenCover(isPresented: Binding(
            get: { !store.state.onboardingCompleted && store.initError == nil },
            set: { _ in }
        )) {
            OnboardingView { enableBiometric in
                store.completeOnboarding(enableBiometric: enableBiometric)
            }
        }
        .sheet(isPresented: $showScanner) {
            QRScannerView(
                onScanned: { value in
                    showScanner = false
                    promptForName(decoding: value)
                },
                onCancel: { showScanner = false }
            )
        }
        .alert(
            "Add contact",
            isPresented: Binding(
                get: { pendingCard != nil },
                set: { isPresented in
                    if !isPresented { resetPending() }
                }
            ),
            presenting: pendingCard
        ) { card in
            TextField("name (e.g. Alice)", text: $pendingName)
                .textInputAutocapitalization(.words)
            Button("Cancel", role: .cancel) { resetPending() }
            Button("Add") {
                store.addContact(card: card, displayName: pendingName)
                resetPending()
            }
        } message: { card in
            Text("Fingerprint \(card.fingerprintShort)\nVerify it matches the QR you scanned in person.")
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
        .sheet(isPresented: $showSecuritySheet) {
            SecuritySettingsView(store: store, onClose: { showSecuritySheet = false })
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

    private func promptForName(decoding raw: String) {
        guard let card = ContactCard.decode(raw) else { return }
        pendingName = ""
        pendingCard = card
    }

    private func resetPending() {
        pendingCard = nil
        pendingName = ""
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
