//
//  ContentView.swift
//  pizzini
//
//  Created by username on 08.05.26.
//

import SwiftUI
import PizziniCryptoCore

struct ContentView: View {
    @State private var model: ChatModel?
    @State private var initError: String?
    @State private var draft: String = ""
    @State private var sender: Sender = .alice

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if let model {
                messages(model: model)
                Divider()
                composer(model: model)
            } else if let initError {
                errorState(initError)
            } else {
                ProgressView("starting session…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .task {
            do {
                model = try ChatModel()
            } catch {
                initError = String(describing: error)
            }
        }
    }

    private var header: some View {
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
        .padding()
    }

    private func messages(model: ChatModel) -> some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 12) {
                    if model.messages.isEmpty {
                        emptyState
                    } else {
                        ForEach(model.messages) { m in
                            MessageRow(message: m).id(m.id)
                        }
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 12)
            }
            .onChange(of: model.messages.count) { _, _ in
                if let last = model.messages.last {
                    withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Text("session ready")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Text("alice and bob have completed PQXDH.\nfirst message will be a PreKey signal,\nsubsequent ones flip to Whisper after a reply.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.top, 48)
    }

    private func composer(model: ChatModel) -> some View {
        VStack(spacing: 10) {
            Picker("sender", selection: $sender) {
                Text("Alice").tag(Sender.alice)
                Text("Bob").tag(Sender.bob)
            }
            .pickerStyle(.segmented)

            HStack {
                TextField("type a message", text: $draft)
                    .textFieldStyle(.roundedBorder)
                    .submitLabel(.send)
                    .onSubmit { send(model: model) }
                Button {
                    send(model: model)
                } label: {
                    Image(systemName: "paperplane.fill")
                        .padding(.horizontal, 4)
                }
                .buttonStyle(.borderedProminent)
                .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding()
    }

    private func send(model: ChatModel) {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        model.send(text, from: sender)
        draft = ""
    }

    private func errorState(_ msg: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.largeTitle)
                .foregroundStyle(.red)
            Text("session init failed")
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

// MARK: - Model

enum Sender: String, Sendable {
    case alice, bob
}

struct ChatMessage: Identifiable, Sendable {
    let id = UUID()
    let sender: Sender
    let text: String
    let ciphertextBytes: Int
    let messageType: LoopbackSession.MessageType
}

@MainActor
@Observable
final class ChatModel {
    var messages: [ChatMessage] = []
    private let session: LoopbackSession

    init() throws {
        self.session = try LoopbackSession()
    }

    func send(_ text: String, from sender: Sender) {
        do {
            let result: LoopbackSession.SendResult
            switch sender {
            case .alice: result = try session.aliceSend(text)
            case .bob:   result = try session.bobSend(text)
            }
            messages.append(ChatMessage(
                sender: sender,
                text: text,
                ciphertextBytes: result.ciphertext.count,
                messageType: result.messageType
            ))
        } catch {
            messages.append(ChatMessage(
                sender: sender,
                text: "[error: \(error)]",
                ciphertextBytes: 0,
                messageType: .preKey
            ))
        }
    }
}

// MARK: - Message bubble

struct MessageRow: View {
    let message: ChatMessage

    var body: some View {
        HStack(alignment: .bottom) {
            if message.sender == .bob { Spacer(minLength: 32) }
            VStack(alignment: message.sender == .alice ? .leading : .trailing, spacing: 4) {
                Text(message.text)
                    .font(.body)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(bubbleColor)
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                metadata
            }
            if message.sender == .alice { Spacer(minLength: 32) }
        }
    }

    private var bubbleColor: Color {
        switch message.sender {
        case .alice: return Color.blue.opacity(0.18)
        case .bob:   return Color.green.opacity(0.18)
        }
    }

    private var metadata: some View {
        HStack(spacing: 6) {
            Text(message.sender.rawValue)
                .foregroundStyle(.secondary)
            Text("·")
                .foregroundStyle(.tertiary)
            Text(message.messageType == .preKey ? "PreKey" : "Whisper")
                .foregroundStyle(message.messageType == .preKey ? .orange : .green)
            Text("·")
                .foregroundStyle(.tertiary)
            Text("\(message.ciphertextBytes) B")
                .foregroundStyle(.secondary)
        }
        .font(.caption2.monospaced())
    }
}

#Preview {
    ContentView()
}
