//
//  ContentView.swift
//  pizzini
//
//  Created by username on 08.05.26.
//

import SwiftUI
import PizziniCryptoCore

struct ContentView: View {
    @State private var keypairBytes: Int?
    @State private var error: String?

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield")
                .imageScale(.large)
                .foregroundStyle(.tint)
                .font(.system(size: 48))

            Text("Pizzini")
                .font(.title)

            VStack(alignment: .leading, spacing: 8) {
                row("crypto-core", PizziniCryptoCore.version)
                if let n = keypairBytes {
                    row("identity keypair", "\(n) bytes")
                } else if let e = error {
                    row("error", e)
                } else {
                    row("identity keypair", "—")
                }
            }
            .font(.system(.body, design: .monospaced))

            Button("Generate identity") {
                do {
                    keypairBytes = try IdentityKeyPair.generate().bytes.count
                    error = nil
                } catch {
                    self.error = String(describing: error)
                    keypairBytes = nil
                }
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value)
        }
    }
}

#Preview {
    ContentView()
}
