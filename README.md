# Pizzini

iOS messenger. Better Signal. End-to-end encrypted, post-quantum, no phone numbers, no metadata. For journalists, activists, and anyone who needs Signal-grade privacy without Signal's compromises (phone-number identity, US jurisdiction, centralized infra).

Domain: pizzini.app

## What "better than Signal" means here

We start from Signal's protocol because it is the gold standard. We diverge where Signal made compromises we don't have to make:

- **No phone number.** Pairwise random IDs, no central directory. Contact via QR / invite link, out of band.
- **Tor-only transport.** No clearnet fallback. Sealed sender + onion routing.
- **Stateless relays in multiple jurisdictions.** No single seizable server.
- **Cryptographic erasure on duress.** Real wipe, not pretend mode.
- **Post-quantum from day one.** PQXDH + Triple Ratchet (already in libsignal as of late 2025).
- **Reproducible builds + multi-maintainer signing.**

Everything else: copy Signal's homework. They got it right.

## Stack (decided)

- **Crypto core:** Rust, using `libsignal` directly. No reinventing.
- **iOS app:** Swift + SwiftUI, native only. No Electron, no React Native, no WebView for content.
- **FFI:** Rust → Swift via C ABI.
- **Storage:** SQLCipher, key in Secure Enclave + Argon2id-derived passphrase.
- **Transport:** Tor via `Tor.framework` (Onion Browser project, established).
- **Server:** Rust, stateless relay, deployed initially in CH/IS/PA.
- **License:** AGPLv3.

## Cryptographic primitives (only these, no others)

- KEM: X25519 + ML-KEM-768 (libsignal's PQXDH)
- Ratchet: Double Ratchet + SPQR (libsignal's Triple Ratchet, deployed by Signal Oct 2025)
- Signature: Ed25519 + ML-DSA-65 hybrid; SLH-DSA-SHA2-128s for long-term identity
- AEAD: ChaCha20-Poly1305
- Hash: SHA-3 / SHAKE-256
- KDF: HKDF-SHA-512
- Password: Argon2id

If you need anything else, stop and ask.

## Hard rules

- No custom crypto. libsignal does the work.
- No phone-number-based identity. Ever.
- No clearnet transport. Tor-only.
- No analytics, no telemetry, no third-party SDKs.
- No automatic media loading (Pegasus 2021 was an iMessage zero-click via image parsing).
- iOS Lockdown Mode must work. Test it.

## Repo layout

```
pizzini/
├── pizzini/           iOS app (Xcode project, SwiftUI)
├── crypto-core/       Rust crate: libsignal wrapper, FFI surface (cbindgen)
├── relay/             Rust crate: stateless Tor relay server
├── swift/             Swift wrapper consuming the XCFramework
├── scripts/           Build helpers (XCFramework, reproducible build)
├── Package.swift      SwiftPM manifest at repo root — adds local-package dep
├── Cargo.toml         Rust workspace
└── build/             generated XCFramework lives here (gitignored)
```

## Building

```sh
# Rust (host) — runs all crypto-core tests including the PQXDH roundtrip
cargo test --workspace
cargo run --example pqxdh_roundtrip -p pizzini-crypto-core

# Build the iOS XCFramework (device + Apple Silicon simulator)
scripts/build-xcframework.sh                # release (default)
PROFILE=debug scripts/build-xcframework.sh  # faster, for dev

# Run the Swift package's iOS-sim tests
xcodebuild test -scheme PizziniCryptoCore \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
```

## Wiring crypto-core into the iOS app

The repo root is also a SwiftPM package (`Package.swift`) that wraps the
XCFramework. To consume it from the Xcode app target:

1. Run `scripts/build-xcframework.sh` once (produces `build/PizziniCryptoCore.xcframework`).
2. In Xcode: `File → Add Package Dependencies… → Add Local…`, select the repo root.
3. On the `pizzini` app target, add the `PizziniCryptoCore` library product to
   "Frameworks, Libraries, and Embedded Content".
4. In Swift code: `import PizziniCryptoCore` and call `PizziniCryptoCore.version`
   or `IdentityKeyPair.generate()`.

After wiring, regenerate the XCFramework whenever the Rust FFI changes; Xcode
will pick up the new binary on next build.

## Status

- [x] Repo skeleton
- [x] Rust crypto core (libsignal wrapper, FFI) — minimal: identity keypair gen + cbindgen
- [ ] iOS app skeleton (SwiftUI, Tor.framework, Keychain integration)
- [x] PQXDH handshake working end-to-end (CLI test client) — `cargo run --example pqxdh_roundtrip`
- [ ] Triple Ratchet messaging working
- [ ] Stateless relay server
- [ ] Contact establishment (QR / invite link)
- [ ] Storage layer (SQLCipher + Secure Enclave)
- [ ] Duress passphrase + cryptographic erasure
- [ ] App Attest + ATS strict
- [ ] Reproducible build script
- [ ] First external audit

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

## Session log (append, don't rewrite)

(Each session adds one line: date — what was done — what's next)

- 2026-05-08 — repo skeleton, Cargo workspace, iOS project renamed pizzini.app→pizzini — next: libsignal wrapper in crypto-core
- 2026-05-08 — libsignal-protocol pinned at v0.93.2; FFI surface for IdentityKeyPair generation; cbindgen header generation wired via build.rs; 5 tests pass — next: PreKey bundle generation + session establishment in crypto-core, then iOS bridging
- 2026-05-08 — full PQXDH handshake roundtrip working in-process (Alice ↔ Bob via InMemSignalProtocolStore), including bidirectional ratchet step (PreKey→Whisper transition); 7 tests pass — next: iOS bridging (XCFramework build phase + Swift wrappers)
- 2026-05-08 — XCFramework build script working (device + arm64 sim); Swift Package at repo root wraps the FFI as `PizziniCryptoCore`; xcodebuild test on iPhone 17 Pro sim — 3/3 Swift tests pass; FFI bridge proven end-to-end Rust → C → Swift on iOS — next: wire local SwiftPM package into the pizzini.xcodeproj app target (manual Xcode click), then start on Tor.framework integration
