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
├── crypto-core/       Rust crate: libsignal wrapper, FFI surface
├── relay/             Rust crate: stateless Tor relay server
├── scripts/           Build helpers (XCFramework, reproducible build)
└── Cargo.toml         Rust workspace
```

## Status

- [x] Repo skeleton
- [x] Rust crypto core (libsignal wrapper, FFI) — minimal: identity keypair gen + cbindgen
- [ ] iOS app skeleton (SwiftUI, Tor.framework, Keychain integration)
- [ ] PQXDH handshake working end-to-end (CLI test client)
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
