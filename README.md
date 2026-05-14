# Pizzini

A post-quantum, end-to-end encrypted iOS messenger. No phone numbers, no central directory, no metadata. Built for journalists, activists, and anyone who needs Signal-grade privacy without Signal's compromises.

[pizzini.app](https://pizzini.app)

## Design goals

Signal is the reference. Pizzini diverges where Signal made compromises we don't have to:

- **No phone number.** Pairwise random IDs. Pairing happens via QR or invite link, out of band.
- **Tor-only transport.** No clearnet fallback. Sealed sender over onion routing.
- **Stateless relays, app-side fanout across a bundled fleet.** Relays hold no per-user accounts and no plaintext message bodies. The current fleet is three Tor onion services hosted in DE / NO / US — but all three are run by a single operator on one provider, so the "multiple jurisdictions / no single seizable server" property is aspirational: it only holds once independent operators run independent infrastructure. Two routing maps persist across restarts under ChaCha20-Poly1305 with 0600 permissions: the offline-message queue (libsignal-sealed ciphertexts, sender-chosen TTL up to 7 days, per-peer cap) and the APNs push-token map (30-day TTL). Live route tables, verify-key caches, hashcash buckets, and token replay sets stay in memory only and are wiped on restart. Encryption at rest is defence-in-depth against operator mistakes, not against an attacker who has seized the machine.
- **Cryptographic erasure on duress.** Real wipe, not pretend mode.
- **Post-quantum from day one.** PQXDH and Triple Ratchet, via libsignal.
- **Reproducible builds, signed transparency log.** Relay binaries are reproducible under a pinned Docker toolchain (`scripts/build-relay-release.sh`); each SHA-256 is signed by the operator's Ed25519 key and committed to `transparency-log.ndjson`. iOS clients verify the running relay against the log on every reconnect. Multi-maintainer co-signing is a known gap.

## Stack

| Layer | Choice |
|---|---|
| Crypto core | Rust, `libsignal` directly |
| iOS app | Swift + SwiftUI, native only |
| FFI | Rust to Swift via C ABI (cbindgen) |
| Storage | SQLCipher v4.6.1 (vendored amalgamation). Key derivation: Secure-Enclave-resident P-256 → ECIES → 32-byte seed in Keychain → HKDF-SHA-512 → Argon2id (M=64 MiB, T=3, P=1) |
| Transport | Tor via embedded Tor.framework v409.6.1 (iCepa, pinned by SHA-256) |
| Relay | Rust, stateless. Live fleet in DE / NO / US |
| License | AGPL-3.0-or-later |

## Cryptographic primitives

- **KEM**: X25519 + ML-KEM-768 (libsignal PQXDH).
- **Ratchet**: Double Ratchet + SPQR, i.e. libsignal's Triple Ratchet — the PQ ratchet stage Signal deployed in October 2025.
- **Signature**: XEd25519 and Ed25519 throughout (identity keys, delivery-token verify keys, group-op signatures, transparency-log operator key). A post-quantum identity signature (ML-DSA-65 or SLH-DSA-SHA2-128s) is on the roadmap.
- **AEAD**: ChaCha20-Poly1305 for relay state files. libsignal uses AES-256-GCM internally for sealed-sender envelopes.
- **Hash**: BLAKE3 for hashcash, group-op and group-bootstrap digests, delivery-token chains, and SAS digits via BLAKE3-XOF. libsignal uses SHA-256 and SHA-512 internally; application code does not call SHA-3 or SHAKE-256.
- **KDF**: HKDF-SHA-512.
- **Password hashing**: Argon2id (RustCrypto `argon2` 0.5; M=64 MiB, T=3, P=1, per OWASP 2025 mobile guidance). Two call sites: SQLCipher key derivation and the app and duress passcode verification slots.

## Hard rules

- No custom crypto. libsignal does the work.
- No phone-number-based identity, ever.
- No clearnet transport. (One exception: the transparency-log fetch from `raw.githubusercontent.com` goes over plain HTTPS.)
- No analytics, telemetry, or third-party SDKs.
- No automatic media loading. Pegasus 2021 was an iMessage zero-click via image parsing.
- No in-app preview of any attachment. Text, image, archive — all the same. Recipient taps "Save to Files" and the OS owns what's inside.
- No auto-download of attachments. The chunked-attachment flow only fires once both peers are paired and the user is in the chat. No thumbnail generation, no in-app archive extraction, no in-app PDF rendering.
- Attachment bytes live only in `Application Support/attachments/` with `FileProtectionType.completeUntilFirstUserAuthentication`, excluded from iCloud backup. Never `PHPhotoLibrary`, never `Documents/`.
- iOS Lockdown Mode must work.

## Architecture

Tor-only transport; three multi-jurisdiction independent onion services with app-side fanout (rather than an OnionBalance frontend); numeric onion vanity prefixes (`pizzini2/3/4` are the live relays; the trailing digit is drawn from Tor v3 base32's `a-z` + `2-7` alphabet, so `pizzini5/6/7` are the unused slots); a bundled relay allowlist with a BYO override.

## Repo layout

```
pizzini/
├── pizzini/         iOS app (Xcode project, SwiftUI)
├── crypto-core/     Rust crate: libsignal wrapper, FFI surface
├── relay/           Rust crate: stateless Tor relay
├── swift/           Swift wrapper consuming the XCFramework
├── scripts/         Build helpers (XCFramework, reproducible relay builds)
├── Package.swift    SwiftPM manifest at repo root
├── Cargo.toml       Rust workspace
└── build/           generated XCFramework (gitignored)
```

## Building

```sh
# Rust workspace, including the PQXDH roundtrip example
cargo test --workspace
cargo run --example pqxdh_roundtrip -p pizzini-crypto-core

# iOS XCFramework (device + Apple Silicon simulator)
scripts/build-xcframework.sh                # release
PROFILE=debug scripts/build-xcframework.sh  # dev

# Embedded Tor static library + headers, pinned by SHA-256 to iCepa
# Tor.framework v409.6.1. Re-run with REBUILD=1 to refresh after a script bump.
scripts/build-tor-xcframework.sh

# Swift package tests on simulator
xcodebuild test -scheme PizziniCryptoCore \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
```

## Wiring crypto-core into the iOS app

The repo root is a SwiftPM package (`Package.swift`) that wraps the XCFramework. To consume it from the Xcode app target:

1. Run `scripts/build-xcframework.sh` once to produce `build/PizziniCryptoCore.xcframework`, and `scripts/build-tor-xcframework.sh` once to produce `build/Tor.xcframework` and stage headers under `swift/Sources/PizziniTorObjC/torheaders/`. The Tor xcframework provides the embedded daemon that `RelayClient` routes `.onion` targets through.
2. In Xcode, choose *File → Add Package Dependencies… → Add Local…* and select the repo root.
3. On the `pizzini` app target, add `PizziniCryptoCore` to *Frameworks, Libraries, and Embedded Content*.
4. In Swift, `import PizziniCryptoCore`.

Regenerate the XCFramework whenever the Rust FFI changes; Xcode will pick up the new binary on next build.

## Status

Pizzini is in pre-audit private beta. The protocol surface, storage layer, and relay fleet are feature-complete. Remaining work is the first external audit and App Attest plus ATS strict enforcement.

Shipping today:

- PQXDH and Triple Ratchet end-to-end, sealed sender, recipient-issued v2 delivery tokens (BLAKE3 hash chains), and first-contact hashcash PoW.
- Multi-relay Tor onion fanout across a three-relay fleet hosted in Germany, Norway, and the USA (one operator, one provider — independent-operator deployment is still future work). App-side broadcast; libsignal's `SealedSenderResult.isDuplicate` handles receive dedup. APNs push registers on exactly one primary relay so an offline-recipient burst doesn't produce N wake-ups.
- Persistent offline-message queue at each relay (ChaCha20-Poly1305, sender-chosen TTL up to 7 days, per-peer cap). APNs payloads carry no peer information; a Notification Service Extension increments the app-icon badge while the app is force-quit.
- Group chat: sender-key fanout, explicit invitation accept and decline, chunked sealed-sender attachments, per-recipient outbox with ⏳ / ✓ / ✓✓ / 👁 / ✗ status, panic-mode wipe.
- Storage: SQLCipher v4.6.1, eleven normalised tables, Argon2id-stretched key derivation from a Secure-Enclave-wrapped seed. One-shot Keychain to SQLCipher migration with verify-before-delete.
- Global chat and message search with in-chat find-bar and deep-link to the cited row.
- App-wide screenshot shield, unconditional: the app window's layer is reparented under a secure-text-entry render-suppressed layer (the view hierarchy itself is left untouched), with a runtime self-test and degraded-mode notice if the mask cannot resolve on the running iOS version. A separate live overlay blanks chat, group chat, contacts, attachment viewers, and settings while iOS reports recording or an external display.
- App-level biometric lock (Face ID and passcode), duress passcode with cryptographic-erasure wipe to an empty-but-lived-in state. Every chat / contact / key / outbox row is gone; only the relay host and the screenshot-self-test cache survive. Face ID, auto-lock, panic mode, and onboarding state are *deliberately* reset to fresh-install defaults — preserving them would make the post-wipe device distinguishable from a clean install.
- Device-integrity warnings: jailbreak indicators, debugger attach in release builds, hook-framework dylib scan via `_dyld_image_*`. Detection only, never refuses to run, no telemetry.
- Reproducible relay builds via `scripts/build-relay-release.sh` (Docker-pinned `rust:1.95.0-bookworm`, offline `cargo vendor`, `--remap-path-prefix`, `SOURCE_DATE_EPOCH` pinned to the commit timestamp).

Pending:

- App Attest and ATS strict.
- First paid external audit.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
