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
- [x] iOS app skeleton (SwiftUI + Keychain integration; Tor.framework still TODO)
- [x] PQXDH handshake working end-to-end (CLI test client) — `cargo run --example pqxdh_roundtrip`
- [x] Triple Ratchet messaging working (PreKey → Whisper transition visible across two devices)
- [x] Dev relay (LAN TCP); production Tor onion still TODO
- [x] Contact establishment (QR + clipboard fallback)
- [x] In-app unread indicators (per-contact badge + app-icon total)
- [x] Push notifications (payload-opaque "New message" wake-up; APNs gated on `APNS_*` env vars)
- [x] App-icon badge increments while the app is force-quit (Notification Service Extension + App Group)
- [ ] Offline-recipient message delivery (push wakes the app but SEND ciphertext is currently dropped — needs queueing)
- [ ] Storage layer (SQLCipher + Secure Enclave)
- [ ] Session persistence across launches (currently identity persists, ratchet state does not)
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
- 2026-05-08 — local SwiftPM package wired into the iOS app target (XCSwiftPackageProductDependency + framework link); ContentView smoke-tests `PizziniCryptoCore.version` and `IdentityKeyPair.generate()`; deployed and launched on physical iPhone 15 Pro — 69-byte identity returned across the FFI, screen renders correctly — next: expand FFI to expose actual session APIs
- 2026-05-08 — loopback chat: in-process Alice↔Bob session exposed via opaque-handle FFI (pizzini_loopback_{new,free,alice_send,bob_send}); Swift `LoopbackSession` class wraps it; chat UI in ContentView shows bubbles with sender/type/ciphertext-bytes metadata; Keychain wrapper persists identity bytes between launches; reset menu for both identity and session — next: replace loopback with proper remote-peer FFI (PreKey bundle, session encrypt/decrypt as separate calls), then transport (Tor)
- 2026-05-08 — UX + infra polish: empty-state "Run a demo exchange" button auto-plays a 4-message script; iOS deployment target lowered 26→17 (aligns with Package.swift, opens up CI on macos-15 runners, keeps Lockdown Mode etc.); release-mode XCFramework verified clean (32MB device .a vs 73MB debug); GitHub Actions workflow drafted at .github/workflows/ci.yml (cargo + iOS build + header-drift check) — staged locally, awaits `gh auth refresh -h github.com -s workflow` to push; scrollDismissesKeyboard for chat UX — running on iPhone 15 Pro with persistent identity, ratchet flips visible — next: replace loopback with real remote-peer flow (bundle serialize/deserialize, separate session encrypt/decrypt) so two devices can talk over copy-paste / QR before we wire Tor
- 2026-05-08 — two-device messaging end-to-end: replaced LoopbackState with `DeviceStore` FFI (opaque-handle Session API: identity{Keypair,Public}, publishBundle, initiateSession, encrypt/decrypt over wire bytes; hand-rolled v1 PreKey-bundle wire format documented in store.rs); dev `pizzini-relay` over Tokio TCP on 0.0.0.0:7777 with length-prefixed frames (HELLO/SEND/BUNDLE_REQUEST/BUNDLE_RESPONSE) and stateless drop-on-offline routing (production Tor onion bind is a separate task); Swift `RelayClient` over Network.framework speaks the same protocol; iOS UI rewrite: contact card (QR via CIFilter.qrCodeGenerator, payload `pizzini1://<peerHex>@<host>:<port>`), AVCapture-based QR scanner with NSCameraUsageDescription wired in pbxproj, "Copy mine"/"Paste theirs" clipboard fallback for sims, relay-host editor sheet, per-peer chat with PreKey/Whisper badges; xcodeproj SwiftPM relativePath `../../pizzini` → `..` so the project resolves equally in worktrees and the main repo; LoopbackState/Session removed entirely. Verified: 11 Rust unit + 2 integration + 5 Swift Testing tests pass; sim ↔ sim relay HELLO + 4-frame Python smoke test of routing + a screenshot showing the QR card on iPhone 17 Pro sim (relay connected). Next: real iPhone 15 Pro pairing using the camera scanner; session persistence (sessions still ephemeral — only identity persists); then Tor onion-bound relay.
- 2026-05-08 — first real cross-device chat: iPhone 15 Pro scanned the iPhone 17 Pro sim's QR over the LAN relay; PQXDH handshake completed; "Hi" → "Hallo" round-tripped with the expected `PreKey` (1759 B) → `Whisper` (72 B) flip visible on both sides. Hit one bug along the way: `UnsafeRawBufferPointer.load(as:)` traps on misaligned offsets when SEND/BUNDLE_RESPONSE payloads land at odd byte positions inside a Data slice — fixed by switching the cursor reads to `loadUnaligned` (commit 533e309). Next: session persistence across launches (so the ratchet survives a relaunch), then SQLCipher storage layer, then Tor-bound relay.
- 2026-05-08 — strict-scan contacts model + session persistence: Rust `DeviceStore` learned `serialize`/`from_serialized` (versioned binary blob walking identity, registration id, prekeys, signed prekeys, kyber prekeys, and per-peer SessionRecord; `peers: Vec<Vec<u8>>` is the index since InMemSessionStore exposes no iterator) and `register_peer`/`forget_peer`. iOS rewrite: `Models.swift` (Codable Contact / PersistedMessage / AppState), `Storage.swift` (Keychain blobs `device-store` + `app-state`, with one-time migration from the legacy `long-term-identity` slot), `ChatStore` is now multi-contact and persists on every mutation, NavigationStack-based UI (ContactsListView home, ChatView with rename / delete-chat / delete-contact, always-reachable "My QR" sheet via top-bar button), trust gate in the relay-handler delegate methods (drop SEND / BUNDLE_REQUEST / BUNDLE_RESPONSE from any identity that isn't already in `state.contacts`). Both peers must scan each other before chat unlocks — defends against unsolicited contact spam over the relay; matches the journalist/activist threat model. Deletion semantics: "delete chat" wipes the per-contact log only; "delete contact" calls `forgetPeer` + drops the row (rescan required to chat again); "delete all chats" wipes every log; "reset identity" wipes everything. Verified: 15 Rust unit + 2 integration + 7 Swift Testing tests pass; sim-1 + sim-2 both HELLO the relay with the same peer-ids across launches (i.e. identity survives). Next: session-persistence on real devices end-to-end test; contact-add via `pizzini1://` URL scheme so iMessage links auto-import; SQLCipher backing for the JSON contacts blob (Keychain has size limits).
- 2026-05-09 — unread indicators + payload-opaque push: `Contact.lastSeenAt` is set on chat enter/leave/log-mutation; `unreadCount` counts peer messages newer than `lastSeenAt`; `AppState.totalUnread` is mirrored to the app icon via `UNUserNotificationCenter.setBadgeCount` (iOS 17 API). Contact rows show the count in a capsule badge next to a bolded display name. New `REGISTER_PUSH = 5` frame on the relay (post-HELLO; `u16 token_len + token_bytes`); when a SEND arrives for an offline peer with a registered token, the relay fires a `{"aps":{"alert":"New message","sound":"default"}}` push via APNs (token-auth, ES256 JWT cached 50 min, sandbox endpoint by default; gated on `APNS_AUTH_KEY_PATH` + `APNS_TEAM_ID` + `APNS_KEY_ID`). Push payload is the literal string "New message" with no peer info — guards against the iOS notification-database extraction path Cellebrite/FBI used on Signal in April 2026 (CVE-2026-28950). iOS side: `UIApplicationDelegateAdaptor` requests `[.alert, .sound, .badge]`, calls `registerForRemoteNotifications`, forwards the device token to `ChatStore.publishPushToken`, which caches it (so a relay-host change re-publishes) and sends the REGISTER_PUSH frame. New `pizzini/pizzini.entitlements` (`aps-environment = development`) wired via `CODE_SIGN_ENTITLEMENTS` in both build configs. Verified locally: Rust workspace tests still 15+2 green, Swift package still 7 green, sim install + launch shows the new permission prompt and the unread badge. **Out-of-band, user must do**: (1) Apple Developer Console → enable Push Notifications capability on the `com.bytepotato.pizzini` App ID; (2) create an APNs auth key (.p8) and note Team ID + Key ID; (3) export `APNS_AUTH_KEY_PATH` / `APNS_TEAM_ID` / `APNS_KEY_ID` before `cargo run -p pizzini-relay`. End-to-end real-device push verification is blocked on those steps. Sim-side push delivery via `xcrun simctl push 6F4CBB51-7DFA-4151-B489-3B80B3C2475C com.bytepotato.pizzini /tmp/pizzini-push.json` works without any Apple cred — useful for validating the iOS handler path. Next: end-to-end real-device push verification once dev-console steps are done; then queueing on the relay so messages held while the recipient is offline actually deliver after the wake-up (currently SEND payload is dropped, push is the only signal).
- 2026-05-09 — push e2e working + Notification Service Extension for badge math. End-to-end verified on real iPhone: force-quit Pizzini, send from sim, "New message" banner appears with no peer info. Two real bugs fixed in the process. (1) Relay route cleanup: when a TCP client disconnected, the old code's `is_closed()` check on the in-map `mpsc::UnboundedSender` ran *before* the writer task's `out_rx` was dropped, so it always returned false; the route stayed in the map forever. Subsequent SENDs to that peer were forwarded into a dead mpsc channel and never fell through to the offline-push path. Fix: keep a `Sender::same_channel(&Sender)`-comparable clone, remove the entry unconditionally on read-loop return *if it's still ours*, then `writer_task.abort()`. (2) `RelayClient` was leaving `state` stuck at `.connected` when NWConnection went into `.waiting` — silent send dropouts. Now `.waiting` surfaces as `.connecting` (transient — NWConnection recovers on its own when the route flap resolves; flagging `.failed` would have implied user intervention was needed, which is wrong). Then the **bigger thing**: replaced the `badge: 1` placeholder with a proper Notification Service Extension. New target `pizziniNotificationService` (bundle id `com.bytepotato.pizzini.NotificationService`, `app-extension` product type, `Info.plist` + `pizziniNotificationService.entitlements` with `application-groups = group.com.bytepotato.pizzini`, `Embed Foundation Extensions` phase added to the main app's pbxproj target). The relay now sends `mutable-content: 1` so iOS invokes the extension before display; the extension reads the unread count from the shared `UserDefaults(suiteName: "group.com.bytepotato.pizzini")`, increments by 1, writes back, and stamps `bestAttemptContent.badge`. Main app mirrors `state.totalUnread` into the same UserDefaults on every mutation, so the count stays authoritative when the app is alive and the NSE only does increments while it's dead. Apple-side requirement: Push Notifications capability on the App ID (already done last commit) and App Groups capability on both `com.bytepotato.pizzini` and `com.bytepotato.pizzini.NotificationService`. Xcode 26 automatic signing handled the latter without manual dev-console clicks. Verified: 3 pushes from sim → iPhone (force-quit) showed banner + badge counts 1, 2, 3 in order. Saved a memory ("never workarounds, always production architecture from the first commit") so this session's `badge:1` mistake doesn't recur. Next: relay queueing so the SEND ciphertext actually reaches the iPhone after the wake-up — today the push fires but the bytes are dropped, so opening the app shows "New message" but no message text. That's the obvious next sub-task.

## Done in early sessions

| Layer | What works |
|---|---|
| Rust crypto-core | libsignal-protocol v0.93.2 pinned; cbindgen FFI surface; `pizzini_identity_keypair_generate`, `pizzini_store_*` (opaque DeviceStore: identity getters, publish_bundle, initiate_session, encrypt/decrypt) |
| Tests | 11 Rust unit + 2 integration (PQXDH, ratchet flip, store + bundle wire roundtrip) + 5 Swift Testing on iOS Simulator |
| Build | `scripts/build-xcframework.sh` (debug+release, drops modulemap, two ios slices), 32 MB release `.a` |
| Swift | `Package.swift` at repo root wraps the xcframework as `PizziniCryptoCore`; `IdentityKeyPair`, `Session`, `RelayClient`, `Keychain` |
| Relay | `pizzini-relay` (Tokio, 0.0.0.0:7777) length-prefixed framing + five frame types: HELLO/SEND/BUNDLE_REQUEST/BUNDLE_RESPONSE/REGISTER_PUSH; stateless drop-on-offline (with payload-opaque APNs wake-up when a token is registered); LAN-IP discovery printed at startup; **DEV ONLY** — production needs onion bind |
| iOS app | Contact card (CoreImage QR + clipboard fallback) + AVCapture scanner; per-peer chat with PreKey/Whisper badges + unread badge; identity persisted in Keychain (AfterFirstUnlockThisDeviceOnly); relay-host editor; APNs registration + REGISTER_PUSH wiring; running on iPhone 17 Pro sim and physical iPhone 15 Pro |
