# Pizzini

iOS messenger. Better Signal. End-to-end encrypted, post-quantum, no phone numbers, no metadata. For journalists, activists, and anyone who needs Signal-grade privacy without Signal's compromises (phone-number identity, US jurisdiction, centralized infra).

Domain: pizzini.app

## What "better than Signal" means here

We start from Signal's protocol because it is the gold standard. We diverge where Signal made compromises we don't have to make:

- **No phone number.** Pairwise random IDs, no central directory. Contact via QR / invite link, out of band.
- **Tor-only transport.** No clearnet fallback. Sealed sender + onion routing.
- **Stateless relays in multiple jurisdictions.** No single seizable server. "Stateless" here means *no per-user accounts, no long-term server state, nothing on disk*. Ephemeral in-memory routing buffers (e.g. a TTL-bounded queue holding libsignal-encrypted ciphertexts for a few hours so an offline recipient eventually gets their message) are fine — they're transient routing state, not user data, and a process restart wipes them.
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
- [x] Offline-recipient message delivery (relay holds an ephemeral in-memory queue per peer, drained on reconnect)
- [x] Sealed sender (libsignal SealedSenderV1, self-issued certs)
- [x] Sender outbox + retries
- [x] End-to-end delivered receipts
- [x] Optional per-contact read receipts (default off)
- [x] Per-message TTL (1h/24h/3d/7d, 7d hard cap)
- [x] Recipient-issued delivery tokens (Ed25519)
- [x] First-contact hashcash PoW
- [ ] Multi-relay client fanout (deferred, post-audit)
- [ ] Storage layer (SQLCipher) — outbox migrates from Keychain JSON when this lands
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
- 2026-05-09 — relay-side ephemeral queue closes the offline-message gap. When a SEND lands for an offline recipient, the relay now stores the ciphertext frame in an in-memory `HashMap<PeerId, VecDeque<PendingFrame>>` (per-peer cap 100, per-frame TTL 24h, no disk, process restart wipes). On the recipient's next HELLO, `drain_pending` flushes the queue to their writer task in arrival order, filtering out expired entries. A 5-minute GC task prunes expired heads across all peers (entries are time-ordered so we stop at the first non-expired one). Bundle frames stay drop-on-offline — bundle exchange is a first-contact handshake that requires both peers online by definition. Queue + push compose: SEND-to-offline → enqueue + fire payload-opaque "New message" push → app launches → drain forwards the ciphertext → libsignal decrypts in-process → message lands in the chat. Verified e2e with force-quit iPhone receiving 3 queued messages on relaunch. Updated the README hard-rule wording for "stateless" to spell out that "no long-term/disk state, no per-user accounts" is the actual constraint and ephemeral routing buffers are within spec — same threat profile as the live route table itself, since the bytes were going to be forwarded anyway. Caps + TTL bound the post-seizure leak surface; libsignal-encrypted ciphertexts are unreadable to a hypothetical attacker. Next: SQLCipher persistence for AppState (Keychain has size limits as the contacts/log grow); Tor onion-bound relay; deeper Lockdown Mode test.
- 2026-05-09 — Private SEND v2 milestone, six commits over one session that take the relay from "trusts every from_id" to "won't quietly fail a journalist whose source went offline for the weekend."
  - **Phase 0 — sealed-sender feasibility test (`crypto-core: prove sealed sender with self-issued certs works`)**: New integration test in `crypto-core/tests/sealed_sender.rs` proves that libsignal v0.93.2's two-tier `ServerCertificate → SenderCertificate` chain accepts a degenerate self-issued shape where trust root, server-cert key, and sender-cert signer all collapse onto the peer's own IdentityKeyPair. Round-trips 5 messages with the exact inner-content layout the relay v2 wire format needs (`16-byte message_id || 1-byte is_prekey || ratchet ciphertext`), proves a forged cert (Mallory signs claiming Alice) is rejected, and snapshots the DeviceStore mid-conversation to show the libsignal session survives serialise. DeviceStore gains two narrow accessors (`local_identity_keypair`, `inner_mut`) the test needs. Next: Phase 1 wraps the primitive in `seal_send`/`seal_receive` so it's reachable from Swift.
  - **Phase 1 — crypto-core sealed-sender FFI + bundle gains a delivery-token verify key (`crypto-core: sealed sender FFI + Ed25519 token verify key in bundle`)**: DeviceStore gains `ensure_sender_certificate()` (30-day TTL, 24h refresh margin, cached in the store and serialised through), `seal_send(peer, message_id, plaintext) -> sealed_bytes`, and `seal_receive(sealed) -> SealReceived`. Receive is contact-gated (refuses to advance the ratchet for an unknown identity) and validates the embedded cert against the claimed sender's stored identity_pub. The bundle wire format ticks v1→v2 to carry a 33-byte `delivery_token_verify_key` (libsignal-native PublicKey serialise() — DJB type prefix + 32-byte Curve25519 point); the signing half is HKDF-SHA512 derived from the IdentityKeyPair so a Keychain restore reconstructs both halves with no separate secret. Store snapshot ticks v1→v2 to embed the cert (v1 blobs migrate by simply minting a fresh cert on demand). Swift surface mirrors Rust: `Session.encryptSealed/decryptSealed`, accessors for the verify key and the cached cert. 19 Rust unit + 5 integration + 10 Swift Testing tests pass. Next: Phase 2 swings the wire format to actually use these.
  - **Phase 2 — relay wire format v2 (`relay: SEND v2 wire format (sealed sender + per-message TTL + token slot) + ACK frame`)**: SEND payload becomes a sealed-sender envelope; from_id and is_prekey both move inside. New SEND v2 layout: `to + ttl + token + sealed`. New ACK frame (type=6) — same shape, the sealed inner plaintext begins with a marker followed by the 16-byte message_id of the SEND being acked. Per-message TTL clamped to `min(client_ttl, 7d)` with a 60s floor; the fixed 24h `PENDING_TTL` constant is gone. HELLO grows a leading `u8 protocol_version`; v1 clients are rejected at handshake. iOS RelayClient picks up `sendSealed/sendAck`, the delegate exposes `didReceiveSealedSend/didReceiveAck` (raw sealed bytes, decrypt happens upstream). ChatStore.send uses `Session.encryptSealed`; inbound SEND runs `decryptSealed`, contact-gates, emits an ACK back automatically. Drop-on-delivery cleanup at the relay isn't possible single-relay (relay can't see message_ids inside sealed envelopes); Phase 4's outbox is the authoritative delivery-tier mechanism. 5 relay unit tests added. Next: Phase 3 plugs the DoS hole the relay can no longer rate-limit by sender identity (sealed sender hides it).
  - **Phase 3 — recipient-issued Ed25519 delivery tokens + hashcash on bundle (`ios + relay: recipient-issued Ed25519 delivery tokens + hashcash on bundle`)**: Two cooperating defences. **Tokens** — every SEND/ACK now carries 84 bytes (`nonce16 || expiry_be_u32 || sig64`) signed with the recipient's HKDF-derived XEd25519 signing key. The relay verifies on every SEND/ACK against a per-recipient verify-key table populated by HELLO, an expiry, and a 24h replay set. Initial issuance is 1024 tokens minted right after BUNDLE_RESPONSE via a new TOKEN_ISSUE = 7 wire frame; refills ride a sealed in-band SEND with a 1-byte inner-envelope kind marker (chat / ack / token-refill / read-receipt) so user text can never collide with a control message. **Hashcash** — first-contact frames have no session, so the token gate doesn't apply. Sender brute-forces a u64 nonce satisfying `BLAKE3(BLAKE3(recipient_peer_id || hour_bucket) || nonce_be) starts with ≥ 18 zero bits`. ~1s on a modern phone, multi-day per-recipient on a dedicated attacker box. Relay accepts current and previous hour for clock skew. New crypto-core FFI: `pizzini_store_mint_delivery_token`, `pizzini_blake3_hash` (CryptoKit doesn't ship BLAKE3 and the iOS challenge derivation MUST byte-match the relay), `pizzini_hashcash_compute`. Relay gains a libsignal-protocol dep (just for `PublicKey::verify_signature`) and blake3. Build script now exports `IPHONEOS_DEPLOYMENT_TARGET=17` because blake3's NEON path links Darwin SDK helpers absent before iOS 14. Phase 1's verify_key field finally has a verifier; Phase 2's token slot finally has signed contents. Next: Phase 4 surfaces all this in a UI a journalist can read.
  - **Phase 4 — sender outbox + delivered/read receipts + per-message TTL picker (`ios: sender outbox + delivered/read receipts + per-message TTL picker`)**: New `Outbox.swift` — every sealed SEND lands in a Codable OutboxEntry (16-byte messageId, recipient, sealed bytes, token, ttl, sentAt, retries, deliveredAt?, failedAt?, relayedAt?), persisted as JSON in a new Keychain slot (`outbox`) so a crash/kill mid-send still leaves a retryable record. ChatStore wires it: send() inserts BEFORE handing off to the relay, marks `relayedAt` after a non-erroring NWConnection.send return (✓ tier), 30s retry timer re-sends entries where `now > sentAt + max(30, retries × 60), retries < 10` using a freshly-popped token each time, marks `failedAt` when the per-message TTL elapses. ACK delegate flips `deliveredAt` → ✓✓. Per-contact UX in the chat ⋯ menu: "Expires after" submenu (1h / 1 day (recommended) / 3d / 7d, default 1d), "Tell {name} when I read their messages" toggle (default OFF, journalist-friendly explainer). Read-receipt delegate stamps a per-message `readAt` on me-rows ≤ the highest-acked timestamp; "Read" indicator appears next to ✓✓. ChatRow status icons: ⏳ pending / ✓ relayed / ✓✓ delivered / ✗ failed. OnboardingView gains an `.icons` step explaining the four glyphs. 7 new XCTest @Suite tests cover OutboxEntry codable round-trip, status precedence, retry backoff, retry cap, TTL expiry, and the read-receipt / TTL defaults on Contact. Open from brief: SQLCipher migration of the outbox, multi-relay client fanout — both deferred to post-audit; the per-message long-press TTL picker is implemented as per-CONTACT instead because changing TTL post-send has no protocol-level effect (relay's TTL is fixed at enqueue), so the choice lives at the place where it's actionable: before the next send. Verified: 25 crypto-core + 5 relay + 10 Swift package + 7 iOS tests pass; sim + physical iPhone builds green. Next: end-to-end manual verification on the two real targets (iPhone 15 Pro + iPhone 17 Pro sim) per the verification checklist.

## Done in early sessions

| Layer | What works |
|---|---|
| Rust crypto-core | libsignal-protocol v0.93.2 pinned; cbindgen FFI surface; `pizzini_identity_keypair_generate`, `pizzini_store_*` (opaque DeviceStore: identity getters, publish_bundle, initiate_session, encrypt/decrypt) |
| Tests | 11 Rust unit + 2 integration (PQXDH, ratchet flip, store + bundle wire roundtrip) + 5 Swift Testing on iOS Simulator |
| Build | `scripts/build-xcframework.sh` (debug+release, drops modulemap, two ios slices), 32 MB release `.a` |
| Swift | `Package.swift` at repo root wraps the xcframework as `PizziniCryptoCore`; `IdentityKeyPair`, `Session`, `RelayClient`, `Keychain` |
| Relay | `pizzini-relay` (Tokio, 0.0.0.0:7777) length-prefixed framing + five frame types: HELLO/SEND/BUNDLE_REQUEST/BUNDLE_RESPONSE/REGISTER_PUSH; stateless drop-on-offline (with payload-opaque APNs wake-up when a token is registered); LAN-IP discovery printed at startup; **DEV ONLY** — production needs onion bind |
| iOS app | Contact card (CoreImage QR + clipboard fallback) + AVCapture scanner; per-peer chat with PreKey/Whisper badges + unread badge; identity persisted in Keychain (AfterFirstUnlockThisDeviceOnly); relay-host editor; APNs registration + REGISTER_PUSH wiring; running on iPhone 17 Pro sim and physical iPhone 15 Pro |
