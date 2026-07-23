# Threat model draft

Status: initial audit draft based on the repository as of
2026-05-21. This document is not a security proof. It is the shared
model the audit should challenge.

## Claims to verify

The audit should verify or narrow every security claim it relies on.
Current repo claims include:

- Messaging is end-to-end encrypted through libsignal-backed PQXDH,
  Triple Ratchet, sealed sender, and sender-key group flows.
- Normal message transport is Tor-only. The README documents the
  clearnet transparency-log HTTPS fetch and the captive-portal probe
  that runs only after Tor bootstrap stalls.
- Relays do not hold plaintext message bodies or per-user accounts.
- Relay persistence is bounded to encrypted offline queues and APNs
  push-token state with documented TTL/cap behavior.
- Attachments are not automatically downloaded or previewed in app,
  and attachment bytes stay in protected app storage until the user
  saves them out.
- Local message storage uses SQLCipher with Keychain and Secure
  Enclave-backed key material.
- App lock, screenshot shielding, screen-capture shielding, and duress
  wipe protect the user under the stated local-device threats.
- Notifications avoid peer identity, message preview, and server-side
  unread-count leakage. (Scope: this covers the APNs payload and the
  relay/server. On-device, the NSE persists a bounded badge count to the
  App Group plist — protected only at CompleteUntilFirstUserAuthentication
  — so a post-first-unlock forensic extraction can read that count. It
  carries no peer identity and is overwritten on next launch; accepted
  residual, see F-PUSH-01 / NotificationService.didReceive.)
  (Update 2026-07-23, F-PUSH-03: the OS notification store retains
  delivered wake-up records — arrival timestamps, not content — and
  CVE-2026-28950 showed deletion from that store could silently fail
  on unpatched iOS. Mitigations shipped: a static `apns-collapse-id`
  on every wake-up so the store holds at most the latest record; a
  delivered-banner clear on every app open; a Notification Center
  purge on the duress wipe and its PZ-M13 retry; foreground pushes
  presented badge-only so they never enter the store; and an in-app
  update advisory on pre-18.7.8 / pre-26.4.2 iOS. Residual: records an
  unpatched OS already failed to delete, and Apple-side APNs metadata,
  are out of the app's reach.)
- Relay binaries and transparency entries support release integrity
  checks.

Claims that are intentionally pending must stay explicit. The README
currently calls out App Attest and strict ATS enforcement.

## Assets

| Asset | Examples |
| --- | --- |
| Message confidentiality | Text, ACK meaning, read-receipt meaning, attachment content |
| Metadata minimization | Peer graph, group membership, unread counts, timing and fanout clues, APNs registration |
| Identity and session state | Identity keys, safety-number material, prekeys, ratchets, sender keys, token chains |
| Local protected state | SQLCipher DB, Keychain rows, Secure Enclave key handle, attachments, app-group state |
| User intent and trust | Pairing approval, group invitation acceptance, blocked-contact decisions, passcode and wipe intent |
| Availability | Relay queue capacity, token refresh, reconnect, Tor bootstrap, background delivery |
| Release integrity | Source-to-binary traceability, XCFramework provenance, relay binary attestation, transparency signatures |

## Trust boundaries

1. The user and a remote peer exchange pairing material through QR,
   invite-card, or pasteboard flows.
2. Untrusted network input enters the client through relay frames,
   sealed envelopes, group envelopes, bundle material, and status
   responses.
3. The main app crosses into Rust through the generated C ABI and Swift
   wrapper layer.
4. The app crosses iOS persistence boundaries: SQLCipher files,
   Keychain, Secure Enclave, attachment directories, UserDefaults,
   and App Group state.
5. The main app and Notification Service Extension share App Group
   badge state while running under different lifecycles.
6. The client reaches Tor onion relays and separately reaches the
   documented HTTPS transparency-log path.
7. The relay crosses from anonymous clients into persistent queue,
   token-validation, APNs token, and operator-managed deployment
   state.
8. Release tooling crosses source, vendored dependencies, generated
   XCFrameworks, signatures, and deployed relay binaries.

## Adversaries

| Adversary | Capabilities to assume | Security question |
| --- | --- | --- |
| Unpaired sender | Sends malformed first-contact traffic, bundle requests, hashcash attempts, and relay frames | Can they crash, allocate unbounded work, bypass pairing, or learn identity metadata? |
| Malicious paired peer | Sends valid and malformed sealed content after session establishment | Can they impersonate other peers, abuse envelope kinds, desync state, or escalate group rights? |
| Malicious group member | Replays or forges group operations and attachment traffic around membership changes | Can removed or non-admin members keep sending or mutate group state? |
| Malicious relay | Drops, delays, duplicates, reorders, truncates, lies in status, and observes timing | Can relay control reveal plaintext, break privacy claims, or turn availability into state corruption? |
| Network observer or active network attacker | Observes or interferes outside onion confidentiality and on the HTTPS transparency path | Is there clearnet fallback, unsafe status trust, or unexpected identifier leakage? |
| APNs-side observer | Sees push registration and payload shape allowed by the Apple delivery path | Does a push reveal peer identity, preview, or count beyond the threat model? |
| Locked-device thief | Reads snapshots, notifications, backups, accessible files, and any data reachable before unlock | Do UI and data-protection claims hold before first unlock? |
| After-first-unlock local attacker | Extracts app containers and reachable Keychain/file-protection state from a device that was unlocked once | What remains protected by SQLCipher, Secure Enclave wrapping, lock state, and erase flow? |
| Instrumented-device attacker | Hooks app APIs, inspects runtime plaintext, bypasses local UI policy, tampers with files | Which controls are only warnings or best-effort on a compromised endpoint? |
| Supply-chain or operator attacker | Modifies dependencies, generated artifacts, relay config, binaries, or signing flow | Can release integrity checks detect meaningful substitution? |

## Invariants to test

### Protocol and trust

- Every untrusted wire parser has size, count, and state-transition
  bounds before expensive work or durable state mutation.
- Frame types and inner-envelope kinds cannot be confused to reach a
  less-protected path.
- HELLO, bundle, token-chain, replay, ACK, read-receipt, and chain
  refresh handling fail closed under replay, reorder, truncation, and
  cross-version traffic.
- Group bootstrap, membership mutation, sender-key distribution, group
  message, and group attachment paths enforce the intended trust
  anchor and current membership state.
- Relay status and transparency data are treated as evidence with the
  intended trust root, not as self-authenticating relay claims.

### Transport and relay

- Production message traffic has no clearnet fallback outside declared
  exceptions.
- A malicious relay cannot convert queueing, fanout, token validation,
  or APNs behavior into plaintext access or identity compromise.
- Queue caps, TTLs, rate limits, replay handling, and hashcash costs
  bound denial-of-service and storage growth.
- Relay persistent files and keys match the stated operator-threat
  limits. Encryption at rest must not be oversold as protection after
  full relay seizure if keys are seized with data.

### iOS storage and local privacy

- SQLCipher files, temporary files, attachments, backups, logs, and
  app-group files contain only the data expected by the threat model.
- Keychain access classes, Secure Enclave usage, rotation, migration,
  restore, crash recovery, and deletion semantics match the stated
  local-device guarantees.
- App lock and duress wipe paths do not leave easy UI, storage, log,
  snapshot, badge, or state-recovery evidence that contradicts their
  explicit design.
- Notification Center shows at most the latest content-free wake-up
  record while the app is unopened, and none after an app open or a
  duress wipe (F-PUSH-03). On patched iOS the underlying store is
  bounded the same way; on builds predating the CVE-2026-28950 fix the
  store may retain replaced or deleted records (the bug itself), so the
  collapse-id and purge bound the visible surface, not the forensic
  one, there. Physical-device verification required.
- Screenshot, screen-capture, notification, pasteboard, share-sheet,
  attachment, and background flows are tested on physical devices, not
  inferred from source alone.

### FFI and implementation

- Swift-to-Rust buffer sizing, ownership, serialization, errors, and
  retry paths cannot mutate ratchets or durable state before success is
  committed.
- Rust parsing and persistence code handles malformed input without
  panic, unchecked growth, stale state, or sensitive debug output.
- Build flags, entitlements, Info.plists, release logging, symbols,
  ATS policy, and App Group scope match the release threat model.

### Release and operations

- Dependency pins and vendored/generated artifacts have reviewable
  provenance.
- Relay reproducibility, signing, transparency-log verification, and
  deployment steps detect or clearly document substitution risk.
- Known operator centralization and co-signing gaps are recorded as
  risk decisions, not hidden behind architecture wording.

## Initial attack trees

Expand these into review matrices and PoCs before the dynamic phase.

1. **First-contact abuse**
   Malformed pairing material or first-contact relay traffic leads to
   identity confusion, excessive work, unwanted durable state, or
   hidden clearnet connection.
2. **Paired-peer envelope abuse**
   A trusted session is used to confuse envelope kinds, exploit replay
   windows, desync ratchets, exhaust tokens, or smuggle content through
   a control path.
3. **Group state abuse**
   Stale, removed, non-admin, or untrusted actors use bootstrap,
   membership, sender-key, or attachment paths to gain group effects
   they should not have.
4. **Relay metadata and availability abuse**
   A relay manipulates queueing, fanout, status, APNs registration, or
   reconnect behavior to reveal state, corrupt client state, or force
   unbounded work.
5. **Local compromise**
   A thief or instrumented endpoint extracts state from files,
   Keychain, notifications, screenshots, logs, app-group files, or
   wipe crash windows beyond the stated guarantees.
6. **Release substitution**
   A changed dependency, generated artifact, relay binary, or
   transparency entry escapes review and becomes trusted by users.

## Questions to settle during scope freeze

- Which exact commit, relay config, and transparency-log state are the
  audit target?
- Which production-like relay and APNs environment may exploit testing
  touch?
- Which security claims are release requirements versus roadmap or
  aspirational architecture?
- What production operator access, backup, logging, and deployment
  assumptions are in scope for the reviewer?
- What local-device guarantee is intended after first unlock versus on
  a fully compromised endpoint?
