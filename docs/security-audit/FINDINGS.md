# Local audit findings

Audit date: 2026-05-21.

Audit target: source commit
`0501a6436018281c84121c003a2ee4a361697cd2` with the remediation diff
described below. The unrelated pre-existing
`scripts/update-macbook.sh` change was not part of the audit target.

## Fixed findings

| Severity | Finding | Exploit shape | Fix and evidence |
| --- | --- | --- | --- |
| High | Queued future group ops skipped the current member-set witness check when a missing parent arrived later. | A malicious admin could queue a signed child op rooted in a ghost member set before the honest parent landed. The fresh apply path checked `priorMemberSetRoot`; the queued reapply path did not. | `GroupApply.applyAlreadyParked` now reuses the member-set-root mismatch guard. `queuedOpRechecksMemberSetRoot` parks the forged child, applies the parent, and checks the child never advances group epoch. The targeted Xcode test passed. |
| Medium | Multi-relay v2 delivery-token replay could suppress a genuine fanout leg. | The sender broadcast one on-wire `(chain_id, index, value)` bearer token to every ready relay. A malicious fleet relay could present the observed token to a sibling inside a SEND with unusable sealed bytes and spend the sibling cursor before the genuine leg arrived. | Chain registration now derives a relay-scoped chain ID from the random base chain ID and the relay target namespace; SEND/ACK fanout rewrites the base token to that relay-local selector before write. `relayScopedChainIDsDoNotCross` and `v2_relay_scoped_chain_id_blocks_sibling_token_preemption` pin the split-selector behavior. |
| Medium | Transparency mismatches were warning-only for bundled relays. | A built-in relay could report a binary SHA absent from the signed log and still receive new outgoing traffic from the app. | Outbound fanout now skips bundled relays with a confirmed `.mismatch` verdict while allowing receives to drain. Unverifiable/log-fetch-failure states and custom relays remain warning-only to avoid network-block deadlock and BYO log mismatch. `RelayAttestationPolicyTests` pins the policy. |
| Medium | Release relay stderr paths disclosed peer routing metadata in error diagnostics outside the debug-only peer log macros. | An operator-visible release log line could carry short peer identifiers from malformed or persistence-error paths despite the relay logging policy. | The affected relay stderr paths now keep error cause without peer IDs and peer-aware diagnostics stay under `dev_peer_log!`/`dev_peer_elog!`. |
| Medium | Rust crypto-core diagnostics printed sealed-sender peer identifiers and message IDs from inside the iOS process. | A device/runtime log capture on a release build could retain contact or message correlation material even though Swift hot paths compile peer-aware `pzLog` out of release. | Store diagnostics now go through debug-only `crypto_diag!`. Sealed receive and corrupted-store recovery paths preserve control flow and errors without release stderr output. |

Documentation corrections made with the findings:

- Attachment-preview and clearnet-exception claims now match current
  code paths.
- Tor pin and the simulator test command now match the current build
  scripts/project.
- Transparency-log fetch comments now distinguish the default clearnet
  GitHub path from optional onion mirrors.
- Relay-state copy now distinguishes memory-only HELLO/hashcash state
  from persisted v2 chain-validator cursors and durable bundle-request
  rate buckets.

## Continued-audit disposition

| Disposition | Priority | Item | Evidence and next step |
| --- | --- | --- | --- |
| Design risk | Low | Hash-chain token steps are bare `BLAKE3(value)` without chain-ID domain separation or chain versioning. | Current random 32-byte seeds make an attacker-useful cross-chain overlap or accidental collision implausible in this source pass, so no practical forgery/suppression path was confirmed from the missing tag alone. The construction still lacks structural domain separation and the current chain/token/store wires have no version field. A vNext needs a coordinated app/relay chain version plus a domain-separated step before changing the hash primitive input. |
| Operational risk requiring acceptance | Operational | `scripts/deploy/bootstrap.sh` deliberately gives `pizzini-admin` `NOPASSWD: ALL`, and relay disks still have a documented full-disk-encryption TODO. | The script records the operator tradeoff. It should be accepted explicitly or tightened before treating host compromise resistance as a release claim. |
| Release gate | Release gate | App Attest and strict ATS remain pending. | README already marks them pending. The static package review found no app ATS relaxation, but the stated strict-enforcement work is still not closed. |

## Continued-audit review notes

- The queued group-op remediation was rechecked in the fresh apply and
  queued-replay paths. `applyAlreadyParked` now reuses the
  `priorMemberSetRoot` witness gate before mutation.
- Group bootstrap, sender-key distribution, group chat, and group
  attachment dispatch were re-read after that fix. The reviewed
  receive paths re-check signed operator trust anchors, active group
  membership, and sender-key distribution IDs before rendering or
  installing state; no additional source-level membership bypass was
  confirmed in this continuation.
- Sealed-sender receive and group FFI buffer paths were re-read at the
  Swift and Rust boundary. The receive-size retry path peeks before the
  destructive ratchet step, and the group/SKDM shims keep explicit
  distribution-ID buffer lengths; no new FFI state-advance or output
  buffer bug was confirmed in this continuation.
- Relay frame parsing, pending-store caps, APNs payload generation,
  push-token persistence, Keychain/SQLCipher setup, attachment
  sandbox/reassembly, notification extension badge state, and private
  logging gates were spot-retested by source review. The remaining
  storage, notification, screenshot, and wipe claims still require the
  physical-device matrix in `REVIEW-MATRIX.md`.

## Limits of this pass

- No physical iPhone, jailbroken/instrumented device, or production
  relay was used.
- No release-equivalent iOS IPA, Tor XCFramework, crypto XCFramework,
  relay binary, or transparency-log entry was frozen and hashed.
- The relay-scoped delivery-token retest covers newly minted and
  registered v2 chains. If a deployment already has unscoped v2
  registrations in live relay/client state, release needs an explicit
  chain refresh or migration plan for those existing registrations.
- The full app simulator test plan did not finish green; the failures
  are listed in `REVIEW-MATRIX.md` and must be triaged before using
  that run as a release gate.

## Post-audit remediations

Dated additions after the 2026-05-21 pass; not part of the frozen
audit record above.

| Date | Severity | Finding | Exploit shape | Fix and evidence |
| --- | --- | --- | --- | --- |
| 2026-07-23 | Medium | F-PUSH-03: delivered wake-up records accumulated in the OS notification store and survived the duress wipe. | The iOS notification store retains one record per delivered push (arrival timestamp; content-free by design). CVE-2026-28950 demonstrated forensic recovery from that store, including records "marked for deletion" on unpatched iOS. Post-wipe, a Notification Center still showing "Pizzini: New message" entries contradicted the fresh-install-indistinguishability contract; between app opens the store accumulated a per-message arrival timeline. | Relay sends a static `apns-collapse-id` so successive wake-ups replace one another (Notification Center shows at most one record; on patched iOS the underlying store is bounded too); the app clears delivered banners on every scene activation; `duressWipe()` and the PZ-M13 retry path purge delivered + pending notifications before the storage erase; `willPresent` returns badge-only so foreground pushes never enter the store; an update advisory shows on pre-18.7.8 / pre-26.4.2 iOS. Pinned by `wakeup_payload_is_the_static_content_free_literal` / `wakeup_headers_carry_collapse_id_and_bounded_expiration` (relay, CI-gated via `cargo test`) and `NotificationPrivacyTests` + `FAQCopyRegressionTests` (app). Enforcement gap: CI does not build the full Xcode app (no `Tor.xcframework` in CI), so the app-side pins run only in the mandated local `xcodebuild test` (CONTRIBUTING.md), not yet as a CI gate — a scoped simulator test job is tracked as follow-up. Residual: records an unpatched OS already failed to delete are unreachable from the app; physical-device verification is on the release checklist. |
