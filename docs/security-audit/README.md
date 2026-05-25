# Security audit packet

This folder is the working packet for Pizzini's first full
vulnerability and exploit audit. The release checklist stays a
release gate. This packet is for the deeper audit work the checklist
explicitly does not cover: protocol review, malicious-peer and
malicious-relay testing, iOS exploit work, storage extraction, and
build and operator integrity.

The audit target must be a frozen commit and a reproducible set of
artifacts. Findings against a moving branch are useful during
preparation but do not close an external audit.

## Sequence

| Phase | Status | Exit condition |
| --- | --- | --- |
| 0. Scope freeze | Local pass recorded | Frozen commit, dirty-remediation diff, and missing release artifacts recorded |
| 1. Threat model | Local pass recorded | Claims, assets, trust boundaries, adversaries, attack trees reviewed |
| 2. Protocol review | Local pass recorded | Frame and state-machine review with crypto integration invariants |
| 3. iOS and extension review | Static pass recorded | Source/package review complete; physical-device privacy/storage testing remains |
| 4. Rust, FFI, and relay review | Local pass recorded | Parser, memory-boundary, persistence, rate-limit, relay abuse review |
| 5. Dynamic exploit work | Partial | Local regressions cover the group-op bypass and the remediated multi-relay v2 token suppression path; physical-device PoCs remain |
| 6. Supply-chain and release review | Partial | Pins, build/deploy flow, and transparency code reviewed; release artifact hashes remain |
| 7. Remediation and retest | Local pass recorded | Fixed findings, test evidence, and residual risk recorded |

Phase 0 and Phase 1 run together. They should finish before an
external reviewer spends time on broad code review so the reviewer
gets a stable target and an explicit threat model.

## Current scope

The audit target is not only the Xcode app.

| Surface | Primary paths | Why it is in scope |
| --- | --- | --- |
| iOS app | `pizzini/pizzini/` | User-facing message, lock, wipe, attachment, pasteboard, screenshot, storage, and relay flows |
| Notification extension | `pizzini/pizziniNotificationService/` | APNs payload handling and App Group state run outside the main app process |
| Swift package wrappers | `swift/Sources/` | Relay transport, Tor wrapper, SQLCipher wrapper, Keychain wrapper, and Rust FFI consumer |
| Rust crypto core | `crypto-core/` | Libsignal integration, FFI ownership, serialization, delivery-token verification |
| Rust relay | `relay/` | Frame parsing, HELLO proof, relay queues, APNs token state, rate limits, metadata exposure |
| Build and operations | `scripts/`, `Package.swift`, Cargo files, `transparency-log.ndjson` | Vendored and generated crypto/Tor artifacts, reproducibility, signing, deployment claims |

## Phase 0 scope freeze

Fill these fields before the audit target is handed to reviewers.

| Field | Frozen value |
| --- | --- |
| Audit commit | `0501a6436018281c84121c003a2ee4a361697cd2` |
| Git tree dirty state | Local remediation and audit-doc diff present. Unrelated pre-existing `scripts/update-macbook.sh` change excluded from the audit target. |
| App marketing/build version | `1.0` / `1` |
| Rust workspace version | `1.0.0` |
| iOS release artifact hash | Not produced in this local source pass |
| Crypto XCFramework hash | Not produced in this local source pass |
| Tor XCFramework hash | Not produced in this local source pass |
| Relay release binary hash | Not produced in this local source pass |
| Transparency-log entry | Verification code reviewed; no release entry frozen for this local pass |
| Relay deployment/config snapshot | `scripts/deploy/` reviewed at the audit commit |
| Audit start date | `2026-05-21` |
| Reviewer access model | Local source/code-execution pass only; no production relay testing |

### Scope-freeze checklist

- [ ] Freeze one commit for the audit and branch remediation from it.
- [ ] Record any local changes that are intentionally not part of the
      audit target.
- [ ] Build release-equivalent iOS, crypto XCFramework, Tor
      XCFramework, and relay artifacts from the frozen commit.
- [ ] Record hashes and toolchain versions for every artifact delivered
      to reviewers.
- [ ] Snapshot the relay allowlist, BYO relay behavior, Tor
      configuration, APNs configuration shape, and transparency-log
      verification flow.
- [ ] Declare known exceptions before review begins. The README
      currently lists App Attest and strict ATS enforcement as pending.
- [ ] Decide whether the reviewer may test production relays. Default
      to an isolated audit relay fleet unless the operator approves a
      production test window.
- [ ] Prepare seeded test devices and test identities for 1:1 chats,
      blocked contacts, pending invitations, active groups, attachment
      transfers, passcode lock, and duress wipe.

## Evidence index

Start the audit with the evidence the repo already has.

| Evidence | Current location |
| --- | --- |
| Product security claims and known gaps | `README.md` |
| Release-only manual checks | `RELEASE-CHECKLIST.md` |
| Security-sensitive contribution rules | `CONTRIBUTING.md` |
| Prior adversarial crypto/FFI probes | `crypto-core/tests/audit_probes.rs`, `crypto-core/tests/fix_review.rs` |
| iOS regression coverage | `pizzini/pizziniTests/` |
| Swift transport and wrapper coverage | `swift/Tests/` |
| Relay parser, persistence, and rate-limit coverage | Rust tests inside `relay/src/` |

The evidence index is not a coverage claim. Phase 0 should turn it
into a test matrix that says which threat-model invariant is covered
by code review, automated tests, physical-device tests, or an exploit
attempt.

The local pass matrix is now in `REVIEW-MATRIX.md`. Confirmed findings,
fixes, retest evidence, and residual risks are in `FINDINGS.md`.

## Phase 1 threat-model inputs

`THREAT-MODEL.md` is the initial draft. Review it against the frozen
target and add attack trees for these flows first:

1. First contact and pairing over QR, invite card, bundle requests,
   hashcash, and HELLO.
2. A paired contact sending text, ACK, read receipt, chain refresh,
   and malformed sealed envelopes.
3. Group bootstrap, invitation acceptance, membership changes, sender
   key distribution, removal, and group attachments.
4. Relay queueing, token-chain validation, APNs wake-up, reconnect,
   and multi-relay fanout under a malicious relay.
5. Device compromise paths for SQLCipher, Keychain, attachments,
   app-group state, lock state, screenshots, and duress wipe.
6. Release integrity paths for vendored dependencies, generated
   XCFrameworks, relay binary attestation, transparency-log signing,
   and update/deployment steps.

## Audit lab

Minimum lab for the exploit phase:

- Two physical non-jailbroken iPhones on current supported iOS for
  APNs, Tor, pairing, backgrounding, and screenshot behavior.
- One instrumented or jailbroken test device for runtime inspection
  and local-control bypass attempts.
- Simulator coverage for repeatable parser, storage, and UI regression
  tests.
- An isolated relay fleet with production-like Tor and APNs shape.
- Disposable identities, APNs tokens, groups, attachments, and
  transparency-log fixtures.

## Handoff gates

Do not call the external audit ready until:

- [ ] The scope-freeze table is filled.
- [ ] The threat-model claims and known exceptions are reviewed.
- [ ] Reviewers can build the frozen target or are given reproducible
      artifacts with hashes.
- [ ] Audit accounts/devices and relay test boundaries are documented.
- [ ] Existing automated and manual security evidence is indexed.
- [ ] The remediation branch and retest process are agreed.

## Next work

Remaining work after the continued local pass:

1. Run the physical-device matrix, freeze release-equivalent artifacts
   and hashes, and triage the non-green full simulator test plan before
   using this packet as release-audit closure evidence.
