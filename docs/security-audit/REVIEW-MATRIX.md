# Local review matrix

This matrix records the source-level vulnerability and exploit pass
performed on 2026-05-21 against commit
`0501a6436018281c84121c003a2ee4a361697cd2` plus the remediation diff
listed in `FINDINGS.md`. It is not a substitute for a signed release
artifact review or physical-device exploit work.

| Surface | Invariants reviewed | Evidence used | Result |
| --- | --- | --- | --- |
| Pairing, HELLO, bundles, token chains | First-contact parsing, possession proof, replay bounds, hashcash, chain registration, sealed-sender entry points | `relay/src/main.rs`, `crypto-core/src/lib.rs`, `crypto-core/src/store.rs`, Swift relay wrapper, Rust parser/replay tests | No first-contact pairing bypass confirmed in this pass. Continued review confirmed and remediated the multi-relay v2 bearer-token suppression path with relay-scoped chain IDs; remaining token-chain design risk is in `FINDINGS.md`. |
| 1:1 sealed traffic | Sender contact gate, certificate binding, message-kind dispatch, duplicate handling, ratchet persistence fail-closed behavior | Rust sealed-sender paths and audit probes, `ChatStore.swift`, FFI buffer-size paths | Existing controls held under reviewed tests. Rust release diagnostics needed remediation. |
| Group state and group traffic | Bootstrap trust anchor, admin authorization, member-set witness, queued future ops, removal gates, sender-key and attachment dispatch | `GroupApply.swift`, `ChatStoreGroups.swift`, `GroupOp.swift`, group tests | Confirmed queued-op member-set witness bypass fixed and regression-added. |
| Relay queue and APNs | Parser bounds, TTL/caps, encrypted restart state, dedupe/rate stores, push payload content, push-token retention | Relay sources/tests, APNs module, deployment env/systemd files | No plaintext/payload expansion found. Relay release stderr peer metadata needed remediation. |
| iOS transport and packaging | Tor posture, clearnet exceptions, ATS/Info settings, entitlements, app-group scope | Xcode build settings, entitlements, Tor/transparency/captive-portal code | App package review found push plus App Group entitlements and no ATS relaxation in generated app build settings. Documentation now names both clearnet exceptions. |
| iOS local storage | SQLCipher key chain, Keychain class/sync policy, file protection, attachment path containment, backup exclusion, wipe recovery | `DBKey.swift`, shared Keychain wrapper, `SQLiteStorage.swift`, attachment sandbox/reassembler | No source-level plaintext storage bypass confirmed. Physical extraction and before-first-unlock tests remain. |
| Local privacy surfaces | Notification service, badge scope, screenshot/capture gates, preview opt-ins, debug logging policy | Notification extension, private log policy, FAQ/settings/preview code | Preview and notification claims aligned after doc fixes. Physical-device validation remains. |
| Release and operations | Dependency pins, release build commands, transparency verdict path, relay systemd/Tor/firewall/bootstrap posture | README, Cargo/Package/Xcode config, `scripts/deploy/`, transparency code | Bundled-relay mismatch now drops that relay from outbound fanout; artifact hashes and operational residuals remain recorded. |

## Commands and outcomes

| Command | Outcome |
| --- | --- |
| `cargo test --workspace` | Passed after remediation. Rust crypto audit probes and relay parser/persistence/rate tests ran in the workspace. |
| `cargo test -p pizzini-relay v2_relay_scoped_chain_id_blocks_sibling_token_preemption` | Passed after remediation. A token carrying relay A's chain ID no longer finds relay B's registered chain; relay B's genuine scoped token still validates. |
| Targeted relay-scoped hash-chain Xcode test | Passed with `-only-testing:pizziniTests/HashChainTokenTests/relayScopedChainIDsDoNotCross` after remediation. |
| Targeted relay-attestation policy Xcode test | Passed with `-only-testing:pizziniTests/RelayAttestationPolicyTests` after remediation. A mismatched bundled relay is excluded from outbound use while warning-only cases stay usable. |
| `cargo test -p pizzini-crypto-core --release --lib` | Passed after the crypto-core release diagnostic gate change and was rerun in the continued audit. |
| `cargo audit` | Completed against 315 locked Rust dependencies with no advisory emitted. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Did not pass because existing lint warnings in crypto-core and relay code/tests/docs fail `-D warnings`; no security defect was inferred from that lint run. |
| `xcodebuild test -scheme pizzini -project pizzini/pizzini.xcodeproj -destination 'platform=iOS Simulator,name=iPhone 17 Pro'` | Ran the app test plan but failed: `QALogTests`, paired QR UI flow tests, and one simulator UI runner launch failed. Result is evidence, not a green gate. |
| Targeted queued group-op Xcode test | Passed with `-only-testing:pizziniTests/ChatGroupApplyQueueTests/queuedOpRechecksMemberSetRoot` and was rerun in the continued audit. |
| `swift test` | Not a usable repo-root gate for this iOS-only package on macOS; the run hit platform availability errors in `PizziniTor`. |

## Physical-device matrix still required

- APNs payload and Notification Service Extension behavior on a release
  build, including locked-screen badge observations.
- Tor bootstrap, captive-portal probe timing, and clearnet traffic
  capture on a real network.
- File protection, Keychain accessibility, app snapshots, screenshot
  shielding, live capture shielding, lock state, and duress wipe before
  first unlock and after first unlock.
- Attachment save, QuickLook, inline-thumbnail opt-in, pasteboard, and
  share-sheet traces on current supported iOS.
