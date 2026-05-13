# Release checklist

Run this end-to-end before every release. Doesn't replace the external
security audit; catches the things automated tests don't and the
security audit won't.

The 2026-05-14 incident that prompted this doc: the Cargo workspace
shipped `version = "0.0.0"` for months and surfaced as
`Crate version: 0.0.0` in the in-app Relay Attestation view. No
automated test could have caught that; a person opening the screen and
reading what's on it would have caught it in 30 seconds. This list
exists so that 30 seconds happens before, not after, the public sees it.

---

## 1. Visible-text walkthrough (10-15 min)

Open the app on a real device. Tap into every screen below and read
every visible string. If anything reads as "wait, what?" or contradicts
something else, write it down.

- [ ] **Launch splash** — icon + wordmark render, no console errors during the 2 - 5 s warm-up.
- [ ] **Onboarding** — every step's copy, every button label.
- [ ] **Contacts list** — empty state copy, toolbar buttons, relay-state indicator.
- [ ] **My QR** — explainer copy, share-sheet text, the warning about screenshots.
- [ ] **Chat view** — pre-pair state copy, send-button states, the SAS verification banner copy.
- [ ] **Group chat** — invitation accept/decline copy, member roster text.
- [ ] **Settings, top to bottom** — every Toggle label, every Section footer, every Picker option label, every navigation-link destination's screen. (`Appearance`, `Privacy`, `Chats`, `Help`, `Advanced`, `Relays`.)
- [ ] **FAQ, every entry** — read each one and ask "does this match what we actually ship today?" The 2026-05-14 incident's worst finding was here: three FAQ entries described features as roadmap that had already shipped.
- [ ] **Diagnostics** — every field. Especially: `Crate version`, `Protocol version`, `Git SHA`, `Binary SHA-256`. None of these should ever be `0.0.0`, `unknown`, an empty string, or a literal placeholder.
- [ ] **Relay attestation** — same check. The relay's self-reported version + git SHA + binary hash should match what the transparency log says.
- [ ] **About / brand footer** — version, copyright year, link targets.
- [ ] **Error states** — force at least one error to fire (airplane mode → tap send → read the error copy). No raw Swift error types in user-visible alerts.

## 2. Version + build artefacts

Run these greps before tagging. None should match in production code.

```sh
# Forbidden placeholder strings in user-visible code paths
grep -rn "0\.0\.0\b" pizzini/pizzini relay/src crypto-core/src \
  --include="*.swift" --include="*.rs" --include="*.toml" \
  | grep -v "//\| \*\|test\|fixture"

# Markers that should never reach a release
grep -rn "TODO\|FIXME\|XXX\|HACK\|STUB\|PLACEHOLDER" \
  pizzini/pizzini swift/Sources relay/src crypto-core/src \
  --include="*.swift" --include="*.rs" \
  | grep -v "//\| \*"

# Hardcoded dev addresses that escape the dev path
grep -rn "127\.0\.0\.1\|localhost\|example\.com\|example\.org" \
  pizzini/pizzini swift/Sources \
  --include="*.swift" | grep -v "//\| \*\|Test"
```

Manual checks:

- [ ] `Cargo.toml` workspace `version` matches Xcode `MARKETING_VERSION`.
- [ ] `Cargo.lock` updated and committed alongside the version bump.
- [ ] `Info.plist` `CFBundleShortVersionString` matches.
- [ ] README's "Status" section matches what's actually checkable in the app FAQ.

## 3. Connection flows (real device, NOT simulator)

The simulator has fake networking and hides real failure modes. Every
release must run these on hardware.

- [ ] Cold launch on **cellular** — Tor bootstraps within 60 s. Time it.
- [ ] Cold launch on **weak WiFi** — same. (Walk to the edge of WiFi range.)
- [ ] **Airplane-mode toggle** mid-session — Tor stays up or recovers cleanly when the path returns.
- [ ] **WiFi ↔ cellular handoff** — circuits rebuild, no stale-state errors.
- [ ] **Background ≥ 60 s** then foreground — relay reconnects within 5 s.
- [ ] **Background ≥ 30 min** then foreground — handles fully expired sessions.
- [ ] **Reconnect now button** — fires from every relay state except `.connected` and produces a visible state change inside 5 s.

## 4. Pairing + messaging (two real devices)

You need two physical devices for this. The simulator doesn't replicate
the QR-camera + Tor-circuit handshake faithfully.

- [ ] QR scan pairing — both ways, both devices end up with each other in contacts.
- [ ] Paste-card pairing fallback — works when `pizzini1://` URL is on the clipboard.
- [ ] Send a text message round-trip. ✓ relayed, ✓✓ delivered icons flip.
- [ ] Send an attachment (tier-2 photo). Recipient saves to Files; no in-app preview surfaces unless they opt in.
- [ ] Mark-as-read + read receipt round-trip (if both have read receipts enabled).
- [ ] Block + unblock — blocked peer's frames silently dropped post-block.
- [ ] Group chat: create, invite, accept, send. Test with three devices if possible.

## 5. Privacy + security spot-checks

- [ ] Screenshot attempt on the chat view returns a black screenshot (real device).
- [ ] AirPlay mirroring → live shield activates over chat content.
- [ ] **Lockdown Mode on** — app still works.
- [ ] Force-quit during a send → message persists in outbox, retries on next launch.
- [ ] Duress wipe ends in an empty-but-lived-in state (relay host, UX prefs, auto-lock, Face ID toggle preserved; contacts/groups/keys/outbox all gone). Verify on a real device with a real contact set first.
- [ ] APNs push payload received on a force-quit device is the literal string `New message` — no peer name, no preview, no count. Confirm via the Notification Service Extension's logs.

## 6. Polish

- [ ] Every tap target ≥ 44×44 pt (Apple HIG). Eyeball pass; flag anything that looks small.
- [ ] Dark mode every screen — no white-on-white or black-on-black.
- [ ] Light mode every screen — no contrast traps.
- [ ] Dynamic Type at AX5 (the largest accessibility text size) — chat list and message bubbles still readable, no clipped buttons.
- [ ] Every error message uses plain language. No `Error(code: -1009, ...)` raw dumps.

## 7. Pre-tag

- [ ] All the above ticked.
- [ ] `xcodebuild ... -only-testing:pizziniTests test` passes on the target simulator.
- [ ] `cargo test --workspace` passes.
- [ ] Reproducible relay build matches the operator co-signer's hash.
- [ ] Tag the release. `git tag v1.x.y && git push --tags`.
- [ ] Sign the new relay binary's SHA-256 with the operator key, append the transparency-log line, commit.
- [ ] Roll out to seed nodes (commands live in `~/.claude/CLAUDE.md` under "Deploying to seed nodes").
- [ ] Tag a fresh QA log post-deploy as a 5-min smoke (paired devices send a message through the live fleet).

---

## Why this exists, and what it isn't

This checklist is **the cheap audit**. One person, one device, an hour
of attention. It catches the "wait, that looks stupid" stuff that
neither `cargo clippy` nor a paid security firm will catch.

It is **NOT** a substitute for the paid external security audit. That
audit asks "is the crypto sound? can a malicious peer escalate? does
the relay leak metadata?" — questions a release checklist can't answer.
Both layers are needed.

Add to this checklist when something slips through. Removing items is
fine if they're genuinely automated elsewhere. The goal is "ten minutes
on a real device before tag" being a hard release gate, not "the longest
possible checklist."
