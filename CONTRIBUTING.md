# Contributing to Pizzini

Pizzini is a secure messenger people use under real risk. Code
quality here is a safety issue, not a style preference.

## Before you tag a release

Run [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) end-to-end. It's a
hard gate, not a suggestion. It exists because:

- `cargo clippy` and `xcodebuild test` don't catch placeholder strings,
  stale FAQ copy, or buttons that look professional but do nothing.
- A paid external security audit doesn't catch them either. Auditors
  ask "is the crypto sound?", not "does the relay-version field say
  0.0.0?".
- These bugs reach users, lose their trust, and a privacy app that
  loses trust loses its reason to exist.

The 2026-05-14 audit caught three such regressions slipping past
prior reviews. Don't be the next one.

## If you are an AI agent

Most lines in this codebase were authored by an AI coding agent.
That's fine if and only if the agent treats the release checklist
as a hard gate, not an optional reference. Specifically:

- Read `RELEASE-CHECKLIST.md` before claiming work is done. Tick the
  items that apply to your change.
- Don't introduce `TODO` / `FIXME` / `XXX` / `HACK` / `STUB` markers.
  If something is unfinished, finish it or revert. Comments
  explaining *why* code is the shape it is are welcome; placeholders
  are not.
- Don't ship `0.0.0` versions, `example.com` URLs, `localhost` in
  release paths, or any other "we'll set this later" defaults. Set
  them now or don't write the call site.
- Match the style of nearby code. Pizzini's voice is direct,
  technical, no marketing fluff. Don't invent a new tone.
- Don't add `Co-Authored-By` lines to commits. Single-author
  attribution is the repo's policy.

## Build and test

```sh
# Rust workspace (crypto-core + relay)
cargo test --workspace

# Swift package (PizziniCryptoCore + PizziniDB + PizziniTor)
xcodebuild test -scheme PizziniCryptoCore \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro'

# iOS app
xcodebuild test -scheme pizzini \
  -destination 'platform=iOS Simulator,id=<your-sim-id>' \
  -only-testing:pizziniTests
```

All three must pass before commit. The iOS app suite is the largest
and catches the most regressions; run it on every Swift change.

## Commits

Read recent commits with `git log --oneline -20` to match style.
Short scope-prefixed subject, imperative mood. Body explains *why*,
not what — the diff already shows what.

```
ios(ux): drop the pb.string?.count BEFORE-read in paste diagnostic

iOS 16+ counts each pb.string access as a paste attempt under the
privacy banner. Reading it for a log line meant each user tap fired
two banner-eligible reads. hasStrings is metadata-only and gives
the same signal.
```

Acceptable scope prefixes seen in the repo today:
`ios(ux)`, `ios(chain)`, `ios(brand)`, `ios(relay)`, `ios(tor)`,
`ios(qa)`, `ios(repair)`, `relay`, `docs`, `repo`.

## Security-sensitive changes

- `crypto-core/` — touch with extreme care. Libsignal is pinned at
  v0.93.2. Don't introduce custom crypto, ever.
- Anything that affects the threat model — make sure you understand
  the threat model before touching it; ask a maintainer if you're
  unsure.
- Identity / persistence / wipe paths — duress wipe must preserve
  the "empty but lived-in" invariant. The coercer-watching design
  is real and the codebase encodes it; don't undo it.
- Pasteboard reads — iOS 16+ counts every `UIPasteboard.string` /
  `.url` access as a paste attempt under privacy. Use metadata
  accessors (`hasStrings`, `hasURLs`, `types`, `items.count`) for
  diagnostics. Content reads belong only inside user-initiated paste
  handlers.

## Code style

- Swift: 4 spaces. No comments explaining *what* the code does —
  well-named identifiers cover that. Comments are for *why* — a
  hidden invariant, a workaround, a surprising behaviour, a past
  incident the code is shaped to avoid.
- Rust: `cargo fmt` (no custom config). Same comment policy.
- No emojis in code or commit messages unless explicitly requested.
- File headers: short doc comment explaining the file's role. Not
  boilerplate.

## Threat-model-adjacent UX

Some UX choices look weird until you remember the threat model:

- The notification payload is the literal string `New message`
  regardless of who sent what. Don't "improve" this by adding
  preview text — it would defeat the iOS-notification-database
  extraction defence (CVE-2026-28950 was the precedent).
- The screenshot mask is unconditional, with no opt-out toggle.
  Don't add one.
- The duress passcode wipes silently. Don't add a confirmation
  prompt; coercion under observation is the design point.
- The paste banner fires once per user tap. Don't read the
  pasteboard outside the user-initiated handler — Handoff prompts
  on the source device are a UX regression we've shipped and
  rolled back twice.

If you don't understand the threat model, ask a maintainer before
changing security-adjacent code.

## License

AGPL-3.0-or-later. Any contribution implies you agree to ship under
that license. There is no CLA.
