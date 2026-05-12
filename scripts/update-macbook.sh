#!/usr/bin/env bash
# One-shot "get my MacBook on the latest version of Pizzini."
#
# Runs:
#   1. `git pull --ff-only` from origin/main
#   2. `scripts/build-xcframework.sh`        (Rust crypto-core XCFramework)
#   3. `scripts/build-tor-xcframework.sh`    (embedded tor XCFramework)
#
# Both XCFrameworks are required dependencies of the iOS app target
# (declared as `.binaryTarget` in Package.swift). Without them the
# Xcode project errors on missing artifacts at open time.
#
# Safety:
#   - Refuses if the working tree is dirty (uncommitted changes
#     would conflict with the pull). Either commit / stash / discard
#     first, or pass `--force` to stash automatically.
#   - Pull uses `--ff-only` so a divergent branch errors loudly
#     instead of silently merging.
#
# Usage:
#   bash scripts/update-macbook.sh           # standard
#   bash scripts/update-macbook.sh --force   # auto-stash local changes
#   bash scripts/update-macbook.sh --no-tor  # skip the tor xcframework
#                                            #   (it's heavy and rarely changes)

set -euo pipefail

# ─── colors / helpers ────────────────────────────────────────────────
say()  { printf "\033[1;36m▶\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m✓\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m!\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m✗\033[0m %s\n" "$*" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FORCE=0
SKIP_TOR=0
for arg in "$@"; do
    case "$arg" in
        --force)   FORCE=1 ;;
        --no-tor)  SKIP_TOR=1 ;;
        *)         err "unknown arg: $arg"; exit 1 ;;
    esac
done

# ─── 1. preflight ────────────────────────────────────────────────────
if [[ "$(git rev-parse --abbrev-ref HEAD)" != "main" ]]; then
    err "not on main (current: $(git rev-parse --abbrev-ref HEAD)). switch to main first."
    exit 1
fi

# Untracked-file exclusions:
#   vendor/, .cargo/        — build artifacts from scripts/build-relay-release.sh
#   scripts/update-macbook.sh — bootstrap chicken-and-egg: a fresh
#       clone that doesn't have this file yet would have an operator
#       hand-paste it before running, which then makes the script see
#       ITSELF as untracked and abort. Once origin's commit lands the
#       file as tracked, the exclusion is a no-op.
if ! git diff --quiet HEAD -- || [[ -n "$(git ls-files --others --exclude-standard | grep -v -E '^(vendor/|.cargo/|scripts/update-macbook.sh$)' || true)" ]]; then
    if (( FORCE == 1 )); then
        STASH_MSG="update-macbook.sh auto-stash $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        warn "working tree dirty — stashing as: $STASH_MSG"
        git stash push -u -m "$STASH_MSG" >/dev/null
        ok  "stashed. restore later with: git stash pop"
    else
        err "working tree has uncommitted changes. commit/stash first, or re-run with --force."
        git status -s | head -10 >&2
        exit 1
    fi
fi

BEFORE_SHA="$(git rev-parse --short HEAD)"

# ─── 2. pull ─────────────────────────────────────────────────────────
say "git pull --ff-only origin main"
START=$(date +%s)
git fetch origin main --quiet
if ! git merge --ff-only origin/main; then
    err "fast-forward merge failed — local branch has commits not on origin."
    err "either rebase (git rebase origin/main) or hard-reset (git reset --hard origin/main)"
    exit 1
fi
AFTER_SHA="$(git rev-parse --short HEAD)"
if [[ "$BEFORE_SHA" == "$AFTER_SHA" ]]; then
    ok "already up to date at $AFTER_SHA"
else
    ok "updated $BEFORE_SHA → $AFTER_SHA ($(( $(date +%s) - START ))s)"
    git log --oneline "$BEFORE_SHA..$AFTER_SHA" | head -10
fi

# ─── 3. crypto-core xcframework ──────────────────────────────────────
say "building PizziniCryptoCore.xcframework"
START=$(date +%s)
bash scripts/build-xcframework.sh
ok "PizziniCryptoCore.xcframework built ($(( $(date +%s) - START ))s)"

# ─── 4. tor xcframework ──────────────────────────────────────────────
if (( SKIP_TOR == 1 )); then
    warn "skipping Tor.xcframework (--no-tor). Only safe if you haven't bumped"
    warn "the pinned tor revision in scripts/build-tor-xcframework.sh."
else
    say "building Tor.xcframework"
    START=$(date +%s)
    bash scripts/build-tor-xcframework.sh
    ok "Tor.xcframework built ($(( $(date +%s) - START ))s)"
fi

# ─── 5. report ───────────────────────────────────────────────────────
echo
ok "MacBook is on $(git rev-parse --short HEAD): $(git log -1 --pretty=%s)"
echo
echo "next steps:"
echo "  1. open pizzini/pizzini.xcodeproj in Xcode"
echo "  2. wait ~5s for SPM to resolve packages"
echo "  3. Product → Run (⌘R) on your simulator/device of choice"
