#!/usr/bin/env bash
# Build the pizzini-relay binary deterministically and report its
# SHA-256 (USP #1: reproducible builds + transparency log).
#
# Two operators running this script on the same git commit, on the
# same Rust toolchain version, MUST get the same hex digest. If
# they don't, this build script has acquired a non-reproducible
# input — investigate before publishing the digest to the
# transparency log.
#
# What this script does that a vanilla `cargo build --release`
# doesn't:
#
#   * Pins the toolchain via `rust-toolchain.toml` (sister file at
#     the repo root). Cargo picks it up automatically; the explicit
#     `rustup which cargo` echo confirms the chosen version.
#   * Refuses if the working tree has uncommitted changes — a dirty
#     build cannot be independently reproduced from public source,
#     so the resulting digest would never roundtrip.
#   * Builds with `--locked --frozen` so a hidden Cargo.lock update
#     or network fetch (e.g. someone slipping a yanked dep) fails
#     the build loud instead of silently producing a different
#     binary.
#   * Strips DWARF path prefixes via `--remap-path-prefix` so the
#     debug-info section is independent of the builder's $HOME
#     and $REPO. Combined with `strip = "symbols"` from the
#     workspace `[profile.release]` (already locked in), this
#     removes the last two path-leak vectors.
#   * Computes SHA-256 over the final binary and prints both that
#     hash and the git SHA so the operator can paste both into the
#     transparency log entry.
#
# The relay's own STATUS_RESPONSE frame re-derives the SHA-256 at
# startup by reading /proc/self/exe; the value below MUST match
# what the running relay reports — if they ever disagree, the
# self-attestation code in the binary was tampered with after
# this script ran.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# 1. Reject dirty trees. Publishing a non-reproducible build to a
#    transparency log is worse than not publishing at all — it
#    teaches users to ignore unmatched digests.
if ! git diff --quiet HEAD --; then
    echo "error: working tree has uncommitted changes." >&2
    echo "       Reproducible builds require a clean checkout. Commit or stash first." >&2
    exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
    echo "error: untracked files present. Clean the tree before building for release." >&2
    git status --short >&2
    exit 1
fi

GIT_SHA="$(git rev-parse HEAD)"
SHORT_SHA="$(git rev-parse --short HEAD)"
echo "==> Reproducible relay build"
echo "    repo  : $REPO_ROOT"
echo "    commit: $GIT_SHA"
echo "    cargo : $(rustup which cargo)"
echo "    rustc : $(rustup which rustc)"

# 2. Build flags. The remap-path-prefix invocations replace the
#    builder-specific absolute paths embedded in DWARF debug info
#    (which would otherwise differ between $HOME=/Users/alice
#    and $HOME=/home/bob and silently make the binaries diverge).
#    The path "/build" is a fixed sentinel every reproducer agrees
#    on.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$REPO_ROOT=/build --remap-path-prefix=$HOME=/build-home"
# Belt + braces: cargo refuses to update the lockfile or hit the
# network. Either condition would mean the build is taking input
# from somewhere other than the committed source.
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"

echo "==> cargo build --release --locked --frozen --bin pizzini-relay"
cargo build --release --locked --frozen --bin pizzini-relay

BIN_PATH="$REPO_ROOT/target/release/pizzini-relay"
if [[ ! -f "$BIN_PATH" ]]; then
    echo "error: expected binary at $BIN_PATH but it does not exist" >&2
    exit 1
fi

# 3. Compute SHA-256. macOS shasum vs Linux sha256sum both produce
#    the same digest; just pick whichever is installed.
if command -v sha256sum >/dev/null 2>&1; then
    BIN_SHA256="$(sha256sum "$BIN_PATH" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    BIN_SHA256="$(shasum -a 256 "$BIN_PATH" | awk '{print $1}')"
else
    echo "error: neither sha256sum nor shasum found in PATH" >&2
    exit 1
fi
BIN_SIZE_BYTES="$(wc -c <"$BIN_PATH" | awk '{print $1}')"

echo
echo "==> Build complete."
echo "    binary    : $BIN_PATH"
echo "    size      : $BIN_SIZE_BYTES bytes"
echo "    sha256    : $BIN_SHA256"
echo "    git commit: $GIT_SHA ($SHORT_SHA)"
echo
echo "Transparency-log entry to publish (single line):"
echo "{\"git_sha\":\"$GIT_SHA\",\"binary_sha256\":\"$BIN_SHA256\",\"binary_size\":$BIN_SIZE_BYTES}"
