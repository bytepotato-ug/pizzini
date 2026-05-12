#!/usr/bin/env bash
# Build the pizzini-relay binary deterministically and report its
# SHA-256 (USP #1: reproducible builds + transparency log).
#
# Two operators running this script on the same git commit MUST get
# the same hex digest. If they don't, this build script has
# acquired a non-reproducible input — investigate before
# publishing the digest to the transparency log.
#
# The relay runs on `x86_64-unknown-linux-gnu` (Hetzner / Cherry
# Servers); macOS / arm64 / musl native builds produce DIFFERENT
# binaries that cannot match the production hash. To keep "two
# operators get the same digest" honest across host platforms, we
# always build inside a pinned Docker image that fixes:
#
#   * the target triple        — `x86_64-unknown-linux-gnu`
#   * the rust toolchain       — from `rust-toolchain.toml`
#   * the OS distribution      — debian bookworm
#   * the system packages      — `protobuf-compiler` + `pkg-config`,
#                                 required by the libsignal
#                                 `sparsepostquantumratchet` build.rs
#   * the path-remap sentinels — `/work` for the repo, `/build-home`
#                                 for $HOME, both inside the container
#                                 so the host's actual paths never
#                                 reach the DWARF section
#   * SOURCE_DATE_EPOCH        — pinned to the commit timestamp so
#                                 any embedded build clock is
#                                 deterministic
#   * `cargo vendor`           — every crate fetched offline from
#                                 the committed `vendor/` directory,
#                                 closing the `--frozen` git-deps
#                                 refresh hole
#
# Operators on a Linux host with all the above already installed
# can opt out of the docker wrapper with `PIZZINI_RELEASE_NO_DOCKER=1`,
# but the canonical path is `Docker required` — the hash published
# to the transparency log is the docker-built one.

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
# Untracked files inside the repo root would also taint a build,
# but `cargo vendor` (re-)generates the `vendor/` directory which
# IS untracked by design; ignore it specifically so the script can
# be re-run from a clean tree where the only delta is the vendored
# dependency tree.
UNTRACKED="$(git ls-files --others --exclude-standard | grep -v '^vendor/' || true)"
if [[ -n "$UNTRACKED" ]]; then
    echo "error: untracked files present (other than vendor/). Clean the tree before building for release." >&2
    echo "$UNTRACKED" >&2
    exit 1
fi

GIT_SHA="$(git rev-parse HEAD)"
SHORT_SHA="$(git rev-parse --short HEAD)"

# Pin SOURCE_DATE_EPOCH to the commit timestamp so any "embedded
# build time" anywhere in the dep tree (cargo metadata, build.rs
# scripts that bake a `BUILT_AT` constant, etc.) is deterministic.
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct HEAD)"
export SOURCE_DATE_EPOCH

if [[ -z "${PIZZINI_RELEASE_NO_DOCKER:-}" ]]; then
    # Outer invocation: re-exec ourselves inside the pinned
    # `rust:1.95.0-bookworm-slim` image with the repo bind-mounted
    # at /work. The inner invocation sets PIZZINI_RELEASE_NO_DOCKER
    # so we don't recurse, and INSIDE_DOCKER so it knows to use
    # the in-container paths for the path-remap.
    #
    # If docker isn't available, fail fast with a clear message:
    # building outside the pinned image silently produces a
    # different hash and breaks the reproducibility promise.
    if ! command -v docker >/dev/null 2>&1; then
        echo "error: docker not found. Reproducible relay builds run inside a pinned image." >&2
        echo "       Install docker, or set PIZZINI_RELEASE_NO_DOCKER=1 to opt out (you" >&2
        echo "       MUST then be on x86_64-linux with the same rustc + protoc as the" >&2
        echo "       canonical builder, or the published hash will not match)." >&2
        exit 1
    fi
    echo "==> Reproducible relay build (inside docker)"
    echo "    repo  : $REPO_ROOT"
    echo "    commit: $GIT_SHA"
    # `cargo vendor` once on the host (outside the container) so the
    # offline build inside docker has every dep on disk. Idempotent;
    # produces `vendor/` + `.cargo/config.toml`-equivalent stdout we
    # capture into `.cargo/config-vendor.toml`.
    if [[ ! -d "$REPO_ROOT/vendor" ]]; then
        echo "==> cargo vendor (one-time)"
        mkdir -p "$REPO_ROOT/.cargo"
        cargo vendor --locked vendor > "$REPO_ROOT/.cargo/config-vendor.toml"
    fi
    # Run docker as root inside the container so `apt-get update +
    # install protobuf-compiler pkg-config` works (the rust:bookworm
    # base image doesn't ship protoc, and apt-get needs root for
    # /var/lib/apt). A `--user $(id -u):$(id -g)` invocation would
    # keep target/ host-owned but would also fail at apt-get with
    # "Permission denied" on /var/lib/apt/lists/partial. We restore
    # host ownership on the bind-mounted artifacts at the end of the
    # container's bash script so the host doesn't need to sudo to
    # clean up target/.
    HOST_UID="$(id -u)"
    HOST_GID="$(id -g)"
    docker run --rm \
        -e PIZZINI_RELEASE_NO_DOCKER=1 \
        -e INSIDE_DOCKER=1 \
        -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        -e CARGO_HOME=/work/.cargo \
        -e HOME=/build-home \
        -e HOST_UID="$HOST_UID" \
        -e HOST_GID="$HOST_GID" \
        -v "$REPO_ROOT":/work:rw \
        -w /work \
        rust:1.95.0-bookworm \
        bash -c '
            set -euo pipefail
            apt-get update -qq
            apt-get install -y --no-install-recommends protobuf-compiler pkg-config >/dev/null
            mkdir -p /build-home
            # Inside-container path-remap: every host-side path
            # disappears, replaced by the fixed sentinels.
            export RUSTFLAGS="--remap-path-prefix=/work=/build --remap-path-prefix=/build-home=/build-home"
            # The .cargo/config-vendor.toml from `cargo vendor`
            # points at /work/vendor — use it via $CARGO_HOME so
            # cargo offlines through the vendored tree.
            mkdir -p /work/.cargo
            cp /work/.cargo/config-vendor.toml /work/.cargo/config.toml
            export CARGO_NET_OFFLINE=true
            # Capture rc so we always chown back even on build failure;
            # otherwise the host is left with a root-owned target/
            # tree that requires sudo to clean.
            rc=0
            /work/scripts/build-relay-release.sh || rc=$?
            chown -R "$HOST_UID:$HOST_GID" /work/target /work/vendor /work/.cargo 2>/dev/null || true
            exit "$rc"
        '
    BIN_PATH="$REPO_ROOT/target/x86_64-unknown-linux-gnu/release/pizzini-relay"
    BIN_PATH="${BIN_PATH:-$REPO_ROOT/target/release/pizzini-relay}"
    if [[ ! -f "$BIN_PATH" ]]; then
        BIN_PATH="$REPO_ROOT/target/release/pizzini-relay"
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        BIN_SHA256="$(sha256sum "$BIN_PATH" | awk '{print $1}')"
    else
        BIN_SHA256="$(shasum -a 256 "$BIN_PATH" | awk '{print $1}')"
    fi
    BIN_SIZE_BYTES="$(wc -c <"$BIN_PATH" | awk '{print $1}')"
    echo
    echo "==> Docker-built relay complete."
    echo "    binary    : $BIN_PATH"
    echo "    size      : $BIN_SIZE_BYTES bytes"
    echo "    sha256    : $BIN_SHA256"
    echo "    git commit: $GIT_SHA ($SHORT_SHA)"
    echo
    echo "Transparency-log entry to publish (single line):"
    echo "{\"git_sha\":\"$GIT_SHA\",\"binary_sha256\":\"$BIN_SHA256\",\"binary_size\":$BIN_SIZE_BYTES}"
    exit 0
fi

# Inner invocation (or `PIZZINI_RELEASE_NO_DOCKER=1` opt-out path).
# `INSIDE_DOCKER=1` flips path-remap to the container-internal
# values; opt-out path uses the host's $REPO_ROOT and $HOME, which
# is only correct on the canonical x86_64-linux builder image.
echo "==> Reproducible relay build"
echo "    repo  : $REPO_ROOT"
echo "    commit: $GIT_SHA"
echo "    cargo : $(command -v cargo)"
echo "    rustc : $(command -v rustc)"
echo "    target: x86_64-unknown-linux-gnu"

# 2. Build flags. The remap-path-prefix invocations replace the
#    builder-specific absolute paths embedded in DWARF debug info
#    (which would otherwise differ between $HOME=/Users/alice
#    and $HOME=/home/bob and silently make the binaries diverge).
#    Inside docker we use the in-container path "/work" + "/build-home"
#    constants; on the opt-out path we substitute the host's actual
#    paths, which is only valid on the canonical builder.
if [[ -n "${INSIDE_DOCKER:-}" ]]; then
    export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=/work=/build --remap-path-prefix=/build-home=/build-home"
else
    export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$REPO_ROOT=/build --remap-path-prefix=$HOME=/build-home"
fi
# Cargo refuses to update the lockfile. `--offline` (set via
# CARGO_NET_OFFLINE in the docker wrapper) closes the network
# entirely; `--locked --frozen` keeps the lockfile + vendored
# tree authoritative even on the opt-out path.
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"

echo "==> cargo build --release --locked --frozen --target x86_64-unknown-linux-gnu --bin pizzini-relay"
cargo build --release --locked --frozen --target x86_64-unknown-linux-gnu --bin pizzini-relay

BIN_PATH="$REPO_ROOT/target/x86_64-unknown-linux-gnu/release/pizzini-relay"
if [[ ! -f "$BIN_PATH" ]]; then
    # Older toolchain configs default the target dir name; check
    # both before giving up.
    BIN_PATH="$REPO_ROOT/target/release/pizzini-relay"
fi
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
