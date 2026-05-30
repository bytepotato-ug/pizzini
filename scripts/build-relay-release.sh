#!/usr/bin/env bash
# Build the pizzini-relay binary deterministically and report its
# SHA-256 (reproducible builds + transparency log).
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
# Docker is required: there is no host opt-out (F-SUP-06), so every
# operator's build runs in the identical pinned environment and the
# hash published to the transparency log is always the docker-built
# one. (`INSIDE_DOCKER=1` is set only by this script's own re-exec
# into the container — it is not an operator-facing escape hatch.)

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

if [[ -z "${INSIDE_DOCKER:-}" ]]; then
    # PZ-C8: HARD-FAIL on unpinned reproducibility inputs BEFORE any
    # build work (and before the docker probe, so a misconfiguration is
    # caught even where docker is absent). A mutable base tag,
    # unversioned apt packages, or an unpinned Debian snapshot each float
    # the binary digest between two builds of the same commit — silently
    # breaking the cross-operator reproducibility the transparency log
    # depends on. There is deliberately NO working unpinned default
    # (the prior WARN-and-continue taught operators to ignore the
    # mismatch): the operator must commit the exact pins.
    RELAY_BASE_IMAGE="${RELAY_BASE_IMAGE:-}"
    APT_PINS="${APT_PINS:-}"
    DEBIAN_SNAPSHOT="${DEBIAN_SNAPSHOT:-}"
    pin_errors=0
    if [[ "$RELAY_BASE_IMAGE" != *"@sha256:"* ]]; then
        echo "error: RELAY_BASE_IMAGE must be digest-pinned (…@sha256:<64 hex>)." >&2
        echo "       e.g. RELAY_BASE_IMAGE='rust:1.95.0-bookworm@sha256:<digest>'" >&2
        echo "       Obtain: docker buildx imagetools inspect rust:1.95.0-bookworm" >&2
        pin_errors=1
    fi
    if [[ "$APT_PINS" != *"="* ]]; then
        echo "error: APT_PINS must pin every package to an exact version (name=version)." >&2
        echo "       e.g. APT_PINS='protobuf-compiler=3.21.12-3 pkg-config=1.8.1-1'" >&2
        pin_errors=1
    fi
    if [[ ! "$DEBIAN_SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
        echo "error: DEBIAN_SNAPSHOT must be a snapshot.debian.org timestamp" >&2
        echo "       (YYYYMMDDThhmmssZ). The pinned apt versions must resolve from a" >&2
        echo "       frozen snapshot, not the rolling mirror (which GCs old versions)." >&2
        echo "       e.g. DEBIAN_SNAPSHOT=20260501T000000Z" >&2
        pin_errors=1
    fi
    if [[ "$pin_errors" -ne 0 ]]; then
        echo "error: refusing to build without pinned, reproducible inputs (PZ-C8)." >&2
        exit 1
    fi
    # Outer invocation: re-exec ourselves inside the pinned
    # `rust:1.95.0-bookworm` image with the repo bind-mounted
    # at /work. The inner invocation sets INSIDE_DOCKER so we
    # don't recurse and so it uses the in-container paths for
    # the path-remap.
    #
    # If docker isn't available, fail fast with a clear message:
    # building outside the pinned image silently produces a
    # different hash and breaks the reproducibility promise.
    if ! command -v docker >/dev/null 2>&1; then
        echo "error: docker not found. Reproducible relay builds run inside a pinned image." >&2
        echo "       Install docker and re-run; there is no non-docker build path." >&2
        exit 1
    fi
    echo "==> Reproducible relay build (inside docker)"
    echo "    repo  : $REPO_ROOT"
    echo "    commit: $GIT_SHA"
    # Inputs validated + pinned at the top of this block (PZ-C8):
    # RELAY_BASE_IMAGE is @sha256-digest-pinned, APT_PINS are
    # name=version, DEBIAN_SNAPSHOT is a frozen snapshot.debian.org
    # timestamp. The container build below points apt at that snapshot
    # so the versioned specs resolve to the exact archived packages.
    echo "    image : $RELAY_BASE_IMAGE"
    echo "    apt   : $APT_PINS @ snapshot $DEBIAN_SNAPSHOT"
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
        -e INSIDE_DOCKER=1 \
        -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        -e CARGO_HOME=/work/.cargo \
        -e HOME=/build-home \
        -e HOST_UID="$HOST_UID" \
        -e HOST_GID="$HOST_GID" \
        -e APT_PINS="$APT_PINS" \
        -e DEBIAN_SNAPSHOT="$DEBIAN_SNAPSHOT" \
        -v "$REPO_ROOT":/work:rw \
        -w /work \
        "$RELAY_BASE_IMAGE" \
        bash -c '
            set -euo pipefail
            # PZ-C8: pin apt to the frozen Debian snapshot so the
            # name=version specs resolve to the EXACT archived packages.
            # The rolling mirror garbage-collects old versions, which
            # would either fail the install or float the binary digest.
            # Replace all default sources (bookworm images ship deb822
            # .sources files) with the snapshot archive; disable the
            # Valid-Until check (snapshot Release files are intentionally
            # stale-dated).
            rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list 2>/dev/null || true
            {
              echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main"
              echo "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main"
            } > /etc/apt/sources.list
            apt-get -o Acquire::Check-Valid-Until=false update -qq
            # Install the exact pinned versions (name=version, enforced by
            # the outer PZ-C8 guard).
            apt-get install -y --no-install-recommends $APT_PINS >/dev/null
            mkdir -p /build-home
            # The bind-mounted repo is owned by HOST_UID but the
            # container runs as root, so git >= 2.35 refuses /work
            # for "dubious ownership" and `relay/build.rs` would fall
            # back to a "unknown" git sha — making the embedded
            # provenance (and therefore the binary digest) depend on
            # the host git config instead of the commit. Mark /work
            # trusted so build.rs always reads the real commit.
            git config --global --add safe.directory /work
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
    # PZ-C8: enforce the committed expected digest. If
    # scripts/relay-expected-sha256.txt exists (one 64-hex line), a
    # mismatch is fatal — a build that does not reproduce the published
    # digest must never be shipped or logged. If absent, this is the
    # first pinned build: print the digest so the operator can commit it,
    # after which CI (PZ-C9) enforces it on every subsequent build.
    EXPECTED_FILE="$REPO_ROOT/scripts/relay-expected-sha256.txt"
    if [[ -f "$EXPECTED_FILE" ]]; then
        EXPECTED_SHA="$(tr -d '[:space:]' <"$EXPECTED_FILE")"
        if [[ "$BIN_SHA256" != "$EXPECTED_SHA" ]]; then
            echo >&2
            echo "error: relay digest mismatch — built $BIN_SHA256," >&2
            echo "       expected $EXPECTED_SHA (scripts/relay-expected-sha256.txt)." >&2
            echo "       The build did NOT reproduce the committed digest. Do not ship or publish." >&2
            exit 1
        fi
        echo "    expected  : matches committed digest"
    else
        echo "    NOTE: no committed expected digest at $EXPECTED_FILE." >&2
        echo "          Commit the sha256 above there so CI enforces reproducibility henceforth." >&2
    fi
    echo
    echo "Transparency-log entry to publish (single line):"
    echo "{\"git_sha\":\"$GIT_SHA\",\"binary_sha256\":\"$BIN_SHA256\",\"binary_size\":$BIN_SIZE_BYTES}"
    exit 0
fi

# Inner invocation: only ever reached inside the pinned Docker image
# (the wrapper re-execs us with INSIDE_DOCKER=1). There is no host
# opt-out path (F-SUP-06), so the path-remap always uses the fixed
# container-internal sentinels.
echo "==> Reproducible relay build"
echo "    repo  : $REPO_ROOT"
echo "    commit: $GIT_SHA"
echo "    cargo : $(command -v cargo)"
echo "    rustc : $(command -v rustc)"
echo "    target: x86_64-unknown-linux-gnu"

# 2. Build flags. The remap-path-prefix invocations replace the
#    container's `/work` + `/build-home` paths embedded in DWARF
#    debug info with fixed sentinels, so no builder-specific path
#    reaches the binary and two operators get a byte-identical
#    digest. This build only ever runs inside the pinned image, so
#    the container paths are the only remap sources — there is no
#    host opt-out that could leak `$HOME`/`$REPO_ROOT` (F-SUP-06).
#    `CARGO_HOME` is supplied by the docker wrapper (`/work/.cargo`)
#    so vendored-crate source paths fall under the `/work` remap.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=/work=/build --remap-path-prefix=/build-home=/build-home"
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
