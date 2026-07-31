#!/usr/bin/env bash
# Build Tor.xcframework for iOS — the C-tor static library plus its
# headers, packaged as an xcframework that SwiftPM can consume as a
# `.binaryTarget`. Pair with the ObjC wrappers vendored under
# `swift/Sources/PizziniTorObjC/` (TORThread, TORController, …) — those
# wrappers `#import <feature/api/tor_api.h>` etc., so the xcframework
# MUST be in the "static library + Headers/" shape, not the framework
# shape (SwiftPM would only set `-F` for the framework form, which
# leaves the bracket-style includes unresolved).
#
# Why we build from source (not just download the prebuilt iCepa zip):
# iCepa's release zip is built without `--enable-gpl --enable-module-pow`,
# so libtor.a ships without the Equi-X PoW client solver. `hs_pow_solve`
# falls back to the static-inline stub in `hs_pow.h` that returns -1,
# and the client connects to the introduction point without a puzzle
# solution. Under DoS — the only time PoW matters — clients are
# queued at the lowest priority and time out. We need the real solver
# in the static lib before the operator can flip
# `HiddenServicePoWDefensesEnabled` on the relay hosts; see
# `audit-2026-05/findings/findings-tor-pow-client.md`.
#
# Build flow:
#   1. Clone iCepa/Tor.framework at the pinned tag.
#   2. Patch their `build-xcframework.sh` to add `--enable-gpl
#      --enable-module-pow` to the libtor `./configure` call. Equi-X
#      is vendored in upstream tor under `src/ext/equix/`; no separate
#      fetch needed.
#   3. Run `./build-xcframework.sh -c` to produce `tor.xcframework` in
#      framework shape, then repackage to static-library shape (each
#      slice's `tor.framework/{tor, Headers}` becomes
#      `libtor.a` + a headers tree under PizziniTorObjC).
#   4. Final regression pin: `nm` every libtor.a slice and fail loudly
#      if `_hs_pow_solve` is absent. This is the canary for future tor
#      bumps — if iCepa or upstream tor change the build wiring and
#      the PoW module silently drops out again, this script must NOT
#      succeed.
#
# Output: build/Tor.xcframework
#
# Force a fresh build with REBUILD=1. The from-source build takes
# roughly 30-60 minutes on Apple Silicon. CI and operator-side
# verification reuse cached intermediate builds via the build dir.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build"
OUTPUT="$BUILD_DIR/Tor.xcframework"
# Headers are staged separately from the xcframework so SwiftPM's
# `headerSearchPath` in PizziniTorObjC can pick them up directly. This
# avoids a `module.modulemap` collision in
# `<DerivedData>/.../Debug-iphonesimulator/include/` between
# Tor.xcframework and PizziniCryptoCore.xcframework — both would
# otherwise emit `module.modulemap` to the same flat output path. By
# keeping Tor's headers + module map out of the xcframework entirely,
# only the static library is processed by ProcessXCFramework, and the
# headers are surfaced through the regular Clang -I flag chain.
HEADERS_OUT="$REPO_ROOT/swift/Sources/PizziniTorObjC/torheaders"

# Pinned upstream tag for iCepa's build-xcframework.sh source. Bumping
# this requires:
#   1. Update VERSION to the new iCepa release tag.
#   2. Re-run this script end-to-end; the nm check at the end will fail
#      if iCepa has restructured the libtor configure flags such that
#      our sed patch no longer hits the right line. In that case,
#      update the sed patterns in `patch_icepa_build_script` below.
#   3. Refresh the ObjC wrappers under swift/Sources/PizziniTorObjC/
#      from Tor/Classes/{Core,CTor}/ in the same release tag — header
#      and API drift between the prebuilt static lib and the wrappers
#      will surface as link errors here.
VERSION="v409.8.1"
ICEPA_REPO="https://github.com/iCepa/Tor.framework.git"

# ----- transport trust anchor: hard-coded, enforced commit pin -----
#
# A git TAG is mutable: the upstream can force-push it, a compromised
# iCepa GitHub account can re-point it, or a TLS intermediary on the
# operator's `git clone` can serve different bytes. Cloning `--branch
# v409.8.1` is therefore NOT a content pin. This is the single
# load-bearing anonymity component — every client routes 100% of its
# traffic through it — so the build MUST refuse to proceed against any
# commit other than the one we reviewed. Mirrors
# `scripts/build-sqlcipher-amalgamation.sh`'s SQLCIPHER_PIN_SHA gate:
# hard-coded SHA, FATAL exit on mismatch, fail CLOSED (never
# warn-and-build).
#
# TOR_PIN_COMMIT is the full 40-char commit that tag `v409.8.1` of
# iCepa/Tor.framework resolved to at review time
# (`git ls-remote --tags iCepa/Tor.framework v409.8.1`). The default
# below is authoritative; the env var only allows an operator to pin a
# DIFFERENT reviewed commit when bumping VERSION — it can never relax
# the gate to "unset". Bumping VERSION REQUIRES updating this constant
# to the new reviewed commit (and re-reviewing the upstream diff); see
# RELEASE-CHECKLIST.md.
TOR_PIN_COMMIT="${TOR_PIN_COMMIT:-5fe6e0442625b5b5bedecbd8f10b9e5cb29c8f05}"
#
# iCepa pins its own submodules by gitlink. At v409.8.1 the only
# submodule in the tree is `Tor/onionmasq` (the arti transport; the
# C-tor source we actually build is fetched separately by iCepa's
# build-xcframework.sh via `git clone --branch tor-0.4.9.8
# tpo/core/tor.git`, not as a recursive submodule). We keep
# `--recursive` for completeness but VERIFY this gitlink so a moved
# submodule pointer is also caught. Reviewed value for v409.8.1:
TOR_SUBMODULE_PATH="Tor/onionmasq"
TOR_SUBMODULE_PIN_COMMIT="${TOR_SUBMODULE_PIN_COMMIT:-641e3349f5b0d181a343496ce0dc94c628f9ac89}"

# ----- helpers -----

# Patch iCepa's build-xcframework.sh so the libtor configure call
# enables the PoW module. The upstream tor build gates `HAVE_MODULE_POW`
# behind both `--enable-gpl` AND (not `--disable-module-pow`); iCepa
# passes neither, so the gate stays closed and Equi-X is compiled out.
# We inject both flags into the existing configure call. Equi-X itself
# is already vendored under `src/ext/equix/` in the tor source tree —
# the build picks it up once the module is enabled.
patch_icepa_build_script() {
    local script="$1"
    if [[ ! -f "$script" ]]; then
        echo "ERROR: missing $script" >&2
        return 1
    fi

    # Idempotency: the presence of `--enable-module-pow` is itself the
    # marker, since iCepa never sets it. Re-running is a no-op.
    if grep -q -- '--enable-module-pow' "$script"; then
        echo "==> iCepa build script already patched (--enable-module-pow present)"
        return 0
    fi

    # iCepa's libtor configure call passes `--disable-module-relay`
    # as its first long-form flag. Insert our two flags right before
    # it. We can't drop a `# comment` line inside the backslash-
    # continued `./configure \` block — bash treats the `#` as ending
    # the command and the next backslash-newline-joined token errors
    # out. So the patch is two clean flag lines, no inline comment.
    # Match must be unique — verified against v409.8.1.
    local hits
    hits="$(grep -c -- '--disable-module-relay' "$script" || true)"
    if [[ "$hits" != "1" ]]; then
        echo "ERROR: expected exactly one '--disable-module-relay' in $script, found $hits" >&2
        echo "  iCepa may have restructured the build; re-audit before bumping the pin." >&2
        return 1
    fi

    sed -i '' \
        -e $'s|        --disable-module-relay \\\\|        --enable-gpl \\\\\\\n        --enable-module-pow \\\\\\\n        --disable-module-relay \\\\|' \
        "$script"

    # Confirm the patch landed and didn't double-insert.
    local pow_hits gpl_hits
    pow_hits="$(grep -c -- '--enable-module-pow' "$script" || true)"
    gpl_hits="$(grep -c -- '--enable-gpl' "$script" || true)"
    if [[ "$pow_hits" != "1" || "$gpl_hits" != "1" ]]; then
        echo "ERROR: sed patch did not land cleanly (--enable-module-pow x$pow_hits, --enable-gpl x$gpl_hits)" >&2
        return 1
    fi
    echo "==> Patched iCepa build script: +--enable-gpl +--enable-module-pow"
}

# Verify the produced libtor.a slices export _hs_pow_solve. This is
# the regression pin — every future tor bump must keep this symbol
# in both slices or the build fails.
nm_check_pow_solver() {
    local xcframework="$1"
    local slices=("ios-arm64" "ios-arm64_x86_64-simulator")
    local missing=0

    for slice in "${slices[@]}"; do
        local lib="$xcframework/$slice/libtor.a"
        if [[ ! -f "$lib" ]]; then
            echo "ERROR: $lib missing" >&2
            missing=1
            continue
        fi
        # `nm -gU` on a static archive walks every member object and
        # emits global defined symbols. The PoW solver is exported as
        # `_hs_pow_solve` on Mach-O (leading underscore).
        #
        # Capture nm's output into a variable BEFORE matching — do NOT
        # pipe it into `grep -q`. `grep -q` exits on the first match and
        # closes the pipe, which SIGPIPEs `nm` (exit 141). Under the
        # `set -o pipefail` at the top of this script that turns a
        # SUCCESSFUL match into a non-zero pipeline, and the `if !`
        # inverts it into a FALSE "_hs_pow_solve missing" — fired
        # non-deterministically, depending on where the symbol lands in
        # nm's 20k-line output (the modern llvm-nm shipped with Xcode
        # makes this reliably reproducible). Reading into `$syms` first
        # removes the pipe, and runs nm once instead of twice.
        local syms
        syms="$(nm -gU "$lib" 2>/dev/null || true)"
        if ! grep -q ' _hs_pow_solve$' <<<"$syms"; then
            echo "ERROR: $lib does not export _hs_pow_solve" >&2
            echo "  PoW client solver missing — this build cannot ride out a DoS." >&2
            echo "  Re-check the sed patch in patch_icepa_build_script()." >&2
            missing=1
        fi
        # Equi-X belt-and-braces: hs_pow_solve calls equix_solve, so
        # the latter must also be present. If the solver linked but
        # equix didn't, that's a more subtle gap.
        if ! grep -qE ' _equix_(solve|alloc|new)' <<<"$syms"; then
            echo "ERROR: $lib does not export any _equix_* symbol" >&2
            echo "  Equi-X library was not staged into the static archive." >&2
            missing=1
        fi
    done

    if [[ "$missing" != "0" ]]; then
        return 1
    fi
    echo "==> nm check OK: _hs_pow_solve + _equix_* present in all slices"
    return 0
}

# Repackage iCepa's framework-shape tor.xcframework into our static-
# library shape. Each slice's `tor.framework/{tor, Headers}` becomes
# `libtor.a` and a headers tree under $HEADERS_OUT. See the file
# header for why we don't ship the framework shape directly.
repackage_to_static() {
    local fw_xcf="$1"
    local out="$2"

    local slices=(
        "ios-arm64"
        "ios-arm64_x86_64-simulator"
    )

    rm -rf "$out"
    mkdir -p "$out"

    local args=()
    local stage
    stage="$(mktemp -d)"
    trap 'rm -rf "$stage"' RETURN

    for slice in "${slices[@]}"; do
        local fw_dir="$fw_xcf/$slice/tor.framework"
        if [[ ! -d "$fw_dir" ]]; then
            echo "ERROR: missing slice $slice in $fw_xcf" >&2
            return 1
        fi
        local lib="$stage/$slice/libtor.a"
        mkdir -p "$stage/$slice"
        cp "$fw_dir/tor" "$lib"
        args+=(-library "$lib")
    done

    xcodebuild -create-xcframework \
        "${args[@]}" \
        -output "$out" >/dev/null

    for slice in "${slices[@]}"; do
        if [[ ! -f "$out/$slice/libtor.a" ]]; then
            echo "ERROR: $out/$slice missing libtor.a after repackage" >&2
            return 1
        fi
    done

    # Stage C-tor's headers under PizziniTorObjC so SwiftPM's
    # `headerSearchPath("torheaders")` cSetting on the PizziniTorObjC
    # target can resolve every `<feature/api/tor_api.h>`,
    # `<event2/event.h>`, `<lib/...>` bracket include in the ObjC
    # wrappers. Each iOS slice ships the same Headers/ payload — the
    # iCepa build picks `ios-arm64` deliberately as the canonical
    # source because device & sim headers are identical.
    rm -rf "$HEADERS_OUT"
    mkdir -p "$HEADERS_OUT"
    cp -R "$fw_xcf/ios-arm64/tor.framework/Headers/." "$HEADERS_OUT/"
}

# ----- main -----

REBUILD="${REBUILD:-0}"
if [[ -d "$OUTPUT" && -d "$HEADERS_OUT" && "$REBUILD" != "1" ]]; then
    echo "==> $OUTPUT + $HEADERS_OUT exist (set REBUILD=1 to force)"
    # Still run the nm check on the cached artifact so an operator who
    # has a stale prebuilt-zip Tor.xcframework on disk (from before the
    # PoW-solver fix) discovers the gap on the next run instead of at
    # runtime under a DoS.
    if ! nm_check_pow_solver "$OUTPUT"; then
        echo "==> Cached $OUTPUT lacks the PoW solver; re-run with REBUILD=1" >&2
        exit 1
    fi
    exit 0
fi

mkdir -p "$BUILD_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ICEPA_DIR="$WORK/Tor.framework"

echo "==> Cloning iCepa/Tor.framework $VERSION"
# Shallow clone of the pinned tag. We need the working tree of iCepa's
# build-xcframework.sh + Tor/mmap-cache.patch, not history.
git clone --depth 1 --branch "$VERSION" --recursive --shallow-submodules \
    "$ICEPA_REPO" "$ICEPA_DIR" 2>&1 | grep -v -E '^(Cloning|remote: |Receiving|Resolving|Updating|Submodule|From )' || true

# F-SUP-02 / S12-01: a git TAG is mutable (the upstream can force-push
# it, or an account/TLS compromise can serve different bytes), so cloning
# `--branch v409.8.1` is NOT a content pin. Resolve the cloned commit and
# FATAL-exit on any mismatch against the hard-coded TOR_PIN_COMMIT — this
# is the transport trust anchor every client routes 100% of traffic
# through, so the gate fails CLOSED. The pin is mandatory: it has a
# reviewed default at the top of this script and can never be unset (an
# empty value is itself a fatal misconfiguration). This mirrors
# build-sqlcipher-amalgamation.sh exactly.
TOR_RESOLVED_COMMIT="$(git -C "$ICEPA_DIR" rev-parse HEAD)"

# A defensively empty pin (e.g. someone passed TOR_PIN_COMMIT= on the
# command line) must NOT degrade to a warn-and-build. Treat it as fatal.
if [[ -z "${TOR_PIN_COMMIT:-}" ]]; then
    echo "FATAL: TOR_PIN_COMMIT is empty." >&2
    echo "  The embedded Tor commit pin is mandatory and fails closed." >&2
    echo "  Restore the reviewed default at the top of this script, or set" >&2
    echo "  TOR_PIN_COMMIT to the reviewed iCepa commit for tag $VERSION." >&2
    exit 1
fi
if [[ "$TOR_RESOLVED_COMMIT" != "$TOR_PIN_COMMIT" ]]; then
    echo "FATAL: iCepa Tor.framework commit mismatch." >&2
    echo "  expected (TOR_PIN_COMMIT): $TOR_PIN_COMMIT" >&2
    echo "  got (tag $VERSION now points at): $TOR_RESOLVED_COMMIT" >&2
    echo "  The tag may have been force-pushed, or a TLS intermediary served" >&2
    echo "  a different tree. Refusing to build the transport library from an" >&2
    echo "  unverified commit. If this is an intentional version bump, review" >&2
    echo "  the upstream diff and update TOR_PIN_COMMIT at the top of this script." >&2
    exit 1
fi
echo "==> Verified iCepa commit matches TOR_PIN_COMMIT ($TOR_RESOLVED_COMMIT)"

# Also verify the submodule gitlink. `--recursive` is kept, but a moved
# submodule pointer is a content-substitution vector too, so we resolve
# the recorded gitlink and FATAL on mismatch. `git submodule status`
# prints `[+-]<sha> <path> ...`; strip the leading +/- status marker.
TOR_SUBMODULE_COMMIT="$(git -C "$ICEPA_DIR" submodule status 2>/dev/null \
    | awk -v p="$TOR_SUBMODULE_PATH" '$2==p {print $1}' | tr -d '+-' || true)"
if [[ -z "$TOR_SUBMODULE_COMMIT" ]]; then
    echo "FATAL: expected submodule '$TOR_SUBMODULE_PATH' not found in the iCepa checkout." >&2
    echo "  iCepa may have restructured its submodules at tag $VERSION." >&2
    echo "  Re-audit and update TOR_SUBMODULE_PATH / TOR_SUBMODULE_PIN_COMMIT." >&2
    exit 1
fi
if [[ "$TOR_SUBMODULE_COMMIT" != "$TOR_SUBMODULE_PIN_COMMIT" ]]; then
    echo "FATAL: iCepa submodule '$TOR_SUBMODULE_PATH' commit mismatch." >&2
    echo "  expected (TOR_SUBMODULE_PIN_COMMIT): $TOR_SUBMODULE_PIN_COMMIT" >&2
    echo "  got:                                 $TOR_SUBMODULE_COMMIT" >&2
    echo "  Refusing to build from a moved submodule pointer." >&2
    exit 1
fi
echo "==> Verified $TOR_SUBMODULE_PATH submodule matches pin ($TOR_SUBMODULE_COMMIT)"

patch_icepa_build_script "$ICEPA_DIR/build-xcframework.sh"

echo "==> Running iCepa build-xcframework.sh -c (this clones tor + builds OpenSSL/libevent/lzma/libtor for iOS + iOS-sim + macOS)"
echo "    Expect 30-60 minutes on Apple Silicon. Log: $ICEPA_DIR/build/*.log"

# iCepa's script chdirs to its own dirname; running it directly is
# the supported invocation. The `-c` flag selects "C-tor only" (skip
# arti).
(
    cd "$ICEPA_DIR"
    ./build-xcframework.sh -c
)

# iCepa emits `tor.xcframework` (framework shape) at the repo root.
# We don't use the `tor-nolzma` variant — Pizzini's torrc uses
# microdesc caches that benefit from lzma decompression.
FW_XCF="$ICEPA_DIR/tor.xcframework"
if [[ ! -d "$FW_XCF" ]]; then
    echo "ERROR: iCepa build did not produce $FW_XCF" >&2
    exit 1
fi

echo "==> Repackaging into static-library xcframework"
repackage_to_static "$FW_XCF" "$OUTPUT"

echo "==> Verifying PoW solver presence in produced libtor.a slices"
if ! nm_check_pow_solver "$OUTPUT"; then
    # The repackage already wrote $OUTPUT and staged $HEADERS_OUT.
    # Leave them in place for forensic inspection — but exit non-zero
    # so CI / the operator notices.
    echo "==> BUILD FAILED: PoW solver regression" >&2
    exit 1
fi

echo "==> Done"
echo "    XCFramework:  $OUTPUT"
echo "    Tor headers:  $HEADERS_OUT"
