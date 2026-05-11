#!/usr/bin/env bash
# Build/fetch Tor.xcframework for iOS — the C-tor static library plus its
# headers, packaged as an xcframework that SwiftPM can consume as a
# `.binaryTarget`. Pair with the ObjC wrappers vendored under
# `swift/Sources/PizziniTorObjC/` (TORThread, TORController, …) — those
# wrappers `#import <feature/api/tor_api.h>` etc., so the xcframework
# MUST be in the "static library + Headers/" shape, not the framework
# shape (SwiftPM would only set `-F` for the framework form, which
# leaves the bracket-style includes unresolved).
#
# Two reasons we don't compile C-tor from source here:
#   1. The upstream build pulls in autotools + OpenSSL + libevent + lzma
#      and is fiddly to drive reproducibly from CI.
#   2. iCepa publishes a pinned, checksummed release of the prebuilt
#      static library on GitHub. The podspec (Tor.podspec) pins the
#      version + sha256 we re-use here, so the artifact identity is
#      anchored upstream.
#
# Repackaging step: the iCepa zip ships a *framework* xcframework
# (tor.framework with a Headers/ dir). SwiftPM's binaryTarget for that
# shape only exposes `<tor/...>` bracket includes, which would break
# every `<feature/api/tor_api.h>` import in the ObjC wrappers. We
# unpack it, lift each slice's `tor.framework/{tor, Headers}` into
# `libtor.a` + `Headers/`, and emit a fresh Info.plist in the static-
# library xcframework shape.
#
# Output: build/Tor.xcframework
#
# Force a fresh download with REBUILD=1.

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

# Pinned upstream artifact. Bumping this requires:
#   1. Replace VERSION + SHA256 with values from the matching iCepa
#      Tor.podspec on https://github.com/iCepa/Tor.framework.
#   2. Refresh the ObjC wrappers under swift/Sources/PizziniTorObjC/
#      from Tor/Classes/{Core,CTor}/ in the same release tag — header
#      and API drift between the prebuilt static lib and the wrappers
#      will surface as link errors here.
VERSION="v409.6.1"
SHA256="518a2984a6f693265833d31c7ed8c7cb0556765f1a3e5b2d7d0138c14b32f70d"
URL="https://github.com/iCepa/Tor.framework/releases/download/${VERSION}/tor.xcframework.zip"

REBUILD="${REBUILD:-0}"
if [[ -d "$OUTPUT" && -d "$HEADERS_OUT" && "$REBUILD" != "1" ]]; then
    echo "==> $OUTPUT + $HEADERS_OUT exist (set REBUILD=1 to force)"
    exit 0
fi

mkdir -p "$BUILD_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ZIP="$WORK/tor.xcframework.zip"
echo "==> Downloading tor.xcframework ${VERSION}"
curl -fSL --progress-bar -o "$ZIP" "$URL"

ACTUAL="$(shasum -a 256 "$ZIP" | awk '{print $1}')"
if [[ "$ACTUAL" != "$SHA256" ]]; then
    echo "ERROR: checksum mismatch" >&2
    echo "  expected $SHA256" >&2
    echo "  got      $ACTUAL"   >&2
    exit 1
fi
echo "==> Checksum OK"

echo "==> Unpacking"
unzip -q "$ZIP" -d "$WORK"
SRC="$WORK/tor.xcframework"

# Slices we keep. macOS slice from the upstream zip is dropped — iOS
# app + simulator are sufficient and the app's Package.swift declares
# .iOS-only platforms.
SLICES=(
    "ios-arm64"
    "ios-arm64_x86_64-simulator"
)

echo "==> Repackaging into static-library xcframework"
rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"

create_xcframework_args=()
for slice in "${SLICES[@]}"; do
    FW_DIR="$SRC/$slice/tor.framework"
    if [[ ! -d "$FW_DIR" ]]; then
        echo "ERROR: missing slice $slice in upstream zip" >&2
        exit 1
    fi
    LIB="$WORK/$slice/libtor.a"
    mkdir -p "$WORK/$slice"
    cp "$FW_DIR/tor" "$LIB"
    # Static-library-only xcframework. No headers, no module map —
    # those are staged into $HEADERS_OUT below.
    create_xcframework_args+=(-library "$LIB")
done

xcodebuild -create-xcframework \
    "${create_xcframework_args[@]}" \
    -output "$OUTPUT" >/dev/null

# Sanity: each slice should now have a libtor.a and no stray Headers/
# directory.
for slice in "${SLICES[@]}"; do
    if [[ ! -f "$OUTPUT/$slice/libtor.a" ]]; then
        echo "ERROR: $OUTPUT/$slice missing libtor.a after repackage" >&2
        exit 1
    fi
done

# Stage C-tor's headers under PizziniTorObjC so SwiftPM's
# `headerSearchPath("torheaders")` cSetting on the PizziniTorObjC
# target can resolve every `<feature/api/tor_api.h>`,
# `<event2/event.h>`, `<lib/...>` bracket include in the ObjC
# wrappers. Each iOS slice ships the same Headers/ payload — the
# iCepa build picks `ios-arm64` deliberately as the canonical source
# because device & sim headers are identical.
echo "==> Staging tor headers at $HEADERS_OUT"
rm -rf "$HEADERS_OUT"
mkdir -p "$HEADERS_OUT"
cp -R "$SRC/ios-arm64/tor.framework/Headers/." "$HEADERS_OUT/"

echo "==> Done"
echo "    XCFramework:  $OUTPUT"
echo "    Tor headers:  $HEADERS_OUT"
