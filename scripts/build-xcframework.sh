#!/usr/bin/env bash
# Build crypto-core as an XCFramework for iOS.
#
# Default targets:
#   aarch64-apple-ios          (device)
#   aarch64-apple-ios-sim      (Apple Silicon simulator)
#
# Set BUILD_X86_64_SIM=1 to also bundle the legacy Intel simulator slice
# (needed only if running tests/builds on an Intel Mac).
# Set PROFILE=debug for a debug build (default: release).
#
# Output: build/PizziniCryptoCore.xcframework

set -euo pipefail

PROFILE="${PROFILE:-release}"
BUILD_X86_64_SIM="${BUILD_X86_64_SIM:-0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="$REPO_ROOT/crypto-core"
TARGET_DIR="$REPO_ROOT/target"
BUILD_DIR="$REPO_ROOT/build"
HEADER_PATH="$CRATE_DIR/include/pizzini_crypto_core.h"
LIB_NAME="libpizzini_crypto_core.a"
FRAMEWORK="PizziniCryptoCore"

DEVICE_TARGETS=(aarch64-apple-ios)
SIM_TARGETS=(aarch64-apple-ios-sim)
if [[ "$BUILD_X86_64_SIM" = "1" ]]; then
    SIM_TARGETS+=(x86_64-apple-ios)
fi
ALL_TARGETS=("${DEVICE_TARGETS[@]}" "${SIM_TARGETS[@]}")

case "$PROFILE" in
    debug)   CARGO_PROFILE_FLAG="" ;;
    release) CARGO_PROFILE_FLAG="--release" ;;
    *) echo "PROFILE must be 'debug' or 'release' (got '$PROFILE')" >&2; exit 1 ;;
esac

echo "==> Ensuring iOS targets installed: ${ALL_TARGETS[*]}"
rustup target add "${ALL_TARGETS[@]}" >/dev/null

echo "==> Building crypto-core ($PROFILE) for ${#ALL_TARGETS[@]} target(s)"
target_args=()
for t in "${ALL_TARGETS[@]}"; do target_args+=(--target "$t"); done
# Match the iOS app's deployment target. Fix: the
# `Package.swift` SwiftPM target is `.iOS(.v18)` (bumped 2026-05-11);
# the previous default `17.0` here would build crypto-core against
# iOS 17 SDK while the app linked against iOS 18. Stale link
# warnings + drift. Sync to 18.0; override per build only via the
# env var.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-18.0}"

# reproducible-build hardening. Three changes:
#
#   1. `SOURCE_DATE_EPOCH` from the git commit time of the working
#      tree. Tools that honour it (lipo on recent Xcode, some
#      strip variants, the cc crate) embed this timestamp instead
#      of `time(2)` so two builds at different wall-clocks produce
#      identical bytes.
#   2. `--remap-path-prefix` so the absolute repo path
#      (`/Users/username/Software/pizzini/`) doesn't end up in
#      Rust debug info / panic strings. Without it, anyone signing
#      a release can't share bit-identical binaries.
#   3. Equivalent `-ffile-prefix-map` for the C compiler used by
#      blake3's NEON sources. Passed through `CFLAGS` which the cc
#      crate picks up.
#
# Reproducibility is still best-effort — `xcodebuild -create-xcframework`
# stamps creation timestamps into the Info.plist, and lipo writes
# Mach-O headers with a creation timestamp. The README's claim that
# every release should be reproducible by a third party stands as a
# work-item; this script gets the Cargo half right so a future
# Apple-tool wrapper completes the picture.
if SOURCE_DATE_EPOCH_AUTO="$(git -C "$REPO_ROOT" log -1 --format=%ct 2>/dev/null)" \
   && [ -n "$SOURCE_DATE_EPOCH_AUTO" ]; then
    export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$SOURCE_DATE_EPOCH_AUTO}"
fi
# Combine RUSTFLAGS rather than overwrite — caller may have set
# their own (e.g. for code coverage instrumentation).
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix $REPO_ROOT=."
export CFLAGS="${CFLAGS:-} -ffile-prefix-map=$REPO_ROOT=."

# Crates with C/asm sources (notably blake3's NEON assembly) bake the
# deployment target into the Mach-O `.o` header at build time. cargo
# doesn't treat env-var changes as a rebuild trigger, so a build that
# ran once without IPHONEOS_DEPLOYMENT_TARGET set sticks with the
# wrong header forever — Xcode then warns "Object file was built for
# newer iOS version (26.0) than being linked (17.0)" on every link.
# Stamp the iOS targets with the current value; if it changes, force
# a clean of the affected crates so they pick it up.
target_marker="$TARGET_DIR/.iphoneos-deployment-target"
if [[ ! -f "$target_marker" || "$(cat "$target_marker")" != "$IPHONEOS_DEPLOYMENT_TARGET" ]]; then
    echo "==> IPHONEOS_DEPLOYMENT_TARGET changed (-> $IPHONEOS_DEPLOYMENT_TARGET); forcing native-code rebuild"
    for t in "${ALL_TARGETS[@]}"; do
        cargo clean -p blake3 -p signal-crypto -p libsignal-protocol --target "$t" 2>/dev/null || true
    done
    mkdir -p "$TARGET_DIR"
    echo -n "$IPHONEOS_DEPLOYMENT_TARGET" > "$target_marker"
fi

cargo build -p pizzini-crypto-core $CARGO_PROFILE_FLAG "${target_args[@]}"

echo "==> Lipoing simulator slices into a fat archive"
mkdir -p "$BUILD_DIR/sim"
sim_lib_paths=()
for t in "${SIM_TARGETS[@]}"; do
    sim_lib_paths+=("$TARGET_DIR/$t/$PROFILE/$LIB_NAME")
done
lipo -create "${sim_lib_paths[@]}" -output "$BUILD_DIR/sim/$LIB_NAME"

echo "==> Assembling $FRAMEWORK.xcframework"
# Per-slice headers + module map so Swift can `import PizziniCryptoCoreFFI`.
mkdir -p "$BUILD_DIR/headers"
cp "$HEADER_PATH" "$BUILD_DIR/headers/"
cat > "$BUILD_DIR/headers/module.modulemap" <<'MODMAP'
module PizziniCryptoCoreFFI {
    header "pizzini_crypto_core.h"
    export *
}
MODMAP

rm -rf "$BUILD_DIR/$FRAMEWORK.xcframework"
xcodebuild -create-xcframework \
    -library "$TARGET_DIR/aarch64-apple-ios/$PROFILE/$LIB_NAME" \
    -headers "$BUILD_DIR/headers" \
    -library "$BUILD_DIR/sim/$LIB_NAME" \
    -headers "$BUILD_DIR/headers" \
    -output "$BUILD_DIR/$FRAMEWORK.xcframework"

echo "==> Done: $BUILD_DIR/$FRAMEWORK.xcframework"
