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
# Match the iOS app's deployment target (17.0). Cargo's aarch64-apple-ios
# default is iOS 10, which is incompatible with blake3's NEON path
# (links against `___chkstk_darwin`, present only since iOS 14).
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"
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
