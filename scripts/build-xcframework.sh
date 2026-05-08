#!/usr/bin/env bash
# Build crypto-core as an XCFramework for the iOS app.
#
# Targets:
#   aarch64-apple-ios          (device)
#   aarch64-apple-ios-sim      (Apple Silicon simulator)
#   x86_64-apple-ios           (Intel simulator — kept for CI compatibility)
#
# Output: build/PizziniCryptoCore.xcframework

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="$REPO_ROOT/crypto-core"
BUILD_DIR="$REPO_ROOT/build"
LIB_NAME="libpizzini_crypto_core.a"
FRAMEWORK_NAME="PizziniCryptoCore"

TARGETS=(
    aarch64-apple-ios
    aarch64-apple-ios-sim
    x86_64-apple-ios
)

echo "==> Ensuring iOS targets are installed"
for t in "${TARGETS[@]}"; do
    rustup target add "$t" >/dev/null
done

echo "==> Building crypto-core for each target"
for t in "${TARGETS[@]}"; do
    (cd "$CRATE_DIR" && cargo build --release --target "$t")
done

echo "==> Lipoing simulator slices into a single fat lib"
SIM_DIR="$BUILD_DIR/sim"
mkdir -p "$SIM_DIR"
lipo -create \
    "$CRATE_DIR/../target/aarch64-apple-ios-sim/release/$LIB_NAME" \
    "$CRATE_DIR/../target/x86_64-apple-ios/release/$LIB_NAME" \
    -output "$SIM_DIR/$LIB_NAME"

echo "==> Assembling XCFramework"
rm -rf "$BUILD_DIR/$FRAMEWORK_NAME.xcframework"
xcodebuild -create-xcframework \
    -library "$CRATE_DIR/../target/aarch64-apple-ios/release/$LIB_NAME" \
    -library "$SIM_DIR/$LIB_NAME" \
    -output "$BUILD_DIR/$FRAMEWORK_NAME.xcframework"

echo "==> Done: $BUILD_DIR/$FRAMEWORK_NAME.xcframework"
