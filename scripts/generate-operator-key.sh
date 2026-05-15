#!/usr/bin/env bash
# Generate the operator's transparency-log signing key.
#
# Run this ONCE per operator, on an airgapped/offline machine that
# never sees the public internet. The output is two files:
#
#   operator-key.pem      — Ed25519 private key. NEVER commit, never
#                            move off the offline machine. Used only
#                            by `scripts/sign-transparency-entry.sh`.
#   operator-key.pub.pem  — Ed25519 public key. PUBLISH widely. Bake
#                            into the iOS app's
#                            `TransparencyLogConfig.swift` so every
#                            client verifies signed entries against
#                            it.
#
# The keypair is the trust root of the entire transparency-log
# chain. If the private key is exfiltrated, the attacker can sign
# arbitrary transparency-log entries — i.e. they can make a
# tampered relay binary look legitimate. Treat it like a code-
# signing certificate: cold storage, two-factor controls on the
# machine that holds it, periodic rotation.
#
# To rotate: generate a new keypair, publish the new public key
# under a versioned name (e.g. `operator-key-v2.pub.pem`),
# co-sign the rotation announcement with both old and new keys.
# Plan the iOS app's ability to accept multiple verify keys
# before rotating.

set -euo pipefail

OUT_DIR="${1:-$(pwd)/operator-keys}"
if [[ -d "$OUT_DIR" ]] && [[ -n "$(ls -A "$OUT_DIR" 2>/dev/null)" ]]; then
    echo "error: $OUT_DIR exists and is not empty. Refusing to overwrite an existing operator key." >&2
    echo "       Move/remove the directory before generating a fresh keypair." >&2
    exit 1
fi
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# `openssl genpkey -algorithm ED25519` produces a PKCS#8 PEM
# containing the 32-byte raw private key plus PKCS#8 framing.
# The matching `openssl pkey -pubout` extracts a 32-byte raw
# public key (also wrapped in PKCS#8 SubjectPublicKeyInfo). Both
# forms round-trip cleanly through `openssl pkeyutl` for signing
# and verification.
openssl genpkey -algorithm ED25519 -out operator-key.pem
chmod 0600 operator-key.pem
openssl pkey -in operator-key.pem -pubout -out operator-key.pub.pem
chmod 0644 operator-key.pub.pem

# Also emit the raw 32-byte public key as base64 — the form the
# iOS `TransparencyLogConfig.swift` constant expects. Helps the
# operator paste it directly into the source without an extra
# extraction step.
RAW_PUBLIC_HEX="$(openssl pkey -pubin -in operator-key.pub.pem -outform DER \
    | tail -c 32 \
    | xxd -p -c 64)"
RAW_PUBLIC_B64="$(echo -n "$RAW_PUBLIC_HEX" | xxd -r -p | base64)"

echo
echo "==> Operator key generated."
echo "    private: $OUT_DIR/operator-key.pem      (mode 0600, NEVER commit)"
echo "    public:  $OUT_DIR/operator-key.pub.pem  (publish widely)"
echo
echo "Raw Ed25519 public key (32 bytes, hex):  $RAW_PUBLIC_HEX"
echo "Raw Ed25519 public key (base64):         $RAW_PUBLIC_B64"
echo
echo "Paste the base64 form into TransparencyLogConfig.swift's"
echo "  operatorVerifyKeyBase64 constant before shipping the iOS app."
