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
# The iOS client already accepts multiple verify keys during a
# rotation window (PZ-M16): add the new key's base64 to
# `TransparencyLogConfig.operatorRotationVerifyKeysBase64` (entries
# signed by EITHER key then verify), ship that build, sign new
# entries under the new key, and drop the retired key from the
# primary/rotation lists in a later release. NB: this is 1-of-M
# rotation, not an N-of-M signing threshold (that would change the
# signed-entry wire schema — a separate, deferred design decision).

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
#
# F-SUP-07 / PZ-M17: the trust-root private key must not sit on disk
# in cleartext. The key is now AES-256 passphrase-encrypted by
# DEFAULT (PKCS#8). `sign-transparency-entry.sh` handles the encrypted
# key — it reads the passphrase from $OPERATOR_KEY_PASS, or prompts on
# the terminal — so the plaintext key never persists.
#
# Passphrase source for generation, mirroring the signer:
#   • $OPERATOR_KEY_PASS set  → used non-interactively (airgapped
#     automation), via `-pass env:OPERATOR_KEY_PASS` (never on argv).
#   • unset                   → openssl prompts interactively.
#
# Escape hatch: OPERATOR_KEY_ENCRYPT=0 writes a legacy plaintext key
# (NOT recommended; only for a hardware-token / `age`-wrapped flow
# that provides at-rest protection by other means).
#
# Destruction: when retiring the key, overwrite + remove it
# (`rm -P operator-key.pem` on macOS, or `shred -u` on Linux) rather
# than a plain `rm`.
# `genpkey` takes `-pass` (passphrase for the key it WRITES); `pkey`
# takes `-passin` (passphrase to DECRYPT the key it READS). Different
# flags for the same secret, so build both forms.
GEN_PASS_ARGS=()
PKEY_PASSIN_ARGS=()
if [[ -n "${OPERATOR_KEY_PASS:-}" ]]; then
    GEN_PASS_ARGS=(-pass env:OPERATOR_KEY_PASS)
    PKEY_PASSIN_ARGS=(-passin env:OPERATOR_KEY_PASS)
fi
if [[ "${OPERATOR_KEY_ENCRYPT:-1}" != "0" ]]; then
    openssl genpkey -algorithm ED25519 -aes256 \
        ${GEN_PASS_ARGS[@]+"${GEN_PASS_ARGS[@]}"} -out operator-key.pem
else
    openssl genpkey -algorithm ED25519 -out operator-key.pem
fi
chmod 0600 operator-key.pem
# Extracting the public half reads the (now encrypted-by-default)
# private key, so it needs the same passphrase. Reuse $OPERATOR_KEY_PASS
# when present; otherwise openssl prompts.
openssl pkey -in operator-key.pem \
    ${PKEY_PASSIN_ARGS[@]+"${PKEY_PASSIN_ARGS[@]}"} -pubout -out operator-key.pub.pem
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
