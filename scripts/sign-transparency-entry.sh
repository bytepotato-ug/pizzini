#!/usr/bin/env bash
# Sign a single transparency-log entry.
#
# Pipe the JSON entry emitted by `scripts/build-relay-release.sh`
# into stdin; this script emits a signed wrapper to stdout.
#
# Usage:
#   scripts/build-relay-release.sh   # prints {"git_sha":"...","binary_sha256":"...","binary_size":...}
#   echo '{ ... entry json ... }' \
#       | scripts/sign-transparency-entry.sh path/to/operator-key.pem
#
# Output (NDJSON-friendly — one line per signed entry, append to
# the public log file):
#
#   {
#     "entry":     <unchanged entry JSON, byte-for-byte>,
#     "signed_at": <ISO-8601 UTC>,
#     "sig_b64":   <base64 Ed25519 signature over entry|signed_at>
#   }
#
# Signature input: the bytes of
#   "<entry_json_compact_no_whitespace>\n<signed_at>"
# i.e. UTF-8 of the compact-JSON `entry` field, newline, then the
# signed_at string. Newline-separated so the verifier can split
# losslessly without ambiguity.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <path-to-operator-key.pem>" >&2
    exit 1
fi

KEY_PATH="$1"
if [[ ! -r "$KEY_PATH" ]]; then
    echo "error: operator key not readable at $KEY_PATH" >&2
    exit 1
fi

ENTRY_RAW="$(cat -)"
if [[ -z "${ENTRY_RAW// /}" ]]; then
    echo "error: empty stdin — expected the JSON line from build-relay-release.sh" >&2
    exit 1
fi

# Canonicalise the entry to a compact form so the verifier and
# signer compute identical signature inputs. `jq -cS` sorts keys
# + strips whitespace; the resulting bytes are deterministic for
# the same logical JSON.
ENTRY_CANON="$(echo "$ENTRY_RAW" | jq -cS '.')"
if [[ -z "$ENTRY_CANON" ]]; then
    echo "error: stdin was not valid JSON (jq failed)" >&2
    exit 1
fi

SIGNED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

# Build the signing-input file. `printf` (not `echo`) so we don't
# accidentally append a literal "\n" on macOS bash.
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
printf '%s\n%s' "$ENTRY_CANON" "$SIGNED_AT" > "$TMP"

SIG_B64="$(openssl pkeyutl -sign -inkey "$KEY_PATH" -rawin -in "$TMP" | base64 | tr -d '\n')"

# `-c` (compact) so each signed wrapper is exactly one line — the
# whole point of the NDJSON shape is that an external verifier can
# `while read -r line; do …; done < transparency-log.ndjson` and get
# one entry per iteration. Pretty-printed output would silently
# break that contract.
jq -cn \
    --argjson entry "$ENTRY_CANON" \
    --arg signed_at "$SIGNED_AT" \
    --arg sig "$SIG_B64" \
    '{entry: $entry, signed_at: $signed_at, sig_b64: $sig}'
