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
#     "entry":     <canonical entry JSON, byte-for-byte as signed>,
#     "signed_at": <ISO-8601 UTC>,
#     "sig_b64":   <base64 Ed25519 signature over entry|signed_at>
#   }
#
# Signature input: the bytes of
#   "<ENTRY_CANON>\n<signed_at>"
# where ENTRY_CANON is `jq -cS` of the entry (sorted keys, no
# whitespace), a newline, then the signed_at string.
#
# PZ-H12 — single canonicaliser: the EXACT ENTRY_CANON bytes that
# are signed are also the bytes emitted in the `entry` field of the
# output line (see the `printf` below — ENTRY_CANON is interpolated
# verbatim, NOT round-tripped back through jq). The Swift verifier
# (TransparencyLog.swift) then lifts those literal bytes straight out
# of the line and verifies over them, rather than re-canonicalising.
# So `jq -cS` is the one and only canonicaliser in the system; the
# verifier never re-derives the bytes, killing the prior
# jq-vs-JSONSerialization divergence hazard.

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

# PZ-M17 — support a passphrase-encrypted operator key (the
# generate-operator-key.sh default is now AES-256-encrypted at
# rest, F-SUP-07). The passphrase is sourced as follows:
#
#   • If OPERATOR_KEY_PASS is set in the environment, it is fed to
#     openssl via `-passin env:OPERATOR_KEY_PASS` (non-interactive —
#     airgapped automation / CI). The value is read from the env,
#     never placed on the command line, so it does not leak via
#     `ps`.
#   • Otherwise no `-passin` is passed: openssl prompts on the
#     controlling terminal (/dev/tty) for an encrypted key, and a
#     plaintext key signs with no prompt at all — so a legacy
#     unencrypted operator-key.pem keeps working unchanged.
#
# The entry JSON was already consumed from stdin above, so the
# interactive prompt (which openssl reads from /dev/tty, not stdin)
# does not collide with it.
PASSIN_ARGS=()
if [[ -n "${OPERATOR_KEY_PASS:-}" ]]; then
    PASSIN_ARGS=(-passin env:OPERATOR_KEY_PASS)
fi

# `${arr[@]+"${arr[@]}"}` expands to nothing when the array is empty
# WITHOUT tripping `set -u` on macOS's bash 3.2 (a bare
# `"${arr[@]}"` on an empty array is an "unbound variable" there).
SIG_B64="$(openssl pkeyutl -sign -inkey "$KEY_PATH" ${PASSIN_ARGS[@]+"${PASSIN_ARGS[@]}"} -rawin -in "$TMP" | base64 | tr -d '\n')"

# Emit exactly one line (NDJSON contract: an external verifier can
# `while read -r line; do …; done < transparency-log.ndjson` and get
# one entry per iteration). ENTRY_CANON is interpolated VERBATIM via
# `%s` — deliberately NOT re-encoded through `jq -cn --argjson`,
# which would reparse + reserialise and could (in principle) emit
# different bytes than were signed. SIGNED_AT is a fixed-shape
# ISO-8601 string and SIG_B64 is base64; neither contains a
# JSON-significant or printf-format character, so direct
# interpolation yields valid JSON whose `entry` field is
# byte-for-byte the signed ENTRY_CANON (PZ-H12).
printf '{"entry":%s,"signed_at":"%s","sig_b64":"%s"}\n' \
    "$ENTRY_CANON" "$SIGNED_AT" "$SIG_B64"
