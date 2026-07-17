#!/usr/bin/env bash
# Verify every entry in the transparency log against the operator's
# public key (PZ-C9). Runs locally AND in CI — both the log and the
# public key are tracked in-repo, so this needs no secrets and no
# build artifacts.
#
# Usage:
#   scripts/verify-transparency-log.sh \
#       [transparency-log.ndjson] [operator-key.pub.pem]
#
# Exit status: 0 iff EVERY non-blank line carries a valid Ed25519
# signature over the H12 signing input; non-zero (with a diagnostic)
# on the first failure or if the log is empty.
#
# Signing input (must match scripts/sign-transparency-entry.sh AND
# pizzini/TransparencyLog.swift, PZ-H12):
#
#   <literal `entry` bytes from the line> || "\n" || <signed_at>
#
# The `entry` bytes are lifted VERBATIM from the line — never
# re-canonicalised here — so `jq -cS` in the signer is the single
# canonicaliser in the whole system. This script deliberately does
# NOT pipe the line through jq before hashing; it slices the literal
# substring, exactly as the Swift client does.

set -euo pipefail

LOG_PATH="${1:-transparency-log.ndjson}"
PUB_PATH="${2:-operator-key.pub.pem}"

if [[ ! -r "$LOG_PATH" ]]; then
    echo "::error::transparency log not readable at $LOG_PATH" >&2
    exit 1
fi
if [[ ! -r "$PUB_PATH" ]]; then
    echo "::error::operator public key not readable at $PUB_PATH" >&2
    exit 1
fi

TMP_MSG="$(mktemp)"
TMP_SIG="$(mktemp)"
trap 'rm -f "$TMP_MSG" "$TMP_SIG"' EXIT

count=0
lineno=0
while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    # Skip blank lines (the NDJSON parser does too).
    [[ -z "${line//[[:space:]]/}" ]] && continue

    # Lift the literal `entry` value bytes:
    #   strip everything up to and including the first  {"entry":
    #   then strip the trailing  ,"signed_at":...
    # The log shape is fixed (the signer emits compact, sorted JSON
    # with exactly one top-level `signed_at` member), so these two
    # parameter expansions recover the exact signed bytes.
    entry="${line#*\"entry\":}"
    entry="${entry%,\"signed_at\":*}"

    signed_at="$(printf '%s' "$line" | jq -r '.signed_at')"
    sig_b64="$(printf '%s' "$line" | jq -r '.sig_b64')"
    if [[ -z "$signed_at" || "$signed_at" == "null" || -z "$sig_b64" || "$sig_b64" == "null" ]]; then
        echo "::error::line $lineno: missing signed_at or sig_b64" >&2
        exit 1
    fi

    printf '%s\n%s' "$entry" "$signed_at" > "$TMP_MSG"
    if ! printf '%s' "$sig_b64" | base64 -d > "$TMP_SIG" 2>/dev/null; then
        echo "::error::line $lineno: sig_b64 is not valid base64" >&2
        exit 1
    fi

    if openssl pkeyutl -verify -pubin -inkey "$PUB_PATH" \
            -rawin -in "$TMP_MSG" -sigfile "$TMP_SIG" >/dev/null 2>&1; then
        count=$((count + 1))
    else
        echo "::error::line $lineno: Ed25519 signature INVALID under $PUB_PATH" >&2
        exit 1
    fi
done < "$LOG_PATH"

if [[ "$count" -eq 0 ]]; then
    echo "::error::transparency log $LOG_PATH has no verifiable entries" >&2
    exit 1
fi

echo "OK: $count transparency-log entr$([ "$count" -eq 1 ] && echo y || echo ies) verified against $PUB_PATH"
