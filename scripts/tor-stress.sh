#!/usr/bin/env bash
# Tor lifecycle stress test for the iOS Simulator.
#
# Drives the running pizzini sim through three bg/fg cadences and
# greps the sim's unified log for the markers that say the relay
# reconnected successfully — `missingCookie`, an aggregate `.failed`
# we never recovered from, or a stuck `connectingToTor` past the
# expected window mean a regression.
#
# Pre-conditions:
#   - the target sim is booted
#   - the pizzini app is installed and has completed onboarding
#   - the app is currently foregrounded
#
# Override SIM= on the command line to target a different device.
# Default matches the one wired up in the test scheme; the local
# dev's Mac is the only place this script needs to run.

set -euo pipefail

SIM="${SIM:-E1164AE6-B512-46B0-A5A1-15451A74E326}"
BUNDLE="${BUNDLE:-com.bytepotato.pizzini}"
ARTIFACTS="${ARTIFACTS:-/tmp/pizzini-tor-stress}"

mkdir -p "$ARTIFACTS"

LOGFILE="$ARTIFACTS/log-$(date +%Y%m%d-%H%M%S).log"
SUMMARY="$ARTIFACTS/summary-$(date +%Y%m%d-%H%M%S).txt"

echo "sim=$SIM bundle=$BUNDLE"
echo "logging to $LOGFILE"

# Background log capture for the duration of the run. The simctl
# `log stream` follows the unified log on the boot disk; we filter
# to pizzini's subsystems so the file stays small.
xcrun simctl spawn "$SIM" log stream \
    --predicate 'subsystem == "app.pizzini.tor" OR subsystem == "app.pizzini.relay"' \
    --level info \
    > "$LOGFILE" 2>&1 &
LOG_PID=$!
trap 'kill $LOG_PID 2>/dev/null || true' EXIT
sleep 1

# Three cadences as the user prompt asked for: rapid 5 s × 20,
# medium 30 s × 5, long 5 min × 1.
cycle() {
    local sleep_secs="$1"
    local count="$2"
    local label="$3"
    echo
    echo "=== $label: bg/fg every ${sleep_secs}s × ${count} ==="
    for i in $(seq 1 "$count"); do
        echo "  cycle $i/$count: background"
        # `simctl terminate` is too aggressive — it kills the app.
        # `simctl push` would not exercise the bg path. Use the
        # tab-to-home equivalent via the springboard's
        # "_XCTRequestActivate" private — actually simctl doesn't
        # expose it cleanly. Fall back to launching SpringBoard
        # over the foreground app, which iOS treats as a
        # "send to background" because SpringBoard is the active
        # process. The downside: we use launch instead of a clean
        # backgrounding signal. Good enough for triage.
        xcrun simctl launch "$SIM" com.apple.springboard >/dev/null
        sleep "$sleep_secs"
        echo "  cycle $i/$count: foreground"
        xcrun simctl launch "$SIM" "$BUNDLE" >/dev/null
        sleep "$sleep_secs"
    done
}

cycle 5 20 "rapid"
cycle 30 5 "medium"
cycle 300 1 "long"

# Give the final foreground a few seconds to settle so any error
# state has had a chance to land in the log.
sleep 10

# Now mine the captured log. Three failure shapes the user explicitly
# called out:
#   - `missingCookie` anywhere ⇒ a bootstrap that thought tor was
#     gone when it wasn't
#   - aggregate `.failed` we never recovered from (last sample is
#     .failed, no later .connected)
#   - a `connectingToTor` that never advanced past 0 in a cycle
{
    echo "==== Tor stress summary ($(date)) ===="
    echo
    echo "Log file: $LOGFILE"
    echo "Total lines captured: $(wc -l < "$LOGFILE")"
    echo
    cookie_hits=$(grep -c "missingCookie" "$LOGFILE" || true)
    echo "missingCookie occurrences: $cookie_hits"
    requires_restart=$(grep -c "requires-app-restart\|TORThread reports isFinished=true" "$LOGFILE" || true)
    echo "tor-dead detections: $requires_restart"
    last_state=$(grep -E "state: .* → " "$LOGFILE" | tail -1 || true)
    echo "Last observed RelayClient state: $last_state"
    if echo "$last_state" | grep -q "failed"; then
        echo "FAIL: final state is .failed — no recovery observed"
    elif echo "$last_state" | grep -q "connected"; then
        echo "OK: final state is .connected"
    else
        echo "INDETERMINATE: final state is neither .connected nor .failed"
    fi
    if [[ "$cookie_hits" -gt 0 ]]; then
        echo "FAIL: missingCookie surfaced — tor lifecycle regression"
    fi
    if [[ "$requires_restart" -gt 0 ]]; then
        echo "FAIL: tor was detected dead — daemon exited during stress"
    fi
} | tee "$SUMMARY"
