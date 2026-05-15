#!/usr/bin/env bash
# Foreground/background reconnect stress for the pizzini iOS app.
#
# Drives N (default 100) bg → wait → fg cycles against a target
# device (simulator or real), tailing the in-app QA-debug log and
# counting how many cycles complete a clean `.connecting → .connected`
# transition inside a per-cycle deadline.
#
# Reads the `[reconnect-cycle] state=<x>` markers that ChatStore emits
# on every aggregate-state transition. Markers land in the app's
# QALog file (Library/Application Support/qa-debug/qa.log inside the
# app container). DEBUG builds only — the marker is gated behind
# `pzLog`, which compiles to a no-op in Release. Build the app from
# Xcode with the Debug configuration before running this script.
#
# Pre-conditions:
#   - target device is booted (this script will boot a sim if needed)
#   - pizzini is installed and has completed onboarding
#   - the app is foregrounded and reached `.connected` at least once
#     (so we have a baseline to drive bg/fg from)
#   - DEBUG build (Release builds never emit reconnect-cycle markers)
#
# Defaults match the iPhone 17 Pro sim wired up in the test scheme.
# Override on the command line:
#   scripts/tor-foreground-stress.sh                  # 100 cycles, default sim
#   scripts/tor-foreground-stress.sh <UDID>           # 100 cycles, custom device
#   CYCLES=20 scripts/tor-foreground-stress.sh <UDID> # 20 cycles, custom device
#
# Tunables (env vars):
#   CYCLES               number of bg/fg cycles (default 100)
#   PER_CYCLE_TIMEOUT    seconds to wait for `.connected` after fg (default 90)
#   BG_MIN / BG_MAX      bg dwell-time range in seconds (default 5 / 30)
#   BUNDLE               app bundle id (default com.bytepotato.pizzini)
#   ARTIFACTS            output dir (default /tmp/pizzini-fg-stress)
#
# Output:
#   $ARTIFACTS/run-<ts>/qa.log.snapshot   the captured log slice
#   $ARTIFACTS/run-<ts>/cycles.tsv        per-cycle: idx, bg_secs, fg_outcome, elapsed_secs
#   $ARTIFACTS/run-<ts>/summary.txt       totals + pass/fail verdict
#
# Pass criteria:
#   cycles_stuck_in_connecting == 0
#   cycles_failed == 0
#   cycles_total == cycles_reconnected_within_${PER_CYCLE_TIMEOUT}s
#
# Sample success summary:
#   cycles_total: 100
#   cycles_reconnected: 100
#   cycles_stuck_in_connecting: 0
#   cycles_failed: 0
#   median_reconnect_ms: 3120
#   p95_reconnect_ms: 6480
#   max_reconnect_ms: 14210
#   VERDICT: PASS
#
# Sample failure summary:
#   cycles_total: 100
#   cycles_reconnected: 97
#   cycles_stuck_in_connecting: 2
#   cycles_failed: 1
#   stuck cycle indices: 47 83
#   failed cycle indices: 19
#   VERDICT: FAIL — 3 cycle(s) did not reach .connected inside 90s
#
# On FAIL: open the relevant slice of $ARTIFACTS/run-<ts>/qa.log.snapshot
# around each stuck/failed cycle index and file as a finding under
# `audit-2026-05/findings/`. Capture: the per-relay `state:` lines just
# before the stuck cycle, whether `[reconnect-cycle] state=connecting`
# appeared at all, and whether the dial budget triggered.
#
# Exit codes: 0 on PASS, 1 on FAIL, 2 on script-setup error.

set -euo pipefail

SIM_DEFAULT="44D20C12-8CC5-427C-8120-6635B710C0E6"   # iPhone 17 Pro
SIM="${1:-$SIM_DEFAULT}"
CYCLES="${CYCLES:-100}"
PER_CYCLE_TIMEOUT="${PER_CYCLE_TIMEOUT:-90}"
BG_MIN="${BG_MIN:-5}"
BG_MAX="${BG_MAX:-30}"
BUNDLE="${BUNDLE:-com.bytepotato.pizzini}"
ARTIFACTS="${ARTIFACTS:-/tmp/pizzini-fg-stress}"

# Pre-flight: validate env.
command -v xcrun >/dev/null || { echo "xcrun not found — Xcode CLT required" >&2; exit 2; }
[[ "$CYCLES" =~ ^[0-9]+$ ]] || { echo "CYCLES must be an integer" >&2; exit 2; }
[[ "$BG_MIN" -le "$BG_MAX" ]] || { echo "BG_MIN must be <= BG_MAX" >&2; exit 2; }

TS="$(date +%Y%m%d-%H%M%S)"
OUTDIR="$ARTIFACTS/run-$TS"
mkdir -p "$OUTDIR"
SNAPSHOT="$OUTDIR/qa.log.snapshot"
TSV="$OUTDIR/cycles.tsv"
SUMMARY="$OUTDIR/summary.txt"

echo "device=$SIM cycles=$CYCLES per-cycle-timeout=${PER_CYCLE_TIMEOUT}s bg-range=${BG_MIN}-${BG_MAX}s"
echo "output: $OUTDIR"

# `get_app_container` is the only sim path that works for both
# /data/Containers/Data/Application/<uuid>/ (data container) and the
# /Bundle/ variant. We want `data` because qa-debug lives under
# Library/Application Support/.
boot_if_needed () {
    local state
    state="$(xcrun simctl list devices | grep "$SIM" | sed -E 's/.*\((Booted|Shutdown|Shutting Down)\).*/\1/' | head -1 || true)"
    if [[ "$state" != "Booted" ]]; then
        echo "booting $SIM..."
        xcrun simctl boot "$SIM"
        # Give Springboard a beat to settle so launch doesn't race.
        sleep 5
    fi
}

resolve_qa_log () {
    local container
    container="$(xcrun simctl get_app_container "$SIM" "$BUNDLE" data 2>/dev/null || true)"
    if [[ -z "$container" ]]; then
        echo "FATAL: app $BUNDLE not installed on $SIM. Install a DEBUG build first." >&2
        exit 2
    fi
    echo "$container/Library/Application Support/qa-debug/qa.log"
}

# Quote a path that may contain spaces (Application Support).
QA_LOG=""

wait_for_marker_state () {
    # Args: target_state, deadline_epoch, start_byte_offset
    # Polls the QA log file (tail from start_byte_offset) for a line
    # matching `[reconnect-cycle] state=<target>`. Returns 0 + prints
    # the elapsed-seconds (epoch ms diff) on success, returns 1 on
    # deadline.
    local target="$1"
    local deadline="$2"
    local start_off="$3"
    local pattern="\\[reconnect-cycle\\] state=${target}"
    while [[ $(date +%s) -lt "$deadline" ]]; do
        if [[ -f "$QA_LOG" ]]; then
            # tail -c +N is 1-indexed; +1 = whole file.
            if tail -c "+$((start_off + 1))" "$QA_LOG" 2>/dev/null \
                 | grep -E "$pattern" >/dev/null 2>&1; then
                return 0
            fi
        fi
        sleep 0.5
    done
    return 1
}

file_size () {
    # Bytes of $1, or 0 if file is missing.
    if [[ -f "$1" ]]; then
        stat -f %z "$1" 2>/dev/null || stat -c %s "$1" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

rand_in_range () {
    # POSIX-friendly random integer in [BG_MIN, BG_MAX].
    local span=$((BG_MAX - BG_MIN + 1))
    echo $((BG_MIN + RANDOM % span))
}

# Backgrounding on the simulator: simctl doesn't expose a clean
# "send to background" verb, so we re-launch SpringBoard, which iOS
# treats as foregrounding home → the pizzini app moves to bg. That's
# the same trick `tor-stress.sh` uses today; we keep it for parity.
send_to_background () {
    xcrun simctl launch "$SIM" com.apple.springboard >/dev/null
}

send_to_foreground () {
    xcrun simctl launch "$SIM" "$BUNDLE" >/dev/null
}

boot_if_needed
QA_LOG="$(resolve_qa_log)"
echo "qa.log: $QA_LOG"
if [[ ! -f "$QA_LOG" ]]; then
    echo "WARN: $QA_LOG does not exist yet. Foreground the app once and let it" >&2
    echo "      reach .connected so the log file gets created, then re-run." >&2
    exit 2
fi

# Establish baseline: wait for an initial `.connected` marker. We
# don't drive bg/fg until we've seen at least one connected state
# in the log; otherwise we'd count the cold-start bootstrap as the
# first "stuck" cycle.
echo "waiting for initial .connected baseline..."
INITIAL_DEADLINE=$(( $(date +%s) + PER_CYCLE_TIMEOUT ))
BASELINE_START_OFF=$(file_size "$QA_LOG")
if ! wait_for_marker_state "connected" "$INITIAL_DEADLINE" 0; then
    # Maybe the app reached .connected before this script started.
    # Check whether the marker exists anywhere in the file.
    if ! grep -E "\\[reconnect-cycle\\] state=connected" "$QA_LOG" >/dev/null 2>&1; then
        echo "FATAL: never observed initial .connected baseline. Either the app" >&2
        echo "       isn't a DEBUG build (no markers), or onboarding/relay isn't" >&2
        echo "       complete. Bring the app to .connected once, then re-run." >&2
        exit 2
    fi
fi
echo "baseline reached. starting $CYCLES bg/fg cycles..."

# Per-cycle TSV header: idx, bg_secs, outcome, elapsed_secs
printf "idx\tbg_secs\toutcome\telapsed_secs\n" > "$TSV"

cycles_reconnected=0
cycles_stuck=0
cycles_failed=0
stuck_indices=()
failed_indices=()
elapsed_samples=()

for i in $(seq 1 "$CYCLES"); do
    bg_secs=$(rand_in_range)
    echo "  cycle $i/$CYCLES: bg ${bg_secs}s..."
    pre_bg_off=$(file_size "$QA_LOG")
    send_to_background
    sleep "$bg_secs"

    fg_start_epoch=$(date +%s)
    send_to_foreground

    # Wait for either `connected` or `failed` after our fg moment.
    # We use the byte offset from BEFORE backgrounding as the search
    # cursor so we definitely see the `connecting → connected` arc.
    deadline=$(( fg_start_epoch + PER_CYCLE_TIMEOUT ))
    outcome="stuck"
    elapsed=""
    while [[ $(date +%s) -lt "$deadline" ]]; do
        slice=$(tail -c "+$((pre_bg_off + 1))" "$QA_LOG" 2>/dev/null || true)
        if echo "$slice" | grep -E "\\[reconnect-cycle\\] state=connected" >/dev/null 2>&1; then
            outcome="connected"
            elapsed=$(( $(date +%s) - fg_start_epoch ))
            break
        fi
        if echo "$slice" | grep -E "\\[reconnect-cycle\\] state=failed" >/dev/null 2>&1; then
            outcome="failed"
            elapsed=$(( $(date +%s) - fg_start_epoch ))
            break
        fi
        sleep 0.5
    done

    case "$outcome" in
        connected)
            cycles_reconnected=$((cycles_reconnected + 1))
            elapsed_samples+=("$elapsed")
            echo "    -> .connected in ${elapsed}s"
            ;;
        failed)
            cycles_failed=$((cycles_failed + 1))
            failed_indices+=("$i")
            echo "    -> .failed in ${elapsed}s"
            ;;
        stuck)
            cycles_stuck=$((cycles_stuck + 1))
            stuck_indices+=("$i")
            elapsed="$PER_CYCLE_TIMEOUT"
            echo "    -> STUCK after ${PER_CYCLE_TIMEOUT}s"
            ;;
    esac
    printf "%d\t%d\t%s\t%s\n" "$i" "$bg_secs" "$outcome" "$elapsed" >> "$TSV"
done

# Snapshot the full QA log post-run for forensic review.
cp "$QA_LOG" "$SNAPSHOT" 2>/dev/null || true

# Compute percentiles (median, p95, max) on the connected-elapsed samples.
median_s="-"
p95_s="-"
max_s="-"
if [[ ${#elapsed_samples[@]} -gt 0 ]]; then
    sorted=$(printf "%s\n" "${elapsed_samples[@]}" | sort -n)
    n=${#elapsed_samples[@]}
    median_idx=$(( (n + 1) / 2 ))
    p95_idx=$(( (n * 95 + 99) / 100 ))
    (( p95_idx > n )) && p95_idx=$n
    median_s=$(echo "$sorted" | sed -n "${median_idx}p")
    p95_s=$(echo "$sorted" | sed -n "${p95_idx}p")
    max_s=$(echo "$sorted" | sed -n "${n}p")
fi

{
    echo "==== pizzini foreground/background stress summary ($(date)) ===="
    echo "device:                       $SIM"
    echo "bundle:                       $BUNDLE"
    echo "cycles_total:                 $CYCLES"
    echo "cycles_reconnected:           $cycles_reconnected"
    echo "cycles_stuck_in_connecting:   $cycles_stuck"
    echo "cycles_failed:                $cycles_failed"
    echo "median_reconnect_s:           $median_s"
    echo "p95_reconnect_s:              $p95_s"
    echo "max_reconnect_s:              $max_s"
    if [[ ${#stuck_indices[@]} -gt 0 ]]; then
        echo "stuck cycle indices:          ${stuck_indices[*]}"
    fi
    if [[ ${#failed_indices[@]} -gt 0 ]]; then
        echo "failed cycle indices:         ${failed_indices[*]}"
    fi
    echo
    if [[ "$cycles_stuck" -eq 0 && "$cycles_failed" -eq 0 ]]; then
        echo "VERDICT: PASS"
    else
        bad=$(( cycles_stuck + cycles_failed ))
        echo "VERDICT: FAIL — $bad cycle(s) did not reach .connected inside ${PER_CYCLE_TIMEOUT}s"
    fi
    echo
    echo "artifacts:"
    echo "  per-cycle tsv: $TSV"
    echo "  qa log slice:  $SNAPSHOT"
} | tee "$SUMMARY"

if [[ "$cycles_stuck" -eq 0 && "$cycles_failed" -eq 0 ]]; then
    exit 0
fi
exit 1
