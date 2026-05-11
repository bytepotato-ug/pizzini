#!/usr/bin/env bash
# Install the pizzini-relay LaunchAgent.
#
# Sets up the relay to:
#   • auto-start on user login
#   • restart automatically if it crashes (KeepAlive)
#   • always run with the APNs credentials needed for push delivery
#   • log to ~/Library/Logs/pizzini-relay.log (persistent across reboots)
#
# Why a LaunchAgent: the relay's APNs configuration lives entirely in
# environment variables (APNS_AUTH_KEY_PATH / APNS_TEAM_ID / APNS_KEY_ID).
# Launching from an ad-hoc shell session that happens to have those
# exported means push silently disables itself the moment that shell
# ends — exactly the failure mode this script fixes. The LaunchAgent's
# `EnvironmentVariables` dict bakes the values in deterministically,
# independent of any shell.
#
# Required env vars (script aborts if any are missing):
#   APNS_AUTH_KEY_PATH   absolute path to the .p8 auth key
#   APNS_TEAM_ID         10-char Apple Developer Team ID
#   APNS_KEY_ID          10-char APNs key ID (matches XXXXXXXXXX in
#                        the filename "AuthKey_XXXXXXXXXX.p8")
#
# Optional env vars:
#   APNS_ENDPOINT        "production" or "sandbox" (default: sandbox).
#                        Sandbox is correct for Debug Xcode builds on a
#                        personal-device install; Production for
#                        TestFlight / App Store.
#   RELAY_BINARY         override the path to the built relay binary
#                        (default: $REPO_ROOT/target/release/pizzini-relay)
#
# Idempotent: re-run after rebuilding the relay to pick up the new
# binary (the LaunchAgent's path doesn't change, but the bytes do, so
# we kickstart -k to swap them in).

set -euo pipefail

LABEL="com.bytepotato.pizzini.relay"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_BINARY="${RELAY_BINARY:-$REPO_ROOT/target/release/pizzini-relay}"
PLIST_PATH="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_PATH="$HOME/Library/Logs/pizzini-relay.log"

# ── env-var gate ──────────────────────────────────────────────────────
missing=()
[ -n "${APNS_AUTH_KEY_PATH:-}" ] || missing+=("APNS_AUTH_KEY_PATH")
[ -n "${APNS_TEAM_ID:-}" ]       || missing+=("APNS_TEAM_ID")
[ -n "${APNS_KEY_ID:-}" ]        || missing+=("APNS_KEY_ID")
if [ "${#missing[@]}" -gt 0 ]; then
    echo "error: missing required env vars: ${missing[*]}" >&2
    echo "" >&2
    echo "Usage:" >&2
    echo "  APNS_AUTH_KEY_PATH=/path/to/AuthKey_XXXXXXXXXX.p8 \\" >&2
    echo "  APNS_TEAM_ID=YOURTEAMID \\" >&2
    echo "  APNS_KEY_ID=XXXXXXXXXX \\" >&2
    echo "  $0" >&2
    exit 1
fi

# ── pre-flight ────────────────────────────────────────────────────────
if [ ! -x "$RELAY_BINARY" ]; then
    echo "error: relay binary not found or not executable at $RELAY_BINARY" >&2
    echo "Run 'cargo build --release -p pizzini-relay' first." >&2
    exit 1
fi
if [ ! -r "$APNS_AUTH_KEY_PATH" ]; then
    echo "error: APNs auth key not readable at $APNS_AUTH_KEY_PATH" >&2
    exit 1
fi

mkdir -p "$(dirname "$PLIST_PATH")"
mkdir -p "$(dirname "$LOG_PATH")"

# Sandbox is the right default for Debug Xcode builds installed on a
# personal device. TestFlight / App Store builds use production.
APNS_ENDPOINT="${APNS_ENDPOINT:-sandbox}"

# ── render plist ──────────────────────────────────────────────────────
# Generated, not authored — re-running this script with different env
# vars rewrites it. Don't hand-edit; edit the script.
cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>

    <key>ProgramArguments</key>
    <array>
        <string>$RELAY_BINARY</string>
    </array>

    <key>WorkingDirectory</key>
    <string>$REPO_ROOT</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>APNS_AUTH_KEY_PATH</key>
        <string>$APNS_AUTH_KEY_PATH</string>
        <key>APNS_TEAM_ID</key>
        <string>$APNS_TEAM_ID</string>
        <key>APNS_KEY_ID</key>
        <string>$APNS_KEY_ID</string>
        <key>APNS_ENDPOINT</key>
        <string>$APNS_ENDPOINT</string>
        <!-- Dev override: the relay defaults to 127.0.0.1:7777
             (production posture, reached only via Tor) so the
             simulator on this Mac and any sibling simulator/device
             on the LAN would fail to connect without this line.
             Production deploys (Hetzner) DROP this env var so the
             default loopback bind takes effect. -->
        <key>PIZZINI_RELAY_BIND</key>
        <string>0.0.0.0:7777</string>
    </dict>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>ProcessType</key>
    <string>Background</string>

    <key>StandardOutPath</key>
    <string>$LOG_PATH</string>
    <key>StandardErrorPath</key>
    <string>$LOG_PATH</string>
</dict>
</plist>
EOF

echo "wrote $PLIST_PATH"

# ── (re)load ──────────────────────────────────────────────────────────
DOMAIN="gui/$(id -u)"
# `bootout` first, ignoring failure — covers both "agent loaded with
# old config, replace it" and "agent never loaded, no-op" without
# branching on prior state.
launchctl bootout "$DOMAIN" "$PLIST_PATH" 2>/dev/null || true
launchctl bootstrap "$DOMAIN" "$PLIST_PATH"
launchctl enable "$DOMAIN/$LABEL"

# ── verify ────────────────────────────────────────────────────────────
sleep 1
if launchctl print "$DOMAIN/$LABEL" 2>/dev/null | grep -q "state = running"; then
    PID=$(launchctl print "$DOMAIN/$LABEL" | awk '/^[[:space:]]*pid =/ {print $3; exit}')
    echo "relay running under launchd (pid $PID)"
    echo ""
    echo "tail -f $LOG_PATH"
    echo ""
    tail -8 "$LOG_PATH" 2>/dev/null || true
else
    echo "warning: relay didn't reach 'running' state — check $LOG_PATH" >&2
    launchctl print "$DOMAIN/$LABEL" 2>&1 | head -20 >&2 || true
    exit 1
fi
