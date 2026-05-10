#!/usr/bin/env bash
# Restart the pizzini-relay LaunchAgent.
#
# Use this after `cargo build --release -p pizzini-relay` to swap the
# running process for the freshly-built binary — launchd keeps the
# old binary's process going until told otherwise. `kickstart -k`
# sends SIGTERM to the current process; launchd's KeepAlive promptly
# starts a new one against whatever the plist's ProgramArguments
# point at (which is the same path, but the bytes have changed).
#
# The persistent push-token store survives the bounce — that's its
# whole point. iOS apps don't need to be re-opened after this.

set -euo pipefail

LABEL="com.bytepotato.pizzini.relay"
DOMAIN="gui/$(id -u)"
LOG_PATH="$HOME/Library/Logs/pizzini-relay.log"

if ! launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1; then
    echo "error: $LABEL is not loaded under $DOMAIN" >&2
    echo "Run scripts/install-relay-launchd.sh first." >&2
    exit 1
fi

launchctl kickstart -k "$DOMAIN/$LABEL"
sleep 1
PID=$(launchctl print "$DOMAIN/$LABEL" | awk '/^[[:space:]]*pid =/ {print $3; exit}')
echo "relay restarted (pid $PID)"
echo ""
tail -8 "$LOG_PATH" 2>/dev/null || true
