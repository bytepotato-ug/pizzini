#!/usr/bin/env bash
# Push a new pizzini-relay binary to one or all relays.
#
# This is the CANONICAL operator deploy path. It uses only the
# capabilities `pizzini-admin` is granted by bootstrap.sh's two
# sudoers drop-ins:
#
#   /etc/sudoers.d/90-pizzini-admin            — systemctl, journalctl, …
#   /etc/sudoers.d/91-pizzini-relay-update     — install -m 0755 -o root -g root
#                                                 /tmp/pizzini-relay-new
#                                                 /usr/local/bin/pizzini-relay
#
# If either drop-in is missing (e.g. you provisioned a box before
# the 91-… entry was added to bootstrap.sh), the script fails loudly
# with the exact missing entry rather than half-deploying and
# leaving you with a stale binary on some boxes.
#
# Usage:
#
#   bash scripts/deploy/redeploy-relay.sh <ssh-alias>           # single box
#   bash scripts/deploy/redeploy-relay.sh --all                 # full fleet
#
# Optional:
#
#   PIZZINI_RELAY_BINARY=/path/to/pizzini-relay   default: target/x86_64-…/release/pizzini-relay
#
# Exit codes: 0 success, 1 prerequisites failed, 2 deploy failed.

set -euo pipefail

# ───── canonical fleet aliases ───────────────────────────────────────
# Must match `~/.ssh/config` Host entries. Adding a relay = add an
# alias here AND make sure `bootstrap.sh` ran (with the 91-… sudoers
# drop-in) on the box.
FLEET=(pizzini-relay pizzini-relay-no pizzini-relay-us)

# ───── helpers ───────────────────────────────────────────────────────
say()  { printf "\033[1;36m▶\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m✓\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m!\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m✗\033[0m %s\n" "$*" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINARY="${PIZZINI_RELAY_BINARY:-$REPO_ROOT/target/x86_64-unknown-linux-gnu/release/pizzini-relay}"

# ───── arg parsing ───────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    err "usage: $0 <ssh-alias>|--all"
    exit 1
fi

if [[ "$1" == "--all" ]]; then
    targets=("${FLEET[@]}")
else
    targets=("$1")
fi

# ───── local prerequisites ───────────────────────────────────────────
if [[ ! -f "$BINARY" ]]; then
    err "binary not found at: $BINARY"
    err "build it first with: bash scripts/build-relay-release.sh"
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    LOCAL_SHA="$(sha256sum "$BINARY" | awk '{print $1}')"
else
    LOCAL_SHA="$(shasum -a 256 "$BINARY" | awk '{print $1}')"
fi
LOCAL_SIZE="$(wc -c <"$BINARY" | awk '{print $1}')"
ok  "local binary"
echo "  path  : $BINARY"
echo "  sha256: $LOCAL_SHA"
echo "  size  : $LOCAL_SIZE bytes"

# ───── per-host preflight ────────────────────────────────────────────
# Verify each target has BOTH expected sudoers entries before we
# scp anything. Fail-fast — better to error here with a clear "the
# box is missing entry X" message than to scp + half-deploy.
preflight_host() {
    local host="$1"
    # Connectivity.
    if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$host" true 2>/dev/null; then
        err "[$host] SSH connect failed (alias resolves? key correct?)"
        return 1
    fi
    # Service exists.
    if ! ssh -o BatchMode=yes "$host" 'sudo systemctl status pizzini-relay --no-pager >/dev/null 2>&1'; then
        err "[$host] pizzini-relay.service not present — was bootstrap.sh ever run here?"
        return 1
    fi
    # Sudoers preflight. We accept TWO equivalent grants:
    #
    #   (a) the path-restricted entry from 91-pizzini-relay-update
    #       (current bootstrap.sh default — recommended), OR
    #
    #   (b) the legacy `NOPASSWD: ALL` (older bootstraps, e.g. the
    #       DE box was provisioned before the capability-restrict
    #       commit landed — functionally permits the install just
    #       fine, but is broader than we'd write today).
    #
    # Both are sufficient for the deploy. If neither matches, we
    # error out with the exact one-liner the operator can paste into
    # the provider's root console.
    local allowed
    allowed="$(ssh -o BatchMode=yes "$host" 'sudo -ln' 2>/dev/null || true)"
    local has_install=0
    if grep -qF '/usr/bin/install -m 0755 -o root -g root /tmp/pizzini-relay-new /usr/local/bin/pizzini-relay' <<<"$allowed"; then
        has_install=1
    elif grep -qE '\(ALL\)[[:space:]]+NOPASSWD:[[:space:]]+ALL' <<<"$allowed"; then
        has_install=1
        warn "[$host] legacy NOPASSWD: ALL — works, but consider tightening to the path-restricted 91-pizzini-relay-update entry"
    fi
    if (( has_install == 0 )); then
        err "[$host] missing sudoers entry — '/usr/bin/install -m 0755 -o root -g root /tmp/pizzini-relay-new /usr/local/bin/pizzini-relay'"
        err "[$host] fix: log in as root via the provider's web console and run:"
        err "[$host]   printf 'pizzini-admin ALL=(ALL) NOPASSWD: /usr/bin/install -m 0755 -o root -g root /tmp/pizzini-relay-new /usr/local/bin/pizzini-relay\\n' > /etc/sudoers.d/91-pizzini-relay-update"
        err "[$host]   chmod 0440 /etc/sudoers.d/91-pizzini-relay-update"
        err "[$host]   visudo -c"
        return 1
    fi
    # Sudoers: systemctl restart must be allowed (covered by 90-pizzini-admin
    # or the legacy NOPASSWD: ALL).
    if ! grep -qE '/(usr/)?bin/systemctl|\(ALL\)[[:space:]]+NOPASSWD:[[:space:]]+ALL' <<<"$allowed"; then
        err "[$host] missing sudoers entry — 'systemctl' (90-pizzini-admin drop-in)"
        return 1
    fi
    return 0
}

say "preflight ${#targets[@]} target(s): ${targets[*]}"
failed_preflight=()
for t in "${targets[@]}"; do
    if preflight_host "$t"; then
        ok  "[$t] preflight"
    else
        failed_preflight+=("$t")
    fi
done
if (( ${#failed_preflight[@]} > 0 )); then
    err "preflight failed for: ${failed_preflight[*]}"
    err "fix the listed sudoers entries via the provider console, then re-run."
    exit 1
fi

# ───── per-host deploy ───────────────────────────────────────────────
deploy_host() {
    local host="$1"
    say "[$host] scp binary"
    scp -q "$BINARY" "$host:/tmp/pizzini-relay-new"

    # Verify scp landed the right bytes — paranoia against a corrupted
    # transfer leaving a different binary on disk than the operator
    # built and audited.
    local remote_sha
    remote_sha="$(ssh -o BatchMode=yes "$host" 'sha256sum /tmp/pizzini-relay-new | awk "{print \$1}"')"
    if [[ "$remote_sha" != "$LOCAL_SHA" ]]; then
        err "[$host] sha256 mismatch after scp: $remote_sha (expected $LOCAL_SHA)"
        ssh -o BatchMode=yes "$host" 'rm -f /tmp/pizzini-relay-new' || true
        return 1
    fi

    say "[$host] install + restart"
    ssh -o BatchMode=yes "$host" '
        set -e
        before=$(sha256sum /usr/local/bin/pizzini-relay | awk "{print \$1}")
        sudo /usr/bin/install -m 0755 -o root -g root /tmp/pizzini-relay-new /usr/local/bin/pizzini-relay
        after=$(sha256sum /usr/local/bin/pizzini-relay | awk "{print \$1}")
        echo "  before: $before"
        echo "  after : $after"
        sudo systemctl restart pizzini-relay
        sleep 2
        sudo systemctl is-active pizzini-relay >/dev/null
        # Listener should be back on 127.0.0.1:7777 within the 2s sleep.
        if ! ss -tln | grep -qF "127.0.0.1:7777"; then
            echo "  ERROR: listener not bound on 127.0.0.1:7777" >&2
            sudo journalctl -u pizzini-relay -n 20 --no-pager >&2
            exit 1
        fi
        rm -f /tmp/pizzini-relay-new
    '

    ok "[$host] deployed + active + listening"
    return 0
}

failed_deploy=()
for t in "${targets[@]}"; do
    if ! deploy_host "$t"; then
        failed_deploy+=("$t")
    fi
done

# ───── summary ───────────────────────────────────────────────────────
echo
if (( ${#failed_deploy[@]} > 0 )); then
    err "deploy failed for: ${failed_deploy[*]}"
    err "successful targets are now on the new binary; failed ones are unchanged."
    exit 2
fi
ok "all ${#targets[@]} target(s) on $LOCAL_SHA"
echo
echo "transparency-log entry (publish when ready):"
echo "  {\"binary_sha256\":\"$LOCAL_SHA\",\"binary_size\":$LOCAL_SIZE}"
