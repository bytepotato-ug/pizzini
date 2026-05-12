#!/usr/bin/env bash
# Pizzini relay first-time bootstrap. Idempotent — running twice
# produces the same end state, with no side effects on the second
# run beyond reloading systemd units.
#
# Invocation:
#
#   ssh monitor@<host> 'sudo bash -s' < scripts/deploy/bootstrap.sh
#
# Expects the following files to be pre-staged at /tmp/pizzini-deploy/
# on the target box (the caller is responsible for scp'ing them
# there before running the script):
#
#   pizzini-relay              — the compiled relay binary (x86_64 Linux)
#   env                        — rendered env file (real APNs identifiers)
#   apns-auth.p8               — Apple APNs auth key
#   onion/hostname             — the .onion address (one line)
#   onion/hs_ed25519_public_key
#   onion/hs_ed25519_secret_key
#   pizzini-relay.service      — systemd unit (this repo's copy)
#   torrc-pizzini.conf         — tor config snippet
#   nftables-pizzini.rules     — firewall ruleset
#
# Anything destructive (`useradd`, `install`, `systemctl restart`)
# only fires when the resulting state differs from the desired
# state, so re-runs are safe.
#
# TODO: full-disk LUKS + dropbear-initramfs for remote unlock at
# reboot. Not in this pass — would require reinstalling the box
# with a custom partition layout. Tracked as a follow-up hardening
# step; until it's done, encryption-at-rest of the relay's
# push-token store is provided by the relay itself (ChaCha20-
# Poly1305 with a key file alongside) but the OS disk is plaintext.

set -euo pipefail

readonly STAGE=/tmp/pizzini-deploy

if [[ $EUID -ne 0 ]]; then
    echo "[bootstrap] must run as root — use sudo" >&2
    exit 1
fi

# ---- 0. preflight: every required staged file must exist ----
required=(
    pizzini-relay
    env
    apns-auth.p8
    onion/hostname
    onion/hs_ed25519_public_key
    onion/hs_ed25519_secret_key
    pizzini-relay.service
    torrc-pizzini.conf
    nftables-pizzini.rules
)
missing=0
for f in "${required[@]}"; do
    if [[ ! -e "$STAGE/$f" ]]; then
        echo "[bootstrap] missing staged file: $STAGE/$f" >&2
        missing=1
    fi
done
if (( missing != 0 )); then
    echo "[bootstrap] cannot continue with missing files" >&2
    exit 1
fi

echo "[bootstrap] target: $(hostname) ($(hostnamectl --static 2>/dev/null || echo ?))"

# ---- 1. apt install ----
echo "[bootstrap] installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    tor nftables fail2ban unattended-upgrades openssl jq curl ca-certificates >/dev/null

# ---- 2. mask ufw (we manage the firewall via nftables directly) ----
# Two firewall managers fighting is the #1 cause of accidental SSH
# lockout. Make sure only nftables is in charge.
if systemctl is-enabled ufw.service >/dev/null 2>&1; then
    systemctl disable --now ufw.service >/dev/null 2>&1 || true
fi
systemctl mask ufw.service >/dev/null 2>&1 || true

# ---- 3. relay user ----
if ! getent passwd pizzini-relay >/dev/null; then
    useradd --system --no-create-home \
            --home /var/lib/pizzini-relay \
            --shell /usr/sbin/nologin \
            pizzini-relay
    echo "[bootstrap] created user pizzini-relay"
fi

# ---- 4. config + state dirs ----
# /etc/pizzini-relay is root-owned but group=pizzini-relay with 0750
# so the service can *traverse* the dir to read the .p8 (which lives
# inside as 0640 root:pizzini-relay). Without group-traversal here
# the systemd sandbox can't even open() the file.
install -d -m 0750 -o root          -g pizzini-relay /etc/pizzini-relay
install -d -m 0700 -o pizzini-relay -g pizzini-relay /var/lib/pizzini-relay

# ---- 5. binary ----
install -m 0755 -o root -g root "$STAGE/pizzini-relay" /usr/local/bin/pizzini-relay
echo "[bootstrap] installed /usr/local/bin/pizzini-relay"
echo "[bootstrap]   sha256: $(sha256sum /usr/local/bin/pizzini-relay | awk '{print $1}')"

# ---- 6. APNs key ----
# Mode 0640 root:pizzini-relay — the relay reads via group, can't write.
install -m 0640 -o root -g pizzini-relay "$STAGE/apns-auth.p8" /etc/pizzini-relay/apns-auth.p8

# ---- 7. env file ----
# Mode 0600 root:root — systemd reads it as PID 1 before dropping
# privs, so the relay user does not need access to the file itself.
install -m 0600 -o root -g root "$STAGE/env" /etc/pizzini-relay/env

# ---- 8. systemd unit ----
install -m 0644 -o root -g root "$STAGE/pizzini-relay.service" /etc/systemd/system/pizzini-relay.service

# ---- 9. tor config ----
install -d -m 0755 -o root -g root /etc/tor/torrc.d
install -m 0644 -o root -g root "$STAGE/torrc-pizzini.conf" /etc/tor/torrc.d/pizzini.conf

# Ubuntu's default /etc/tor/torrc does NOT auto-include torrc.d/.
# Append the include line idempotently.
if ! grep -qE '^[[:space:]]*%include[[:space:]]+/etc/tor/torrc\.d/pizzini\.conf' /etc/tor/torrc; then
    printf '\n# Pizzini relay (added by bootstrap.sh)\n%%include /etc/tor/torrc.d/pizzini.conf\n' \
        >> /etc/tor/torrc
fi

# Ubuntu's `system_tor` AppArmor profile only whitelists
# `/etc/tor/torrc`. Reading our `/etc/tor/torrc.d/pizzini.conf`
# from the include directive above gets DENIED at kernel level by
# AppArmor even though file perms are 0644 — tor fails to start
# with "Could not open ... Permission denied" and the `[err]
# Reading config failed`. The fix is a one-line local override
# (the upstream profile includes `local/system_tor` for exactly
# this purpose). Idempotent: rewrites the same content if it
# already exists.
install -d -m 0755 -o root -g root /etc/apparmor.d/local
echo '/etc/tor/torrc.d/*.conf r,' > /etc/apparmor.d/local/system_tor
chmod 0644 /etc/apparmor.d/local/system_tor
if command -v apparmor_parser >/dev/null 2>&1 && [[ -f /etc/apparmor.d/system_tor ]]; then
    apparmor_parser -r /etc/apparmor.d/system_tor 2>/dev/null || true
fi

# ---- 10. onion key material ----
# debian-tor is the user Ubuntu's tor package runs as. /var/lib/tor
# already exists (created by the tor postinst) so just nest pizzini/
# inside with the right ownership.
install -d -m 0700 -o debian-tor -g debian-tor /var/lib/tor/pizzini
install -m 0600 -o debian-tor -g debian-tor "$STAGE/onion/hs_ed25519_secret_key" /var/lib/tor/pizzini/hs_ed25519_secret_key
install -m 0600 -o debian-tor -g debian-tor "$STAGE/onion/hs_ed25519_public_key" /var/lib/tor/pizzini/hs_ed25519_public_key
install -m 0600 -o debian-tor -g debian-tor "$STAGE/onion/hostname"              /var/lib/tor/pizzini/hostname

# ---- 11. nftables ruleset ----
install -m 0644 -o root -g root "$STAGE/nftables-pizzini.rules" /etc/nftables.conf
# Validate before activating. `nft -c -f` parses + checks without
# loading — if anything is wrong we abort BEFORE flushing the
# current ruleset, so an SSH session in progress survives.
if ! nft -c -f /etc/nftables.conf; then
    echo "[bootstrap] nftables ruleset failed validation — leaving existing ruleset in place" >&2
    exit 1
fi
systemctl enable nftables >/dev/null 2>&1
systemctl restart nftables

# ---- 12a. self-lock guard: ensure a non-root sudo user exists ----
# `PermitRootLogin no` below would lock the operator out of a fresh
# Hetzner-style image where root is the only login user. Mirror
# root's authorized_keys into a `pizzini-admin` account with NOPASSWD
# sudo before disabling root, so there is always a way back in.
#
# Idempotent: if the user already exists (e.g. operator already
# created their own `monitor` / `deploy` user and ran the script as
# them), we still ensure `pizzini-admin` exists as a guaranteed
# fallback. We don't enable it as the *primary* shell account — it's
# strictly a break-glass.
if ! getent passwd pizzini-admin >/dev/null; then
    useradd --create-home --shell /bin/bash --user-group pizzini-admin
    echo "[bootstrap] created user pizzini-admin"
fi
install -d -m 0700 -o pizzini-admin -g pizzini-admin /home/pizzini-admin/.ssh
# Seed authorized_keys from EVERY plausible source of root's current
# SSH keys so the post-PermitRootLogin-no fallback works regardless
# of how the operator originally landed in /root:
#
#   1. /root/.ssh/authorized_keys                — the conventional file
#   2. /root/.ssh/authorized_keys2               — legacy second file
#   3. /etc/ssh/authorized_keys/root             — distro-overridden path
#      (Hetzner Cloud cloud-init / Cherry Servers etc. sometimes
#      drop keys here via AuthorizedKeysFile inside sshd_config.d)
#   4. `sshd -G | grep authorizedkeysfile`        — whatever sshd
#      actually resolves at runtime, expanded for the root user.
#   5. $SUDO_USER's authorized_keys              — when bootstrap was
#      run via `sudo bash -s` from a non-root login.
#
# A bare $SUDO_USER absent + /root/.ssh/authorized_keys missing path
# (an AuthorizedKeysCommand-only host, for example) would otherwise
# leave pizzini-admin without keys and the guard below would abort
# AFTER nftables / fail2ban / apparmor were already applied — half-
# configured state. The expanded lookup eliminates that footgun.
seed_authorized_keys() {
    [[ -r /root/.ssh/authorized_keys  ]] && cat /root/.ssh/authorized_keys
    [[ -r /root/.ssh/authorized_keys2 ]] && cat /root/.ssh/authorized_keys2
    [[ -r /etc/ssh/authorized_keys/root ]] && cat /etc/ssh/authorized_keys/root
    # Resolve sshd's actual AuthorizedKeysFile setting and substitute
    # the standard tokens for root. `sshd -G` prints effective config
    # post-Match-block evaluation; pre-Match (global) is enough for
    # the AuthorizedKeysFile token.
    if command -v sshd >/dev/null 2>&1; then
        local akf
        akf="$(sshd -G 2>/dev/null | awk '/^authorizedkeysfile / { for (i=2;i<=NF;i++) print $i }')"
        if [[ -n "$akf" ]]; then
            while IFS= read -r path; do
                # %h → home (/root), %u → user (root), %% → literal %
                local expanded="${path//%h//root}"
                expanded="${expanded//%u/root}"
                expanded="${expanded//%%/%}"
                # Skip paths that aren't absolute (relative to home) —
                # ssh prepends $home automatically; we already did %h.
                case "$expanded" in
                    /*) [[ -r "$expanded" ]] && cat "$expanded" ;;
                esac
            done <<< "$akf"
        fi
    fi
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        local sudo_user_home
        sudo_user_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
        [[ -r "$sudo_user_home/.ssh/authorized_keys" ]] && cat "$sudo_user_home/.ssh/authorized_keys"
    fi
}
seed_authorized_keys | awk 'NF && !seen[$0]++' > /home/pizzini-admin/.ssh/authorized_keys
chown pizzini-admin:pizzini-admin /home/pizzini-admin/.ssh/authorized_keys
chmod 0600 /home/pizzini-admin/.ssh/authorized_keys
# Final guard: only proceed if pizzini-admin actually has at least
# one key. Otherwise disabling root login *would* lock the box.
# We do this BEFORE installing the sudoers drop-in below — bailing
# here leaves the system without an unnecessary NOPASSWD entry, and
# with sshd still permitting root, so the operator can re-run after
# fixing their key state.
if [[ ! -s /home/pizzini-admin/.ssh/authorized_keys ]]; then
    echo "[bootstrap] refusing to harden sshd: pizzini-admin has no SSH keys (would lock you out)" >&2
    echo "[bootstrap]   seed sources tried: /root/.ssh/authorized_keys, /root/.ssh/authorized_keys2, /etc/ssh/authorized_keys/root, sshd -G AuthorizedKeysFile, SUDO_USER home" >&2
    exit 1
fi
# Capability-restricted sudo. The pre-fix `NOPASSWD: ALL` made any
# remote code execution that landed as `pizzini-admin` an instant
# root escalation; cap to the smallest set of commands the
# break-glass story actually needs:
#
#   * systemctl  — restart / status / journal-style ops
#   * journalctl — read service logs to diagnose
#   * apt-get update / upgrade — apply security patches manually if
#     unattended-upgrades got stuck
#   * nft list ruleset — inspect the firewall without mutating it
#   * tail / less of /var/log — read log files unrelated to journald
#
# Anything destructive beyond service restarts (useradd,
# usermod, partition ops, mount changes) still requires the
# operator to first log in as root via a recovery image or
# Hetzner / Cherry Servers' rescue console. That's a deliberate
# operational handcuff: a pwned shell user can't, e.g., add their
# own SSH key to /root or rotate the box password.
install -d -m 0750 -o root -g root /etc/sudoers.d
cat > /etc/sudoers.d/90-pizzini-admin <<'SUDOEOF'
# Pizzini relay break-glass account — installed by scripts/deploy/bootstrap.sh.
# Capability-restricted NOPASSWD: a remote RCE landing as pizzini-admin
# cannot escalate to arbitrary root via sudo. Full root recovery
# requires the provider's rescue console (a separate, physical-key
# trust path).
pizzini-admin ALL=(ALL) NOPASSWD: /bin/systemctl, /usr/bin/systemctl, /bin/journalctl, /usr/bin/journalctl, /usr/sbin/nft list ruleset, /usr/bin/apt-get update, /usr/bin/apt-get upgrade -y, /usr/bin/apt-get dist-upgrade -y, /usr/bin/tail, /usr/bin/less
SUDOEOF
chmod 0440 /etc/sudoers.d/90-pizzini-admin
# Validate the sudoers drop-in before continuing — a syntax error
# in a sudoers.d file can break sudo entirely. `visudo -cf` parses
# without applying. If it rejects our file, remove it and fall
# back to passwordful sudo so we don't soft-lock the operator.
if ! visudo -cf /etc/sudoers.d/90-pizzini-admin >/dev/null 2>&1; then
    echo "[bootstrap] sudoers drop-in failed validation — removing" >&2
    rm -f /etc/sudoers.d/90-pizzini-admin
    exit 1
fi

# ---- 12b. sshd hardening ----
install -d -m 0755 -o root -g root /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/90-pizzini-hardening.conf <<'SSHEOF'
# Pizzini relay sshd hardening — installed by scripts/deploy/bootstrap.sh.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PrintMotd no
ClientAliveInterval 60
ClientAliveCountMax 3
SSHEOF
chmod 0644 /etc/ssh/sshd_config.d/90-pizzini-hardening.conf

if ! sshd -t; then
    echo "[bootstrap] sshd config invalid — leaving prior config active" >&2
    exit 1
fi
# `reload` not `restart` so the active SSH session isn't dropped.
systemctl reload ssh

# ---- 13. fail2ban for sshd ----
install -d -m 0755 -o root -g root /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/sshd-pizzini.conf <<'F2BEOF'
[sshd]
enabled = true
bantime = 1h
findtime = 10m
maxretry = 5
F2BEOF
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban

# ---- 14. unattended-upgrades ----
# Enable the periodic update timer + the security archive (default)
# + 04:00 auto-reboot when a kernel/security patch needs it.
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'AUEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUEOF
cat > /etc/apt/apt.conf.d/52unattended-upgrades-pizzini <<'UUEOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
UUEOF
systemctl enable unattended-upgrades >/dev/null 2>&1
systemctl restart unattended-upgrades

# ---- 15. enable + start services ----
systemctl daemon-reload
systemctl enable tor.service pizzini-relay.service >/dev/null 2>&1
# Clear ONLY tor's network-consensus caches before the final
# restart — the consensus / microdesc tail is what slows a cold
# start (tor refetches from authorities) and is safely recomputed.
#
# CRITICALLY: `/var/lib/tor/state` is NOT deleted.
#
# The state file holds the v3 hidden-service `HidServRevCounter`
# (rend-spec-v3 §2.5.1.2): HSDirs that have already cached a
# previous descriptor for our service reject any descriptor whose
# revision-counter is ≤ the cached one. Pruning state resets that
# counter to 0; clients that hit a stale HSDir then can't resolve
# our onion until the cache expires (~3h on the descriptor TTL,
# longer on slow HSDirs). The previous version of this script did
# `rm -f /var/lib/tor/state`, which produced a deploy-window
# resolvability gap every time the bootstrap touched tor. The new
# logic preserves state across reboots / config changes.
#
# The legacy cached-* files (descriptors / microdescs / extrainfo /
# rend) ARE pruned: those are network-side data with no per-service
# replay invariant to protect, and a stale consensus is the most
# common reason a re-bootstrapped relay can't reach its directory
# authorities on the first attempt.
systemctl stop tor.service tor@default.service 2>/dev/null || true
rm -f /var/lib/tor/cached-descriptors  /var/lib/tor/cached-descriptors.new \
      /var/lib/tor/cached-microdescs   /var/lib/tor/cached-microdescs.new  \
      /var/lib/tor/cached-extrainfo    /var/lib/tor/cached-extrainfo.new   \
      /var/lib/tor/cached-rend
# Tiny safety net: if /var/lib/tor/state is missing on the very
# first run (fresh install, tor hasn't started yet), that's fine
# — tor will create one. If it's present, leave it alone so the
# revision counter survives.
if [[ -f /var/lib/tor/state ]]; then
    echo "[bootstrap] preserving /var/lib/tor/state (HS revision counter)"
fi
systemctl reset-failed tor.service tor@default.service 2>/dev/null || true
systemctl restart tor.service

# Tor reads HiddenServiceDir on start; we pre-populated the key
# files so the hostname is the operator's vanity address from the
# very first boot. Give Tor a moment to settle before we start the
# relay (the relay doesn't strictly depend on Tor being up, but the
# operational story is "Tor terminates the onion, relay handles the
# decrypted bytes" and starting them in that order avoids a brief
# window where Tor would forward to a closed port).
for _ in $(seq 1 10); do
    if [[ -s /var/lib/tor/pizzini/hostname ]] && systemctl is-active --quiet tor.service; then
        break
    fi
    sleep 1
done

systemctl restart pizzini-relay.service

# ---- 16. final report ----
echo
echo "================================================================"
echo "Bootstrap complete."
echo
echo "SSH access:"
echo "  ssh pizzini-admin@$(hostname --ip-address 2>/dev/null | awk '{print $1}')"
echo "  (root login disabled by the sshd hardening; pizzini-admin"
echo "   has NOPASSWD sudo and the same authorized_keys you used"
echo "   to run this bootstrap.)"
echo
echo ".onion address:"
echo "  $(cat /var/lib/tor/pizzini/hostname)"
echo
echo "pizzini-relay listener (should show 127.0.0.1:7777 only):"
ss -tlnp 'sport = :7777' 2>/dev/null || ss -tlnp | grep -F :7777 || echo "  (no listener yet — check journal below)"
echo
echo "Recent pizzini-relay journal (look for build-attestation line):"
journalctl -u pizzini-relay.service -n 30 --no-pager
echo
echo "Recent tor journal:"
journalctl -u tor@default.service -n 15 --no-pager 2>/dev/null \
    || journalctl -u tor.service -n 15 --no-pager
echo
echo "Service status:"
systemctl is-active pizzini-relay.service tor.service nftables.service fail2ban.service
echo
echo "TODO (follow-up hardening, not done in this pass):"
echo "  - full-disk LUKS encryption with dropbear-initramfs remote unlock."
echo "================================================================"
