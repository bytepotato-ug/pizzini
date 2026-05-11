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
install -d -m 0700 -o root          -g root          /etc/pizzini-relay
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

# ---- 12. sshd hardening ----
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
