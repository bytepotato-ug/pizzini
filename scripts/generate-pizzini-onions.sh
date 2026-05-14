#!/usr/bin/env bash
# Brute-force the six production Tor v3 onion vanity addresses for the
# Pizzini production rollout (`pizzini2..pizzini7` per docs/relay-
# architecture.md, decision D4). Idempotent — re-running picks up
# whatever's already in the output dir and only brute-forces the
# missing prefixes.
#
# Designed for Apple Silicon (M1 / M2 / M3 / M4). Tested mental-model
# on M4 Max — should land in roughly 1–3 hours of all-cores work; your
# fans will be loud but the machine will not crash.
#
# Usage:
#   bash scripts/generate-pizzini-onions.sh
#
# Knobs (env vars):
#   OUTDIR=…/path     where to write the .onion subdirs (default ./onions)
#   WORKDIR=…/path    where to clone mkp224o (default ~/pizzini-onion-build)
#   RESERVE_CORES=N   leave this many cores idle for the system (default 2)
#   STATS_INTERVAL=N  mkp224o stats print interval in seconds (default 30)
#
# Output: one directory per onion under $OUTDIR. Each contains:
#   hostname                ← the .onion address itself (safe to share)
#   hs_ed25519_secret_key   ← THE SECRET. Treat as you would a TLS cert
#                             private key. Never commit, never email.
#   hs_ed25519_public_key   ← public half of the onion's keypair
#
# Stops automatically the moment all six prefixes have at least one
# match. Ctrl-C is also safe — partial progress is preserved on disk.

set -euo pipefail

# ───── config ─────────────────────────────────────────────────────────
# Six prefixes, one per planned production relay (CH/IS/PA + room to
# add three more without re-running). Tor v3 onion addresses use base32
# alphabet a-z + 2-7, so 1/0/8/9 are not valid characters.
PREFIXES=(pizzini2 pizzini3 pizzini4 pizzini5 pizzini6 pizzini7)
WORKDIR="${WORKDIR:-$HOME/pizzini-onion-build}"
OUTDIR="${OUTDIR:-$PWD/onions}"
RESERVE_CORES="${RESERVE_CORES:-2}"
STATS_INTERVAL="${STATS_INTERVAL:-30}"

# ───── output helpers ─────────────────────────────────────────────────
say()  { printf "\033[1;36m▶\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m✓\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m!\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m✗\033[0m %s\n" "$*" >&2; }

# ───── platform sanity ────────────────────────────────────────────────
[[ "$(uname -s)" == "Darwin" ]] || { err "macOS only."; exit 1; }
[[ "$(uname -m)" == "arm64" ]]  || { err "Apple Silicon only (this script assumes /opt/homebrew)."; exit 1; }

# ───── Xcode Command Line Tools ───────────────────────────────────────
if ! xcode-select -p >/dev/null 2>&1; then
    say "Installing Xcode Command Line Tools (this opens a system prompt)…"
    xcode-select --install || true
    err "Re-run this script once the CLT install finishes."
    exit 1
fi
ok "Xcode CLT at $(xcode-select -p)."

# ───── Homebrew ───────────────────────────────────────────────────────
if ! command -v brew >/dev/null 2>&1; then
    if [[ -x /opt/homebrew/bin/brew ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    else
        say "Installing Homebrew (this prompts for your password)…"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
fi
ok "Homebrew at $(command -v brew)."

# ───── build deps ─────────────────────────────────────────────────────
need=()
for p in libsodium autoconf automake libtool; do
    brew list --formula "$p" >/dev/null 2>&1 || need+=("$p")
done
if [[ ${#need[@]} -gt 0 ]]; then
    say "Installing brew packages: ${need[*]}"
    brew install "${need[@]}"
fi
ok "libsodium + autotools present."

# ───── mkp224o clone + build ──────────────────────────────────────────
mkdir -p "$WORKDIR"
cd "$WORKDIR"
if [[ ! -d mkp224o/.git ]]; then
    say "Cloning mkp224o…"
    git clone --depth=1 https://github.com/cathugger/mkp224o.git
fi
cd mkp224o
if [[ ! -x ./mkp224o ]]; then
    say "Building mkp224o for ARM64…"
    ./autogen.sh
    LDFLAGS="-L$(brew --prefix libsodium)/lib" \
    CFLAGS="-I$(brew --prefix libsodium)/include -O3" \
        ./configure
    make -j"$(sysctl -n hw.logicalcpu)"
fi
[[ -x ./mkp224o ]] || { err "Build failed: ./mkp224o not found."; exit 1; }
ok "mkp224o built at $(pwd)/mkp224o."

# ───── thread budget ──────────────────────────────────────────────────
TOTAL=$(sysctl -n hw.logicalcpu)
THREADS=$(( TOTAL - RESERVE_CORES ))
(( THREADS >= 1 )) || THREADS=1
PCORES=$(sysctl -n hw.perflevel0.physicalcpu 2>/dev/null || echo "?")
ECORES=$(sysctl -n hw.perflevel1.physicalcpu 2>/dev/null || echo "?")
ok "Cores: ${TOTAL} total (P-cores: ${PCORES}, E-cores: ${ECORES}). Using ${THREADS}, reserving ${RESERVE_CORES} for the system."

# ───── output dir ─────────────────────────────────────────────────────
mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"
ok "Output dir: $OUTDIR (chmod 700)"

# ───── pre-flight: anything already done? ─────────────────────────────
# Restart-friendly: pre-existing matches in $OUTDIR count, and we only
# ask mkp224o to search for the prefixes we still need. Without this,
# mkp224o would keep finding extra matches for already-done prefixes
# until the completion poll catches up — pure wasted work on resume.
shopt -s nullglob
remaining=()
for prefix in "${PREFIXES[@]}"; do
    found=("$OUTDIR/${prefix}"*".onion")
    if (( ${#found[@]} > 0 )); then
        ok "Already have $prefix → ${found[0]##*/}"
    else
        remaining+=("$prefix")
    fi
done
shopt -u nullglob
if (( ${#remaining[@]} == 0 )); then
    ok "All six prefixes already present. Nothing to do."
    exit 0
fi
say "Need to find ${#remaining[@]} more prefix(es): ${remaining[*]}"
echo

# ───── kick off mkp224o ───────────────────────────────────────────────
say "Starting mkp224o (this will sit at high CPU for a while; the fans"
say "are doing their job, the machine is fine)."
say "Ctrl-C is safe — partial progress on disk is preserved."
echo

# Run in background so we can poll for "all six found" and stop early.
# -d  output dir
# -t  threads
# -S  stats interval
# -s  print summary on exit
# -v  verbose (per-find output)
"$WORKDIR/mkp224o/mkp224o" \
    -d "$OUTDIR" \
    -t "$THREADS" \
    -S "$STATS_INTERVAL" \
    -s -v \
    "${remaining[@]}" &
MKP_PID=$!

cleanup() {
    if kill -0 "$MKP_PID" 2>/dev/null; then
        warn "Stopping mkp224o (PID $MKP_PID)…"
        kill -INT "$MKP_PID" 2>/dev/null || true
        wait "$MKP_PID" 2>/dev/null || true
    fi
}
trap cleanup INT TERM EXIT

# ───── completion poll ────────────────────────────────────────────────
# mkp224o has its own per-filter limit flags (-N), but their behaviour
# can vary by version. Polling the output dir is robust regardless: as
# soon as we see one match per prefix we stop.
while kill -0 "$MKP_PID" 2>/dev/null; do
    sleep 5
    shopt -s nullglob
    have=0
    for prefix in "${PREFIXES[@]}"; do
        found=("$OUTDIR/${prefix}"*".onion")
        (( ${#found[@]} > 0 )) && have=$(( have + 1 ))
    done
    shopt -u nullglob
    if (( have == ${#PREFIXES[@]} )); then
        ok "All six prefixes matched — stopping mkp224o."
        cleanup
        break
    fi
done

# ───── final summary ──────────────────────────────────────────────────
echo
say "Generated onions:"
shopt -s nullglob
missing=0
for prefix in "${PREFIXES[@]}"; do
    found=("$OUTDIR/${prefix}"*".onion")
    if (( ${#found[@]} > 0 )); then
        printf "  \033[1;32m%-10s\033[0m %s\n" "$prefix" "${found[0]##*/}"
    else
        printf "  \033[1;33m%-10s\033[0m (NOT FOUND)\n" "$prefix"
        missing=$(( missing + 1 ))
    fi
done
shopt -u nullglob
echo

if (( missing > 0 )); then
    warn "$missing prefix(es) didn't finish. Re-run the script to continue;"
    warn "the existing matches will be preserved."
    exit 2
fi

cat <<EOF

NEXT STEPS:

  1) Verify the addresses on the box you trust most. Each subdir under
     $OUTDIR contains:

        hostname                ← the .onion address (safe to share)
        hs_ed25519_secret_key   ← THE SECRET KEY (treat like a TLS key:
                                  never commit, never email, never copy
                                  to a machine you don't fully control)
        hs_ed25519_public_key

  2) Move each subdirectory into the corresponding Tor server's
     HiddenServiceDir on the production box (over Tor / SCP-via-Tor,
     not clearnet). Then bounce Tor and confirm the address comes up.

  3) Add the six addresses to the app's bundled allowlist (per
     the relay architecture doc, D5) and ship a release.

EOF

ok "Done."
