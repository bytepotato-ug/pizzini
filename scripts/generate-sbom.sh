#!/usr/bin/env bash
# Generate a reproducible CycloneDX SBOM for the Rust workspace and
# pin its SHA-256, mirroring the SQLCipher-amalgamation model
# (scripts/build-sqlcipher-amalgamation.sh + the CI `sha256 -c` gate).
#
# PZ-M18. Closes the supply-chain-visibility gap: a committed,
# digest-pinned SBOM lets an auditor diff the exact dependency tree
# (name + version + source) that ships in any release, and CI fails if
# that tree changes without a reviewed SBOM + digest update.
#
# REQUIRES (one-time, operator-approved — needs network):
#   cargo install --locked cargo-cyclonedx --version "=0.5.7"
#
# Chosen defaults (flagged for review — change here if undesired):
#   • Format:  CycloneDX JSON (standard, lightweight, jq-normalisable).
#   • Scope:   whole workspace (`--all`), one component tree.
#   • Pin:     a committed expected digest at
#              scripts/sbom-expected-sha256.txt. Absent ⇒ first run
#              prints the digest to commit (then CI enforces it).
#
# Reproducibility note: CycloneDX boms carry a random `serialNumber`
# and a `metadata.timestamp`; both are stripped via jq before hashing
# so the digest depends only on the dependency tree, not on wall-clock
# or RNG.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CYCLONEDX_PIN="0.5.7"
OUT="$REPO_ROOT/sbom.cdx.json"
NORM="$REPO_ROOT/sbom.normalized.json"
EXPECTED="$REPO_ROOT/scripts/sbom-expected-sha256.txt"

if ! cargo cyclonedx --version >/dev/null 2>&1; then
    echo "error: cargo-cyclonedx not installed." >&2
    echo "       cargo install --locked cargo-cyclonedx --version \"=$CYCLONEDX_PIN\"" >&2
    exit 1
fi

# Lockfile must be frozen — an SBOM of a floating dep tree is
# meaningless. `--locked` makes cargo error if Cargo.lock is stale.
echo "==> Generating CycloneDX SBOM (workspace, JSON)"
cargo cyclonedx --format json --all --locked

# cargo-cyclonedx writes one bom per package (e.g. <crate>.cdx.json)
# next to each Cargo.toml. Collect them deterministically (sorted),
# normalise away non-deterministic fields, and concatenate into one
# canonical document so the digest is stable across machines.
# (Portable array fill — `mapfile` is bash 4+, absent on macOS 3.2.)
BOMS=()
while IFS= read -r f; do
    BOMS+=("$f")
done < <(find . -name '*.cdx.json' -not -path './target/*' | sort)
if [[ "${#BOMS[@]}" -eq 0 ]]; then
    echo "error: cargo-cyclonedx produced no *.cdx.json files" >&2
    exit 1
fi

# Strip the random serialNumber + timestamp from each bom, then emit a
# sorted-key compact array — one canonical, reproducible artifact.
jq -cS 'del(.serialNumber, .metadata.timestamp)' "${BOMS[@]}" \
    | jq -cs '.' > "$NORM"
cp "$NORM" "$OUT"

if command -v sha256sum >/dev/null 2>&1; then
    SBOM_SHA="$(sha256sum "$NORM" | awk '{print $1}')"
else
    SBOM_SHA="$(shasum -a 256 "$NORM" | awk '{print $1}')"
fi

echo "    normalized SBOM: $NORM"
echo "    sha256         : $SBOM_SHA"

if [[ -f "$EXPECTED" ]]; then
    EXP="$(tr -d '[:space:]' < "$EXPECTED")"
    if [[ "$SBOM_SHA" != "$EXP" ]]; then
        echo "::error::SBOM digest mismatch — built $SBOM_SHA, expected $EXP." >&2
        echo "         The dependency tree changed. Review the diff, then commit the new" >&2
        echo "         digest to $EXPECTED if the change is intended." >&2
        exit 1
    fi
    echo "    expected       : matches committed digest"
else
    echo "    NOTE: no committed expected digest at $EXPECTED." >&2
    echo "          Commit the sha256 above there so CI enforces SBOM reproducibility henceforth." >&2
fi
