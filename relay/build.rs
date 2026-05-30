// Embed reproducible-build provenance into the relay binary.
//
// At compile time we capture:
//   * `GIT_SHA`   — full 40-char hex of the source commit producing this
//                   binary. The single most useful "what code is running
//                   on the relay" identifier; reported verbatim through
//                   the `STATUS_RESPONSE` frame.
//   * `GIT_DIRTY` — "1" iff the working tree had uncommitted changes at
//                   build time; "0" otherwise.
//
// PZ-M14: these come from ENVIRONMENT VARIABLES injected by the
// reproducible-build wrapper (`scripts/build-relay-release.sh`), NOT
// from shelling out to `git` here. Invoking `git` inside build.rs is
// non-hermetic: it depends on `git` being installed and configured in
// the build environment (the container `safe.directory` workaround it
// used to need), and it makes the embedded provenance — and therefore
// the binary digest — a function of the build host's git state rather
// than purely of the injected, recorded inputs. Reading env vars
// removes that dependency: the wrapper computes GIT_SHA/GIT_DIRTY once,
// on the host where git is clean, and passes them into the pinned
// container.
//
// When the vars are absent (a bare `cargo build` / `cargo test` outside
// the wrapper) the provenance is the explicit "unknown" sentinel — never
// a silently-wrong value, and distinct from "clean" so the
// transparency-log verifier refuses to treat such a binary as
// reproducible. The reproducible/publish path always goes through the
// wrapper, which sets both vars; a bare release build is for local
// verification only and is not transparency-log-eligible.
//
// Determinism caveat: we deliberately embed no build time, hostname, or
// absolute paths — those would diverge between builds of the same commit
// and break reproducibility.

const UNKNOWN: &str = "unknown";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Re-run when the injected provenance changes. We no longer watch
    // `.git/` because build.rs no longer reads it.
    println!("cargo:rerun-if-env-changed=GIT_SHA");
    println!("cargo:rerun-if-env-changed=GIT_DIRTY");

    let git_sha = provenance("GIT_SHA");
    let git_dirty = normalize_dirty(provenance("GIT_DIRTY"));

    println!("cargo:rustc-env=PIZZINI_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=PIZZINI_GIT_DIRTY={git_dirty}");
}

/// Read an injected provenance var, trimming whitespace; absent or empty
/// becomes the `UNKNOWN` sentinel.
fn provenance(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => UNKNOWN.to_string(),
    }
}

/// Canonicalise the dirty flag to the wire vocabulary the relay's
/// `RelayStatus` decoder expects: "0" (clean), "1" (dirty), or the
/// "unknown" sentinel (decoded as 2). Any other truthy value is treated
/// as dirty, fail-safe.
fn normalize_dirty(v: String) -> String {
    match v.as_str() {
        "0" | "1" | UNKNOWN => v,
        _ => "1".to_string(),
    }
}
