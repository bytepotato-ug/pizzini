// Embed reproducible-build provenance into the relay binary (USP #1).
//
// At compile time we capture:
//   * `GIT_SHA`  — full 40-char hex of the source commit producing
//                  this binary. The single most useful "what code
//                  is running on the relay" identifier; reported
//                  verbatim through the `STATUS_RESPONSE` frame.
//   * `GIT_DIRTY` — "1" iff the working tree had uncommitted changes
//                   at build time; "0" otherwise. Production builds
//                   refuse to publish a transparency-log entry if
//                   this is "1", because a dirty build cannot be
//                   independently reproduced from public source.
//
// Determinism caveat: we deliberately do NOT embed the build time,
// hostname, or absolute paths — these would diverge between
// builds of the same commit on different machines and break
// reproducibility. `cargo` doesn't embed them by default; we just
// avoid the build-script anti-patterns that would.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Only need to re-run when HEAD moves or the working tree
    // changes. Cargo doesn't natively watch .git/, so we instruct
    // it to rerun if either of these moves.
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");

    let git_sha = run_git(&["rev-parse", "HEAD"]).unwrap_or_else(|| {
        // Not-a-git-checkout fallback (e.g. building from a `cargo
        // package` tarball). Make the absence loud so a release
        // build is obviously not transparency-log-eligible.
        "unknown".to_string()
    });
    let dirty = run_git(&["status", "--porcelain"])
        .map(|s| if s.trim().is_empty() { "0" } else { "1" })
        .unwrap_or("unknown")
        .to_string();

    println!("cargo:rustc-env=PIZZINI_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=PIZZINI_GIT_DIRTY={dirty}");
}

fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
