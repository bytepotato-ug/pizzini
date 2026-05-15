// Embed reproducible-build provenance into the relay binary.
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

    // On the release profile the embedded provenance must be a
    // deterministic function of the commit, never of the build
    // host's git configuration (e.g. a `safe.directory` miss under
    // a container bind-mount making `git` fail). A release build
    // that cannot read its own commit refuses to build rather than
    // baking the "unknown" sentinel — which would also change the
    // binary digest and silently break the reproducible-build
    // contract the transparency log depends on.
    let is_release = std::env::var("PROFILE").as_deref() == Ok("release");
    let git_sha = match run_git(&["rev-parse", "HEAD"]) {
        Some(sha) => sha,
        None if is_release => panic!(
            "relay build.rs: `git rev-parse HEAD` failed on the release \
             profile. The relay's transparency-log self-attestation requires \
             a real commit sha; refusing to bake the \"unknown\" sentinel. If \
             building inside a container over a bind-mount, run `git config \
             --global --add safe.directory <repo>` first."
        ),
        // Not-a-git-checkout fallback for non-release builds (e.g.
        // building from a `cargo package` tarball, or a dev build
        // outside a checkout). Make the absence loud in the embedded
        // value so it is obviously not transparency-log-eligible.
        None => "unknown".to_string(),
    };
    let dirty = match run_git(&["status", "--porcelain"]) {
        Some(s) => if s.trim().is_empty() { "0" } else { "1" }.to_string(),
        None if is_release => panic!(
            "relay build.rs: `git status --porcelain` failed on the release \
             profile. Cannot determine whether the working tree is clean; \
             refusing to bake the \"unknown\" sentinel."
        ),
        None => "unknown".to_string(),
    };

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
