//! Bakes the fee1dead commit into the binary for `run-meta.json`. The image
//! builds without `.git`, so a `FEE1DEAD_SHA` build arg takes precedence.

use std::process::Command;

/// What the binary is built from, so only their edits mark a build dirty.
const INPUTS: &[&str] = &["src", "prompts", "schema", "Cargo.toml", "Cargo.lock"];

fn main() {
    println!("cargo:rerun-if-env-changed=FEE1DEAD_SHA");
    for path in [".git/HEAD", ".git/logs/HEAD", ".git/index"]
        .iter()
        .chain(INPUTS)
    {
        println!("cargo:rerun-if-changed={path}");
    }
    let sha = std::env::var("FEE1DEAD_SHA")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(git_sha)
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=FEE1DEAD_SHA={sha}");
}

fn git_sha() -> Option<String> {
    let run = |args: &[&str]| {
        let out = Command::new("git").args(args).output().ok()?;
        out.status.success().then_some(out.stdout)
    };
    let head = String::from_utf8(run(&["rev-parse", "HEAD"])?).ok()?;
    let mut status = vec!["status", "--porcelain", "--untracked-files=no", "--"];
    status.extend(INPUTS);
    let dirty = !run(&status)?.is_empty();
    Some(format!(
        "{}{}",
        head.trim(),
        if dirty { "-dirty" } else { "" }
    ))
}
