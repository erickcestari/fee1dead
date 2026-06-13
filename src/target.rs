//! Target repository acquisition.
//!
//! If `[target].repo` is configured, the harness clones it into
//! `run.target_dir` (at an optional `ref`) before any stage runs. Otherwise the
//! target is expected to already be present there (e.g. a mounted volume).
//!
//! The clone runs after the egress firewall is up, so the git host must be in
//! `[firewall].allow`.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use tracing::info;

use crate::config::Config;

/// Make `run.target_dir` contain the code to hunt. Idempotent: an existing
/// clone is fetched and re-checked-out rather than re-cloned.
pub fn ensure_target(cfg: &Config) -> Result<()> {
    let dir = &cfg.run.target_dir;

    let Some(repo) = cfg.target.repo.as_deref() else {
        // No repo configured: the target must already be present.
        if !dir.exists() {
            bail!(
                "run.target_dir {} does not exist and no [target].repo is configured",
                dir.display()
            );
        }
        return Ok(());
    };

    let dir_str = dir
        .to_str()
        .with_context(|| format!("target_dir {} is not valid UTF-8", dir.display()))?;

    if dir.join(".git").is_dir() {
        info!(%dir_str, "target repo present; fetching updates");
        git(&["-C", dir_str, "fetch", "--tags", "--prune", "origin"])?;
    } else {
        if dir.exists() && !is_empty_dir(dir)? {
            bail!(
                "target_dir {} is non-empty and not a git repo; refusing to clone over it",
                dir.display()
            );
        }
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating target_dir {}", dir.display()))?;
        info!(repo, "cloning target repo");
        git(&["clone", repo, dir_str])?;
    }

    if let Some(git_ref) = cfg.target.git_ref.as_deref() {
        info!(git_ref, "checking out ref");
        git(&["-C", dir_str, "checkout", "--force", git_ref])?;
    }

    // Record exactly what we hunted.
    if let Ok(head) = git_capture(&["-C", dir_str, "rev-parse", "HEAD"]) {
        info!(head = head.trim(), "target checked out");
    }
    Ok(())
}

fn is_empty_dir(dir: &Path) -> Result<bool> {
    Ok(std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .next()
        .is_none())
}

/// Run a git command, surfacing stderr on failure.
fn git(args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    if !status.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&status.stderr).trim()
        );
    }
    Ok(())
}

fn git_capture(args: &[&str]) -> Result<String> {
    let out = Command::new("git").args(args).output()?;
    if !out.status.success() {
        bail!("git {} failed", args.join(" "));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
