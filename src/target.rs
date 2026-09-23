//! Repository acquisition for the target and the optional reference.
//!
//! If `[target].repo` is configured, the harness clones it into
//! `run.target_dir` (at an optional `ref`) before any stage runs. Otherwise the
//! target is expected to already be present there (e.g. a mounted volume).
//!
//! If `[reference].repo` is configured, that spec / known-good implementation is
//! cloned into `[reference].dir` and exposed to the agents as ground truth.
//!
//! Submodules, when present, are initialized recursively after checkout, then
//! `[target].prepare` commands run in the target dir.
//!
//! Clones run after the egress firewall is up, so each git host must be in
//! `[firewall].allow` — including the hosts of any submodule URL.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use tracing::{info, warn};

use crate::config::Config;

/// Make `run.target_dir` contain the code to hunt, then run `[target].prepare`.
/// Idempotent: an existing clone is fetched and re-checked-out rather than
/// re-cloned.
pub fn ensure_target(cfg: &Config) -> Result<()> {
    let dir = &cfg.run.target_dir;

    match cfg.target.repo.as_deref() {
        Some(repo) => clone_or_update(repo, dir, cfg.target.git_ref.as_deref(), "target")?,
        // No repo configured: the target must already be present.
        None if !dir.exists() => bail!(
            "run.target_dir {} does not exist and no [target].repo is configured",
            dir.display()
        ),
        None => {}
    }

    for command in &cfg.target.prepare {
        run_prepare(command, dir);
    }
    Ok(())
}

/// Run one prepare command in the target dir. A failure only warns: a cold
/// package cache makes agents slower, not wrong, so it must not sink the run.
fn run_prepare(command: &str, dir: &Path) {
    info!(command, "running target prepare command");
    match Command::new("sh")
        .args(["-c", command])
        .current_dir(dir)
        .output()
    {
        Ok(out) if out.status.success() => {}
        Ok(out) => warn!(
            command,
            code = out.status.code(),
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "prepare command failed; continuing"
        ),
        Err(e) => warn!(command, error = %e, "prepare command could not start; continuing"),
    }
}

/// Clone the optional reference repo (spec / known-good implementation) into
/// `reference.dir`. No-op when no reference repo is configured.
pub fn ensure_reference(cfg: &Config) -> Result<()> {
    let Some(repo) = cfg.reference.repo.as_deref() else {
        return Ok(());
    };
    clone_or_update(
        repo,
        &cfg.reference.dir,
        cfg.reference.git_ref.as_deref(),
        "reference",
    )
}

/// Clone `repo` into `dir` (or fetch if already cloned) and check out `git_ref`.
/// `label` names the repo's role for logs. The clone runs after the egress
/// firewall is up, so the git host must be in `[firewall].allow`.
fn clone_or_update(repo: &str, dir: &Path, git_ref: Option<&str>, label: &str) -> Result<()> {
    let dir_str = dir
        .to_str()
        .with_context(|| format!("{label}_dir {} is not valid UTF-8", dir.display()))?;

    if dir.join(".git").is_dir() {
        info!(%dir_str, "{label} repo present; fetching updates");
        git(&["-C", dir_str, "fetch", "--tags", "--prune", "origin"])?;
    } else {
        if dir.exists() && !is_empty_dir(dir)? {
            bail!(
                "{label}_dir {} is non-empty and not a git repo; refusing to clone over it",
                dir.display()
            );
        }
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating {label}_dir {}", dir.display()))?;
        info!(repo, "cloning {label} repo");
        git(&["clone", repo, dir_str])?;
    }

    if let Some(git_ref) = git_ref {
        info!(git_ref, "checking out {label} ref");
        git(&["-C", dir_str, "checkout", "--force", git_ref])?;
    }

    // Submodules carry code the agents must be able to read; sync after the
    // checkout so they match the ref actually in use.
    if dir.join(".gitmodules").is_file() {
        info!("initializing {label} submodules");
        git(&[
            "-C",
            dir_str,
            "submodule",
            "update",
            "--init",
            "--recursive",
        ])?;
    }

    // Record exactly what we used.
    if let Ok(head) = git_capture(&["-C", dir_str, "rev-parse", "HEAD"]) {
        info!(label, head = head.trim(), "checked out");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config(target_dir: &Path, prepare: &[&str]) -> Config {
        let prepare = prepare
            .iter()
            .map(|c| format!("{c:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        toml::from_str(&format!(
            r#"
[run]
target_dir = {target:?}
scratch_root = "/tmp/s"
out_dir = "/tmp/o"
[target]
prepare = [{prepare}]
[provider]
default = "c"
[providers.c]
type = "claude-code"
[firewall]
allow = ["x"]
[report]
sink = "jsonl"
path = "/tmp/o/f.jsonl"
[stages]
enabled = ["recon"]
"#,
            target = target_dir.to_str().unwrap(),
        ))
        .unwrap()
    }

    #[test]
    fn prepare_runs_in_the_mounted_target_and_a_failure_does_not_abort() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path(), &["exit 3", "touch prepared"]);
        ensure_target(&cfg).unwrap();
        assert!(dir.path().join("prepared").exists());
    }
}
