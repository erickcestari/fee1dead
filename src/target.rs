//! Acquire the target (and the optional reference) before any stage runs:
//! clone or update it when a repo is configured, else expect it mounted.
//! Clones run behind the egress firewall, so every git host, submodules'
//! included, must be in `[firewall].allow`.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use tracing::{info, warn};

use crate::config::Config;

/// Make `run.target_dir` hold the code to hunt, then run `[target].prepare`.
pub fn ensure_target(cfg: &Config) -> Result<()> {
    let dir = &cfg.run.target_dir;
    match &cfg.target.repo {
        Some(repo) => clone_or_update(repo, dir, cfg.target.git_ref.as_deref(), "target")?,
        None => ensure!(
            dir.exists(),
            "run.target_dir {} does not exist and no [target].repo is configured",
            dir.display()
        ),
    }
    for command in &cfg.target.prepare {
        run_prepare(command, dir);
    }
    Ok(())
}

pub fn ensure_reference(cfg: &Config) -> Result<()> {
    match &cfg.reference.repo {
        Some(repo) => clone_or_update(
            repo,
            &cfg.reference.dir,
            cfg.reference.git_ref.as_deref(),
            "reference",
        ),
        None => Ok(()),
    }
}

/// A failure only warns: a cold package cache makes agents slower, not wrong.
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

/// Clone `repo` into `dir`, or fetch if already cloned, then check out
/// `git_ref` and sync submodules to it. `label` names the repo in logs.
fn clone_or_update(repo: &str, dir: &Path, git_ref: Option<&str>, label: &str) -> Result<()> {
    let dir_str = dir
        .to_str()
        .with_context(|| format!("{label}_dir {} is not valid UTF-8", dir.display()))?;

    if dir.join(".git").is_dir() {
        info!(dir = dir_str, "{label} repo present; fetching updates");
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
    if let Ok(head) = git(&["-C", dir_str, "rev-parse", "HEAD"]) {
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

/// Run git, returning its stdout; a failure carries its stderr.
fn git(args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    ensure!(
        out.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(target_dir: &Path, prepare: &[&str]) -> Config {
        toml::from_str(&format!(
            r#"
[run]
target_dir = {target:?}
scratch_root = "/tmp/s"
out_dir = "/tmp/o"
[target]
prepare = {prepare:?}
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
        ensure_target(&config(dir.path(), &["exit 3", "touch prepared"])).unwrap();
        assert!(dir.path().join("prepared").exists());
    }

    #[test]
    fn a_missing_mount_without_a_repo_fails_fast() {
        let dir = tempfile::tempdir().unwrap();
        let err = ensure_target(&config(&dir.path().join("absent"), &[])).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }
}
