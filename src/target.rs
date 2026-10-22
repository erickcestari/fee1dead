//! Acquire the target and optional reference before any stage: clone or
//! update a configured repo, else expect it mounted. The pipeline fetches
//! behind the firewall, so every git host (submodules too) must be allowed,
//! even when `[target].setup` already cloned it.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use tracing::{info, warn};

use crate::config::Config;

/// Make `run.target_dir` hold the code to hunt, then run `[target].prepare`.
pub fn ensure_target(cfg: &Config) -> Result<()> {
    acquire_target(cfg)?;
    for command in &cfg.target.prepare {
        run_prepare(command, &cfg.run.target_dir);
    }
    Ok(())
}

/// Run `[target].setup` in the acquired target. The container calls it as
/// root before the firewall comes up, so the script has open egress.
pub fn run_setup(cfg: &Config) -> Result<()> {
    let Some(script) = &cfg.target.setup else {
        info!("no [target].setup script");
        return Ok(());
    };
    acquire_target(cfg)?;
    ensure_reference(cfg)?;
    info!("running [target].setup");
    let started = std::time::Instant::now();
    // xtrace: builds are silent for minutes, so show which command is running.
    let status = Command::new("bash")
        .args(["-euxo", "pipefail", "-c", script])
        .current_dir(&cfg.run.target_dir)
        .status()
        .context("starting bash for [target].setup")?;
    ensure!(status.success(), "[target].setup failed ({status})");
    info!(secs = started.elapsed().as_secs(), "[target].setup done");
    Ok(())
}

fn acquire_target(cfg: &Config) -> Result<()> {
    let dir = &cfg.run.target_dir;
    match &cfg.target.repo {
        Some(repo) => clone_or_update(repo, dir, cfg.target.git_ref.as_deref(), "target"),
        None => {
            ensure!(
                dir.exists(),
                "run.target_dir {} does not exist and no [target].repo is configured",
                dir.display()
            );
            Ok(())
        }
    }
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
    if let Some(head) = head_commit(dir) {
        info!(label, head, "checked out");
    }
    Ok(())
}

/// The commit checked out in `dir`; `None` when it is not a git checkout.
pub fn head_commit(dir: &Path) -> Option<String> {
    let head = git(&["-C", dir.to_str()?, "rev-parse", "HEAD"]).ok()?;
    Some(head.trim().to_string())
}

/// The repo-relative paths that differ between `from` and HEAD in `dir`.
/// Commit to commit, so a read-only checkout needs no index refresh.
pub fn changed_since(dir: &Path, from: &str) -> Result<HashSet<String>> {
    let dir = dir
        .to_str()
        .context("the checkout path is not valid UTF-8")?;
    let out = git(&[
        "-C",
        dir,
        "diff",
        "--name-only",
        "--relative",
        from,
        "HEAD",
        "--",
    ])?;
    Ok(out.lines().map(str::to_string).collect())
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
        config_with(target_dir, &format!("prepare = {prepare:?}"))
    }

    /// A config whose `[target]` table holds `target_extra`.
    fn config_with(target_dir: &Path, target_extra: &str) -> Config {
        toml::from_str(&format!(
            r#"
[run]
target_dir = {target:?}
scratch_root = "/tmp/s"
out_dir = "/tmp/o"
[target]
{target_extra}
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
    fn setup_runs_in_the_target_and_stops_at_the_first_failing_line() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with(dir.path(), "setup = \"touch built\\nfalse\\ntouch after\"");
        let err = run_setup(&cfg).unwrap_err();
        assert!(err.to_string().contains("[target].setup failed"), "{err}");
        assert!(dir.path().join("built").exists());
        assert!(!dir.path().join("after").exists());
    }

    #[test]
    fn setup_without_a_script_does_not_touch_the_target() {
        let dir = tempfile::tempdir().unwrap();
        run_setup(&config(&dir.path().join("absent"), &[])).unwrap();
    }

    #[test]
    fn a_missing_mount_without_a_repo_fails_fast() {
        let dir = tempfile::tempdir().unwrap();
        let err = ensure_target(&config(&dir.path().join("absent"), &[])).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    /// Commit `contents` to `file` in `repo`, returning the new HEAD.
    fn commit(repo: &Path, file: &str, contents: &str) -> String {
        let repo = repo.to_str().unwrap();
        std::fs::write(Path::new(repo).join(file), contents).unwrap();
        git(&["-C", repo, "add", file]).unwrap();
        // Pinned identity and no signing, so a developer's git config can't interfere.
        git(&[
            "-C",
            repo,
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            contents,
        ])
        .unwrap();
        head(Path::new(repo))
    }

    fn head(repo: &Path) -> String {
        head_commit(repo).unwrap()
    }

    #[test]
    fn clone_or_update_clones_then_fetches_and_forces_the_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let origin = tmp.path().join("origin");
        git(&["init", "-q", origin.to_str().unwrap()]).unwrap();
        let first = commit(&origin, "a.txt", "first");
        let origin_url = origin.to_str().unwrap();
        let clone = tmp.path().join("nested/clone");

        clone_or_update(origin_url, &clone, Some(&first), "target").unwrap();
        assert_eq!(head(&clone), first);

        // A commit made after the clone is only reachable through a fetch.
        let second = commit(&origin, "a.txt", "second");
        std::fs::write(clone.join("a.txt"), "local edit").unwrap();
        clone_or_update(origin_url, &clone, Some(&second), "target").unwrap();
        assert_eq!(head(&clone), second);
        assert_eq!(
            std::fs::read_to_string(clone.join("a.txt")).unwrap(),
            "second"
        );
    }

    #[test]
    fn changed_since_lists_the_files_a_later_commit_touched() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        git(&["init", "-q", repo.to_str().unwrap()]).unwrap();
        let first = commit(repo, "a.txt", "first");
        commit(repo, "b.txt", "second");
        assert_eq!(
            changed_since(repo, &first).unwrap(),
            HashSet::from(["b.txt".to_string()])
        );
        assert!(changed_since(repo, &head(repo)).unwrap().is_empty());
        assert!(changed_since(repo, "0000000000000000000000000000000000000000").is_err());
    }

    #[test]
    fn a_repo_without_commits_has_no_head() {
        let tmp = tempfile::tempdir().unwrap();
        git(&["init", "-q", tmp.path().to_str().unwrap()]).unwrap();
        assert_eq!(head_commit(tmp.path()), None);
    }

    #[test]
    fn clone_or_update_refuses_to_clone_over_a_non_git_dir() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("keep.txt"), "mine").unwrap();
        let err = clone_or_update("/nonexistent", tmp.path(), None, "target").unwrap_err();
        assert!(err.to_string().contains("refusing to clone"), "{err}");
        assert!(tmp.path().join("keep.txt").exists());
    }
}
