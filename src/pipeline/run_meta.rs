//! `run-meta.json`: the commits a run audited and the harness build, models,
//! and efforts it used. A finding's `file:line` is ambiguous without the
//! target commit, and two runs compare only at known settings.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{StageCtx, stage_effort};
use crate::artifacts::{Artifacts, names};
use crate::config::{Config, ProviderConfig, Stage};
use crate::provider::Effort;
use crate::target::head_commit;

/// The fee1dead commit this binary was built from; see `build.rs`.
const FEE1DEAD_SHA: &str = env!("FEE1DEAD_SHA");

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct RunMeta {
    pub run_id: String,
    /// Suffixed `-dirty` when built from uncommitted changes.
    pub fee1dead: String,
    pub target: Checkout,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<Checkout>,
    pub provider: String,
    /// opencode's effort knob, used in place of each stage's `effort`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub stages: Vec<StageMeta>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Checkout {
    pub dir: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    /// `None` when `dir` is not a git checkout.
    pub commit: Option<String>,
}

impl Checkout {
    fn of(dir: &Path, repo: &Option<String>, git_ref: &Option<String>) -> Self {
        Self {
            dir: dir.to_path_buf(),
            repo: repo.clone(),
            git_ref: git_ref.clone(),
            commit: head_commit(dir),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct StageMeta {
    pub stage: Stage,
    /// `None` means the CLI's own default.
    pub model: Option<String>,
    pub effort: Effort,
}

impl RunMeta {
    fn collect(cfg: &Config, run_id: String) -> Self {
        let (provider_model, variant) = match cfg.default_provider() {
            ProviderConfig::ClaudeCode(c) => (c.model.clone(), None),
            ProviderConfig::OpenCode(c) => (c.model.clone(), c.variant.clone()),
            ProviderConfig::Exec(_) => (None, None),
        };
        let mut stages: Vec<StageMeta> = Vec::new();
        for &stage in &cfg.stages.enabled {
            let Some(effort) = stage_effort(stage) else {
                continue;
            };
            if stages.iter().all(|s| s.stage != stage) {
                stages.push(StageMeta {
                    stage,
                    model: cfg.stage_model(stage).or_else(|| provider_model.clone()),
                    effort,
                });
            }
        }
        Self {
            run_id,
            fee1dead: FEE1DEAD_SHA.to_string(),
            target: Checkout::of(&cfg.run.target_dir, &cfg.target.repo, &cfg.target.git_ref),
            reference: cfg
                .reference
                .active_dir()
                .map(|dir| Checkout::of(dir, &cfg.reference.repo, &cfg.reference.git_ref)),
            provider: cfg.provider.default.clone(),
            variant,
            stages,
        }
    }
}

/// Write `run-meta.json` for a new run. A resumed run keeps the original and
/// only warns if the target moved, since its findings would then mix commits.
pub(super) fn record(ctx: &StageCtx, resume: bool) -> Result<()> {
    let run_id = ctx
        .artifacts
        .read_line(names::RUN_ID)
        .context("the run has no id")?;
    let meta = RunMeta::collect(&ctx.config, run_id);
    if meta.target.commit.is_none() {
        warn!(
            dir = %meta.target.dir.display(),
            "the target is not a git checkout; findings cannot be pinned to a commit"
        );
    }
    if resume && let Some(started) = read(&ctx.artifacts)? {
        if started.target.commit != meta.target.commit {
            warn!(
                started = ?started.target.commit,
                now = ?meta.target.commit,
                "the target moved since this run started; its findings may refer to either commit"
            );
        }
        return Ok(());
    }
    let json = serde_json::to_string_pretty(&meta)?;
    ctx.artifacts.write_text(names::RUN_META, &json)
}

/// `None` for a run that predates `run-meta.json`.
pub(super) fn read(artifacts: &Artifacts) -> Result<Option<RunMeta>> {
    if !artifacts.exists(names::RUN_META) {
        return Ok(None);
    }
    let json = artifacts.read_text(names::RUN_META)?;
    serde_json::from_str(&json)
        .with_context(|| format!("parsing {}", names::RUN_META))
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(target_dir: &Path, stages: &str) -> Config {
        toml::from_str(&format!(
            r#"
[run]
target_dir = {target:?}
scratch_root = "/tmp/s"
out_dir = "/tmp/o"
[provider]
default = "claude-code"
[providers.claude-code]
type = "claude-code"
model = "claude-opus-5"
[firewall]
allow = ["x"]
[report]
sink = "jsonl"
path = "/tmp/o/f.jsonl"
[stages]
enabled = [{stages}]
models = {{ validate = "claude-sonnet-5" }}
"#,
            target = target_dir.to_str().unwrap(),
        ))
        .unwrap()
    }

    #[test]
    fn lists_each_agent_stage_once_with_its_effective_model_and_effort() {
        let cfg = config(
            Path::new("/nonexistent"),
            r#""recon", "hunt", "gapfill", "hunt", "skip-reported", "validate", "report""#,
        );
        let meta = RunMeta::collect(&cfg, "R".into());
        let stages: Vec<(Stage, Option<&str>, Effort)> = meta
            .stages
            .iter()
            .map(|s| (s.stage, s.model.as_deref(), s.effort))
            .collect();
        assert_eq!(
            stages,
            [
                (Stage::Recon, Some("claude-opus-5"), Effort::Xhigh),
                (Stage::Hunt, Some("claude-opus-5"), Effort::Xhigh),
                (Stage::SkipReported, Some("claude-haiku-4-5"), Effort::Low),
                (Stage::Validate, Some("claude-sonnet-5"), Effort::High),
            ]
        );
        assert_eq!(meta.provider, "claude-code");
        assert_eq!(meta.target.commit, None);
        assert!(meta.reference.is_none());
    }

    #[test]
    fn records_the_target_commit_and_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap();
        let git = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .args(["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t"])
                .args(["-c", "commit.gpgsign=false"])
                .args(args)
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?}");
        };
        git(&["init", "-q"]);
        git(&["commit", "-q", "--allow-empty", "-m", "c"]);
        let meta = RunMeta::collect(&config(tmp.path(), r#""recon""#), "R".into());
        let commit = meta.target.commit.clone().unwrap();
        assert_eq!(commit.len(), 40);

        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"effort\":\"xhigh\""), "{json}");
        let back: RunMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target.commit, Some(commit));
    }
}
