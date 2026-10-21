//! Runs the configured stages in order. Each stage is a function over
//! [`StageCtx`]; stages talk only through artifacts, so this just sequences them.

mod aggregate;
mod dedupe;
mod feedback;
mod gapfill;
mod hunt;
mod loc;
mod prompt;
mod recon;
mod report;
mod run_meta;
mod salvage;
mod similarity;
mod skip_reported;
mod validate;
mod wishlist;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, bail, ensure};
use tracing::{error, info, warn};

use crate::artifacts::{Artifacts, names};
use crate::config::{Config, Stage};
use crate::provider::{AgentRequest, AgentRunner, Effort, RetryOnRateLimit, build_runner};
use crate::scratch::ScratchRoot;

/// Tools removed from every stage agent: the harness owns parallelism, agents
/// run unattended, and the rest don't help read code. Every schema is re-read
/// each turn, so each one dropped cuts cost. A deny-list because only
/// `--disallowedTools` removes a tool from context.
const DISABLED_TOOLS: &[&str] = &[
    "Task",
    "TaskCreate",
    "TaskGet",
    "TaskList",
    "TaskOutput",
    "TaskStop",
    "TaskUpdate",
    "Workflow",
    "AskUserQuestion",
    "CronCreate",
    "CronDelete",
    "CronList",
    "ScheduleWakeup",
    "Monitor",
    "RemoteTrigger",
    "PushNotification",
    "SendMessage",
    "DesignSync",
    "NotebookEdit",
    "EnterWorktree",
    "ExitWorktree",
    "ToolSearch",
    "WebFetch",
    "WebSearch",
];

pub struct StageCtx {
    pub config: Config,
    pub artifacts: Artifacts,
    pub scratch: ScratchRoot,
    pub runner: Arc<dyn AgentRunner>,
}

/// The reasoning effort a stage's agents run at; `None` for a stage without
/// agents. Hunters fork recon's session at recon's effort: another effort
/// misses the prompt cache and re-bills the whole session per hunter.
fn stage_effort(stage: Stage) -> Option<Effort> {
    match stage {
        Stage::Recon | Stage::Hunt => Some(Effort::Xhigh),
        Stage::Validate => Some(Effort::High),
        Stage::SkipReported => Some(Effort::Low),
        Stage::Gapfill | Stage::Dedupe | Stage::Report | Stage::Feedback | Stage::Aggregate => None,
    }
}

impl StageCtx {
    /// A cold run in the agent's own `<stage>-<key>` scratch dir and transcript.
    fn agent_request(&self, stage: Stage, key: &str, prompt: String) -> Result<AgentRequest> {
        let effort = stage_effort(stage).unwrap_or_else(|| panic!("{stage} runs no agent"));
        let label = format!("{stage}-{key}");
        let dir = self.scratch.for_agent(&label)?;
        Ok(AgentRequest {
            extra_dirs: self.reference_dirs(),
            disallowed_tools: DISABLED_TOOLS.iter().map(ToString::to_string).collect(),
            model: self.config.stage_model(stage),
            stream_log_path: Some(self.artifacts.log_path(&format!("{label}.jsonl"))),
            ..AgentRequest::new(prompt, dir, self.config.run.agent_timeout(), effort)
        })
    }

    fn reference_dirs(&self) -> Vec<PathBuf> {
        self.config
            .reference
            .active_dir()
            .map(Path::to_path_buf)
            .into_iter()
            .collect()
    }
}

pub struct Pipeline {
    ctx: StageCtx,
}

impl Pipeline {
    pub fn new(config: Config) -> Result<Self> {
        let runner = build_runner(&config.provider.default, config.default_provider());
        Self::with_runner(config, runner)
    }

    /// A pipeline over a caller-supplied runner, e.g. the mock provider.
    pub fn with_runner(config: Config, runner: Arc<dyn AgentRunner>) -> Result<Self> {
        Ok(Self {
            ctx: StageCtx {
                artifacts: Artifacts::new(&config.run.out_dir)?,
                scratch: ScratchRoot::new(&config.run.scratch_root)?,
                runner: Arc::new(RetryOnRateLimit::new(runner)),
                config,
            },
        })
    }

    pub async fn run(&self) -> Result<()> {
        self.execute(false).await
    }

    /// Continue the last run in `out_dir`: every stage but recon, keeping all
    /// artifacts, so hunt picks up the tasks a usage limit or crash left.
    pub async fn resume(&self) -> Result<()> {
        self.execute(true).await
    }

    async fn execute(&self, resume: bool) -> Result<()> {
        let ctx = &self.ctx;
        let mut stages = ctx.config.stages.enabled.clone();
        if resume {
            ensure!(
                ctx.artifacts.exists(names::QUEUE),
                "nothing to resume: {} has no {}; run without --resume",
                ctx.config.run.out_dir.display(),
                names::QUEUE
            );
            stages.retain(|&s| s != Stage::Recon);
        }

        crate::target::ensure_target(&ctx.config)?;
        crate::target::ensure_reference(&ctx.config)?;
        if stages.contains(&Stage::Recon) {
            ctx.artifacts.reset_run()?;
        }
        if !ctx.artifacts.exists(names::RUN_ID) {
            ctx.artifacts.write_text(names::RUN_ID, &new_run_id())?;
        }
        // Bookkeeping: a failure to record the run must not stop it.
        if let Err(e) = run_meta::record(ctx, resume) {
            warn!(
                error = format!("{e:#}"),
                "could not write {}",
                names::RUN_META
            );
        }

        let names: Vec<&str> = stages.iter().map(|s| s.name()).collect();
        info!(
            provider = ctx.runner.name(),
            stages = %names.join(" -> "),
            resume,
            "starting pipeline"
        );
        // A failed stage does not stop the rest: each reads whatever artifacts
        // exist, so e.g. feedback still records a run whose report failed.
        let mut failed = Vec::new();
        for &stage in &stages {
            info!(%stage, "stage start");
            match run_stage(stage, ctx).await {
                Ok(()) => info!(%stage, "stage done"),
                Err(e) => {
                    error!(%stage, error = format!("{e:#}"), "stage failed; continuing");
                    failed.push(stage.name());
                }
            }
        }
        if !failed.is_empty() {
            bail!("stages failed: {}", failed.join(", "));
        }
        Ok(())
    }
}

/// Compile a possibly partial run in `out_dir` into `findings.json`, with no
/// runner, target, or reset, so it is safe after a run spent its budget.
pub fn aggregate_dir(out_dir: impl Into<PathBuf>) -> Result<()> {
    aggregate::write_report(&Artifacts::new(out_dir)?)
}

/// The UTC start time, so ids sort by run and read as a date.
fn new_run_id() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

async fn run_stage(stage: Stage, ctx: &StageCtx) -> Result<()> {
    match stage {
        Stage::Recon => recon::run(ctx).await,
        Stage::Hunt => hunt::run(ctx).await,
        Stage::Gapfill => gapfill::run(ctx),
        Stage::Dedupe => dedupe::run(ctx),
        Stage::SkipReported => skip_reported::run(ctx).await,
        Stage::Validate => validate::run(ctx).await,
        Stage::Report => report::run(ctx),
        Stage::Feedback => feedback::run(ctx),
        Stage::Aggregate => aggregate::run(ctx),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_the_agent_stages_have_an_effort() {
        for stage in Stage::ALL {
            assert_eq!(stage_effort(stage).is_some(), stage.runs_agent(), "{stage}");
        }
    }
}
