//! Pipeline orchestration.
//!
//! A [`Pipeline`] owns the shared run context and runs the configured stages in
//! order. Each stage is a self-contained function over [`StageCtx`]; they
//! communicate only through artifacts, so the orchestrator just sequences them.

mod aggregate;
mod dedupe;
mod feedback;
mod gapfill;
mod hunt;
mod recon;
mod report;
mod salvage;
mod similarity;
mod skip_reported;
mod validate;

use std::sync::Arc;

use anyhow::{Result, bail};
use tracing::{error, info};

use crate::artifacts::Artifacts;
use crate::config::Config;
use crate::provider::{AgentRunner, RetryOnRateLimit, build_runner};
use crate::scratch::ScratchRoot;

/// Tools every stage agent is denied, for two reasons:
///
/// - `Task` and the orchestration tools (`Task*`, `Workflow`): the harness owns
///   parallelism. A stage spawning its own sub-agents only multiplies cost
///   without adding coverage.
/// - `AskUserQuestion`: agents run unattended, so a question would only stall
///   the agent until its timeout (skills such as fp-check suggest asking).
/// - The rest are irrelevant to reading code and finding bugs — scheduling,
///   notebooks, notifications, worktrees, deferred-tool search, and web access
///   (egress is firewalled to a deny-default allow-list anyway). Every tool's
///   schema sits in the cached system-prompt prefix that is re-read on every
///   agent turn, so dropping the unused ones shrinks the per-turn cost across
///   the whole run.
///
/// A deny-list (not an allow-list) because `--disallowedTools` is what removes a
/// tool from the model's context; if the CLI adds a new irrelevant tool later,
/// add it here. `Read`, `Bash`, `Write`, `Edit`, and `Skill` are what the stages
/// actually use, so they are deliberately absent.
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

/// The shared deny-list as owned strings for an [`AgentRequest`].
pub(crate) fn disabled_tools() -> Vec<String> {
    DISABLED_TOOLS.iter().map(|s| s.to_string()).collect()
}

/// Shared context handed to every stage.
pub struct StageCtx {
    pub config: Config,
    pub artifacts: Artifacts,
    pub scratch: ScratchRoot,
    pub runner: Arc<dyn AgentRunner>,
}

pub struct Pipeline {
    ctx: StageCtx,
}

impl Pipeline {
    /// Build a pipeline from config, constructing the default provider runner.
    pub fn new(config: Config) -> Result<Self> {
        let runner = Arc::from(build_runner(
            &config.provider.default,
            config.default_provider(),
        ));
        Self::with_runner(config, runner)
    }

    /// Build a pipeline with a caller-supplied runner (used by tests and
    /// offline runs with the mock provider).
    pub fn with_runner(config: Config, runner: Arc<dyn AgentRunner>) -> Result<Self> {
        let artifacts = Artifacts::new(&config.run.out_dir)?;
        let scratch = ScratchRoot::new(&config.run.scratch_root)?;
        Ok(Self {
            ctx: StageCtx {
                config,
                artifacts,
                scratch,
                runner: Arc::new(RetryOnRateLimit::new(runner)),
            },
        })
    }

    /// Run the stages listed in `stages.enabled`, in order.
    pub async fn run(&self) -> Result<()> {
        self.execute(false).await
    }

    /// Continue the last run in `out_dir`: run the listed stages except recon,
    /// keeping every artifact, so hunt picks up the tasks a usage limit or crash
    /// left unprocessed and later stages see the whole run.
    pub async fn resume(&self) -> Result<()> {
        self.execute(true).await
    }

    async fn execute(&self, resume: bool) -> Result<()> {
        use crate::artifacts::names;

        let mut stages = self.ctx.config.stages.enabled.clone();
        if resume {
            if !self.ctx.artifacts.exists(names::QUEUE) {
                bail!(
                    "nothing to resume: {} has no {}; run without --resume",
                    self.ctx.config.run.out_dir.display(),
                    names::QUEUE
                );
            }
            stages.retain(|s| s != "recon");
        }

        // Acquire the target and optional reference repo (clone if configured)
        // before any stage reads them.
        crate::target::ensure_target(&self.ctx.config)?;
        crate::target::ensure_reference(&self.ctx.config)?;

        // A recon-led run starts fresh: clear last run's per-run artifacts so a
        // reused out_dir cannot leak stale state (e.g. the hunt ledger). The
        // durable feedback memory (SEEDS) is deliberately preserved.
        if stages.iter().any(|s| s == "recon") {
            for name in names::PER_RUN {
                self.ctx.artifacts.remove(name)?;
            }
            for dir in names::PER_RUN_DIRS {
                self.ctx.artifacts.remove_dir(dir)?;
            }
        }
        if !self.ctx.artifacts.exists(names::RUN_ID) {
            self.ctx
                .artifacts
                .write_text(names::RUN_ID, &new_run_id())?;
        }

        info!(
            provider = self.ctx.runner.name(),
            ?stages,
            resume,
            "starting pipeline"
        );
        // A failed stage does not stop the ones after it: each reads whatever
        // artifacts exist, so e.g. a report that fails on a sink error still
        // leaves feedback to record the run. The run still exits non-zero.
        let mut failed = Vec::new();
        for stage in &stages {
            info!(stage = %stage, "stage start");
            match run_stage(stage, &self.ctx).await {
                Ok(()) => info!(stage = %stage, "stage done"),
                Err(e) => {
                    error!(stage = %stage, error = format!("{e:#}"), "stage failed; continuing");
                    failed.push(stage.as_str());
                }
            }
        }
        if !failed.is_empty() {
            bail!("stages failed: {}", failed.join(", "));
        }
        Ok(())
    }
}

/// Compile a (possibly partial) run's hunter output into `findings.json` without
/// running the pipeline. Reads the artifacts in `out_dir` only — no runner, no
/// target acquisition, no artifact reset — so it is safe to call after a run that
/// spent its token budget before the review stages. `out_dir` is taken directly
/// (not from config) so the host path can override a container path like
/// `/work/out`.
pub fn aggregate_dir(out_dir: impl Into<std::path::PathBuf>) -> Result<()> {
    let artifacts = Artifacts::new(out_dir)?;
    aggregate::write_report(&artifacts)
}

/// A fresh run id: the UTC start time, so ids sort by run and read as a date.
fn new_run_id() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

async fn run_stage(stage: &str, ctx: &StageCtx) -> Result<()> {
    match stage {
        "recon" => recon::run(ctx).await,
        "hunt" => hunt::run(ctx).await,
        "validate" => validate::run(ctx).await,
        "gapfill" => gapfill::run(ctx).await,
        "dedupe" => dedupe::run(ctx).await,
        "skip-reported" => skip_reported::run(ctx).await,
        "feedback" => feedback::run(ctx).await,
        "aggregate" => aggregate::run(ctx).await,
        "report" => report::run(ctx).await,
        other => bail!("unknown stage '{other}'"),
    }
}
