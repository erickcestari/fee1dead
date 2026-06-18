//! Pipeline orchestration.
//!
//! A [`Pipeline`] owns the shared run context and runs the configured stages in
//! order. Each stage is a self-contained function over [`StageCtx`]; they
//! communicate only through artifacts, so the orchestrator just sequences them.

mod dedupe;
mod feedback;
mod gapfill;
mod hunt;
mod recon;
mod report;
mod validate;

use std::sync::Arc;

use anyhow::{Result, bail};
use tracing::info;

use crate::artifacts::Artifacts;
use crate::config::Config;
use crate::provider::{AgentRunner, build_runner};
use crate::scratch::ScratchRoot;

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
        let artifacts = Artifacts::new(&config.run.out_dir)?;
        let scratch = ScratchRoot::new(&config.run.scratch_root)?;
        let runner: Arc<dyn AgentRunner> = Arc::from(build_runner(
            &config.provider.default,
            config.default_provider(),
        ));
        Ok(Self {
            ctx: StageCtx {
                config,
                artifacts,
                scratch,
                runner,
            },
        })
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
                runner,
            },
        })
    }

    /// Run the stages listed in `stages.enabled`, in order.
    pub async fn run(&self) -> Result<()> {
        // Acquire the target and optional reference repo (clone if configured)
        // before any stage reads them.
        crate::target::ensure_target(&self.ctx.config)?;
        crate::target::ensure_reference(&self.ctx.config)?;

        let stages = self.ctx.config.stages.enabled.clone();

        // A recon-led run starts fresh: clear last run's per-run artifacts so a
        // reused out_dir cannot leak stale state (e.g. the hunt ledger). The
        // durable feedback memory (SEEDS) is deliberately preserved.
        if stages.iter().any(|s| s == "recon") {
            for name in crate::artifacts::names::PER_RUN {
                self.ctx.artifacts.remove(name)?;
            }
            // Stream transcripts live in a directory, not a single file, so they
            // are cleared separately from the PER_RUN file list.
            self.ctx
                .artifacts
                .remove_dir(crate::artifacts::names::LOGS)?;
        }

        info!(
            provider = self.ctx.runner.name(),
            ?stages,
            "starting pipeline"
        );
        for stage in &stages {
            info!(stage = %stage, "stage start");
            run_stage(stage, &self.ctx).await?;
            info!(stage = %stage, "stage done");
        }
        Ok(())
    }
}

async fn run_stage(stage: &str, ctx: &StageCtx) -> Result<()> {
    match stage {
        "recon" => recon::run(ctx).await,
        "hunt" => hunt::run(ctx).await,
        "validate" => validate::run(ctx).await,
        "gapfill" => gapfill::run(ctx).await,
        "dedupe" => dedupe::run(ctx).await,
        "feedback" => feedback::run(ctx).await,
        "report" => report::run(ctx).await,
        other => bail!("unknown stage '{other}'"),
    }
}
