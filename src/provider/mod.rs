//! Provider abstraction: how the harness invokes an AI coding CLI.
//!
//! Every stage talks to a provider only through [`AgentRunner`]. Adding a new
//! CLI means either implementing this trait (for custom output parsing) or, for
//! most CLIs, adding a `[providers.<name>]` block of `type = "exec"` to the
//! config with no Rust code at all (see [`generic_exec`]).

mod claude_code;
mod generic_exec;
#[cfg(any(test, feature = "mock-runner"))]
mod mock;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;

use crate::config::ProviderConfig;

/// A provider failure the orchestrator reacts to differently than a generic
/// error.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The backend rejected the request because an account usage / session /
    /// rate limit was reached. Retrying immediately just bounces off the same
    /// limit, so a stage that sees this should stop spawning new agents rather
    /// than burn the rest of its queue on certain failures.
    #[error("usage limit reached: {0}")]
    UsageLimited(String),
}

/// Whether an error chain carries a [`ProviderError::UsageLimited`].
pub fn is_usage_limited(err: &anyhow::Error) -> bool {
    err.downcast_ref::<ProviderError>()
        .is_some_and(|e| matches!(e, ProviderError::UsageLimited(_)))
}

/// Filename the agent is instructed to write its complete final answer to,
/// inside its working dir. The harness reads this back as the agent's result,
/// so the consumed output is decoupled from the streamed event log (and survives
/// even if the chat output is noisy). A `.json` file because every stage's final
/// answer is a bare JSON document (no markdown fence). Defined once here because
/// it is a contract shared between the prompt instruction and the read-back; see
/// [`final_output_path`].
pub const FINAL_OUTPUT_FILE: &str = "agent-final-output.json";

/// Absolute path of the agent's final-output file for a given working dir.
pub fn final_output_path(working_dir: &Path) -> PathBuf {
    working_dir.join(FINAL_OUTPUT_FILE)
}

pub use claude_code::ClaudeCodeRunner;
pub use generic_exec::ExecRunner;
#[cfg(any(test, feature = "mock-runner"))]
pub use mock::{CannedReply, MockRunner};

/// Reasoning effort for an agent run, mapped to `CLAUDE_CODE_EFFORT_LEVEL`.
///
/// Higher levels think longer before acting: more thorough, more tokens (and
/// more turns, each re-reading the cached context). Match it to the stage's
/// actual need — open-ended multi-hop tracing wants [`Effort::Xhigh`]; a
/// mechanical, schema-bound transform wants [`Effort::Low`]. Providers without
/// an effort knob ignore it.
#[derive(Debug, Clone, Copy)]
pub enum Effort {
    Low,
    Medium,
    High,
    Xhigh,
}

impl Effort {
    pub fn as_str(self) -> &'static str {
        match self {
            Effort::Low => "low",
            Effort::Medium => "medium",
            Effort::High => "high",
            Effort::Xhigh => "xhigh",
        }
    }
}

/// A request to run one agent task.
#[derive(Debug, Clone)]
pub struct AgentRequest {
    /// The user-turn prompt for the agent.
    pub prompt: String,
    /// An optional system/role prompt, when the provider supports one.
    pub system: Option<String>,
    /// The directory the agent runs in (its per-task scratch dir).
    pub working_dir: PathBuf,
    /// Extra directories the agent may read beyond `working_dir` (e.g. the
    /// cloned reference repo). Providers that gate file access by directory add
    /// each one; others ignore them.
    pub extra_dirs: Vec<PathBuf>,
    /// Tools the agent is permitted to use, when the provider supports an
    /// allow-list. Empty means "provider default".
    pub allowed_tools: Vec<String>,
    /// Tools the agent is forbidden from using, when the provider supports a
    /// deny-list. Takes precedence over the allow-list. Used to stop a stage
    /// agent from spawning its own sub-agents (the orchestrator owns
    /// parallelism). Empty means "no extra restriction".
    pub disallowed_tools: Vec<String>,
    /// Wall-clock timeout.
    pub timeout: Duration,
    /// Max agent turns, when supported.
    pub max_turns: Option<u32>,
    /// When set, fork a prior agent session so this run inherits its
    /// conversation context. Providers without a session concept ignore it.
    pub resume: Option<ResumeSession>,
    /// Extend the prompt cache from the default 5m TTL to 1h. Worth its higher
    /// write premium only for a session that is forked from and whose prefix
    /// must outlive the 5m window (recon); a leaf agent that nothing forks from
    /// should leave it false. Providers without prompt caching ignore it.
    pub cache_1h: bool,
    /// Reasoning effort for this run. Set per stage to its actual need.
    pub effort: Effort,
    /// When set, tee the provider's full event stream to this file as it runs,
    /// one JSON event per line. Lets a run's agent transcripts be inspected
    /// after the fact, and preserves partial output if the agent times out.
    /// Providers that don't stream ignore it.
    pub stream_log_path: Option<PathBuf>,
}

/// A prior session to fork from.
///
/// `session_id` identifies the conversation; `project_dir` is the directory it
/// was created in. Session lookup is scoped to that directory, so a forking
/// provider must run there rather than in the request's `working_dir`.
#[derive(Debug, Clone)]
pub struct ResumeSession {
    pub session_id: String,
    pub project_dir: PathBuf,
}

/// The result of an agent run.
///
/// Cost and usage (tokens, prompt-cache hits, timing) are intentionally *not*
/// here: a streaming provider tees its full event log to disk
/// ([`AgentRequest::stream_log_path`]), and the final `result` event in that log
/// already carries `total_cost_usd`, `usage`, `duration_ms`, etc. Re-surfacing
/// them through a struct would duplicate that record; profile a run from the
/// logs instead.
#[derive(Debug, Clone)]
pub struct AgentResult {
    /// Raw text the agent produced (its final message, or stdout).
    pub stdout: String,
    pub exit_code: i32,
    /// This run's session id, when the provider exposes one. Lets a later stage
    /// fork from this conversation (see [`ResumeSession`]).
    pub session_id: Option<String>,
}

/// The single seam between the harness and any AI CLI.
#[async_trait]
pub trait AgentRunner: Send + Sync {
    /// Provider name, for logging.
    fn name(&self) -> &str;

    /// Run one agent task to completion.
    async fn run(&self, req: AgentRequest) -> Result<AgentResult>;
}

/// Build the runner selected by a [`ProviderConfig`].
///
/// This is the only place that maps config variants to concrete adapters; new
/// adapter types are wired in here.
pub fn build_runner(name: &str, cfg: &ProviderConfig) -> Box<dyn AgentRunner> {
    match cfg {
        ProviderConfig::ClaudeCode { model, extra_args } => Box::new(ClaudeCodeRunner::new(
            name.to_string(),
            model.clone(),
            extra_args.clone(),
        )),
        ProviderConfig::Exec {
            command,
            args,
            output,
        } => Box::new(ExecRunner::new(
            name.to_string(),
            command.clone(),
            args.clone(),
            *output,
        )),
    }
}
