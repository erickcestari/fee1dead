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

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;

use crate::config::ProviderConfig;

pub use claude_code::ClaudeCodeRunner;
pub use generic_exec::ExecRunner;
#[cfg(any(test, feature = "mock-runner"))]
pub use mock::{CannedReply, MockRunner};

/// A request to run one agent task.
#[derive(Debug, Clone)]
pub struct AgentRequest {
    /// The user-turn prompt for the agent.
    pub prompt: String,
    /// An optional system/role prompt, when the provider supports one.
    pub system: Option<String>,
    /// The directory the agent runs in (its per-task scratch dir).
    pub working_dir: PathBuf,
    /// Tools the agent is permitted to use, when the provider supports an
    /// allow-list. Empty means "provider default".
    pub allowed_tools: Vec<String>,
    /// Skill names the agent should load (e.g. "fp-check").
    pub skills: Vec<String>,
    /// Wall-clock timeout.
    pub timeout: Duration,
    /// Max agent turns, when supported.
    pub max_turns: Option<u32>,
    /// When set, fork a prior agent session so this run inherits its
    /// conversation context. Providers without a session concept ignore it.
    pub resume: Option<ResumeSession>,
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
#[derive(Debug, Clone)]
pub struct AgentResult {
    /// Raw text the agent produced (its final message, or stdout).
    pub stdout: String,
    /// Parsed structured payload, when the provider emits JSON.
    pub structured: Option<serde_json::Value>,
    pub exit_code: i32,
    /// Reported cost in USD, when the provider exposes it.
    pub cost_usd: Option<f64>,
    /// Wall-clock time the agent took to finish, measured by the provider around
    /// the underlying process call.
    pub duration: Duration,
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
