//! The only seam between the harness and an AI CLI. Built-in adapters stream
//! their CLI's events; any other CLI is a `type = "exec"` config block.

mod claude_code;
mod error;
mod final_output;
mod generic_exec;
#[cfg(any(test, feature = "mock-runner"))]
mod mock;
mod opencode;
mod retry;
mod stream;
mod usage;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::ProviderConfig;

pub use claude_code::ClaudeCodeRunner;
pub use error::{ProviderError, is_rate_limited, is_usage_limited, timed_out_session};
pub use generic_exec::ExecRunner;
#[cfg(any(test, feature = "mock-runner"))]
pub use mock::{CannedReply, MockRunner};
pub use opencode::OpenCodeRunner;
pub use retry::RetryOnRateLimit;
pub use usage::Usage;

/// Reasoning effort for one run. Providers without an effort knob ignore it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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

/// One agent run. Adapters ignore fields their CLI has no equivalent for.
#[derive(Debug, Clone)]
pub struct AgentRequest {
    pub prompt: String,
    pub working_dir: PathBuf,
    /// Where the agent writes its answer file. Must be unique per run, or one
    /// agent could be credited with another's answer.
    pub output_dir: PathBuf,
    /// Extra directories the agent may read (e.g. the reference repo).
    pub extra_dirs: Vec<PathBuf>,
    /// Tools removed from the agent's context.
    pub disallowed_tools: Vec<String>,
    pub timeout: Duration,
    /// Fork this prior session, inheriting its context.
    pub resume: Option<ResumeSession>,
    /// 1h prompt-cache TTL instead of 5m, for a session forked after 5m.
    pub cache_1h: bool,
    pub effort: Effort,
    /// Overrides the provider's configured model.
    pub model: Option<String>,
    /// Tee the CLI's event stream here, one event per line.
    pub stream_log_path: Option<PathBuf>,
}

impl AgentRequest {
    /// A cold run in `dir` (also its output dir) with every option off.
    pub fn new(prompt: String, dir: PathBuf, timeout: Duration, effort: Effort) -> Self {
        Self {
            prompt,
            output_dir: dir.clone(),
            working_dir: dir,
            extra_dirs: Vec::new(),
            disallowed_tools: Vec::new(),
            timeout,
            resume: None,
            cache_1h: false,
            effort,
            model: None,
            stream_log_path: None,
        }
    }

    /// Where this run's own session lives, for forking it later: a fork runs
    /// in the forked session's project dir.
    pub fn session_dir(&self) -> &Path {
        self.resume
            .as_ref()
            .map_or(&self.working_dir, |r| &r.project_dir)
    }
}

/// A prior session to fork. Session lookup is scoped to `project_dir`, so a
/// forking adapter must run there.
#[derive(Debug, Clone)]
pub struct ResumeSession {
    pub session_id: String,
    pub project_dir: PathBuf,
}

/// Cost and usage live in the stream log, read back by [`Usage::from_log`].
#[derive(Debug, Clone)]
pub struct AgentResult {
    /// The agent's final answer.
    pub stdout: String,
    pub session_id: Option<String>,
}

#[async_trait]
pub trait AgentRunner: Send + Sync {
    /// Provider name, for logging.
    fn name(&self) -> &str;

    async fn run(&self, req: AgentRequest) -> Result<AgentResult>;
}

pub fn build_runner(name: &str, cfg: &ProviderConfig) -> Arc<dyn AgentRunner> {
    let name = name.to_string();
    match cfg {
        ProviderConfig::ClaudeCode(c) => Arc::new(ClaudeCodeRunner::new(name, c.clone())),
        ProviderConfig::OpenCode(c) => Arc::new(OpenCodeRunner::new(name, c.clone())),
        ProviderConfig::Exec(c) => Arc::new(ExecRunner::new(name, c.clone())),
    }
}
