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
mod opencode;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::fs;
use tracing::warn;

use crate::config::ProviderConfig;

/// A provider failure the orchestrator reacts to differently than a generic
/// error.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The backend rejected the request because an account usage / session /
    /// rate limit was reached, or the operator's own usage cap was. Retrying
    /// immediately just bounces off the same limit, so a stage that sees this
    /// should stop spawning new agents rather than burn the rest of its queue
    /// on certain failures.
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

/// Append the "write your final answer to a file" instruction to the user
/// prompt. Shared by every streaming adapter, since the file is the contract
/// the harness reads results back through (see [`FINAL_OUTPUT_FILE`]).
///
/// It goes in the per-agent user prompt — never a shared system prefix — on
/// purpose: the path is per-agent (the working dir), so injecting it into the
/// cached system prompt would bust the cross-fork cache the whole design relies
/// on. A new user turn is uncached regardless, so this costs nothing extra.
pub(crate) fn with_final_output_instruction(prompt: &str, working_dir: &Path) -> String {
    let path = final_output_path(working_dir);
    format!(
        "{prompt}\n\n---\nWhen you are finished, use the Write tool to save your \
         COMPLETE final answer — the exact content you would otherwise print, \
         verbatim and in full — to this file:\n  {}\nThat file, not your chat \
         output, is what gets consumed downstream, so it must stand on its own.",
        path.display()
    )
}

/// Read back the answer the agent was told to write to [`FINAL_OUTPUT_FILE`],
/// and mirror it beside its transcript in the out dir so it is visible there
/// without reaching into the agent's scratch dir.
///
/// `fallback` is the provider's own notion of the agent's last message, used
/// when the agent forgot to write the file (or lacked a write tool), so a stray
/// run still makes progress. Mirroring is best-effort: it must never fail a run.
pub(crate) async fn read_final_output(req: &AgentRequest, fallback: &str) -> String {
    let final_path = final_output_path(&req.working_dir);
    let output = match fs::read_to_string(&final_path).await {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            warn!(
                path = %final_path.display(),
                "agent did not write its final-output file; using the provider's last message"
            );
            fallback.to_string()
        }
    };

    if let Some(log_path) = &req.stream_log_path {
        let sidecar = output_sidecar(log_path);
        if let Err(e) = fs::write(&sidecar, &output).await {
            warn!(error = %e, path = %sidecar.display(), "failed to persist agent final output");
        }
    }
    output
}

/// Path of the final-answer sidecar that sits beside a stream log: the
/// transcript `<base>.jsonl` is paired with the consumed answer
/// `<base>.output.json` in the same dir.
fn output_sidecar(stream_log_path: &Path) -> PathBuf {
    stream_log_path.with_extension("output.json")
}

/// Create (truncating) an agent's stream-log file, making parent dirs as needed.
pub(crate) async fn open_log(path: &Path) -> Result<fs::File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating log dir {}", parent.display()))?;
    }
    fs::File::create(path)
        .await
        .with_context(|| format!("creating stream log {}", path.display()))
}

/// Heuristic: does an error message describe a usage/session/rate limit?
///
/// Matched against the human strings the CLIs surface, e.g. claude's "You've hit
/// your session limit · resets 2:50am" or an upstream provider's "rate limit
/// exceeded". Kept deliberately broad-but-anchored on the word "limit" so a new
/// phrasing still trips it without matching unrelated errors.
pub(crate) fn is_usage_limit_message(msg: &str) -> bool {
    let m = msg.to_lowercase();
    m.contains("limit")
        && (m.contains("session")
            || m.contains("usage")
            || m.contains("rate")
            || m.contains("hit your")
            || m.contains("resets"))
}

pub use claude_code::ClaudeCodeRunner;
pub use generic_exec::ExecRunner;
#[cfg(any(test, feature = "mock-runner"))]
pub use mock::{CannedReply, MockRunner};
pub use opencode::OpenCodeRunner;

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
    /// Override the provider's configured model for this one run. Lets a stage
    /// pick a cheaper model for a cheap sub-task (e.g. a lightweight dedup judge)
    /// without a second provider. `None` uses the provider default. Providers
    /// without a model knob ignore it.
    pub model: Option<String>,
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
        ProviderConfig::ClaudeCode {
            model,
            extra_args,
            max_weekly_usage_pct,
        } => Box::new(ClaudeCodeRunner::new(
            name.to_string(),
            model.clone(),
            extra_args.clone(),
            *max_weekly_usage_pct,
        )),
        ProviderConfig::OpenCode {
            model,
            agent,
            variant,
            auto,
            extra_args,
        } => Box::new(OpenCodeRunner::new(
            name.to_string(),
            model.clone(),
            agent.clone(),
            variant.clone(),
            *auto,
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn final_output_instruction_keeps_prompt_and_points_at_working_dir() {
        let out = with_final_output_instruction("do the thing", Path::new("/work/scratch/t1"));
        // Original prompt is preserved verbatim at the front.
        assert!(out.starts_with("do the thing"));
        // And the agent is pointed at the file the harness will read back.
        assert!(out.contains("/work/scratch/t1/agent-final-output.json"));
        assert!(out.contains("Write tool"));
    }

    #[test]
    fn output_sidecar_sits_beside_the_transcript() {
        let log = Path::new("/work/out/logs/hunt-G-0093.jsonl");
        assert_eq!(
            output_sidecar(log),
            Path::new("/work/out/logs/hunt-G-0093.output.json")
        );
    }

    #[test]
    fn detects_usage_limit_messages_only() {
        // The real strings the CLIs emit for a depleted account.
        assert!(is_usage_limit_message(
            "You've hit your session limit · resets 2:50am (UTC)"
        ));
        assert!(is_usage_limit_message("Usage limit reached"));
        assert!(is_usage_limit_message("rate limit exceeded, please retry"));
        // Ordinary failures must NOT be classified as a usage limit, or the
        // stage would abort on a one-off error.
        assert!(!is_usage_limit_message("hunter output was not valid json"));
        assert!(!is_usage_limit_message("file not found"));
        assert!(!is_usage_limit_message(""));
    }

    #[test]
    fn usage_limit_error_is_recognized_through_anyhow() {
        let err: anyhow::Error =
            ProviderError::UsageLimited("hit your session limit".into()).into();
        assert!(is_usage_limited(&err));
        // A plain error is not a usage limit.
        assert!(!is_usage_limited(&anyhow::anyhow!("boom")));
    }

    #[tokio::test]
    async fn open_log_creates_missing_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs").join("hunt-T-0001.jsonl");
        let mut f = open_log(&path).await.unwrap();
        f.write_all(b"{}\n").await.unwrap();
        f.flush().await.unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}\n");
    }

    #[tokio::test]
    async fn final_output_file_wins_over_the_fallback_and_is_mirrored() {
        let dir = tempfile::tempdir().unwrap();
        let working_dir = dir.path().join("scratch");
        std::fs::create_dir_all(&working_dir).unwrap();
        std::fs::write(final_output_path(&working_dir), "{\"findings\":[]}").unwrap();
        let log = dir.path().join("logs").join("hunt-T-0001.jsonl");
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();

        let req = AgentRequest {
            prompt: "find bugs".into(),
            system: None,
            working_dir,
            extra_dirs: Vec::new(),
            allowed_tools: Vec::new(),
            disallowed_tools: Vec::new(),
            timeout: Duration::from_secs(1),
            resume: None,
            cache_1h: false,
            effort: Effort::Low,
            model: None,
            stream_log_path: Some(log.clone()),
        };
        let out = read_final_output(&req, "chat text").await;
        assert_eq!(out, "{\"findings\":[]}");
        // Mirrored beside the transcript so the answer is visible in the out dir.
        assert_eq!(
            std::fs::read_to_string(output_sidecar(&log)).unwrap(),
            "{\"findings\":[]}"
        );
    }

    #[tokio::test]
    async fn missing_final_output_falls_back_to_the_provider_message() {
        let dir = tempfile::tempdir().unwrap();
        let req = AgentRequest {
            prompt: "find bugs".into(),
            system: None,
            working_dir: dir.path().to_path_buf(),
            extra_dirs: Vec::new(),
            allowed_tools: Vec::new(),
            disallowed_tools: Vec::new(),
            timeout: Duration::from_secs(1),
            resume: None,
            cache_1h: false,
            effort: Effort::Low,
            model: None,
            stream_log_path: None,
        };
        assert_eq!(read_final_output(&req, "chat text").await, "chat text");
    }
}
