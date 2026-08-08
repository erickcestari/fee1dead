//! opencode CLI adapter (`type = "opencode"`).
//!
//! Invokes `opencode run --format json ...` and consumes its raw event stream
//! line by line, teeing it to a per-agent log file as it runs (so a timed-out
//! agent still leaves a transcript). As with the claude-code adapter, the agent
//! is told to write its complete final answer to a file (see
//! [`super::FINAL_OUTPUT_FILE`]) and the harness reads that back as the result,
//! decoupling the consumed output from the noisy stream.
//!
//! Every JSON event opencode emits carries the `sessionID`, so this adapter
//! supports session forking (`run.fork_hunters`): a resumed request runs
//! `--session <id> --fork` in the session's project dir.
//!
//! Knobs opencode does not expose are ignored, not emulated: there is no
//! per-tool allow/deny list and no system-prompt flag (a
//! request's `system` prompt is prepended to the user prompt instead). Reasoning
//! effort maps to `--variant`, which is provider-specific, so it is opt-in via
//! the `variant` config field rather than derived from [`super::Effort`].

use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tracing::warn;

use super::{
    AgentRequest, AgentResult, AgentRunner, ProviderError, is_usage_limit_message, open_log,
    read_final_output, with_final_output_instruction,
};

pub struct OpenCodeRunner {
    name: String,
    model: Option<String>,
    agent: Option<String>,
    variant: Option<String>,
    auto: bool,
    extra_args: Vec<String>,
}

impl OpenCodeRunner {
    pub fn new(
        name: String,
        model: Option<String>,
        agent: Option<String>,
        variant: Option<String>,
        auto: bool,
        extra_args: Vec<String>,
    ) -> Self {
        Self {
            name,
            model,
            agent,
            variant,
            auto,
            extra_args,
        }
    }
}

/// One request's full prompt: the optional system prompt, then the task, then
/// the final-output instruction. opencode has no `--append-system-prompt`
/// equivalent for `run`, so the role framing rides in the user turn.
fn full_prompt(req: &AgentRequest) -> String {
    let body = match &req.system {
        Some(system) => format!("{system}\n\n---\n\n{}", req.prompt),
        None => req.prompt.clone(),
    };
    with_final_output_instruction(&body, &req.working_dir)
}

/// Build the `opencode` argv (after the program name) and the directory to run
/// in for one request.
///
/// Factored out of [`OpenCodeRunner::run`] so the flag wiring is unit-testable
/// without spawning a process.
fn build_invocation(
    req: &AgentRequest,
    model: Option<&str>,
    agent: Option<&str>,
    variant: Option<&str>,
    auto: bool,
    extra_args: &[String],
) -> (Vec<String>, PathBuf) {
    // opencode scopes session lookup to a project directory, so forking a prior
    // session must run in that session's dir rather than the agent's scratch
    // dir. Absent a resume we simply run in the working dir.
    let cwd = match &req.resume {
        Some(r) => r.project_dir.clone(),
        None => req.working_dir.clone(),
    };

    let mut args = vec![
        "run".to_string(),
        // Raw JSON events, one per line: teeable live, and every event carries
        // the session id we need for later forks.
        "--format".to_string(),
        "json".to_string(),
        "--dir".to_string(),
        cwd.to_string_lossy().into_owned(),
        // opencode's own error events are opaque ("Unexpected server error");
        // the actionable cause is in its server log. Route that log's errors to
        // stderr so a failed run reports why, not just that.
        "--print-logs".to_string(),
        "--log-level".to_string(),
        "ERROR".to_string(),
    ];

    // The container is the security boundary, not a permission prompt; without
    // this the agent's writes (including its final-output file) are rejected.
    if auto {
        args.push("--auto".to_string());
    }
    if let Some(r) = &req.resume {
        args.push("--session".to_string());
        args.push(r.session_id.clone());
        args.push("--fork".to_string());
    }
    if let Some(model) = model {
        args.push("--model".to_string());
        args.push(model.to_string());
    }
    if let Some(agent) = agent {
        args.push("--agent".to_string());
        args.push(agent.to_string());
    }
    if let Some(variant) = variant {
        args.push("--variant".to_string());
        args.push(variant.to_string());
    }
    args.extend(extra_args.iter().cloned());

    // The prompt goes last, behind `--`, so a prompt starting with a dash is
    // never parsed as a flag.
    args.push("--".to_string());
    args.push(full_prompt(req));

    (args, cwd)
}

/// What the event stream told us about a run.
#[derive(Debug, Default)]
struct StreamOutcome {
    /// Session id, taken off any event (all of them carry it). Lets a later
    /// stage fork this conversation.
    session_id: Option<String>,
    /// Concatenated assistant text, used only as a fallback when the agent
    /// didn't write its final-output file.
    text: String,
    /// Message of the last `error` event, if any.
    error: Option<String>,
}

impl StreamOutcome {
    /// Fold one stream line into the outcome. Non-JSON lines are ignored:
    /// opencode still prints a few human notices (share URL, agent fallback
    /// warnings) to stdout in JSON mode.
    fn absorb(&mut self, line: &str) {
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
            return;
        };
        if self.session_id.is_none()
            && let Some(id) = event.get("sessionID").and_then(|v| v.as_str())
        {
            self.session_id = Some(id.to_string());
        }
        match event.get("type").and_then(|t| t.as_str()) {
            Some("text") => {
                if let Some(text) = event.pointer("/part/text").and_then(|v| v.as_str()) {
                    if !self.text.is_empty() {
                        self.text.push('\n');
                    }
                    self.text.push_str(text);
                }
            }
            Some("error") => self.error = Some(error_message(event.get("error"))),
            _ => {}
        }
    }
}

/// The tail of opencode's stderr (its server log, thanks to `--print-logs`),
/// appended to an error so the opaque event message comes with its cause.
/// Bounded, since a long run's log can be large and only the end is relevant.
fn stderr_context(stderr: &str) -> String {
    const TAIL_LINES: usize = 20;
    let stderr = stderr.trim();
    if stderr.is_empty() {
        return String::new();
    }
    let lines: Vec<&str> = stderr.lines().collect();
    let tail = lines[lines.len().saturating_sub(TAIL_LINES)..].join("\n");
    format!("\nopencode log (last {TAIL_LINES} lines):\n{tail}")
}

/// Human message for an opencode error event. The shape is
/// `{"name": "...", "data": {"message": "..."}}`; fall back to the name, then to
/// the raw JSON, so an unfamiliar shape still surfaces something actionable.
fn error_message(error: Option<&serde_json::Value>) -> String {
    let Some(error) = error else {
        return "unknown error".to_string();
    };
    if let Some(msg) = error.pointer("/data/message").and_then(|v| v.as_str()) {
        return msg.to_string();
    }
    if let Some(name) = error.get("name").and_then(|v| v.as_str()) {
        return name.to_string();
    }
    error.to_string()
}

#[async_trait]
impl AgentRunner for OpenCodeRunner {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(&self, req: AgentRequest) -> Result<AgentResult> {
        // A per-request override (e.g. a cheap dedup judge) wins over the
        // provider's configured model; otherwise fall back to the configured one.
        let model = req.model.as_deref().or(self.model.as_deref());
        let (args, cwd) = build_invocation(
            &req,
            model,
            self.agent.as_deref(),
            self.variant.as_deref(),
            self.auto,
            &self.extra_args,
        );

        let mut cmd = Command::new("opencode");
        cmd.args(&args)
            .current_dir(&cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // If we abandon the child on timeout, don't leak the process.
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawning opencode for provider '{}'", self.name))?;
        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");

        // Drain stderr concurrently: a full stderr pipe would otherwise deadlock
        // the child while we read stdout.
        let stderr_task = tokio::spawn(async move {
            let mut buf = String::new();
            let _ = BufReader::new(stderr).read_to_string(&mut buf).await;
            buf
        });

        // Open the live event-stream tee, if requested. A logging failure must
        // not abort the run, so it degrades to "no tee" with a warning.
        let mut log = match &req.stream_log_path {
            Some(p) => match open_log(p).await {
                Ok(f) => Some(f),
                Err(e) => {
                    warn!(error = %e, path = %p.display(), "failed to open agent stream log");
                    None
                }
            },
            None => None,
        };

        let mut lines = BufReader::new(stdout).lines();
        let mut outcome = StreamOutcome::default();
        let pump = async {
            while let Some(line) = lines.next_line().await? {
                if let Some(f) = log.as_mut() {
                    // Flush per line so a kill-on-timeout still leaves a usable
                    // partial transcript.
                    f.write_all(line.as_bytes()).await?;
                    f.write_all(b"\n").await?;
                    f.flush().await?;
                }
                outcome.absorb(&line);
            }
            anyhow::Ok(())
        };

        match tokio::time::timeout(req.timeout, pump).await {
            Err(_) => {
                let _ = child.start_kill();
                bail!(
                    "provider '{}' timed out (partial stream log kept)",
                    self.name
                );
            }
            Ok(Err(e)) => {
                return Err(e)
                    .with_context(|| format!("reading opencode stream for '{}'", self.name));
            }
            Ok(Ok(())) => {}
        }

        let status = child
            .wait()
            .await
            .with_context(|| format!("waiting on opencode for '{}'", self.name))?;
        let exit_code = status.code().unwrap_or(-1);
        let stderr_out = stderr_task.await.unwrap_or_default();

        // opencode reports model/provider failures as an `error` event and exits
        // non-zero. Tag the account-limit ones so the orchestrator can stop
        // spawning agents instead of burning the queue on certain failures.
        if let Some(msg) = &outcome.error {
            if is_usage_limit_message(msg) {
                return Err(ProviderError::UsageLimited(msg.clone()).into());
            }
            bail!(
                "opencode reported an error: {msg}{}",
                stderr_context(&stderr_out)
            );
        }
        if exit_code != 0 {
            bail!(
                "opencode exited with code {exit_code}: stderr=[{}]",
                stderr_out.trim()
            );
        }

        let stdout = read_final_output(&req, &outcome.text).await;

        Ok(AgentResult {
            stdout,
            exit_code,
            session_id: outcome.session_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Effort, ResumeSession};
    use std::time::Duration;

    fn req() -> AgentRequest {
        AgentRequest {
            prompt: "find bugs".into(),
            system: None,
            working_dir: PathBuf::from("/work/scratch/t1"),
            extra_dirs: Vec::new(),
            allowed_tools: Vec::new(),
            disallowed_tools: Vec::new(),
            timeout: Duration::from_secs(1),
            resume: None,
            cache_1h: false,
            effort: Effort::Xhigh,
            model: None,
            stream_log_path: None,
        }
    }

    /// Find the value following `flag` in an argv, if present.
    fn arg_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        args.iter()
            .position(|a| a == flag)
            .map(|i| args[i + 1].as_str())
    }

    #[test]
    fn base_invocation_streams_json_and_runs_in_the_working_dir() {
        let (args, cwd) = build_invocation(
            &req(),
            Some("anthropic/claude-opus-4-5"),
            None,
            None,
            true,
            &[],
        );
        assert_eq!(args[0], "run");
        assert_eq!(arg_after(&args, "--format"), Some("json"));
        assert_eq!(arg_after(&args, "--dir"), Some("/work/scratch/t1"));
        assert_eq!(
            arg_after(&args, "--model"),
            Some("anthropic/claude-opus-4-5")
        );
        assert!(args.contains(&"--auto".to_string()));
        assert_eq!(cwd, PathBuf::from("/work/scratch/t1"));
        // No resume: nothing to fork.
        assert!(!args.contains(&"--session".to_string()));
        assert!(!args.contains(&"--fork".to_string()));
        // The prompt is the last arg, guarded by `--`, and carries the
        // final-output instruction.
        assert_eq!(args[args.len() - 2], "--");
        let prompt = args.last().unwrap();
        assert!(prompt.starts_with("find bugs"));
        assert!(prompt.contains("/work/scratch/t1/agent-final-output.json"));
    }

    #[test]
    fn resume_forks_the_session_in_its_project_dir() {
        let mut r = req();
        r.resume = Some(ResumeSession {
            session_id: "ses_abc".into(),
            project_dir: PathBuf::from("/work/target"),
        });
        let (args, cwd) = build_invocation(&r, None, None, None, true, &[]);
        assert_eq!(arg_after(&args, "--session"), Some("ses_abc"));
        assert!(args.contains(&"--fork".to_string()));
        // Session lookup is directory-scoped, so both --dir and the cwd are the
        // session's project dir, not the agent's scratch dir.
        assert_eq!(arg_after(&args, "--dir"), Some("/work/target"));
        assert_eq!(cwd, PathBuf::from("/work/target"));
        // No model configured -> no --model flag.
        assert!(!args.contains(&"--model".to_string()));
    }

    #[test]
    fn optional_flags_and_extra_args_are_appended() {
        let (args, _) = build_invocation(
            &req(),
            None,
            Some("build"),
            Some("high"),
            false,
            &["--share".to_string()],
        );
        assert_eq!(arg_after(&args, "--agent"), Some("build"));
        assert_eq!(arg_after(&args, "--variant"), Some("high"));
        assert!(args.contains(&"--share".to_string()));
        // auto = false means no --auto flag.
        assert!(!args.contains(&"--auto".to_string()));
    }

    #[test]
    fn system_prompt_rides_in_the_user_turn() {
        let mut r = req();
        r.system = Some("be terse".into());
        let prompt = full_prompt(&r);
        assert!(prompt.starts_with("be terse"));
        assert!(prompt.contains("find bugs"));
    }

    #[test]
    fn stream_yields_session_id_and_assistant_text() {
        let mut outcome = StreamOutcome::default();
        outcome.absorb(r#"{"type":"step_start","sessionID":"ses_abc","part":{}}"#);
        outcome.absorb(r#"{"type":"text","sessionID":"ses_abc","part":{"text":"first"}}"#);
        outcome.absorb("not json — opencode still prints notices in json mode");
        outcome.absorb(r#"{"type":"text","sessionID":"ses_abc","part":{"text":"second"}}"#);
        assert_eq!(outcome.session_id.as_deref(), Some("ses_abc"));
        assert_eq!(outcome.text, "first\nsecond");
        assert!(outcome.error.is_none());
    }

    #[test]
    fn stream_surfaces_the_error_message() {
        let mut outcome = StreamOutcome::default();
        outcome.absorb(
            r#"{"type":"error","sessionID":"ses_abc","error":{"name":"ProviderAuthError","data":{"message":"rate limit exceeded"}}}"#,
        );
        assert_eq!(outcome.error.as_deref(), Some("rate limit exceeded"));
        // ...and that message is what the usage-limit classifier sees.
        assert!(is_usage_limit_message(outcome.error.as_deref().unwrap()));
    }

    #[test]
    fn error_message_falls_back_to_the_error_name() {
        let error = serde_json::json!({"name": "UnknownError"});
        assert_eq!(error_message(Some(&error)), "UnknownError");
        assert_eq!(error_message(None), "unknown error");
    }
}
