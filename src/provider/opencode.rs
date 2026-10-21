//! opencode adapter: `opencode run --format json`. No tool deny-list, and its
//! effort (`--variant`) is provider-specific, so it comes from config.

use std::ops::ControlFlow;
use std::path::PathBuf;

use anyhow::{Result, bail};
use async_trait::async_trait;
use serde_json::Value;
use tokio::process::Command;

use super::error::limit_error;
use super::final_output::{clear_final_output, read_final_output, with_final_output_instruction};
use super::stream::{StreamObserver, run_streaming};
use super::usage::tokens;
use super::{AgentRequest, AgentResult, AgentRunner, Usage};
use crate::config::OpenCodeConfig;

pub struct OpenCodeRunner {
    name: String,
    cfg: OpenCodeConfig,
}

impl OpenCodeRunner {
    pub fn new(name: String, cfg: OpenCodeConfig) -> Self {
        Self { name, cfg }
    }
}

/// The `opencode` argv and the directory to run it in.
fn build_invocation(
    req: &AgentRequest,
    cfg: &OpenCodeConfig,
    model: Option<&str>,
) -> (Vec<String>, PathBuf) {
    // opencode scopes session lookup to a project directory.
    let cwd = match &req.resume {
        Some(r) => r.project_dir.clone(),
        None => req.working_dir.clone(),
    };
    let mut args = vec![
        "run".to_string(),
        "--format".to_string(),
        "json".to_string(),
        "--dir".to_string(),
        cwd.to_string_lossy().into_owned(),
        // Its error events are opaque ("Unexpected server error"); the cause is
        // in its server log, which this routes to stderr.
        "--print-logs".to_string(),
        "--log-level".to_string(),
        "ERROR".to_string(),
    ];
    if cfg.auto {
        args.push("--auto".to_string());
    }
    if let Some(r) = &req.resume {
        args.extend([
            "--session".to_string(),
            r.session_id.clone(),
            "--fork".to_string(),
        ]);
    }
    for (flag, value) in [
        ("--model", model),
        ("--agent", cfg.agent.as_deref()),
        ("--variant", cfg.variant.as_deref()),
    ] {
        if let Some(value) = value {
            args.extend([flag.to_string(), value.to_string()]);
        }
    }
    args.extend(cfg.extra_args.iter().cloned());
    // Last and behind `--`, so a prompt starting with a dash is not a flag.
    args.push("--".to_string());
    args.push(with_final_output_instruction(&req.prompt, &req.output_dir));
    (args, cwd)
}

#[derive(Debug, Default)]
struct OpenCodeStream {
    session_id: Option<String>,
    /// Assistant text, the fallback answer when no answer file is written.
    text: String,
    /// Message of the last `error` event.
    error: Option<String>,
}

impl StreamObserver for OpenCodeStream {
    /// Non-JSON lines are skipped: opencode still prints a few human notices.
    fn observe(&mut self, line: &str) -> ControlFlow<()> {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            return ControlFlow::Continue(());
        };
        if self.session_id.is_none() {
            self.session_id = event["sessionID"].as_str().map(str::to_owned);
        }
        match event["type"].as_str() {
            Some("text") => {
                if let Some(text) = event.pointer("/part/text").and_then(Value::as_str) {
                    if !self.text.is_empty() {
                        self.text.push('\n');
                    }
                    self.text.push_str(text);
                }
            }
            Some("error") => self.error = Some(error_message(&event["error"])),
            _ => {}
        }
        ControlFlow::Continue(())
    }

    fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
}

/// One model step's spend: opencode reports usage per `step_finish`, so a run
/// cut short still accounts for the steps it finished.
pub(super) fn usage(event: &Value) -> Option<Usage> {
    if event["type"] != "step_finish" {
        return None;
    }
    let part = &event["part"];
    Some(Usage {
        total_cost_usd: part["cost"].as_f64().unwrap_or(0.0),
        input_tokens: tokens(part, "/tokens/input"),
        // Billed as output.
        output_tokens: tokens(part, "/tokens/output") + tokens(part, "/tokens/reasoning"),
        cache_read_input_tokens: tokens(part, "/tokens/cache/read"),
        cache_creation_input_tokens: tokens(part, "/tokens/cache/write"),
    })
}

/// `{"name": .., "data": {"message": ..}}`, falling back to the name, then the
/// raw JSON, so an unfamiliar shape still says something.
fn error_message(error: &Value) -> String {
    if let Some(msg) = error.pointer("/data/message").and_then(Value::as_str) {
        return msg.to_string();
    }
    match error {
        Value::Null => "unknown error".to_string(),
        _ => error["name"]
            .as_str()
            .map_or_else(|| error.to_string(), str::to_owned),
    }
}

/// The tail of opencode's server log, so an opaque error comes with its cause.
fn stderr_tail(stderr: &str) -> String {
    const TAIL_LINES: usize = 20;
    let lines: Vec<&str> = stderr.trim().lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let tail = lines[lines.len().saturating_sub(TAIL_LINES)..].join("\n");
    format!("\nopencode log (last {TAIL_LINES} lines):\n{tail}")
}

#[async_trait]
impl AgentRunner for OpenCodeRunner {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(&self, req: AgentRequest) -> Result<AgentResult> {
        let model = req.model.as_deref().or(self.cfg.model.as_deref());
        let (args, cwd) = build_invocation(&req, &self.cfg, model);
        clear_final_output(&req).await?;

        let mut cmd = Command::new("opencode");
        cmd.args(&args).current_dir(&cwd);
        let mut stream = OpenCodeStream::default();
        let exit = run_streaming(cmd, &req, &mut stream).await?;

        if let Some(msg) = &stream.error {
            if let Some(limit) = limit_error(msg) {
                return Err(limit.into());
            }
            bail!(
                "opencode reported an error: {msg}{}",
                stderr_tail(&exit.stderr)
            );
        }
        if exit.code != 0 {
            bail!(
                "opencode exited with code {}: stderr=[{}]",
                exit.code,
                exit.stderr.trim()
            );
        }
        let stdout = read_final_output(&req, &stream.text).await;
        Ok(AgentResult {
            stdout,
            session_id: stream.session_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Effort, ProviderError, ResumeSession};
    use std::time::Duration;

    fn req() -> AgentRequest {
        AgentRequest::new(
            "find bugs".into(),
            PathBuf::from("/work/scratch/t1"),
            Duration::from_secs(1),
            Effort::Xhigh,
        )
    }

    fn arg_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        args.iter()
            .position(|a| a == flag)
            .map(|i| args[i + 1].as_str())
    }

    #[test]
    fn base_invocation_streams_json_in_the_working_dir() {
        let (args, cwd) = build_invocation(
            &req(),
            &OpenCodeConfig::default(),
            Some("anthropic/claude-opus-5"),
        );
        assert_eq!(args[0], "run");
        assert_eq!(arg_after(&args, "--format"), Some("json"));
        assert_eq!(arg_after(&args, "--dir"), Some("/work/scratch/t1"));
        assert_eq!(arg_after(&args, "--model"), Some("anthropic/claude-opus-5"));
        assert!(args.contains(&"--auto".to_string()));
        assert_eq!(cwd, PathBuf::from("/work/scratch/t1"));
        assert!(!args.contains(&"--session".to_string()));
        assert!(!args.contains(&"--fork".to_string()));
        assert_eq!(args[args.len() - 2], "--");
        let prompt = args.last().unwrap();
        assert!(prompt.starts_with("find bugs"));
        assert!(prompt.contains("/work/scratch/t1/agent-final-output.json"));
    }

    #[test]
    fn resume_forks_the_session_in_its_project_dir() {
        let r = AgentRequest {
            resume: Some(ResumeSession {
                session_id: "ses_abc".into(),
                project_dir: PathBuf::from("/work/target"),
            }),
            ..req()
        };
        let (args, cwd) = build_invocation(&r, &OpenCodeConfig::default(), None);
        assert_eq!(arg_after(&args, "--session"), Some("ses_abc"));
        assert!(args.contains(&"--fork".to_string()));
        assert_eq!(arg_after(&args, "--dir"), Some("/work/target"));
        assert_eq!(cwd, PathBuf::from("/work/target"));
        assert!(!args.contains(&"--model".to_string()));
    }

    #[test]
    fn optional_flags_and_extra_args_are_appended() {
        let cfg = OpenCodeConfig {
            agent: Some("build".into()),
            variant: Some("high".into()),
            auto: false,
            extra_args: vec!["--share".into()],
            ..OpenCodeConfig::default()
        };
        let (args, _) = build_invocation(&req(), &cfg, None);
        assert_eq!(arg_after(&args, "--agent"), Some("build"));
        assert_eq!(arg_after(&args, "--variant"), Some("high"));
        assert!(args.contains(&"--share".to_string()));
        assert!(!args.contains(&"--auto".to_string()));
    }

    fn stream(lines: &[&str]) -> OpenCodeStream {
        let mut s = OpenCodeStream::default();
        for line in lines {
            assert!(s.observe(line).is_continue(), "opencode never stops a run");
        }
        s
    }

    #[test]
    fn stream_yields_session_id_and_assistant_text() {
        let s = stream(&[
            r#"{"type":"step_start","sessionID":"ses_abc","part":{}}"#,
            r#"{"type":"text","sessionID":"ses_abc","part":{"text":"first"}}"#,
            "not json: opencode still prints notices in json mode",
            r#"{"type":"text","sessionID":"ses_abc","part":{"text":"second"}}"#,
        ]);
        assert_eq!(s.session_id(), Some("ses_abc"));
        assert_eq!(s.text, "first\nsecond");
        assert!(s.error.is_none());
    }

    #[test]
    fn stream_error_feeds_the_limit_classifier() {
        let s = stream(&[
            r#"{"type":"error","sessionID":"ses_abc","error":{"name":"ProviderAuthError","data":{"message":"rate limit exceeded"}}}"#,
        ]);
        assert_eq!(s.error.as_deref(), Some("rate limit exceeded"));
        assert!(matches!(
            limit_error(s.error.as_deref().unwrap()),
            Some(ProviderError::RateLimited(_))
        ));
    }

    #[test]
    fn error_message_falls_back_to_the_name() {
        assert_eq!(
            error_message(&serde_json::json!({"name": "UnknownError"})),
            "UnknownError"
        );
        assert_eq!(error_message(&Value::Null), "unknown error");
    }
}
