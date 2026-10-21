//! Claude Code adapter: `claude -p --output-format stream-json`.

use std::ops::ControlFlow;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde_json::Value;
use tokio::process::Command;

use super::error::limit_error;
use super::final_output::{clear_final_output, read_final_output, with_final_output_instruction};
use super::stream::{StreamObserver, run_streaming};
use super::usage::tokens;
use super::{AgentRequest, AgentResult, AgentRunner, ProviderError, Usage};
use crate::config::ClaudeCodeConfig;

/// Keep the cached system-prompt prefix stable across targets. A target's
/// `CLAUDE.md` is also a prompt-injection channel.
const BASE_ENV: &[(&str, &str)] = &[
    ("CLAUDE_CODE_DISABLE_CLAUDE_MDS", "1"),
    ("CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS", "1"),
    ("CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1"),
];

fn agent_env(req: &AgentRequest) -> Vec<(&'static str, &'static str)> {
    let mut env = BASE_ENV.to_vec();
    if req.cache_1h {
        env.push(("ENABLE_PROMPT_CACHING_1H", "1"));
    }
    env.push(("CLAUDE_CODE_EFFORT_LEVEL", req.effort.as_str()));
    env
}

pub struct ClaudeCodeRunner {
    name: String,
    cfg: ClaudeCodeConfig,
}

impl ClaudeCodeRunner {
    pub fn new(name: String, cfg: ClaudeCodeConfig) -> Self {
        Self { name, cfg }
    }
}

/// The `claude` argv and the directory to run it in.
fn build_invocation(
    req: &AgentRequest,
    model: Option<&str>,
    extra_args: &[String],
) -> (Vec<String>, PathBuf) {
    let mut args = vec![
        "-p".to_string(),
        with_final_output_instruction(&req.prompt, &req.output_dir),
        "--output-format".to_string(),
        "stream-json".to_string(),
        // Required for stream-json under -p.
        "--verbose".to_string(),
        "--add-dir".to_string(),
        req.working_dir.to_string_lossy().into_owned(),
        // Forks run in other dirs than recon; this lets them share its cache.
        "--exclude-dynamic-system-prompt-sections".to_string(),
    ];
    let mut add_dir = |dir: &PathBuf| {
        args.push("--add-dir".to_string());
        args.push(dir.to_string_lossy().into_owned());
    };
    if req.output_dir != req.working_dir {
        add_dir(&req.output_dir);
    }
    req.extra_dirs.iter().for_each(add_dir);

    // claude scopes `--resume` lookup to the current directory.
    let cwd = match &req.resume {
        Some(r) => {
            args.extend([
                "--resume".to_string(),
                r.session_id.clone(),
                "--fork-session".to_string(),
            ]);
            r.project_dir.clone()
        }
        None => req.working_dir.clone(),
    };
    if let Some(model) = model {
        args.extend(["--model".to_string(), model.to_string()]);
    }
    if !req.disallowed_tools.is_empty() {
        args.extend([
            "--disallowedTools".to_string(),
            req.disallowed_tools.join(","),
        ]);
    }
    args.extend(extra_args.iter().cloned());
    (args, cwd)
}

/// The account's weekly utilization (0..=1), if `event` is a
/// `rate_limit_event` carrying one. API-key auth emits none.
fn weekly_utilization(event: &Value) -> Option<f64> {
    if event["type"] != "rate_limit_event" {
        return None;
    }
    event
        .pointer("/rate_limit_info/unifiedWindows/seven_day/utilization")?
        .as_f64()
}

/// The run's totals, carried by its one `result` event.
pub(super) fn usage(event: &Value) -> Option<Usage> {
    if event["type"] != "result" {
        return None;
    }
    Some(Usage {
        total_cost_usd: event["total_cost_usd"].as_f64().unwrap_or(0.0),
        input_tokens: tokens(event, "/usage/input_tokens"),
        output_tokens: tokens(event, "/usage/output_tokens"),
        cache_read_input_tokens: tokens(event, "/usage/cache_read_input_tokens"),
        cache_creation_input_tokens: tokens(event, "/usage/cache_creation_input_tokens"),
    })
}

fn reached_cap(utilization: f64, cap_pct: u8) -> bool {
    utilization >= f64::from(cap_pct) / 100.0
}

#[derive(Default)]
struct ClaudeStream {
    /// Checked against the first weekly reading only, so an agent that crosses
    /// the cap mid-run still finishes the tokens it already spent.
    weekly_cap: Option<u8>,
    over_cap: Option<f64>,
    session_id: Option<String>,
    /// The final event: the only one with the answer text and is_error.
    result: Option<Value>,
}

impl StreamObserver for ClaudeStream {
    fn observe(&mut self, line: &str) -> ControlFlow<()> {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            return ControlFlow::Continue(());
        };
        if self.session_id.is_none() {
            self.session_id = event["session_id"].as_str().map(str::to_owned);
        }
        if event["type"] == "result" {
            self.result = Some(event);
        } else if let Some(cap) = self.weekly_cap
            && let Some(used) = weekly_utilization(&event)
        {
            self.weekly_cap = None;
            if reached_cap(used, cap) {
                self.over_cap = Some(used);
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }

    fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
}

#[async_trait]
impl AgentRunner for ClaudeCodeRunner {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(&self, req: AgentRequest) -> Result<AgentResult> {
        let model = req.model.as_deref().or(self.cfg.model.as_deref());
        let (args, cwd) = build_invocation(&req, model, &self.cfg.extra_args);
        clear_final_output(&req).await?;

        let mut cmd = Command::new("claude");
        cmd.args(&args).envs(agent_env(&req)).current_dir(&cwd);
        let mut stream = ClaudeStream {
            weekly_cap: self.cfg.max_weekly_usage_pct,
            ..ClaudeStream::default()
        };
        let exit = run_streaming(cmd, &req, &mut stream).await?;

        if let Some(used) = stream.over_cap {
            return Err(ProviderError::UsageLimited(format!(
                "weekly usage at {:.0}%, max_weekly_usage_pct is {}%",
                used * 100.0,
                self.cfg.max_weekly_usage_pct.unwrap_or_default()
            ))
            .into());
        }
        // Limits arrive as an is_error result event, whatever the exit code.
        if let Some(event) = &stream.result
            && event["is_error"] == true
        {
            let msg = event["result"].as_str().unwrap_or_default();
            if let Some(limit) = limit_error(msg) {
                return Err(limit.into());
            }
            bail!("claude reported an error: {msg}");
        }
        if exit.code != 0 {
            if let Some(limit) = limit_error(&exit.stderr) {
                return Err(limit.into());
            }
            bail!(
                "claude exited with code {}: stderr=[{}]",
                exit.code,
                exit.stderr.trim()
            );
        }

        let result = stream
            .result
            .with_context(|| format!("claude stream for '{}' had no result event", self.name))?;
        let stdout = read_final_output(&req, result["result"].as_str().unwrap_or_default()).await;
        let session_id = result["session_id"]
            .as_str()
            .map(str::to_owned)
            .or(stream.session_id);
        Ok(AgentResult { stdout, session_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Effort, ResumeSession};
    use std::collections::HashMap;
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

    fn add_dirs(args: &[String]) -> Vec<&str> {
        args.windows(2)
            .filter(|w| w[0] == "--add-dir")
            .map(|w| w[1].as_str())
            .collect()
    }

    #[test]
    fn every_invocation_stabilizes_the_cache_prefix() {
        let (args, cwd) = build_invocation(&req(), Some("claude-opus-5"), &[]);
        assert!(args.contains(&"--exclude-dynamic-system-prompt-sections".to_string()));
        let prompt = arg_after(&args, "-p").unwrap();
        assert!(prompt.starts_with("find bugs"));
        assert!(prompt.contains("/work/scratch/t1/agent-final-output.json"));
        assert_eq!(arg_after(&args, "--output-format"), Some("stream-json"));
        assert!(args.contains(&"--verbose".to_string()));
        assert_eq!(add_dirs(&args), ["/work/scratch/t1"]);
        assert_eq!(arg_after(&args, "--model"), Some("claude-opus-5"));
        assert_eq!(cwd, PathBuf::from("/work/scratch/t1"));
        assert!(!args.contains(&"--resume".to_string()));
        assert!(!args.contains(&"--disallowedTools".to_string()));
    }

    #[test]
    fn output_and_extra_dirs_each_get_an_add_dir() {
        let r = AgentRequest {
            working_dir: PathBuf::from("/work/target"),
            extra_dirs: vec![PathBuf::from("/work/reference")],
            ..req()
        };
        let (args, _) = build_invocation(&r, None, &[]);
        assert_eq!(
            add_dirs(&args),
            ["/work/target", "/work/scratch/t1", "/work/reference"]
        );
        // The answer goes to the output dir, not the (possibly read-only) target.
        let prompt = arg_after(&args, "-p").unwrap();
        assert!(prompt.contains("/work/scratch/t1/agent-final-output.json"));
    }

    #[test]
    fn resume_forks_the_session_in_its_project_dir() {
        let r = AgentRequest {
            resume: Some(ResumeSession {
                session_id: "sess-123".into(),
                project_dir: PathBuf::from("/work/target"),
            }),
            ..req()
        };
        let (args, cwd) = build_invocation(&r, None, &[]);
        assert_eq!(arg_after(&args, "--resume"), Some("sess-123"));
        assert!(args.contains(&"--fork-session".to_string()));
        assert_eq!(cwd, PathBuf::from("/work/target"));
        // The working dir stays writable for PoCs.
        assert_eq!(add_dirs(&args), ["/work/scratch/t1"]);
        assert!(!args.contains(&"--model".to_string()));
    }

    #[test]
    fn tool_deny_list_and_extra_args_are_appended() {
        let r = AgentRequest {
            disallowed_tools: vec!["Task".into(), "WebFetch".into()],
            ..req()
        };
        let extra = vec!["--dangerously-skip-permissions".to_string()];
        let (args, _) = build_invocation(&r, None, &extra);
        assert_eq!(arg_after(&args, "--disallowedTools"), Some("Task,WebFetch"));
        assert_eq!(args.last().unwrap(), "--dangerously-skip-permissions");
    }

    #[test]
    fn env_gates_cache_and_effort_per_request() {
        let low = AgentRequest {
            effort: Effort::Low,
            ..req()
        };
        let env: HashMap<_, _> = agent_env(&low).into_iter().collect();
        for (var, value) in BASE_ENV {
            assert_eq!(env.get(var), Some(value));
        }
        assert_eq!(env.get("CLAUDE_CODE_EFFORT_LEVEL"), Some(&"low"));
        assert_eq!(env.get("ENABLE_PROMPT_CACHING_1H"), None);

        let recon = AgentRequest {
            cache_1h: true,
            ..req()
        };
        let env: HashMap<_, _> = agent_env(&recon).into_iter().collect();
        assert_eq!(env.get("ENABLE_PROMPT_CACHING_1H"), Some(&"1"));
        assert_eq!(env.get("CLAUDE_CODE_EFFORT_LEVEL"), Some(&"xhigh"));
    }

    #[test]
    fn weekly_utilization_is_read_from_rate_limit_events_only() {
        let event: Value = serde_json::from_str(
            r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","resetsAt":1789880400,"rateLimitType":"five_hour","unifiedWindows":{"five_hour":{"utilization":0.01,"resetsAt":1789880400},"seven_day":{"utilization":0.13,"resetsAt":1790028000}}}}"#,
        )
        .unwrap();
        assert_eq!(weekly_utilization(&event), Some(0.13));
        let no_week =
            serde_json::json!({"type":"rate_limit_event","rate_limit_info":{"status":"allowed"}});
        assert_eq!(weekly_utilization(&no_week), None);
        let other = serde_json::json!({"type":"result","rate_limit_info":{"unifiedWindows":{"seven_day":{"utilization":0.9}}}});
        assert_eq!(weekly_utilization(&other), None);
    }

    #[test]
    fn cap_trips_at_the_threshold_not_below() {
        assert!(!reached_cap(0.79, 80));
        assert!(reached_cap(0.8, 80));
        assert!(reached_cap(1.0, 100));
    }

    #[test]
    fn stream_stops_at_the_first_reading_over_the_cap_only() {
        let reading = |pct: f64| {
            format!(
                r#"{{"type":"rate_limit_event","session_id":"s","rate_limit_info":{{"unifiedWindows":{{"seven_day":{{"utilization":{pct}}}}}}}}}"#
            )
        };
        let mut under = ClaudeStream {
            weekly_cap: Some(80),
            ..ClaudeStream::default()
        };
        assert!(under.observe(&reading(0.5)).is_continue());
        // Later readings no longer gate a run that started under the cap.
        assert!(under.observe(&reading(0.95)).is_continue());
        assert_eq!(under.session_id(), Some("s"));

        let mut over = ClaudeStream {
            weekly_cap: Some(80),
            ..ClaudeStream::default()
        };
        assert!(over.observe(&reading(0.85)).is_break());
        assert_eq!(over.over_cap, Some(0.85));
    }
}
