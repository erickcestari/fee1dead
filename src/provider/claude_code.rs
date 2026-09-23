//! Claude Code CLI adapter.
//!
//! Invokes `claude -p <prompt> --output-format stream-json --verbose ...` and
//! consumes the event stream line by line, teeing it to a per-agent log file as
//! it runs (so a timed-out agent still leaves a transcript, and cost/usage stay
//! in that log's final `result` event). The agent is told to write its complete
//! final answer to a file (see [`super::FINAL_OUTPUT_FILE`]); the harness reads
//! that back as the result, decoupling the consumed output from the noisy
//! stream. The agent runs with whatever extra args the config supplies
//! (typically `--dangerously-skip-permissions`, since the container is the
//! security boundary, not the tool allow-list — which also lets it `Write`).

use std::process::Stdio;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tracing::warn;

use super::{
    AgentRequest, AgentResult, AgentRunner, clear_final_output, limit_error, open_log,
    read_final_output, with_final_output_instruction,
};

/// Environment applied to every `claude` invocation, regardless of stage. These
/// stabilize the cacheable system-prompt prefix and keep runs reproducible:
///
/// - `CLAUDE_CODE_DISABLE_CLAUDE_MDS`: target repos are untrusted clones; a
///   `CLAUDE.md` in the clone would otherwise be auto-loaded into the agent's
///   context (a prompt-injection channel) and would also vary the prefix per
///   target, defeating the cache.
/// - `CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS`: the agents never commit or open
///   PRs against the target, so dropping the git instruction block shortens
///   and stabilizes the system-prompt prefix kept in the shared cache.
/// - `CLAUDE_CODE_DISABLE_AUTO_MEMORY`: keep each run reproducible and
///   uncontaminated by prior scans of other targets (the harness has its own
///   cross-run memory in `feedback-seeds.jsonl`).
///
/// Reasoning effort (`CLAUDE_CODE_EFFORT_LEVEL`) is *not* here: it is set per
/// stage via [`AgentRequest::effort`], since the stages' needs differ (deep
/// multi-hop tracing in hunt vs. a mechanical schema transform in report).
const BASE_ENV: &[(&str, &str)] = &[
    ("CLAUDE_CODE_DISABLE_CLAUDE_MDS", "1"),
    ("CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS", "1"),
    ("CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1"),
];

/// Extend the prompt-cache TTL from 5m to 1h. Set only for a session that is
/// *forked from* and whose prefix must outlive the 5m window — i.e. recon, which
/// every hunter forks. Hunters run at
/// `concurrency` 10+ with per-agent timeouts of 30–40 minutes, so under the
/// default 5m TTL its prefix expires before most forked agents start, re-billing
/// recon's whole context at full input rates instead of cache-read rates.
///
/// Not worth it for a leaf agent (hunt/validate/report): nothing forks from it,
/// and its own context is re-read only by its own sub-5m-apart turns, so 1h just
/// pays the higher cache-write premium (2x vs 1.25x base input) for no reuse.
/// Gated per request via [`AgentRequest::cache_1h`].
const CACHE_1H_ENV: (&str, &str) = ("ENABLE_PROMPT_CACHING_1H", "1");

/// Environment for one invocation: the always-on base, the per-stage reasoning
/// effort, plus 1h caching when the request opts in.
fn agent_env(req: &AgentRequest) -> Vec<(&'static str, &'static str)> {
    let mut env = BASE_ENV.to_vec();
    if req.cache_1h {
        env.push(CACHE_1H_ENV);
    }
    env.push(("CLAUDE_CODE_EFFORT_LEVEL", req.effort.as_str()));
    env
}

pub struct ClaudeCodeRunner {
    name: String,
    model: Option<String>,
    extra_args: Vec<String>,
    max_weekly_usage_pct: Option<u8>,
}

impl ClaudeCodeRunner {
    pub fn new(
        name: String,
        model: Option<String>,
        extra_args: Vec<String>,
        max_weekly_usage_pct: Option<u8>,
    ) -> Self {
        Self {
            name,
            model,
            extra_args,
            max_weekly_usage_pct,
        }
    }
}

/// The account's weekly (seven-day) utilization as a 0..=1 fraction, if `event`
/// is a `rate_limit_event` carrying one. API-key auth emits no such event.
fn weekly_utilization(event: &serde_json::Value) -> Option<f64> {
    if event.get("type")?.as_str()? != "rate_limit_event" {
        return None;
    }
    event
        .pointer("/rate_limit_info/unifiedWindows/seven_day/utilization")?
        .as_f64()
}

/// Whether a weekly utilization fraction has reached the configured cap.
fn reached_cap(utilization: f64, cap_pct: u8) -> bool {
    utilization >= f64::from(cap_pct) / 100.0
}

/// Build the `claude` argv (after the program name) and the directory to run
/// in for one request.
///
/// Factored out of [`ClaudeCodeRunner::run`] so the flag wiring — in particular
/// the cache-stabilization flag every forked stage depends on — is unit-testable
/// without spawning a process. The env ([`agent_env`]) is applied separately
/// at spawn time; it is not part of the argv.
fn build_invocation(
    req: &AgentRequest,
    model: Option<&str>,
    extra_args: &[String],
) -> (Vec<String>, std::path::PathBuf) {
    let mut args = vec![
        "-p".to_string(),
        with_final_output_instruction(&req.prompt, &req.output_dir),
        // Stream the event log so a long-running (or timed-out) agent can be
        // teed to disk live; `--verbose` is required for stream-json under -p.
        "--output-format".to_string(),
        "stream-json".to_string(),
        "--verbose".to_string(),
        "--add-dir".to_string(),
        req.working_dir.to_string_lossy().into_owned(),
        // Stabilize the cacheable system-prompt prefix. Forks run in different
        // working dirs from recon (each scratch dir, or recon's own project dir
        // on resume), so the default system prompt's per-machine sections (cwd,
        // env, git status) would differ per process and the forked prefix would
        // never match recon's cache entry. Moving those sections into the first
        // user message lets every fork hit the shared cache. Applies only with
        // the default system prompt, which we keep (we only *append* to it via
        // --append-system-prompt below).
        "--exclude-dynamic-system-prompt-sections".to_string(),
    ];

    // The answer file's dir must be writable, and extra readable dirs (e.g. the
    // cloned reference repo) readable, without a permission prompt.
    if req.output_dir != req.working_dir {
        args.push("--add-dir".to_string());
        args.push(req.output_dir.to_string_lossy().into_owned());
    }
    for dir in &req.extra_dirs {
        args.push("--add-dir".to_string());
        args.push(dir.to_string_lossy().into_owned());
    }

    // Forking a prior session must run in that session's project dir, since
    // claude scopes `--resume` lookup to the current directory. The agent's own
    // working dir is still added so it stays writable for PoCs; absent a resume
    // we simply run in the working dir.
    let cwd = match &req.resume {
        Some(r) => {
            args.push("--resume".to_string());
            args.push(r.session_id.clone());
            args.push("--fork-session".to_string());
            r.project_dir.clone()
        }
        None => req.working_dir.clone(),
    };

    if let Some(model) = model {
        args.push("--model".to_string());
        args.push(model.to_string());
    }
    if let Some(system) = &req.system {
        args.push("--append-system-prompt".to_string());
        args.push(system.clone());
    }
    if !req.allowed_tools.is_empty() {
        args.push("--allowedTools".to_string());
        args.push(req.allowed_tools.join(","));
    }
    if !req.disallowed_tools.is_empty() {
        args.push("--disallowedTools".to_string());
        args.push(req.disallowed_tools.join(","));
    }
    args.extend(extra_args.iter().cloned());

    (args, cwd)
}

#[async_trait]
impl AgentRunner for ClaudeCodeRunner {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(&self, req: AgentRequest) -> Result<AgentResult> {
        // A per-request override (e.g. a cheap dedup judge) wins over the
        // provider's configured model; otherwise fall back to the configured one.
        let model = req.model.as_deref().or(self.model.as_deref());
        let (args, cwd) = build_invocation(&req, model, &self.extra_args);
        clear_final_output(&req).await?;

        let mut cmd = Command::new("claude");
        cmd.args(&args);
        cmd.envs(agent_env(&req));
        cmd.current_dir(&cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // If we abandon the child on timeout, don't leak the process.
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawning claude for provider '{}'", self.name))?;
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

        // Consume the stream line by line, teeing each event and keeping the
        // final `result` event (the only one carrying cost/usage/session id).
        let mut lines = BufReader::new(stdout).lines();
        let mut result_event: Option<serde_json::Value> = None;
        // Every event carries the session id, starting with the init event, so
        // a timed-out agent can still be resumed.
        let mut session_id: Option<String> = None;
        // The weekly cap gates agent *starts*: only an agent's first reading is
        // checked, so one that crosses the cap mid-run still finishes instead of
        // throwing away the tokens it already spent.
        let mut weekly_cap = self.max_weekly_usage_pct;
        let mut over_cap: Option<f64> = None;
        let pump = async {
            while let Some(line) = lines.next_line().await? {
                if let Some(f) = log.as_mut() {
                    // Flush per line so a kill-on-timeout still leaves a usable
                    // partial transcript.
                    f.write_all(line.as_bytes()).await?;
                    f.write_all(b"\n").await?;
                    f.flush().await?;
                }
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
                    continue;
                };
                if session_id.is_none()
                    && let Some(id) = v.get("session_id").and_then(|s| s.as_str())
                {
                    session_id = Some(id.to_owned());
                }
                if v.get("type").and_then(|t| t.as_str()) == Some("result") {
                    result_event = Some(v);
                } else if let Some(cap) = weekly_cap
                    && let Some(used) = weekly_utilization(&v)
                {
                    weekly_cap = None;
                    if reached_cap(used, cap) {
                        over_cap = Some(used);
                        break;
                    }
                }
            }
            anyhow::Ok(())
        };

        match tokio::time::timeout(req.timeout, pump).await {
            Err(_) => {
                let _ = child.start_kill();
                return Err(super::ProviderError::TimedOut { session_id }.into());
            }
            Ok(Err(e)) => {
                return Err(e)
                    .with_context(|| format!("reading claude stream for '{}'", self.name));
            }
            Ok(Ok(())) => {}
        }

        if let Some(used) = over_cap {
            let _ = child.start_kill();
            return Err(super::ProviderError::UsageLimited(format!(
                "weekly usage at {:.0}%, max_weekly_usage_pct is {}%",
                used * 100.0,
                self.max_weekly_usage_pct.unwrap_or_default()
            ))
            .into());
        }

        let status = child
            .wait()
            .await
            .with_context(|| format!("waiting on claude for '{}'", self.name))?;
        let exit_code = status.code().unwrap_or(-1);
        let stderr_out = stderr_task.await.unwrap_or_default();

        // claude reports usage/session/rate limits as a result event with
        // is_error=true and a human message in `.result`, whatever its exit
        // code, so read that before the exit code. Tag limits so the
        // orchestrator can stop on a quota and back off on a throttle.
        if let Some(event) = &result_event
            && event.get("is_error").and_then(|v| v.as_bool()) == Some(true)
        {
            let msg = event.get("result").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(limit) = limit_error(msg) {
                return Err(limit.into());
            }
            bail!("claude reported an error: {msg}");
        }
        if exit_code != 0 {
            if let Some(limit) = limit_error(&stderr_out) {
                return Err(limit.into());
            }
            bail!(
                "claude exited with code {exit_code}: stderr=[{}]",
                stderr_out.trim()
            );
        }

        let result_event = result_event
            .with_context(|| format!("claude stream for '{}' had no result event", self.name))?;

        // The agent was told to write its complete final answer to a file; that
        // is the result we consume, with the result event's text as the fallback.
        let fallback = result_event
            .get("result")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let stdout = read_final_output(&req, fallback).await;

        // Cost, timing, and token usage (prompt-cache hits included) all live in
        // the result event, which has already been teed to the stream log; we
        // only need the session id off it here, for later forks.
        let session_id = result_event
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or(session_id);

        Ok(AgentResult {
            stdout,
            exit_code,
            session_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Effort, ResumeSession};
    use std::path::PathBuf;
    use std::time::Duration;

    fn req() -> AgentRequest {
        AgentRequest {
            prompt: "find bugs".into(),
            system: None,
            working_dir: PathBuf::from("/work/scratch/t1"),
            output_dir: PathBuf::from("/work/scratch/t1"),
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
    fn base_invocation_always_stabilizes_cache_prefix() {
        // The whole point of the cache work: every invocation, forked or not,
        // must carry the prefix-stabilization flag or forks miss recon's cache.
        let (args, cwd) = build_invocation(&req(), Some("claude-opus-5"), &[]);
        assert!(args.contains(&"--exclude-dynamic-system-prompt-sections".to_string()));
        // The prompt carries the original text plus the final-output instruction
        // (with the working dir's path), and the stream-json format is requested.
        let prompt = arg_after(&args, "-p").unwrap();
        assert!(prompt.starts_with("find bugs"));
        assert!(prompt.contains("agent-final-output.json"));
        assert!(prompt.contains("/work/scratch/t1"));
        assert_eq!(arg_after(&args, "--output-format"), Some("stream-json"));
        assert!(args.contains(&"--verbose".to_string()));
        assert_eq!(arg_after(&args, "--add-dir"), Some("/work/scratch/t1"));
        assert_eq!(arg_after(&args, "--model"), Some("claude-opus-5"));
        // No resume: run in the working dir, no --resume/--fork-session.
        assert_eq!(cwd, PathBuf::from("/work/scratch/t1"));
        assert!(!args.contains(&"--resume".to_string()));
        assert!(!args.contains(&"--fork-session".to_string()));
    }

    #[test]
    fn extra_dirs_each_get_an_add_dir_flag() {
        let mut r = req();
        r.extra_dirs = vec![
            PathBuf::from("/work/reference"),
            PathBuf::from("/work/spec"),
        ];
        let (args, _) = build_invocation(&r, None, &[]);
        // Working dir plus each extra dir are all passed as --add-dir.
        let add_dirs: Vec<&str> = args
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--add-dir")
            .map(|(i, _)| args[i + 1].as_str())
            .collect();
        assert_eq!(
            add_dirs,
            vec!["/work/scratch/t1", "/work/reference", "/work/spec"]
        );
    }

    #[test]
    fn separate_output_dir_is_writable_and_named_in_the_prompt() {
        // Recon/validate run in the (possibly read-only) target but answer into
        // a private scratch dir.
        let mut r = req();
        r.working_dir = PathBuf::from("/work/target");
        r.output_dir = PathBuf::from("/work/scratch/recon");
        let (args, _) = build_invocation(&r, None, &[]);
        let prompt = arg_after(&args, "-p").unwrap();
        assert!(prompt.contains("/work/scratch/recon/agent-final-output.json"));
        let add_dirs: Vec<&str> = args
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--add-dir")
            .map(|(i, _)| args[i + 1].as_str())
            .collect();
        assert_eq!(add_dirs, vec!["/work/target", "/work/scratch/recon"]);
    }

    #[test]
    fn agent_env_stabilizes_prefix_and_gates_cache_and_effort_per_request() {
        // The base env stabilizes the cacheable prefix and is applied to every
        // agent regardless of stage.
        let mut r = req();
        r.cache_1h = false;
        r.effort = Effort::Low;
        let base: std::collections::HashMap<_, _> = agent_env(&r).into_iter().collect();
        assert_eq!(base.get("CLAUDE_CODE_DISABLE_CLAUDE_MDS"), Some(&"1"));
        assert_eq!(base.get("CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS"), Some(&"1"));
        assert_eq!(base.get("CLAUDE_CODE_DISABLE_AUTO_MEMORY"), Some(&"1"));
        // Effort is per-request, not a global constant.
        assert_eq!(base.get("CLAUDE_CODE_EFFORT_LEVEL"), Some(&"low"));
        // 1h caching is opt-in: only the forked-from session (recon) pays its
        // write premium; leaf agents leave it off and keep the 5m default.
        assert_eq!(base.get("ENABLE_PROMPT_CACHING_1H"), None);

        r.cache_1h = true;
        r.effort = Effort::Xhigh;
        let opted_in: std::collections::HashMap<_, _> = agent_env(&r).into_iter().collect();
        assert_eq!(opted_in.get("ENABLE_PROMPT_CACHING_1H"), Some(&"1"));
        assert_eq!(opted_in.get("CLAUDE_CODE_EFFORT_LEVEL"), Some(&"xhigh"));
    }

    #[test]
    fn resume_forks_session_and_runs_in_project_dir() {
        let mut r = req();
        r.resume = Some(ResumeSession {
            session_id: "sess-123".into(),
            project_dir: PathBuf::from("/work/target"),
        });
        let (args, cwd) = build_invocation(&r, None, &[]);
        assert_eq!(arg_after(&args, "--resume"), Some("sess-123"));
        assert!(args.contains(&"--fork-session".to_string()));
        // Forks must run in the session's project dir, not the working dir, but
        // the working dir stays add-dir'd so PoCs remain writable.
        assert_eq!(cwd, PathBuf::from("/work/target"));
        assert_eq!(arg_after(&args, "--add-dir"), Some("/work/scratch/t1"));
        // No model passed -> no --model flag.
        assert!(!args.contains(&"--model".to_string()));
    }

    #[test]
    fn optional_flags_and_extra_args_are_appended() {
        let mut r = req();
        r.system = Some("be terse".into());
        r.allowed_tools = vec!["Read".into(), "Grep".into()];
        r.disallowed_tools = vec!["Task".into()];
        let extra = vec!["--dangerously-skip-permissions".to_string()];
        let (args, _) = build_invocation(&r, None, &extra);
        assert_eq!(arg_after(&args, "--append-system-prompt"), Some("be terse"));
        assert_eq!(arg_after(&args, "--allowedTools"), Some("Read,Grep"));
        assert_eq!(arg_after(&args, "--disallowedTools"), Some("Task"));
        assert_eq!(args.last().unwrap(), "--dangerously-skip-permissions");
    }

    #[test]
    fn weekly_utilization_is_read_from_rate_limit_events_only() {
        // A real event from `claude -p --output-format stream-json`.
        let event: serde_json::Value = serde_json::from_str(
            r#"{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","resetsAt":1789880400,"rateLimitType":"five_hour","unifiedWindows":{"five_hour":{"utilization":0.01,"resetsAt":1789880400},"seven_day":{"utilization":0.13,"resetsAt":1790028000}}}}"#,
        )
        .unwrap();
        assert_eq!(weekly_utilization(&event), Some(0.13));
        // No seven-day window, or another event type: no reading.
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
        assert!(reached_cap(0.93, 80));
        assert!(reached_cap(1.0, 100));
    }

    #[test]
    fn empty_tool_lists_omit_flags() {
        let (args, _) = build_invocation(&req(), None, &[]);
        assert!(!args.contains(&"--allowedTools".to_string()));
        assert!(!args.contains(&"--disallowedTools".to_string()));
        assert!(!args.contains(&"--append-system-prompt".to_string()));
    }
}
