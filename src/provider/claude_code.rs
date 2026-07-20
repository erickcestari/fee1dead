//! Claude Code CLI adapter — the only built-in provider implementation.
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

use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tracing::warn;

use super::{AgentRequest, AgentResult, AgentRunner, final_output_path};

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
/// every hunter (and the validate/report agents) forks. Recon runs at
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
}

impl ClaudeCodeRunner {
    pub fn new(name: String, model: Option<String>, extra_args: Vec<String>) -> Self {
        Self {
            name,
            model,
            extra_args,
        }
    }
}

/// Append the "write your final answer to a file" instruction to the user
/// prompt.
///
/// It goes in the per-agent user prompt — never the shared system prefix — on
/// purpose: the path is per-agent (the working dir), so injecting it into the
/// cached system prompt would bust the cross-fork cache the whole design relies
/// on. A new user turn is uncached regardless, so this costs nothing extra.
fn with_final_output_instruction(prompt: &str, working_dir: &Path) -> String {
    let path = final_output_path(working_dir);
    format!(
        "{prompt}\n\n---\nWhen you are finished, use the Write tool to save your \
         COMPLETE final answer — the exact content you would otherwise print, \
         verbatim and in full — to this file:\n  {}\nThat file, not your chat \
         output, is what gets consumed downstream, so it must stand on its own.",
        path.display()
    )
}

/// Build the `claude` argv (after the program name) and the directory to run
/// in for one request.
///
/// Factored out of [`ClaudeCodeRunner::run`] so the flag wiring — in particular
/// the cache-stabilization flag every forked stage depends on — is unit-testable
/// without spawning a process. The cache env (`CACHE_ENV`) is applied separately
/// at spawn time; it is not part of the argv.
fn build_invocation(
    req: &AgentRequest,
    model: Option<&str>,
    extra_args: &[String],
) -> (Vec<String>, std::path::PathBuf) {
    let mut args = vec![
        "-p".to_string(),
        with_final_output_instruction(&req.prompt, &req.working_dir),
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

    // Extra readable dirs (e.g. the cloned reference repo) so the agent can read
    // them without a permission prompt.
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
    if let Some(max_turns) = req.max_turns {
        args.push("--max-turns".to_string());
        args.push(max_turns.to_string());
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
        let pump = async {
            while let Some(line) = lines.next_line().await? {
                if let Some(f) = log.as_mut() {
                    // Flush per line so a kill-on-timeout still leaves a usable
                    // partial transcript.
                    f.write_all(line.as_bytes()).await?;
                    f.write_all(b"\n").await?;
                    f.flush().await?;
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line)
                    && v.get("type").and_then(|t| t.as_str()) == Some("result")
                {
                    result_event = Some(v);
                }
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
                    .with_context(|| format!("reading claude stream for '{}'", self.name));
            }
            Ok(Ok(())) => {}
        }

        let status = child
            .wait()
            .await
            .with_context(|| format!("waiting on claude for '{}'", self.name))?;
        let exit_code = status.code().unwrap_or(-1);
        let stderr_out = stderr_task.await.unwrap_or_default();

        if exit_code != 0 {
            bail!(
                "claude exited with code {exit_code}: stderr=[{}]",
                stderr_out.trim()
            );
        }

        let result_event = result_event
            .with_context(|| format!("claude stream for '{}' had no result event", self.name))?;
        if result_event.get("is_error").and_then(|v| v.as_bool()) == Some(true) {
            // claude reports usage/session/rate limits as a successful-subtype
            // result with is_error=true and a human message in `.result`. Tag
            // those so the orchestrator can stop hammering a limited account.
            let msg = result_event
                .get("result")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if is_usage_limit_message(msg) {
                return Err(super::ProviderError::UsageLimited(msg.to_string()).into());
            }
            bail!("claude reported an error: {msg}");
        }

        // The agent was told to write its complete final answer to a file; that
        // is the result we consume. Fall back to the result event's text if it
        // forgot (or lacked the Write tool), so a stray run still makes progress.
        let final_path = final_output_path(&req.working_dir);
        let stdout = match fs::read_to_string(&final_path).await {
            Ok(s) if !s.trim().is_empty() => s,
            _ => {
                warn!(
                    path = %final_path.display(),
                    "agent did not write its final-output file; using the result event text"
                );
                result_event
                    .get("result")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string()
            }
        };

        // Mirror the consumed final answer next to its transcript in the out
        // dir, so it's visible there without reaching into the agent's scratch
        // dir. Best-effort: persisting it must never fail the run.
        if let Some(log_path) = &req.stream_log_path {
            let sidecar = output_sidecar(log_path);
            if let Err(e) = fs::write(&sidecar, &stdout).await {
                warn!(error = %e, path = %sidecar.display(), "failed to persist agent final output");
            }
        }

        // Cost, timing, and token usage (prompt-cache hits included) all live in
        // the result event, which has already been teed to the stream log; we
        // only need the session id off it here, for later forks.
        let session_id = result_event
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        Ok(AgentResult {
            stdout,
            exit_code,
            session_id,
        })
    }
}

/// Heuristic: does an error `.result` message describe a usage/session/rate
/// limit? Matched against the human strings claude emits, e.g. "You've hit your
/// session limit · resets 2:50am". Kept deliberately broad-but-anchored on the
/// word "limit" so a new phrasing still trips it without matching unrelated
/// errors.
fn is_usage_limit_message(msg: &str) -> bool {
    let m = msg.to_lowercase();
    m.contains("limit")
        && (m.contains("session")
            || m.contains("usage")
            || m.contains("rate")
            || m.contains("hit your")
            || m.contains("resets"))
}

/// Path of the final-answer sidecar that sits beside a stream log: the
/// transcript `<base>.jsonl` is paired with the consumed answer
/// `<base>.output.json` in the same dir.
fn output_sidecar(stream_log_path: &Path) -> std::path::PathBuf {
    stream_log_path.with_extension("output.json")
}

/// Create (truncating) the stream-log file, making parent dirs as needed.
async fn open_log(path: &Path) -> Result<fs::File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating log dir {}", parent.display()))?;
    }
    fs::File::create(path)
        .await
        .with_context(|| format!("creating stream log {}", path.display()))
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
            extra_dirs: Vec::new(),
            allowed_tools: Vec::new(),
            disallowed_tools: Vec::new(),
            timeout: Duration::from_secs(1),
            max_turns: None,
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
        let (args, cwd) = build_invocation(&req(), Some("claude-opus-4-8"), &[]);
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
        assert_eq!(arg_after(&args, "--model"), Some("claude-opus-4-8"));
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
        r.max_turns = Some(7);
        let extra = vec!["--dangerously-skip-permissions".to_string()];
        let (args, _) = build_invocation(&r, None, &extra);
        assert_eq!(arg_after(&args, "--append-system-prompt"), Some("be terse"));
        assert_eq!(arg_after(&args, "--allowedTools"), Some("Read,Grep"));
        assert_eq!(arg_after(&args, "--disallowedTools"), Some("Task"));
        assert_eq!(arg_after(&args, "--max-turns"), Some("7"));
        assert_eq!(args.last().unwrap(), "--dangerously-skip-permissions");
    }

    #[test]
    fn empty_tool_lists_omit_flags() {
        let (args, _) = build_invocation(&req(), None, &[]);
        assert!(!args.contains(&"--allowedTools".to_string()));
        assert!(!args.contains(&"--disallowedTools".to_string()));
        assert!(!args.contains(&"--max-turns".to_string()));
        assert!(!args.contains(&"--append-system-prompt".to_string()));
    }

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
    fn detects_usage_limit_messages_only() {
        // The real strings claude emits for a depleted account.
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
            super::super::ProviderError::UsageLimited("hit your session limit".into()).into();
        assert!(crate::provider::is_usage_limited(&err));
        // A plain error is not a usage limit.
        assert!(!crate::provider::is_usage_limited(&anyhow::anyhow!("boom")));
    }

    #[test]
    fn output_sidecar_sits_beside_the_transcript() {
        let log = Path::new("/work/out/logs/hunt-G-0093.jsonl");
        assert_eq!(
            output_sidecar(log),
            Path::new("/work/out/logs/hunt-G-0093.output.json")
        );
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
}
