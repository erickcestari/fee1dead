//! Claude Code CLI adapter — the only built-in provider implementation.
//!
//! Invokes `claude -p <prompt> --output-format json ...` and unwraps the JSON
//! result envelope into an [`AgentResult`]. The agent runs with whatever extra
//! args the config supplies (typically `--dangerously-skip-permissions`, since
//! the container is the security boundary, not the tool allow-list).

use std::process::Stdio;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::process::Command;

use super::{AgentRequest, AgentResult, AgentRunner};

/// Environment that makes session forking actually cheap.
///
/// The harness forks every hunter (and the validate/report agents) from the
/// recon session so they inherit its codebase exploration as a cached prefix.
/// That only pays off if the prefix stays cacheable and the cache lives long
/// enough — which requires turning these knobs on explicitly:
///
/// - `ENABLE_PROMPT_CACHING_1H`: extend the prompt-cache TTL from 5m to 1h.
///   Hunters run with `concurrency` of 10+ and per-agent timeouts of 30–40
///   minutes, so under the default 5m TTL recon's prefix expires before most
///   hunters (and the later stages) start — re-billing recon's whole context
///   at full input rates instead of cache-read rates.
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
/// - `CLAUDE_CODE_EFFORT_LEVEL`: hunters trace multi-hop code paths; xhigh
///   gives deeper adaptive thinking before they report, which finds more.
const CACHE_ENV: &[(&str, &str)] = &[
    ("ENABLE_PROMPT_CACHING_1H", "1"),
    ("CLAUDE_CODE_DISABLE_CLAUDE_MDS", "1"),
    ("CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS", "1"),
    ("CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1"),
    ("CLAUDE_CODE_EFFORT_LEVEL", "xhigh"),
];

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
        req.prompt.clone(),
        "--output-format".to_string(),
        "json".to_string(),
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
        let (args, cwd) = build_invocation(&req, self.model.as_deref(), &self.extra_args);

        let mut cmd = Command::new("claude");
        cmd.args(&args);
        cmd.envs(CACHE_ENV.iter().copied());

        cmd.current_dir(&cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let started = std::time::Instant::now();
        let output = tokio::time::timeout(req.timeout, cmd.output())
            .await
            .with_context(|| format!("provider '{}' timed out", self.name))?
            .with_context(|| format!("spawning claude for provider '{}'", self.name))?;
        let duration = started.elapsed();

        let raw = String::from_utf8_lossy(&output.stdout).into_owned();
        let exit_code = output.status.code().unwrap_or(-1);

        if exit_code != 0 {
            // claude reports errors on stdout under --output-format json, so
            // surface both streams.
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "claude exited with code {exit_code}: stderr=[{}] stdout=[{}]",
                stderr.trim(),
                raw.trim()
            );
        }

        let envelope: serde_json::Value = serde_json::from_str(raw.trim())
            .with_context(|| format!("claude did not emit valid JSON: {}", raw.trim()))?;

        if envelope.get("is_error").and_then(|v| v.as_bool()) == Some(true) {
            bail!(
                "claude reported an error: {}",
                envelope
                    .get("result")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            );
        }

        // The textual result lives in `.result`; fall back to the whole payload.
        let stdout = envelope
            .get("result")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| raw.clone());

        let cost_usd = envelope.get("total_cost_usd").and_then(|v| v.as_f64());
        let session_id = envelope
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        Ok(AgentResult {
            stdout,
            structured: Some(envelope),
            exit_code,
            cost_usd,
            duration,
            session_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ResumeSession;
    use std::path::PathBuf;
    use std::time::Duration;

    fn req() -> AgentRequest {
        AgentRequest {
            prompt: "find bugs".into(),
            system: None,
            working_dir: PathBuf::from("/work/scratch/t1"),
            allowed_tools: Vec::new(),
            skills: Vec::new(),
            timeout: Duration::from_secs(1),
            max_turns: None,
            resume: None,
        }
    }

    /// Find the value following `flag` in an argv, if present.
    fn arg_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        args.iter().position(|a| a == flag).map(|i| args[i + 1].as_str())
    }

    #[test]
    fn base_invocation_always_stabilizes_cache_prefix() {
        // The whole point of the cache work: every invocation, forked or not,
        // must carry the prefix-stabilization flag or forks miss recon's cache.
        let (args, cwd) = build_invocation(&req(), Some("claude-opus-4-8"), &[]);
        assert!(args.contains(&"--exclude-dynamic-system-prompt-sections".to_string()));
        assert_eq!(arg_after(&args, "-p"), Some("find bugs"));
        assert_eq!(arg_after(&args, "--output-format"), Some("json"));
        assert_eq!(arg_after(&args, "--add-dir"), Some("/work/scratch/t1"));
        assert_eq!(arg_after(&args, "--model"), Some("claude-opus-4-8"));
        // No resume: run in the working dir, no --resume/--fork-session.
        assert_eq!(cwd, PathBuf::from("/work/scratch/t1"));
        assert!(!args.contains(&"--resume".to_string()));
        assert!(!args.contains(&"--fork-session".to_string()));
    }

    #[test]
    fn cache_env_enables_1h_caching_and_xhigh_effort() {
        // CACHE_ENV is what makes session forking actually cheap; guard its keys.
        let env: std::collections::HashMap<_, _> = CACHE_ENV.iter().copied().collect();
        assert_eq!(env.get("ENABLE_PROMPT_CACHING_1H"), Some(&"1"));
        assert_eq!(env.get("CLAUDE_CODE_DISABLE_CLAUDE_MDS"), Some(&"1"));
        assert_eq!(env.get("CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS"), Some(&"1"));
        assert_eq!(env.get("CLAUDE_CODE_DISABLE_AUTO_MEMORY"), Some(&"1"));
        assert_eq!(env.get("CLAUDE_CODE_EFFORT_LEVEL"), Some(&"xhigh"));
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
        r.max_turns = Some(7);
        let extra = vec!["--dangerously-skip-permissions".to_string()];
        let (args, _) = build_invocation(&r, None, &extra);
        assert_eq!(arg_after(&args, "--append-system-prompt"), Some("be terse"));
        assert_eq!(arg_after(&args, "--allowedTools"), Some("Read,Grep"));
        assert_eq!(arg_after(&args, "--max-turns"), Some("7"));
        assert_eq!(args.last().unwrap(), "--dangerously-skip-permissions");
    }

    #[test]
    fn empty_allowed_tools_omits_flag() {
        let (args, _) = build_invocation(&req(), None, &[]);
        assert!(!args.contains(&"--allowedTools".to_string()));
        assert!(!args.contains(&"--max-turns".to_string()));
        assert!(!args.contains(&"--append-system-prompt".to_string()));
    }
}
