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

#[async_trait]
impl AgentRunner for ClaudeCodeRunner {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(&self, req: AgentRequest) -> Result<AgentResult> {
        let mut cmd = Command::new("claude");
        cmd.arg("-p")
            .arg(&req.prompt)
            .arg("--output-format")
            .arg("json")
            .arg("--add-dir")
            .arg(&req.working_dir);

        if let Some(model) = &self.model {
            cmd.arg("--model").arg(model);
        }
        if let Some(system) = &req.system {
            cmd.arg("--append-system-prompt").arg(system);
        }
        if !req.allowed_tools.is_empty() {
            cmd.arg("--allowedTools").arg(req.allowed_tools.join(","));
        }
        if let Some(max_turns) = req.max_turns {
            cmd.arg("--max-turns").arg(max_turns.to_string());
        }
        cmd.args(&self.extra_args);

        cmd.current_dir(&req.working_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = tokio::time::timeout(req.timeout, cmd.output())
            .await
            .with_context(|| format!("provider '{}' timed out", self.name))?
            .with_context(|| format!("spawning claude for provider '{}'", self.name))?;

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
                envelope.get("result").and_then(|v| v.as_str()).unwrap_or("")
            );
        }

        // The textual result lives in `.result`; fall back to the whole payload.
        let stdout = envelope
            .get("result")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| raw.clone());

        let cost_usd = envelope.get("total_cost_usd").and_then(|v| v.as_f64());

        Ok(AgentResult {
            stdout,
            structured: Some(envelope),
            exit_code,
            cost_usd,
        })
    }
}
