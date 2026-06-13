//! Config-driven adapter: run any CLI described by a command template.
//!
//! This is the zero-code extension path. A `[providers.<name>]` block with
//! `type = "exec"` names a `command` and an `args` template; the placeholders
//! `{prompt}` and `{working_dir}` are substituted per request.

use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::process::Command;

use super::{AgentRequest, AgentResult, AgentRunner};
use crate::config::ExecOutput;

pub struct ExecRunner {
    name: String,
    command: String,
    args: Vec<String>,
    output: ExecOutput,
}

impl ExecRunner {
    pub fn new(name: String, command: String, args: Vec<String>, output: ExecOutput) -> Self {
        Self {
            name,
            command,
            args,
            output,
        }
    }

    /// Render the argv template against a request, substituting placeholders.
    fn render_args(&self, prompt: &str, working_dir: &Path) -> Vec<String> {
        let wd = working_dir.to_string_lossy();
        self.args
            .iter()
            .map(|a| a.replace("{prompt}", prompt).replace("{working_dir}", &wd))
            .collect()
    }
}

#[async_trait]
impl AgentRunner for ExecRunner {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(&self, req: AgentRequest) -> Result<AgentResult> {
        let args = self.render_args(&req.prompt, &req.working_dir);
        let mut cmd = Command::new(&self.command);
        cmd.args(&args)
            .current_dir(&req.working_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = tokio::time::timeout(req.timeout, cmd.output())
            .await
            .with_context(|| format!("provider '{}' timed out", self.name))?
            .with_context(|| format!("spawning provider '{}' ({})", self.name, self.command))?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let exit_code = output.status.code().unwrap_or(-1);

        let structured = match self.output {
            ExecOutput::Text => None,
            ExecOutput::Json => Some(
                serde_json::from_str(stdout.trim())
                    .with_context(|| format!("provider '{}' did not emit valid JSON", self.name))?,
            ),
        };

        if exit_code != 0 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "provider '{}' exited with code {exit_code}: {}",
                self.name,
                stderr.trim()
            );
        }

        Ok(AgentResult {
            stdout,
            structured,
            exit_code,
            cost_usd: None,
            // Exec providers have no session concept; nothing to fork from.
            session_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn substitutes_placeholders() {
        let r = ExecRunner::new(
            "codex".into(),
            "codex".into(),
            vec![
                "exec".into(),
                "--cd".into(),
                "{working_dir}".into(),
                "{prompt}".into(),
            ],
            ExecOutput::Text,
        );
        let args = r.render_args("find bugs", &PathBuf::from("/work/scratch/t1"));
        assert_eq!(args, vec!["exec", "--cd", "/work/scratch/t1", "find bugs"]);
    }
}
