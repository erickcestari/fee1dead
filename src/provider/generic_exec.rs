//! Config-driven adapter (`type = "exec"`): any CLI described by a command and
//! an argv template. It has no sessions and reads the answer from stdout.

use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tokio::process::Command;

use super::{AgentRequest, AgentResult, AgentRunner, ProviderError};
use crate::config::{ExecConfig, ExecOutput};

pub struct ExecRunner {
    name: String,
    cfg: ExecConfig,
}

impl ExecRunner {
    pub fn new(name: String, cfg: ExecConfig) -> Self {
        Self { name, cfg }
    }

    fn render_args(&self, prompt: &str, working_dir: &Path) -> Vec<String> {
        let wd = working_dir.to_string_lossy();
        self.cfg
            .args
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
        let mut cmd = Command::new(&self.cfg.command);
        cmd.args(self.render_args(&req.prompt, &req.working_dir))
            .current_dir(&req.working_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let output = tokio::time::timeout(req.timeout, cmd.output())
            .await
            .map_err(|_| ProviderError::TimedOut { session_id: None })?
            .with_context(|| format!("spawning provider '{}' ({})", self.name, self.cfg.command))?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

        if self.cfg.output == ExecOutput::Json {
            serde_json::from_str::<serde_json::Value>(stdout.trim())
                .with_context(|| format!("provider '{}' did not emit valid JSON", self.name))?;
        }
        if !output.status.success() {
            bail!(
                "provider '{}' exited with code {}: {}",
                self.name,
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(AgentResult {
            stdout,
            session_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Effort, timed_out_session};
    use std::path::PathBuf;
    use std::time::Duration;

    fn runner(command: &str, args: &[&str]) -> ExecRunner {
        ExecRunner::new(
            "test".into(),
            ExecConfig {
                command: command.into(),
                args: args.iter().map(ToString::to_string).collect(),
                output: ExecOutput::Text,
            },
        )
    }

    #[test]
    fn substitutes_placeholders() {
        let r = runner("codex", &["exec", "--cd", "{working_dir}", "{prompt}"]);
        let args = r.render_args("find bugs", &PathBuf::from("/work/scratch/t1"));
        assert_eq!(args, vec!["exec", "--cd", "/work/scratch/t1", "find bugs"]);
    }

    #[tokio::test]
    async fn a_timeout_is_a_provider_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let req = AgentRequest::new(
            "p".into(),
            dir.path().to_path_buf(),
            Duration::from_millis(200),
            Effort::Low,
        );
        let err = runner("sleep", &["30"]).run(req).await.unwrap_err();
        assert!(matches!(
            err.downcast_ref(),
            Some(ProviderError::TimedOut { .. })
        ));
        assert_eq!(timed_out_session(&err), None);
    }
}
