//! Running a CLI that streams JSON events on stdout: each line is teed to the
//! agent's log as it arrives, so a timed-out agent still leaves a transcript.

use std::ops::ControlFlow;
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tracing::warn;

use super::{AgentRequest, ProviderError};

/// Folds an adapter's event stream into what it needs from the run.
pub(super) trait StreamObserver {
    /// Take one stdout line; `Break` kills the agent.
    fn observe(&mut self, line: &str) -> ControlFlow<()>;

    /// The session seen so far, reported if the agent times out.
    fn session_id(&self) -> Option<&str>;
}

#[derive(Debug)]
pub(super) struct Exit {
    pub code: i32,
    pub stderr: String,
}

/// Spawn `cmd`, feed its stdout lines to `observer`, and wait for it to exit
/// (or be killed by a `Break`). A timeout is a [`ProviderError::TimedOut`].
pub(super) async fn run_streaming(
    mut cmd: Command,
    req: &AgentRequest,
    observer: &mut impl StreamObserver,
) -> Result<Exit> {
    let program = cmd.as_std().get_program().to_string_lossy().into_owned();
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd.spawn().with_context(|| format!("spawning {program}"))?;
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    // Drained concurrently: a full stderr pipe would block the child.
    let stderr = tokio::spawn(async move {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf).await;
        buf
    });
    let mut log = match &req.stream_log_path {
        Some(path) => open_log(path)
            .await
            .inspect_err(|e| warn!(error = %e, "agent stream log disabled"))
            .ok(),
        None => None,
    };

    let pump = async {
        let mut lines = BufReader::new(stdout).lines();
        while let Some(line) = lines.next_line().await? {
            if let Some(f) = log.as_mut() {
                // Flushed per line, so a kill leaves a usable partial transcript.
                f.write_all(line.as_bytes()).await?;
                f.write_all(b"\n").await?;
                f.flush().await?;
            }
            if observer.observe(&line).is_break() {
                return anyhow::Ok(true);
            }
        }
        anyhow::Ok(false)
    };
    let stopped = match tokio::time::timeout(req.timeout, pump).await {
        Err(_) => {
            let _ = child.start_kill();
            stderr.abort();
            return Err(ProviderError::TimedOut {
                session_id: observer.session_id().map(str::to_owned),
            }
            .into());
        }
        Ok(read) => read.with_context(|| format!("reading the {program} event stream"))?,
    };
    if stopped {
        let _ = child.start_kill();
        // The agent's own subprocesses may still hold stderr open.
        stderr.abort();
    }
    let status = child
        .wait()
        .await
        .with_context(|| format!("waiting on {program}"))?;
    Ok(Exit {
        code: status.code().unwrap_or(-1),
        stderr: stderr.await.unwrap_or_default(),
    })
}

/// Open a stream-log file for append, making parent dirs as needed. Appended,
/// so an agent re-run (a retry, or on resume) keeps its earlier spend on record.
async fn open_log(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating log dir {}", parent.display()))?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .with_context(|| format!("opening stream log {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Effort, timed_out_session};
    use std::time::Duration;

    #[derive(Default)]
    struct Lines {
        seen: Vec<String>,
        stop_at: Option<String>,
    }

    impl StreamObserver for Lines {
        fn observe(&mut self, line: &str) -> ControlFlow<()> {
            self.seen.push(line.to_string());
            if self.stop_at.as_deref() == Some(line) {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }

        fn session_id(&self) -> Option<&str> {
            self.seen.first().map(String::as_str)
        }
    }

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script]);
        cmd
    }

    fn req(dir: &Path, timeout: Duration) -> AgentRequest {
        AgentRequest {
            stream_log_path: Some(dir.join("logs").join("agent.jsonl")),
            ..AgentRequest::new("p".into(), dir.to_path_buf(), timeout, Effort::Low)
        }
    }

    #[tokio::test]
    async fn tees_every_line_and_reports_exit_and_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let req = req(dir.path(), Duration::from_secs(10));
        let mut lines = Lines::default();
        let exit = run_streaming(
            sh("echo a; echo b; echo oops >&2; exit 3"),
            &req,
            &mut lines,
        )
        .await
        .unwrap();
        assert_eq!(lines.seen, ["a", "b"]);
        assert_eq!(exit.code, 3);
        assert_eq!(exit.stderr.trim(), "oops");
        let log = std::fs::read_to_string(req.stream_log_path.unwrap()).unwrap();
        assert_eq!(log, "a\nb\n");
    }

    #[tokio::test]
    async fn a_rerun_appends_to_the_log_so_earlier_spend_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let req = req(dir.path(), Duration::from_secs(10));
        for line in ["first", "second"] {
            run_streaming(sh(&format!("echo {line}")), &req, &mut Lines::default())
                .await
                .unwrap();
        }
        let log = std::fs::read_to_string(req.stream_log_path.unwrap()).unwrap();
        assert_eq!(log, "first\nsecond\n");
    }

    #[tokio::test]
    async fn a_break_kills_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        let mut lines = Lines {
            stop_at: Some("stop".into()),
            ..Lines::default()
        };
        let req = req(dir.path(), Duration::from_secs(10));
        run_streaming(sh("echo stop; sleep 30; echo late"), &req, &mut lines)
            .await
            .unwrap();
        assert_eq!(lines.seen, ["stop"]);
    }

    #[tokio::test]
    async fn a_timeout_reports_the_session_seen_so_far() {
        let dir = tempfile::tempdir().unwrap();
        let req = req(dir.path(), Duration::from_millis(300));
        let err = run_streaming(sh("echo sess-1; sleep 30"), &req, &mut Lines::default())
            .await
            .unwrap_err();
        assert_eq!(timed_out_session(&err).as_deref(), Some("sess-1"));
    }
}
