//! An agent CLI runs in its own process group, so stopping it also stops the
//! builds, tests, and fuzzers it started, which would otherwise outlive it.

use std::io;
use std::process::Output;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

/// A spawned agent whose whole process group is killed on drop, unless the
/// agent exited and was reaped first.
pub(super) struct AgentProcess {
    pub child: Child,
}

impl AgentProcess {
    pub fn spawn(cmd: &mut Command) -> io::Result<Self> {
        let child = cmd.process_group(0).kill_on_drop(true).spawn()?;
        Ok(Self { child })
    }

    /// SIGKILL the agent and everything in its group.
    pub fn kill_group(&mut self) {
        // `None` once reaped: the pid, and so the group id, may then be reused.
        if let Some(pid) = self.child.id() {
            let pgid = libc::pid_t::try_from(pid).expect("a pid fits in pid_t");
            // SAFETY: killpg has no memory-safety preconditions. An unreaped
            // leader's pid cannot be reused, so the group is still the agent's.
            unsafe { libc::killpg(pgid, libc::SIGKILL) };
        }
    }

    /// Collect stdout and stderr until the agent exits, like
    /// `Command::output`, with the group still killed if this is cancelled.
    pub async fn output(&mut self) -> io::Result<Output> {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let read_stdout = read_all(self.child.stdout.take(), &mut stdout);
        let read_stderr = read_all(self.child.stderr.take(), &mut stderr);
        let (status, (), ()) = tokio::try_join!(self.child.wait(), read_stdout, read_stderr)?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        self.kill_group();
    }
}

async fn read_all(pipe: Option<impl AsyncReadExt + Unpin>, buf: &mut Vec<u8>) -> io::Result<()> {
    if let Some(mut pipe) = pipe {
        pipe.read_to_end(buf).await?;
    }
    Ok(())
}

/// Polls `/proc` until `pid` is gone or a zombie; false if it still runs after 5s.
#[cfg(all(test, target_os = "linux"))]
pub(super) async fn exits(pid: &str) -> bool {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        // The state letter follows the parenthesized command name.
        let running = stat.is_ok_and(|s| {
            s.rsplit_once(") ")
                .is_some_and(|(_, state)| !state.starts_with('Z'))
        });
        if !running {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    false
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[tokio::test]
    async fn dropping_an_agent_kills_what_it_started() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 30 & echo $!; wait"])
            .stdout(Stdio::piped());
        let mut agent = AgentProcess::spawn(&mut cmd).unwrap();
        let mut line = String::new();
        let mut stdout = tokio::io::BufReader::new(agent.child.stdout.take().unwrap());
        tokio::io::AsyncBufReadExt::read_line(&mut stdout, &mut line)
            .await
            .unwrap();
        drop(agent);
        assert!(exits(line.trim()).await, "the background sleep survived");
    }

    #[tokio::test]
    async fn output_collects_both_streams_and_the_status() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo out; echo err >&2; exit 4"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = AgentProcess::spawn(&mut cmd)
            .unwrap()
            .output()
            .await
            .unwrap();
        assert_eq!(out.stdout, b"out\n");
        assert_eq!(out.stderr, b"err\n");
        assert_eq!(out.status.code(), Some(4));
    }
}
