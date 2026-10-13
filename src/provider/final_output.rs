//! The answer-file contract: a streaming agent writes its final answer to a
//! file in its output dir, and the harness reads that back instead of the
//! noisy event stream.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs;
use tracing::warn;

use super::AgentRequest;

const FINAL_OUTPUT_FILE: &str = "agent-final-output.json";

fn final_output_path(output_dir: &Path) -> PathBuf {
    output_dir.join(FINAL_OUTPUT_FILE)
}

/// Append the answer-file instruction to the user prompt. It stays out of any
/// system prompt: the path is per agent, and would bust the shared fork cache.
pub(super) fn with_final_output_instruction(prompt: &str, output_dir: &Path) -> String {
    format!(
        "{prompt}\n\n---\nWhen you are finished, use the Write tool to save your \
         complete final answer to this file:\n  {}\nThe harness reads that file, \
         not your chat output, so it must stand on its own. After writing it, \
         reply with only the word `done`: repeating the answer in chat would \
         pay for all of its tokens a second time.",
        final_output_path(output_dir).display()
    )
}

/// Remove a stale answer file (creating the output dir if needed), so an agent
/// that writes nothing is never credited with a previous agent's answer.
pub(super) async fn clear_final_output(req: &AgentRequest) -> Result<()> {
    fs::create_dir_all(&req.output_dir)
        .await
        .with_context(|| format!("creating output dir {}", req.output_dir.display()))?;
    let path = final_output_path(&req.output_dir);
    match fs::remove_file(&path).await {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("removing stale {}", path.display()))
        }
        _ => Ok(()),
    }
}

/// Read the agent's answer file, falling back to `fallback` (the provider's
/// last message) when it wrote none. The answer is mirrored beside the
/// transcript on a best-effort basis.
pub(super) async fn read_final_output(req: &AgentRequest, fallback: &str) -> String {
    let path = final_output_path(&req.output_dir);
    let output = match fs::read_to_string(&path).await {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            warn!(path = %path.display(), "agent wrote no final-output file; using its last message");
            fallback.to_string()
        }
    };
    if let Some(log) = &req.stream_log_path {
        let sidecar = output_sidecar(log);
        if let Err(e) = fs::write(&sidecar, &output).await {
            warn!(error = %e, path = %sidecar.display(), "failed to persist agent final output");
        }
    }
    output
}

/// `<base>.jsonl` transcript → `<base>.output.json` answer, in the same dir.
fn output_sidecar(stream_log_path: &Path) -> PathBuf {
    stream_log_path.with_extension("output.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Effort;
    use std::time::Duration;

    fn req_in(dir: &Path, stream_log_path: Option<PathBuf>) -> AgentRequest {
        AgentRequest {
            stream_log_path,
            ..AgentRequest::new(
                "p".into(),
                dir.to_path_buf(),
                Duration::from_secs(1),
                Effort::Low,
            )
        }
    }

    #[test]
    fn instruction_keeps_the_prompt_and_names_the_answer_file() {
        let out = with_final_output_instruction("do the thing", Path::new("/work/scratch/t1"));
        assert!(out.starts_with("do the thing"));
        assert!(out.contains("/work/scratch/t1/agent-final-output.json"));
        assert!(out.contains("reply with only the word `done`"));
    }

    #[test]
    fn sidecar_sits_beside_the_transcript() {
        assert_eq!(
            output_sidecar(Path::new("/work/out/logs/hunt-G-0093.jsonl")),
            Path::new("/work/out/logs/hunt-G-0093.output.json")
        );
    }

    #[tokio::test]
    async fn answer_file_wins_over_the_fallback_and_is_mirrored() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(final_output_path(&scratch), "{\"findings\":[]}").unwrap();
        let log = dir.path().join("hunt-T-0001.jsonl");

        let out = read_final_output(&req_in(&scratch, Some(log.clone())), "chat text").await;
        assert_eq!(out, "{\"findings\":[]}");
        assert_eq!(
            std::fs::read_to_string(output_sidecar(&log)).unwrap(),
            "{\"findings\":[]}"
        );
    }

    #[tokio::test]
    async fn a_previous_agents_answer_is_never_read_back() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(final_output_path(dir.path()), "{\"duplicate\": true}").unwrap();
        let req = req_in(dir.path(), None);
        clear_final_output(&req).await.unwrap();
        assert_eq!(read_final_output(&req, "chat text").await, "chat text");
    }

    #[tokio::test]
    async fn clearing_creates_a_missing_output_dir() {
        let dir = tempfile::tempdir().unwrap();
        let req = req_in(&dir.path().join("agents").join("recon"), None);
        clear_final_output(&req).await.unwrap();
        assert!(req.output_dir.is_dir());
    }
}
