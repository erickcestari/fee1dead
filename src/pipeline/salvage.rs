//! One repair turn for an agent whose answer the harness could not use.
//!
//! A hunter that traced a bug for 30 minutes and then wrote malformed JSON, or
//! ran out of time before writing anything, still has its analysis in its
//! session. Forking that session with a narrow instruction reuses the cached
//! context and recovers the answer for a fraction of a rerun.
//!
//! The repair turn keeps the request's model and effort: prompt caches are
//! per model, and changing effort mid-conversation invalidates the cached
//! messages, which would re-bill the whole session at full input price.

use std::time::Duration;

use anyhow::{Context, Result};
use tracing::warn;

use crate::provider::{AgentRequest, AgentResult, AgentRunner, ResumeSession, timed_out_session};

/// Wall-clock cap on the repair turn. It only rewrites or finishes an answer
/// from context the agent already has, so it needs minutes, not a full run.
const REPAIR_TIMEOUT: Duration = Duration::from_secs(600);

/// Why the first answer was unusable, which decides the repair instruction.
enum Problem {
    Unparseable(String),
    TimedOut,
}

impl Problem {
    fn prompt(&self) -> String {
        match self {
            Problem::Unparseable(error) => format!(
                "The harness could not use the final answer you wrote: {error}\n\n\
                 Write the complete answer again, in the exact output format your \
                 task specified, fixing what that error points at. Your analysis \
                 is already done, so this turn only rewrites the answer."
            ),
            Problem::TimedOut => "Your time for this task is up. Stop investigating and \
                 write your final answer now, in the exact output format your task \
                 specified, from what you have already established. Record work you \
                 did not finish where that format has a place for it (such as gaps) \
                 rather than making more tool calls."
                .to_string(),
        }
    }
}

/// Run `req` and parse its answer with `parse`. If the answer does not parse,
/// or the agent timed out, fork its session once with a repair instruction and
/// parse that answer instead. Errors other than a timeout, and a first run
/// that reported no session, are returned as they are.
pub(super) async fn run_parsed<T>(
    runner: &dyn AgentRunner,
    req: AgentRequest,
    parse: impl Fn(&AgentResult) -> Result<T>,
) -> Result<T> {
    let (session_id, problem, first_error) = match runner.run(req.clone()).await {
        Ok(result) => match parse(&result) {
            Ok(value) => return Ok(value),
            Err(e) => (result.session_id, Problem::Unparseable(format!("{e:#}")), e),
        },
        Err(e) => match timed_out_session(&e) {
            Some(id) => (Some(id), Problem::TimedOut, e),
            None => return Err(e),
        },
    };
    let Some(session_id) = session_id else {
        return Err(first_error);
    };
    warn!(
        error = format!("{first_error:#}"),
        "agent answer unusable; resuming its session to repair it"
    );

    let repair = AgentRequest {
        prompt: problem.prompt(),
        resume: Some(ResumeSession {
            session_id,
            project_dir: req.session_dir().to_path_buf(),
        }),
        timeout: REPAIR_TIMEOUT.min(req.timeout),
        stream_log_path: req
            .stream_log_path
            .as_ref()
            .map(|p| p.with_extension("repair.jsonl")),
        ..req
    };
    let result = runner
        .run(repair)
        .await
        .with_context(|| format!("repair turn failed after: {first_error:#}"))?;
    parse(&result).with_context(|| {
        format!("answer still unusable after a repair turn (first: {first_error:#})")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Effort, ProviderError};
    use async_trait::async_trait;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// Replays scripted outcomes in order and records each request.
    struct Scripted {
        outcomes: Mutex<Vec<Result<AgentResult>>>,
        seen: Mutex<Vec<AgentRequest>>,
    }

    impl Scripted {
        fn new(mut outcomes: Vec<Result<AgentResult>>) -> Self {
            outcomes.reverse();
            Self {
                outcomes: Mutex::new(outcomes),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl AgentRunner for Scripted {
        fn name(&self) -> &str {
            "scripted"
        }

        async fn run(&self, req: AgentRequest) -> Result<AgentResult> {
            self.seen.lock().unwrap().push(req);
            self.outcomes
                .lock()
                .unwrap()
                .pop()
                .expect("no outcome left")
        }
    }

    fn answer(stdout: &str, session: Option<&str>) -> Result<AgentResult> {
        Ok(AgentResult {
            stdout: stdout.into(),
            exit_code: 0,
            session_id: session.map(Into::into),
        })
    }

    fn req() -> AgentRequest {
        AgentRequest {
            prompt: "hunt".into(),
            system: None,
            working_dir: PathBuf::from("/work/scratch/T-1"),
            output_dir: PathBuf::from("/work/scratch/T-1"),
            extra_dirs: Vec::new(),
            allowed_tools: Vec::new(),
            disallowed_tools: Vec::new(),
            timeout: Duration::from_secs(1800),
            resume: Some(ResumeSession {
                session_id: "recon".into(),
                project_dir: PathBuf::from("/work/target"),
            }),
            cache_1h: false,
            effort: Effort::Xhigh,
            model: Some("m".into()),
            stream_log_path: Some(PathBuf::from("/work/out/logs/hunt-T-1.jsonl")),
        }
    }

    fn parse_number(r: &AgentResult) -> Result<u32> {
        r.stdout.trim().parse::<u32>().context("not a number")
    }

    #[tokio::test]
    async fn a_usable_answer_needs_no_repair() {
        let runner = Scripted::new(vec![answer("7", Some("s"))]);
        assert_eq!(run_parsed(&runner, req(), parse_number).await.unwrap(), 7);
        assert_eq!(runner.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_malformed_answer_is_repaired_in_a_fork_of_its_own_session() {
        let runner = Scripted::new(vec![answer("seven", Some("hunter-s")), answer("7", None)]);
        assert_eq!(run_parsed(&runner, req(), parse_number).await.unwrap(), 7);

        let seen = runner.seen.lock().unwrap();
        let repair = &seen[1];
        let resume = repair.resume.as_ref().unwrap();
        // It forks the hunter's own session, where that session lives.
        assert_eq!(resume.session_id, "hunter-s");
        assert_eq!(resume.project_dir, PathBuf::from("/work/target"));
        assert!(repair.prompt.contains("not a number"));
        // Same model and effort, so the cached session is reused.
        assert_eq!(repair.model.as_deref(), Some("m"));
        assert!(matches!(repair.effort, Effort::Xhigh));
        assert_eq!(repair.timeout, REPAIR_TIMEOUT);
        assert_eq!(
            repair.stream_log_path.as_deref(),
            Some(std::path::Path::new("/work/out/logs/hunt-T-1.repair.jsonl"))
        );
    }

    #[tokio::test]
    async fn a_timed_out_agent_is_asked_for_what_it_has() {
        let timed_out = Err(ProviderError::TimedOut {
            session_id: Some("hunter-s".into()),
        }
        .into());
        let runner = Scripted::new(vec![timed_out, answer("3", None)]);
        assert_eq!(run_parsed(&runner, req(), parse_number).await.unwrap(), 3);
        assert!(
            runner.seen.lock().unwrap()[1]
                .prompt
                .contains("time for this task is up")
        );
    }

    #[tokio::test]
    async fn no_session_or_other_errors_are_returned_unrepaired() {
        let runner = Scripted::new(vec![answer("seven", None)]);
        assert!(run_parsed(&runner, req(), parse_number).await.is_err());
        assert_eq!(runner.seen.lock().unwrap().len(), 1);

        let runner = Scripted::new(vec![Err(anyhow::anyhow!("spawn failed"))]);
        assert!(run_parsed(&runner, req(), parse_number).await.is_err());
        assert_eq!(runner.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_failed_repair_reports_both_problems() {
        let runner = Scripted::new(vec![answer("seven", Some("s")), answer("still no", None)]);
        let err = format!(
            "{:#}",
            run_parsed(&runner, req(), parse_number).await.unwrap_err()
        );
        assert!(err.contains("still unusable"), "got: {err}");
    }
}
