//! Offline end-to-end runs of the pipeline over the mock provider. Requires
//! `--features mock-runner`.
#![cfg(feature = "mock-runner")]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fee1dead::config::Config;
use fee1dead::domain::Task;
use fee1dead::json_block;
use fee1dead::pipeline::Pipeline;
use fee1dead::provider::{AgentRequest, AgentResult, AgentRunner, CannedReply, MockRunner};
use serde_json::{Value, json};

const RECON_SESSION_ID: &str = "recon-sess-abc123";

/// Canned agent replies keyed by a substring unique to each stage's prompt.
fn replies() -> Vec<CannedReply> {
    vec![
        // Recon: a threat model with a one-task queue, and a session to fork.
        CannedReply {
            match_substr: Some("reconnaissance phase of a multi-phase audit".into()),
            stdout: r#"{
  "repo_size": "small",
  "loc_estimate": 1200,
  "language": "rust",
  "product_summary": "A byte parser.",
  "trust_boundaries": [{"name": "input", "description": "untrusted bytes"}],
  "assets": ["memory safety"],
  "entry_points": [{"type": "file", "handler": "parse::decode", "file": "src/parse.rs", "untrusted_inputs": "length prefix", "reaches": "allocator", "validation_present": "no"}],
  "invariants": [{"id": "INV-1", "statement": "length is bounds-checked before alloc", "relevant_modules": ["src/parse.rs"], "adversary": "file author", "how_to_falsify": "find an alloc before the check", "tags": ["deserialization"]}],
  "priority_targets": [{"file": "src/parse.rs", "function": "decode", "tied_to": ["INV-1"], "risk": "deserialization", "reason": "length math before bounds check"}],
  "protocol_specs": [],
  "hunt_tasks": [{"attack_class": "integer overflow", "scope_paths": ["src/parse.rs"], "targets": ["src/parse.rs:42"], "hypothesis": "INV-1: length added without bounds check", "suggested_skills": ["sharp-edges"], "priority": "high"}],
  "recent_changes": [],
  "notes": "mock recon report"
}"#
            .into(),
            session_id: Some(RECON_SESSION_ID.into()),
            render: None,
        },
        // Hunter: one finding, one gap.
        CannedReply {
            match_substr: Some("You are a Hunter".into()),
            stdout: r#"```json
{
  "findings": [
    {"title": "unchecked add overflows length", "severity": "high", "confidence": 0.8,
     "location": "src/parse.rs:42",
     "description": "attacker-controlled length added without bounds check"}
  ],
  "gaps": [{"area": "src/parse.rs error path", "reason": "did not test truncated input"}]
}
```"#
                .into(),
            session_id: None,
            render: None,
        },
        // Reviewer: confirms every finding, echoing the run-scoped ids.
        CannedReply {
            match_substr: Some("You are the Reviewer".into()),
            stdout: String::new(),
            session_id: None,
            render: Some(confirm_all),
        },
    ]
}

fn confirm_all(prompt: &str) -> String {
    let findings: Vec<Value> = json_block::parse(prompt, "review input").unwrap();
    let reviews: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({
                "finding_id": f["finding_id"], "verdict": "confirmed",
                "evidence": "len*4 wraps for len > u32::MAX/4",
                "impact": "heap buffer overflow leading to RCE",
                "recommendation": "use checked_add and reject oversized lengths"
            })
        })
        .collect();
    serde_json::to_string(&reviews).unwrap()
}

/// The mock replies, with recon queueing three hunt tasks instead of one.
fn three_task_replies() -> Vec<CannedReply> {
    let mut replies = replies();
    replies[0].stdout = r#"{"hunt_tasks":[
        {"attack_class":"integer overflow","scope_paths":["src/parse.rs"]},
        {"attack_class":"panic-dos","scope_paths":["src/net.rs"]},
        {"attack_class":"auth-bypass","scope_paths":["src/rpc.rs"]}
    ]}"#
    .into();
    replies
}

/// A config for `stages` under `tmp`, with `run_extra` appended to `[run]`.
fn setup_with(tmp: &Path, stages: &str, run_extra: &str) -> (Config, PathBuf) {
    let target = tmp.join("target");
    std::fs::create_dir_all(&target).unwrap();
    let out = tmp.join("out");
    let toml = format!(
        r#"
[run]
target_dir = {target:?}
scratch_root = {scratch:?}
out_dir = {out:?}
concurrency = 1
hunter_stagger_ms = 0
{run_extra}

[provider]
default = "claude-code"

[providers.claude-code]
type = "claude-code"

[firewall]
allow = ["api.anthropic.com"]

[report]
sink = "sqlite"
path = {db:?}

[stages]
enabled = [{stages}]
"#,
        scratch = tmp.join("scratch"),
        db = out.join("findings.db"),
    );
    let cfg_path = tmp.join("harness.toml");
    std::fs::write(&cfg_path, toml).unwrap();
    (Config::load(&cfg_path).unwrap(), out)
}

fn setup(tmp: &Path, stages: &str) -> (Config, PathBuf) {
    setup_with(tmp, stages, "")
}

async fn run_with(cfg: Config, runner: Arc<dyn AgentRunner>) -> anyhow::Result<()> {
    Pipeline::with_runner(cfg, runner).unwrap().run().await
}

fn read_jsonl<T: serde::de::DeserializeOwned>(path: &Path) -> Vec<T> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[tokio::test]
async fn full_pipeline_reports_one_finding() {
    let tmp = tempfile::tempdir().unwrap();
    let (cfg, out) = setup(tmp.path(), r#""recon", "hunt", "validate", "report""#);
    run_with(cfg, Arc::new(MockRunner::new(replies())))
        .await
        .unwrap();

    for artifact in [
        "recon.json",
        "queue.jsonl",
        "candidates.jsonl",
        "gaps.jsonl",
        "validated.jsonl",
    ] {
        assert!(out.join(artifact).exists(), "{artifact} missing");
    }
    let conn = rusqlite::Connection::open(out.join("findings.db")).unwrap();
    let (n, severity): (i64, String) = conn
        .query_row("SELECT COUNT(*), MAX(severity) FROM findings", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((n, severity.as_str()), (1, "high"));

    // The JSONL is written alongside the configured sink.
    let payloads: Vec<Value> = read_jsonl(&out.join("findings.jsonl"));
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0]["impact"], "heap buffer overflow leading to RCE");
    assert_eq!(payloads[0]["verdict"], "confirmed");
    let run_id = std::fs::read_to_string(out.join("run-id.txt")).unwrap();
    assert_eq!(payloads[0]["id"], format!("{}-T-0001-F01", run_id.trim()));
}

/// Run 1 writes seeds; run 2's recon sees them as leads and consumes them.
#[tokio::test]
async fn feedback_seeds_reach_the_next_recon_as_leads() {
    let tmp = tempfile::tempdir().unwrap();
    let (cfg, out) = setup(tmp.path(), r#""recon", "hunt", "validate", "feedback""#);
    run_with(cfg, Arc::new(MockRunner::new(replies())))
        .await
        .unwrap();
    let seeds: Vec<Task> = read_jsonl(&out.join("feedback-seeds.jsonl"));
    assert_eq!(seeds.len(), 2, "expected one variant seed + one gap seed");

    let (cfg, _) = setup(tmp.path(), r#""recon""#);
    let runner = Arc::new(MockRunner::new(replies()));
    run_with(cfg, runner.clone()).await.unwrap();

    let recon_prompt = runner.seen.lock().unwrap()[0].clone();
    assert!(recon_prompt.contains("<leads>"));
    assert!(
        recon_prompt.contains("src/parse.rs error path"),
        "gap seed missing"
    );
    assert!(recon_prompt.contains("variant"), "variant seed missing");
    let queue: Vec<Task> = read_jsonl(&out.join("queue.jsonl"));
    assert_eq!(queue.len(), 1, "only recon's own tasks are queued");
    let left: Vec<Task> = read_jsonl(&out.join("feedback-seeds.jsonl"));
    assert!(left.is_empty(), "recon consumes the seeds it was shown");
}

#[tokio::test]
async fn hunters_fork_from_recon_session() {
    let tmp = tempfile::tempdir().unwrap();
    let (cfg, out) = setup(tmp.path(), r#""recon", "hunt""#);
    let runner = Arc::new(MockRunner::new(replies()));
    run_with(cfg, runner.clone()).await.unwrap();

    let recorded = std::fs::read_to_string(out.join("recon-session.txt")).unwrap();
    assert_eq!(recorded.trim(), RECON_SESSION_ID);
    let resumes = runner.seen_resume.lock().unwrap();
    assert_eq!(resumes.first(), Some(&None), "recon runs without forking");
    assert!(
        resumes.contains(&Some(RECON_SESSION_ID.to_string())),
        "a hunter should have forked from recon's session, saw: {resumes:?}"
    );
}

#[tokio::test]
async fn fork_hunters_false_disables_forking() {
    let tmp = tempfile::tempdir().unwrap();
    let (cfg, _) = setup_with(tmp.path(), r#""recon", "hunt""#, "fork_hunters = false");
    let runner = Arc::new(MockRunner::new(replies()));
    run_with(cfg, runner.clone()).await.unwrap();

    let resumes = runner.seen_resume.lock().unwrap();
    assert!(
        resumes.iter().all(Option::is_none),
        "no agent should fork, saw: {resumes:?}"
    );
}

/// Counts, at each hunter start, the candidates already on disk.
struct CandidateProbe {
    inner: MockRunner,
    candidates: PathBuf,
    on_disk_at_start: Mutex<Vec<usize>>,
}

#[async_trait::async_trait]
impl AgentRunner for CandidateProbe {
    fn name(&self) -> &str {
        "probe"
    }

    async fn run(&self, req: AgentRequest) -> anyhow::Result<AgentResult> {
        if req.prompt.contains("You are a Hunter") {
            let n = std::fs::read_to_string(&self.candidates)
                .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
                .unwrap_or(0);
            self.on_disk_at_start.lock().unwrap().push(n);
        }
        self.inner.run(req).await
    }
}

/// A finished hunter's findings are on disk before the next hunter starts, so
/// a crash mid-hunt cannot take them with it.
#[tokio::test]
async fn each_hunter_is_persisted_before_the_next_starts() {
    let tmp = tempfile::tempdir().unwrap();
    let (cfg, out) = setup(tmp.path(), r#""recon", "hunt""#);
    let probe = Arc::new(CandidateProbe {
        inner: MockRunner::new(three_task_replies()),
        candidates: out.join("candidates.jsonl"),
        on_disk_at_start: Mutex::default(),
    });
    run_with(cfg, probe.clone()).await.unwrap();
    assert_eq!(*probe.on_disk_at_start.lock().unwrap(), vec![0, 1, 2]);
}

/// `--resume` skips recon, hunts the queue it left, and keeps the run id.
#[tokio::test]
async fn resume_hunts_the_pending_queue_without_rerunning_recon() {
    let tmp = tempfile::tempdir().unwrap();
    // Run 1 stops after recon, as a usage limit before hunt would leave it.
    let (cfg, out) = setup(tmp.path(), r#""recon""#);
    run_with(cfg, Arc::new(MockRunner::new(replies())))
        .await
        .unwrap();
    let run_id = std::fs::read_to_string(out.join("run-id.txt")).unwrap();

    let (cfg, _) = setup(tmp.path(), r#""recon", "hunt""#);
    let runner = Arc::new(MockRunner::new(replies()));
    Pipeline::with_runner(cfg, runner.clone())
        .unwrap()
        .resume()
        .await
        .unwrap();

    let seen = runner.seen.lock().unwrap();
    assert!(
        !seen.iter().any(|p| p.contains("reconnaissance phase")),
        "resume must not rerun recon"
    );
    let candidates: Vec<Value> = read_jsonl(&out.join("candidates.jsonl"));
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        std::fs::read_to_string(out.join("run-id.txt")).unwrap(),
        run_id
    );
}

#[tokio::test]
async fn resume_without_a_prior_run_fails_fast() {
    let tmp = tempfile::tempdir().unwrap();
    let (cfg, _) = setup(tmp.path(), r#""recon", "hunt""#);
    let err = Pipeline::with_runner(cfg, Arc::new(MockRunner::new(replies())))
        .unwrap()
        .resume()
        .await
        .unwrap_err();
    assert!(err.to_string().contains("nothing to resume"), "got: {err}");
}

#[tokio::test]
async fn a_failed_stage_does_not_stop_the_rest() {
    let tmp = tempfile::tempdir().unwrap();
    let (cfg, out) = setup(tmp.path(), r#""recon", "hunt", "validate", "feedback""#);
    // No reviewer reply: the validate agent fails.
    let mut replies = replies();
    replies.retain(|r| r.match_substr.as_deref() != Some("You are the Reviewer"));
    let err = run_with(cfg, Arc::new(MockRunner::new(replies)))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("validate"), "got: {err}");
    // Feedback still recorded the hunter's gap for the next run.
    let seeds: Vec<Value> = read_jsonl(&out.join("feedback-seeds.jsonl"));
    assert_eq!(seeds.len(), 1);
}

/// A hunter whose answer does not parse is resumed once to rewrite it, so its
/// finding survives instead of the whole task being discarded.
#[tokio::test]
async fn a_malformed_hunter_answer_is_repaired_not_discarded() {
    let tmp = tempfile::tempdir().unwrap();
    let (cfg, out) = setup(tmp.path(), r#""recon", "hunt""#);
    let mut replies = replies();
    let hunter = replies
        .iter_mut()
        .find(|r| r.match_substr.as_deref() == Some("You are a Hunter"))
        .unwrap();
    let good = std::mem::replace(&mut hunter.stdout, "{\"findings\": [ oops".into());
    hunter.session_id = Some("hunter-sess".into());
    replies.push(CannedReply {
        match_substr: Some("could not use the final answer".into()),
        stdout: good,
        session_id: None,
        render: None,
    });

    let runner = Arc::new(MockRunner::new(replies));
    run_with(cfg, runner.clone()).await.unwrap();

    let candidates: Vec<Value> = read_jsonl(&out.join("candidates.jsonl"));
    assert_eq!(candidates.len(), 1, "the repaired answer's finding is kept");
    let resumes = runner.seen_resume.lock().unwrap();
    assert_eq!(
        resumes.last().unwrap().as_deref(),
        Some("hunter-sess"),
        "the repair forks the hunter's own session"
    );
}
