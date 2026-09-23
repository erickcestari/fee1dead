//! Offline end-to-end test: drive the full skeleton pipeline with the mock
//! provider (no network, no API). Requires `--features mock-runner`.
#![cfg(feature = "mock-runner")]

use std::sync::Arc;

use fee1dead::artifacts::extract_json_block;
use fee1dead::config::Config;
use fee1dead::pipeline::Pipeline;
use fee1dead::provider::{AgentRequest, AgentResult, AgentRunner, CannedReply, MockRunner};
use serde_json::{Value, json};

/// Canned agent responses keyed by a substring unique to each stage's prompt.
fn replies() -> Vec<CannedReply> {
    vec![
        // Recon: a structured threat model (its whole final answer) carrying a
        // one-task queue. Reports a session id so the fork-from-recon path is
        // exercised.
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
        // Hunter: one finding (with confidence), one gap.
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

/// The findings a review prompt embeds: its first ```json block.
fn prompt_findings(prompt: &str) -> Vec<Value> {
    serde_json::from_str(extract_json_block(prompt).unwrap()).unwrap()
}

fn confirm_all(prompt: &str) -> String {
    let reviews: Vec<Value> = prompt_findings(prompt)
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

/// Session id the mock recon agent reports; hunters must fork from it.
const RECON_SESSION_ID: &str = "recon-sess-abc123";

fn config_toml(target: &str, scratch: &str, out: &str, db: &str, stages: &str) -> String {
    format!(
        r#"
[run]
target_dir = "{target}"
scratch_root = "{scratch}"
out_dir = "{out}"
concurrency = 4

[provider]
default = "claude-code"

[providers.claude-code]
type = "claude-code"

[firewall]
allow = ["api.anthropic.com"]

[report]
sink = "sqlite"
path = "{db}"

[stages]
enabled = [{stages}]
"#
    )
}

#[tokio::test]
async fn full_skeleton_pipeline_with_mock() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    std::fs::create_dir_all(&target).unwrap();
    let scratch = tmp.path().join("scratch");
    let out = tmp.path().join("out");
    let db = out.join("findings.db");

    let cfg_path = tmp.path().join("harness.toml");
    std::fs::write(
        &cfg_path,
        config_toml(
            target.to_str().unwrap(),
            scratch.to_str().unwrap(),
            out.to_str().unwrap(),
            db.to_str().unwrap(),
            r#""recon", "hunt", "validate", "report""#,
        ),
    )
    .unwrap();

    let cfg = Config::load(&cfg_path).unwrap();
    let runner = Arc::new(MockRunner::new(replies()));
    let pipeline = Pipeline::with_runner(cfg, runner).unwrap();
    pipeline.run().await.unwrap();

    // Artifacts produced by each stage.
    assert!(out.join("recon.json").exists(), "recon report missing");
    assert!(out.join("queue.jsonl").exists(), "queue missing");
    assert!(out.join("candidates.jsonl").exists(), "candidates missing");
    assert!(out.join("gaps.jsonl").exists(), "gaps missing");
    assert!(out.join("validated.jsonl").exists(), "validations missing");

    // One finding made it all the way into the store.
    let conn = rusqlite::Connection::open(&db).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1, "expected exactly one reported finding");
    let sev: String = conn
        .query_row("SELECT severity FROM findings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(sev, "high");

    // A findings JSONL is always written alongside the configured sink, even
    // though this run reports into sqlite.
    let jsonl = std::fs::read_to_string(out.join("findings.jsonl")).unwrap();
    let lines: Vec<&str> = jsonl.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "expected one finding in the JSONL tee");
    let payload: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(payload["severity"], "high");
    // The report is built from the reviewer's own impact and recommendation.
    assert_eq!(payload["impact"], "heap buffer overflow leading to RCE");
    assert_eq!(payload["verdict"], "confirmed");
    // Finding ids carry the run id, so they never collide with a past run's.
    let run_id = std::fs::read_to_string(out.join("run-id.txt")).unwrap();
    assert_eq!(payload["id"], format!("{}-T-0001-F01", run_id.trim()));
}

/// The feedback loop: run 1 writes seeds; run 2's recon merges them, so the
/// second run starts with more tasks than recon alone produced.
#[tokio::test]
async fn feedback_seeds_reach_the_next_recon_as_leads() {
    use fee1dead::domain::Task;

    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    std::fs::create_dir_all(&target).unwrap();
    let out = tmp.path().join("out");
    let db = out.join("findings.db");

    let cfg_path = tmp.path().join("harness.toml");
    std::fs::write(
        &cfg_path,
        config_toml(
            target.to_str().unwrap(),
            tmp.path().join("scratch").to_str().unwrap(),
            out.to_str().unwrap(),
            db.to_str().unwrap(),
            r#""recon", "hunt", "validate", "feedback""#,
        ),
    )
    .unwrap();

    // Run 1: recon emits 1 task; the confirmed finding + 1 gap become 2 seeds.
    let cfg = Config::load(&cfg_path).unwrap();
    Pipeline::with_runner(cfg, Arc::new(MockRunner::new(replies())))
        .unwrap()
        .run()
        .await
        .unwrap();

    let seeds: Vec<Task> = read_jsonl(&out.join("feedback-seeds.jsonl"));
    assert_eq!(seeds.len(), 2, "expected one variant seed + one gap seed");

    // Run 2 stops after recon: the seeds are in its prompt as leads, not
    // queued directly, and recon consumed them.
    std::fs::write(
        &cfg_path,
        std::fs::read_to_string(&cfg_path)
            .unwrap()
            .replace(r#""recon", "hunt", "validate", "feedback""#, r#""recon""#),
    )
    .unwrap();
    let runner = Arc::new(MockRunner::new(replies()));
    Pipeline::with_runner(Config::load(&cfg_path).unwrap(), runner.clone())
        .unwrap()
        .run()
        .await
        .unwrap();

    let recon_prompt = runner.seen.lock().unwrap()[0].clone();
    assert!(
        recon_prompt.contains("<leads>"),
        "no leads block in recon's prompt"
    );
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

/// Recon records its session id, and the hunter forks from it.
#[tokio::test]
async fn hunters_fork_from_recon_session() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    std::fs::create_dir_all(&target).unwrap();
    let out = tmp.path().join("out");
    let db = out.join("findings.db");

    let cfg_path = tmp.path().join("harness.toml");
    std::fs::write(
        &cfg_path,
        config_toml(
            target.to_str().unwrap(),
            tmp.path().join("scratch").to_str().unwrap(),
            out.to_str().unwrap(),
            db.to_str().unwrap(),
            r#""recon", "hunt""#,
        ),
    )
    .unwrap();

    let cfg = Config::load(&cfg_path).unwrap();
    let runner = Arc::new(MockRunner::new(replies()));
    Pipeline::with_runner(cfg, runner.clone())
        .unwrap()
        .run()
        .await
        .unwrap();

    // Recon persisted its session id for downstream stages.
    let recorded = std::fs::read_to_string(out.join("recon-session.txt")).unwrap();
    assert_eq!(recorded.trim(), RECON_SESSION_ID);

    // The hunter asked to fork from exactly that session; recon itself did not.
    let resumes = runner.seen_resume.lock().unwrap();
    assert!(
        resumes.contains(&Some(RECON_SESSION_ID.to_string())),
        "a hunter should have forked from recon's session, saw: {resumes:?}"
    );
    assert_eq!(resumes.first(), Some(&None), "recon runs without forking");
}

/// With forking disabled, recon still records its session but hunters run cold.
#[tokio::test]
async fn fork_hunters_false_disables_forking() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    std::fs::create_dir_all(&target).unwrap();
    let out = tmp.path().join("out");
    let db = out.join("findings.db");

    let cfg_path = tmp.path().join("harness.toml");
    let mut toml = config_toml(
        target.to_str().unwrap(),
        tmp.path().join("scratch").to_str().unwrap(),
        out.to_str().unwrap(),
        db.to_str().unwrap(),
        r#""recon", "hunt""#,
    );
    toml = toml.replace("concurrency = 4", "concurrency = 4\nfork_hunters = false");
    std::fs::write(&cfg_path, toml).unwrap();

    let cfg = Config::load(&cfg_path).unwrap();
    let runner = Arc::new(MockRunner::new(replies()));
    Pipeline::with_runner(cfg, runner.clone())
        .unwrap()
        .run()
        .await
        .unwrap();

    let resumes = runner.seen_resume.lock().unwrap();
    assert!(
        resumes.iter().all(|r| r.is_none()),
        "no agent should fork when fork_hunters = false, saw: {resumes:?}"
    );
}

fn read_jsonl<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Vec<T> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Writes a config for `stages` under `tmp` and returns (config, out_dir).
fn setup(tmp: &std::path::Path, stages: &str) -> (Config, std::path::PathBuf) {
    let target = tmp.join("target");
    std::fs::create_dir_all(&target).unwrap();
    let out = tmp.join("out");
    let cfg_path = tmp.join("harness.toml");
    std::fs::write(
        &cfg_path,
        config_toml(
            target.to_str().unwrap(),
            tmp.join("scratch").to_str().unwrap(),
            out.to_str().unwrap(),
            out.join("findings.db").to_str().unwrap(),
            stages,
        )
        .replace("concurrency = 4", "concurrency = 1\nhunter_stagger_ms = 0"),
    )
    .unwrap();
    (Config::load(&cfg_path).unwrap(), out)
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

/// Counts, at each hunter start, the candidates already on disk.
struct CandidateProbe {
    inner: MockRunner,
    candidates: std::path::PathBuf,
    on_disk_at_start: std::sync::Mutex<Vec<usize>>,
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
        on_disk_at_start: Default::default(),
    });
    Pipeline::with_runner(cfg, probe.clone())
        .unwrap()
        .run()
        .await
        .unwrap();
    assert_eq!(*probe.on_disk_at_start.lock().unwrap(), vec![0, 1, 2]);
}

/// `--resume` continues a stopped run: recon is skipped, the queue it left is
/// hunted, and the run keeps its id.
#[tokio::test]
async fn resume_hunts_the_pending_queue_without_rerunning_recon() {
    let tmp = tempfile::tempdir().unwrap();
    // Run 1 stops after recon (as a usage limit before hunt would leave it).
    let (cfg, out) = setup(tmp.path(), r#""recon""#);
    Pipeline::with_runner(cfg, Arc::new(MockRunner::new(replies())))
        .unwrap()
        .run()
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

/// A failed stage is reported but does not stop the stages after it.
#[tokio::test]
async fn a_failed_stage_does_not_stop_the_rest() {
    let tmp = tempfile::tempdir().unwrap();
    let (cfg, out) = setup(tmp.path(), r#""recon", "hunt", "validate", "feedback""#);
    // No reviewer reply: the validate agent fails.
    let mut replies = replies();
    replies.retain(|r| r.match_substr.as_deref() != Some("You are the Reviewer"));
    let err = Pipeline::with_runner(cfg, Arc::new(MockRunner::new(replies)))
        .unwrap()
        .run()
        .await
        .unwrap_err();
    assert!(err.to_string().contains("validate"), "got: {err}");
    // Feedback still ran and recorded the hunter's gap for the next run.
    let seeds: Vec<Value> = read_jsonl(&out.join("feedback-seeds.jsonl"));
    assert_eq!(seeds.len(), 1);
}

/// A hunter whose answer does not parse is resumed once to rewrite it, and its
/// finding is kept instead of the whole task being discarded.
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
    Pipeline::with_runner(cfg, runner.clone())
        .unwrap()
        .run()
        .await
        .unwrap();

    let candidates: Vec<Value> = read_jsonl(&out.join("candidates.jsonl"));
    assert_eq!(candidates.len(), 1, "the repaired answer's finding is kept");
    let resumes = runner.seen_resume.lock().unwrap();
    assert_eq!(
        resumes.last().unwrap().as_deref(),
        Some("hunter-sess"),
        "the repair forks the hunter's own session"
    );
}
