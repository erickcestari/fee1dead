//! Offline end-to-end test: drive the full skeleton pipeline with the mock
//! provider (no network, no API). Requires `--features mock-runner`.
#![cfg(feature = "mock-runner")]

use std::sync::Arc;

use fee1dead::config::Config;
use fee1dead::pipeline::Pipeline;
use fee1dead::provider::{CannedReply, MockRunner};

/// Canned agent responses keyed by a substring unique to each stage's prompt.
fn replies() -> Vec<CannedReply> {
    vec![
        // Recon: architecture doc + a one-task queue. Reports a session id so
        // the fork-from-recon path is exercised.
        CannedReply {
            match_substr: Some("You are the Recon agent".into()),
            stdout: r#"# Architecture

Build: `cargo build`. Entry point: src/parse.rs.

```json
[{"attack_class": "integer overflow", "scope_hint": "src/parse.rs decode loop"}]
```"#
                .into(),
            session_id: Some(RECON_SESSION_ID.into()),
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
        },
        // Reviewer: batched verdict array, keyed by finding_id. Confirms it.
        CannedReply {
            match_substr: Some("You are the Reviewer".into()),
            stdout: r#"```json
[{"finding_id": "T-0001-F01", "verdict": "confirmed", "evidence": "len*4 wraps for len > u32::MAX/4"}]
```"#
                .into(),
            session_id: None,
        },
        // Report: batched array of schema-valid records, keyed by id.
        CannedReply {
            match_substr: Some("You are the Report agent".into()),
            stdout: r#"```json
[{
  "id": "T-0001-F01",
  "title": "unchecked add overflows length",
  "attack_class": "integer overflow",
  "severity": "high",
  "location": "src/parse.rs:42",
  "description": "attacker-controlled length added without bounds check",
  "impact": "heap buffer overflow leading to RCE",
  "recommendation": "use checked_add and reject oversized lengths"
}]
```"#
                .into(),
            session_id: None,
        },
    ]
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
    assert!(out.join("ARCHITECTURE.md").exists(), "recon doc missing");
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
}

/// The feedback loop: run 1 writes seeds; run 2's recon merges them, so the
/// second run starts with more tasks than recon alone produced.
#[tokio::test]
async fn feedback_carries_seeds_into_next_run() {
    use fee1dead::domain::{Task, TaskOrigin};

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

    // Run 2: reuses the same out_dir; recon must merge the 2 carried seeds.
    let cfg = Config::load(&cfg_path).unwrap();
    Pipeline::with_runner(cfg, Arc::new(MockRunner::new(replies())))
        .unwrap()
        .run()
        .await
        .unwrap();

    let queue: Vec<Task> = read_jsonl(&out.join("queue.jsonl"));
    assert_eq!(
        queue.len(),
        3,
        "1 fresh recon task + 2 carried feedback seeds"
    );
    assert_eq!(
        queue
            .iter()
            .filter(|t| t.origin == TaskOrigin::Feedback)
            .count(),
        2
    );
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
