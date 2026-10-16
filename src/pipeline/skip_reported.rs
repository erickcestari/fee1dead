//! skip-reported stage: drop candidates the sink already holds before
//! validate spends tokens on them. A no-op for sinks that upsert by id.
//!
//! Token overlap decides the clear cases; only the ambiguous band goes to a
//! cheap judge, which fails open: a duplicate issue is cheaper to close than
//! a real finding lost.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn};

use super::StageCtx;
use super::similarity::{finding_signature, jaccard, report_signature, tokenize};
use crate::artifacts::names;
use crate::config::Stage;
use crate::domain::Finding;
use crate::json_block;
use crate::provider::{AgentRequest, AgentResult, Effort};
use crate::store::{ExistingReport, build_sink};

/// At or above this overlap, a pair is a confident duplicate.
const DUP_HIGH: f64 = 0.6;
/// Below this, confidently distinct; in between goes to the judge.
const DUP_LOW: f64 = 0.2;

const JUDGE_PROMPT: &str = include_str!("../../prompts/report-dedupe.md");

pub async fn run(ctx: &StageCtx) -> Result<()> {
    // The report stage builds its own sink, keeping the stages decoupled.
    let existing = build_sink(&ctx.config.report)?.existing_reports()?;
    if existing.is_empty() {
        info!("skip-reported: the sink holds nothing already filed");
        return Ok(());
    }
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    if candidates.is_empty() {
        return Ok(());
    }
    let before = candidates.len();
    let kept = drop_reported(ctx, candidates, &existing).await?;
    ctx.artifacts.write_jsonl(names::CANDIDATES, &kept)?;
    info!(
        before,
        after = kept.len(),
        pruned = before - kept.len(),
        existing = existing.len(),
        "skip-reported complete"
    );
    Ok(())
}

/// The algorithmic verdict against the closest existing report.
#[derive(Debug, PartialEq)]
enum Band {
    Duplicate,
    Distinct,
    /// Escalate to the judge against the existing report at this index.
    Uncertain(usize),
}

async fn drop_reported(
    ctx: &StageCtx,
    candidates: Vec<Finding>,
    existing: &[ExistingReport],
) -> Result<Vec<Finding>> {
    let existing_tokens: Vec<HashSet<String>> = existing
        .iter()
        .map(|e| tokenize(&report_signature(e)))
        .collect();
    let mut duplicate = vec![false; candidates.len()];
    let slots = Arc::new(Semaphore::new(ctx.config.run.concurrency));
    let mut judging = JoinSet::new();
    for (i, finding) in candidates.iter().enumerate() {
        match classify(&tokenize(&finding_signature(finding)), &existing_tokens) {
            Band::Distinct => {}
            Band::Duplicate => duplicate[i] = true,
            Band::Uncertain(closest) => {
                let req = judge_request(ctx, finding, &existing[closest])?;
                let runner = Arc::clone(&ctx.runner);
                let slots = Arc::clone(&slots);
                let id = finding.id.clone();
                judging.spawn(async move {
                    let _slot = slots.acquire_owned().await.expect("never closed");
                    (i, judge_verdict(&id, runner.run(req).await))
                });
            }
        }
    }
    while let Some(done) = judging.join_next().await {
        let (i, verdict) = done.context("dedup judge panicked")?;
        duplicate[i] = verdict;
    }

    let mut kept = Vec::new();
    for (finding, duplicate) in candidates.into_iter().zip(duplicate) {
        if duplicate {
            info!(id = %finding.id, "pruning candidate already reported");
        } else {
            kept.push(finding);
        }
    }
    Ok(kept)
}

fn classify(tokens: &HashSet<String>, existing: &[HashSet<String>]) -> Band {
    let (best, score) = existing
        .iter()
        .map(|e| jaccard(tokens, e))
        .enumerate()
        .fold(
            (0, 0.0),
            |(bi, bs), (i, s)| if s > bs { (i, s) } else { (bi, bs) },
        );
    if score >= DUP_HIGH {
        Band::Duplicate
    } else if score < DUP_LOW {
        Band::Distinct
    } else {
        Band::Uncertain(best)
    }
}

fn judge_request(
    ctx: &StageCtx,
    finding: &Finding,
    existing: &ExistingReport,
) -> Result<AgentRequest> {
    let prompt = JUDGE_PROMPT
        .replace("{new_finding}", &finding_signature(finding))
        .replace(
            "{existing_finding}",
            &format!("{}\n{}", existing.title, existing.text),
        );
    Ok(AgentRequest {
        // It compares two texts; it reads no code.
        extra_dirs: Vec::new(),
        ..ctx.agent_request(Stage::SkipReported, &finding.id, prompt, Effort::Low)?
    })
}

/// Fails open: any judge error keeps the candidate.
fn judge_verdict(id: &str, out: Result<AgentResult>) -> bool {
    match out {
        Ok(result) => parse_duplicate_verdict(&result.stdout),
        Err(e) => {
            warn!(id, error = %e, "dedup judge failed; keeping candidate");
            false
        }
    }
}

/// `{"duplicate": bool}`; anything unparseable means "keep".
fn parse_duplicate_verdict(stdout: &str) -> bool {
    json_block::extract(stdout)
        .and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok())
        .and_then(|v| v["duplicate"].as_bool())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::similarity::signature;

    fn tokens(title: &str, location: &str, class: &str) -> HashSet<String> {
        tokenize(&signature(title, location, class))
    }

    #[tokio::test]
    async fn concurrent_verdicts_land_on_their_own_candidates() {
        use crate::artifacts::Artifacts;
        use crate::provider::{CannedReply, MockRunner};
        use crate::scratch::ScratchRoot;

        let dir = tempfile::tempdir().unwrap();
        let config = toml::from_str(
            r#"
[run]
target_dir = "/t"
scratch_root = "/s"
out_dir = "/o"
concurrency = 2
[provider]
default = "c"
[providers.c]
type = "claude-code"
[firewall]
allow = ["x"]
[report]
sink = "jsonl"
path = "/o/f.jsonl"
[stages]
enabled = ["skip-reported"]
"#,
        )
        .unwrap();
        let reply = |match_substr: Option<&str>, stdout: &str| CannedReply {
            match_substr: match_substr.map(Into::into),
            stdout: stdout.into(),
            session_id: None,
            render: None,
        };
        let ctx = StageCtx {
            config,
            artifacts: Artifacts::new(dir.path().join("out")).unwrap(),
            scratch: ScratchRoot::new(dir.path().join("scratch")).unwrap(),
            runner: Arc::new(MockRunner::new(vec![
                reply(Some("Unbounded allocation"), "{\"duplicate\": true}"),
                reply(None, "{\"duplicate\": false}"),
            ])),
        };
        let existing = [ExistingReport {
            id: "old".into(),
            title: "Missing bounds check before allocation".into(),
            location: "src/net.rs:42".into(),
            attack_class: "dos".into(),
            text: String::new(),
        }];
        let candidate = |id: &str, title: &str, location: &str, class: &str| Finding {
            title: title.into(),
            location: location.into(),
            attack_class: class.into(),
            ..crate::domain::fixtures::finding(id)
        };
        let candidates = vec![
            // Uncertain, judged a duplicate.
            candidate(
                "a",
                "Unbounded allocation from length field",
                "src/net.rs:42",
                "resource exhaustion",
            ),
            candidate(
                "b",
                "Integer overflow in parser",
                "src/parse.rs:900",
                "overflow",
            ),
            candidate(
                "c",
                "Missing bounds check before allocation",
                "src/net.rs:42",
                "dos",
            ),
            // Uncertain, judged new.
            candidate(
                "d",
                "Missing length check before copy",
                "src/net.rs:42",
                "memory",
            ),
        ];
        let kept = drop_reported(&ctx, candidates, &existing).await.unwrap();
        let ids: Vec<&str> = kept.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["b", "d"]);
    }

    #[test]
    fn identical_signatures_are_duplicates() {
        let existing = [tokens(
            "Unbounded alloc",
            "src/net.rs:42",
            "resource exhaustion",
        )];
        let s = tokens("Unbounded alloc", "src/net.rs:42", "resource exhaustion");
        assert_eq!(classify(&s, &existing), Band::Duplicate);
    }

    #[test]
    fn unrelated_signatures_are_distinct() {
        let existing = [tokens(
            "SQL injection in login",
            "src/auth.rs:10",
            "injection",
        )];
        let s = tokens("Integer overflow in parser", "src/parse.rs:900", "overflow");
        assert_eq!(classify(&s, &existing), Band::Distinct);
        assert_eq!(classify(&s, &[]), Band::Distinct);
    }

    #[test]
    fn partial_overlap_is_uncertain_and_points_at_the_closest() {
        let existing = [
            tokens("Totally unrelated thing", "x/y.rs:1", "misc"),
            tokens(
                "Missing bounds check before allocation",
                "src/net.rs:42",
                "dos",
            ),
        ];
        let s = tokens(
            "Unbounded allocation from length field",
            "src/net.rs:42",
            "resource exhaustion",
        );
        assert_eq!(classify(&s, &existing), Band::Uncertain(1));
    }

    #[test]
    fn a_report_filed_with_a_long_body_still_matches() {
        let existing = ExistingReport {
            id: "old-T-0003-F01".into(),
            title: "Unbounded alloc".into(),
            location: "src/net.rs:42".into(),
            attack_class: "resource exhaustion".into(),
            text: "## Description\n\n".to_string() + &"lots of prose ".repeat(40),
        };
        let s = tokens("Unbounded alloc", "src/net.rs:42", "resource exhaustion");
        assert_eq!(
            classify(&s, &[tokenize(&report_signature(&existing))]),
            Band::Duplicate
        );
    }

    #[test]
    fn verdict_parses_the_flag_and_fails_open() {
        assert!(parse_duplicate_verdict("{\"duplicate\": true}"));
        assert!(!parse_duplicate_verdict("{\"duplicate\": false}"));
        assert!(!parse_duplicate_verdict("not json"));
        assert!(!parse_duplicate_verdict("{\"other\": 1}"));
    }
}
