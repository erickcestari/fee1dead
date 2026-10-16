//! skip-reported stage: drop candidates the sink already holds before
//! validate spends tokens on them. A no-op for sinks that upsert by id.
//!
//! Token overlap decides the clear cases; only the ambiguous band goes to a
//! cheap judge, which fails open: a duplicate issue is cheaper to close than
//! a real finding lost.

use std::collections::HashSet;

use anyhow::Result;
use tracing::{info, warn};

use super::StageCtx;
use super::similarity::{jaccard, tokenize};
use crate::artifacts::names;
use crate::config::Stage;
use crate::domain::Finding;
use crate::json_block;
use crate::provider::{AgentRequest, Effort};
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
    let mut kept = Vec::new();
    for finding in candidates {
        let duplicate = match classify(&tokenize(&finding_signature(&finding)), &existing_tokens) {
            Band::Distinct => false,
            Band::Duplicate => true,
            Band::Uncertain(i) => judge_is_duplicate(ctx, &finding, &existing[i]).await?,
        };
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

/// Fails open: any judge error keeps the candidate.
async fn judge_is_duplicate(
    ctx: &StageCtx,
    finding: &Finding,
    existing: &ExistingReport,
) -> Result<bool> {
    let prompt = JUDGE_PROMPT
        .replace("{new_finding}", &finding_signature(finding))
        .replace(
            "{existing_finding}",
            &format!("{}\n{}", existing.title, existing.text),
        );
    let req = AgentRequest {
        // It compares two texts; it reads no code.
        extra_dirs: Vec::new(),
        ..ctx.agent_request(Stage::SkipReported, &finding.id, prompt, Effort::Low)?
    };
    match ctx.runner.run(req).await {
        Ok(result) => Ok(parse_duplicate_verdict(&result.stdout)),
        Err(e) => {
            warn!(id = %finding.id, error = %e, "dedup judge failed; keeping candidate");
            Ok(false)
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

/// The fields that identify a bug, not its prose. Scoring against a whole
/// issue body would dilute every overlap below [`DUP_LOW`].
fn signature(title: &str, location: &str, attack_class: &str) -> String {
    format!("{title} {location} {attack_class}")
}

fn finding_signature(f: &Finding) -> String {
    signature(&f.title, &f.location, &f.attack_class)
}

fn report_signature(e: &ExistingReport) -> String {
    signature(&e.title, &e.location, &e.attack_class)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(title: &str, location: &str, class: &str) -> HashSet<String> {
        tokenize(&signature(title, location, class))
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
    fn signature_uses_identity_fields_only() {
        let f = Finding {
            title: "Bug".into(),
            attack_class: "dos".into(),
            description: "long prose that should not dominate the signature".into(),
            ..crate::domain::fixtures::finding("F-1")
        };
        let s = finding_signature(&f);
        assert!(s.contains("Bug") && s.contains("a.rs:1") && s.contains("dos"));
        assert!(!s.contains("prose"));
    }

    #[test]
    fn verdict_parses_the_flag_and_fails_open() {
        assert!(parse_duplicate_verdict("{\"duplicate\": true}"));
        assert!(!parse_duplicate_verdict("{\"duplicate\": false}"));
        assert!(!parse_duplicate_verdict("not json"));
        assert!(!parse_duplicate_verdict("{\"other\": 1}"));
    }
}
