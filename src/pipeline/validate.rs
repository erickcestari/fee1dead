//! Validate stage: one independent reviewer re-reads the code and tags every
//! candidate finding in a single batched call.
//!
//! It never deletes findings — it assigns a verdict (confirmed / downgraded /
//! likely_false_positive) so a real-but-unproven bug is surfaced for review
//! rather than silently dropped. Reviewing the whole set in one call (instead
//! of one agent per finding) is both far cheaper and lets the reviewer weigh
//! findings against each other.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use super::StageCtx;
use crate::artifacts::{extract_json_block, names};
use crate::domain::{Finding, Severity, Validation, Verdict};
use crate::provider::{AgentRequest, Effort};

const PROMPT: &str = include_str!("../../prompts/validate.md");

/// One reviewer verdict, keyed back to the finding by id.
#[derive(Debug, Deserialize)]
struct RawReview {
    finding_id: String,
    verdict: Verdict,
    #[serde(default)]
    evidence: String,
    #[serde(default)]
    corrected_severity: Option<Severity>,
}

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    if candidates.is_empty() {
        warn!("no candidate findings to validate");
        ctx.artifacts
            .write_jsonl::<Validation>(names::VALIDATED, &[])?;
        return Ok(());
    }

    let target = ctx.config.run.target_dir.to_string_lossy().into_owned();
    let prompt = PROMPT
        .replace("{target_dir}", &target)
        .replace("{findings_json}", &review_input(&candidates))
        + &ctx.config.reference.prompt_note()
        + &ctx.config.run.skills_directive();

    // Reviewing re-reads the source, so it runs in the target dir.
    let req = AgentRequest {
        prompt,
        system: None,
        working_dir: ctx.config.run.target_dir.clone(),
        extra_dirs: ctx
            .config
            .reference
            .active_dir()
            .map(|d| vec![d.to_path_buf()])
            .unwrap_or_default(),
        allowed_tools: Vec::new(),
        disallowed_tools: super::disabled_tools(),
        timeout: Duration::from_secs(ctx.config.run.agent_timeout_secs),
        max_turns: None,
        resume: None,
        // Leaf agent: nothing forks from it, so the default 5m cache suffices.
        cache_1h: false,
        // Re-tracing a specific claim to confirm or refute it: careful, but
        // bounded, not open-ended discovery. High is plenty; xhigh is marginal.
        effort: Effort::High,
        model: None,
        stream_log_path: Some(ctx.artifacts.log_path("validate-review.jsonl")),
    };

    let result = ctx.runner.run(req).await.context("review agent failed")?;

    let reviews = parse_reviews(&result.stdout)?;
    let validations = reconcile(&candidates, reviews);

    let (mut confirmed, mut downgraded, mut likely_fp) = (0usize, 0usize, 0usize);
    for v in &validations {
        match v.verdict {
            Verdict::Confirmed => confirmed += 1,
            Verdict::Downgraded => downgraded += 1,
            Verdict::LikelyFalsePositive => likely_fp += 1,
        }
    }
    info!(confirmed, downgraded, likely_fp, "review complete");
    ctx.artifacts.write_jsonl(names::VALIDATED, &validations)?;
    Ok(())
}

/// Serialize the candidate set into the compact JSON the reviewer reads.
fn review_input(candidates: &[Finding]) -> String {
    let items: Vec<_> = candidates
        .iter()
        .map(|f| {
            json!({
                "finding_id": f.id,
                "title": f.title,
                "attack_class": f.attack_class,
                "severity": f.severity,
                "confidence": f.confidence,
                "location": f.location,
                "description": f.description,
            })
        })
        .collect();
    // Pretty so the model reads it cleanly; falls back to "[]" which the
    // empty-candidate guard above means we never actually hit.
    serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".into())
}

/// Pull the reviewer's verdict array out of its (possibly prose-wrapped) output.
fn parse_reviews(stdout: &str) -> Result<Vec<RawReview>> {
    let json = extract_json_block(stdout).context("reviewer output had no json block")?;
    serde_json::from_str(json).context("reviewer output was not a valid review array")
}

/// Pair each candidate with its review. A finding the reviewer omitted is kept
/// (tag-don't-drop) as `confirmed` so it still reaches a human, flagged as
/// unreviewed. `corrected_severity` is honored only for `downgraded`.
fn reconcile(candidates: &[Finding], reviews: Vec<RawReview>) -> Vec<Validation> {
    let mut by_id: HashMap<String, RawReview> = reviews
        .into_iter()
        .map(|r| (r.finding_id.clone(), r))
        .collect();

    candidates
        .iter()
        .map(|f| match by_id.remove(&f.id) {
            Some(r) => Validation {
                finding_id: f.id.clone(),
                corrected_severity: match r.verdict {
                    Verdict::Downgraded => r.corrected_severity,
                    _ => None,
                },
                verdict: r.verdict,
                evidence: r.evidence,
            },
            None => Validation {
                finding_id: f.id.clone(),
                verdict: Verdict::Confirmed,
                evidence: "reviewer returned no verdict for this finding".into(),
                corrected_severity: None,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str) -> Finding {
        Finding {
            id: id.into(),
            task_id: "T".into(),
            title: "t".into(),
            attack_class: "c".into(),
            severity: Severity::High,
            location: "a.rs:1".into(),
            description: "d".into(),
            confidence: 0.5,
            poc_path: None,
        }
    }

    #[test]
    fn parses_review_array() {
        let out =
            "```json\n[{\"finding_id\":\"F-1\",\"verdict\":\"confirmed\",\"evidence\":\"e\"}]\n```";
        let reviews = parse_reviews(out).unwrap();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].verdict, Verdict::Confirmed);
    }

    #[test]
    fn rejects_non_array_output() {
        assert!(parse_reviews("no json here").is_err());
    }

    #[test]
    fn reconcile_matches_by_id_and_keeps_corrected_severity_only_when_downgraded() {
        let candidates = vec![finding("F-1"), finding("F-2"), finding("F-3")];
        let reviews = vec![
            RawReview {
                finding_id: "F-1".into(),
                verdict: Verdict::Downgraded,
                evidence: "latent".into(),
                corrected_severity: Some(Severity::Low),
            },
            // Confirmed but reviewer left a stray severity: must be dropped.
            RawReview {
                finding_id: "F-2".into(),
                verdict: Verdict::Confirmed,
                evidence: "real".into(),
                corrected_severity: Some(Severity::Critical),
            },
            RawReview {
                finding_id: "F-3".into(),
                verdict: Verdict::LikelyFalsePositive,
                evidence: "guarded".into(),
                corrected_severity: None,
            },
        ];
        let v = reconcile(&candidates, reviews);
        assert_eq!(v[0].verdict, Verdict::Downgraded);
        assert_eq!(v[0].corrected_severity, Some(Severity::Low));
        assert_eq!(v[1].verdict, Verdict::Confirmed);
        assert_eq!(v[1].corrected_severity, None);
        assert_eq!(v[2].verdict, Verdict::LikelyFalsePositive);
    }

    #[test]
    fn unreviewed_finding_is_kept_as_confirmed_not_dropped() {
        // Tag-don't-drop: a finding the reviewer ignored must still be reported.
        let candidates = vec![finding("F-1"), finding("F-2")];
        let reviews = vec![RawReview {
            finding_id: "F-1".into(),
            verdict: Verdict::LikelyFalsePositive,
            evidence: "x".into(),
            corrected_severity: None,
        }];
        let v = reconcile(&candidates, reviews);
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].finding_id, "F-2");
        assert_eq!(v[1].verdict, Verdict::Confirmed);
        assert!(v[1].evidence.contains("no verdict"));
    }
}
