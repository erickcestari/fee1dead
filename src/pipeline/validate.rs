//! Validate stage: independent reviewers re-read the code and tag every
//! candidate finding, in parallel batches of findings grouped by file.
//!
//! It never deletes findings — it assigns a verdict (confirmed / downgraded /
//! likely_false_positive / needs_review) so a real-but-unproven bug is surfaced
//! for review rather than silently dropped. Having traced each bug, the
//! reviewer also writes its impact and recommendation, which is everything the
//! report stage needs.
//!
//! Batches bound each reviewer's load: one agent reviewing a whole run's
//! findings outlasts its timeout, while a few findings in nearby code share
//! the reading. Validation is incremental: findings already in
//! `validated.jsonl` are skipped, so `run --resume` reviews only the findings
//! of batches that failed.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn};

use super::StageCtx;
use super::salvage::run_parsed;
use crate::artifacts::{extract_json_block, names};
use crate::domain::{Finding, Severity, Validation, Verdict};
use crate::provider::{AgentRequest, Effort};

const PROMPT: &str = include_str!("../../prompts/validate.md");

/// Most findings one reviewer takes. Enough to share reading across a file,
/// few enough that full verification of each fits the agent timeout.
const BATCH_SIZE: usize = 8;

/// One reviewer verdict, keyed back to the finding by id.
#[derive(Debug, Deserialize)]
struct RawReview {
    finding_id: String,
    verdict: Verdict,
    #[serde(default)]
    evidence: String,
    #[serde(default)]
    corrected_severity: Option<Severity>,
    #[serde(default)]
    impact: String,
    #[serde(default)]
    recommendation: String,
}

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    ctx.artifacts.ensure_jsonl(names::VALIDATED)?;
    let reviewed: HashSet<String> = ctx
        .artifacts
        .read_jsonl::<Validation>(names::VALIDATED)?
        .into_iter()
        .map(|v| v.finding_id)
        .collect();
    let pending: Vec<Finding> = candidates
        .into_iter()
        .filter(|f| !reviewed.contains(&f.id))
        .collect();
    if pending.is_empty() {
        info!("no unreviewed findings");
        return Ok(());
    }

    let batches = batch_by_file(pending, BATCH_SIZE);
    let total = batches.len();
    let slots = Arc::new(Semaphore::new(ctx.config.run.concurrency));
    let mut running = JoinSet::new();
    for batch in batches {
        let req = review_request(ctx, &batch)?;
        let runner = Arc::clone(&ctx.runner);
        let slots = Arc::clone(&slots);
        running.spawn(async move {
            let _slot = slots.acquire_owned().await.expect("never closed");
            let out = run_parsed(runner.as_ref(), req, |r| parse_reviews(&r.stdout)).await;
            (batch, out)
        });
    }

    // Each batch's verdicts are persisted as soon as it finishes.
    let mut counts: HashMap<Verdict, usize> = HashMap::new();
    let (mut failed, mut unreviewed) = (0usize, 0usize);
    while let Some(done) = running.join_next().await {
        let (batch, out) = done.context("review task panicked")?;
        match out {
            Ok(reviews) => {
                for v in reconcile(&batch, reviews) {
                    *counts.entry(v.verdict).or_default() += 1;
                    ctx.artifacts.append_jsonl(names::VALIDATED, &v)?;
                }
            }
            Err(e) => {
                failed += 1;
                unreviewed += batch.len();
                warn!(
                    findings = batch.len(),
                    error = format!("{e:#}"),
                    "review batch failed"
                );
            }
        }
    }
    let count = |v| counts.get(&v).copied().unwrap_or(0);
    info!(
        batches = total,
        failed,
        confirmed = count(Verdict::Confirmed),
        downgraded = count(Verdict::Downgraded),
        likely_fp = count(Verdict::LikelyFalsePositive),
        needs_review = count(Verdict::NeedsReview),
        "review complete"
    );
    if failed > 0 {
        bail!(
            "{failed} of {total} review batches failed; `fee1dead run --resume` reviews \
             their {unreviewed} findings"
        );
    }
    Ok(())
}

/// The reviewer request for one batch. Its label (the batch's first finding
/// id, unique across runs) keeps each batch's scratch dir and transcript apart.
fn review_request(ctx: &StageCtx, batch: &[Finding]) -> Result<AgentRequest> {
    let label = format!("validate-{}", batch[0].id);
    let prompt = PROMPT
        .replace("{target_dir}", &ctx.config.run.target_dir.to_string_lossy())
        .replace("{findings_json}", &review_input(batch))
        + &ctx.config.reference.prompt_note()
        + &ctx.config.run.skills_directive();
    Ok(AgentRequest {
        prompt,
        system: None,
        // Reviewing re-reads the source, so it runs in the target dir; it
        // answers into a private dir since the target may be read-only.
        working_dir: ctx.config.run.target_dir.clone(),
        output_dir: ctx.scratch.for_agent(&label)?,
        extra_dirs: ctx
            .config
            .reference
            .active_dir()
            .map(|d| vec![d.to_path_buf()])
            .unwrap_or_default(),
        allowed_tools: Vec::new(),
        disallowed_tools: super::disabled_tools(),
        timeout: Duration::from_secs(ctx.config.run.agent_timeout_secs),
        resume: None,
        // Leaf agent: nothing forks from it, so the default 5m cache suffices.
        cache_1h: false,
        // Re-tracing a specific claim to confirm or refute it: careful, but
        // bounded, not open-ended discovery. High is plenty; xhigh is marginal.
        effort: Effort::High,
        model: ctx.config.stage_model("validate"),
        stream_log_path: Some(ctx.artifacts.log_path(&format!("{label}.jsonl"))),
    })
}

/// Split findings into review batches of at most `max`, keeping each file's
/// findings together and neighbouring files adjacent, so a reviewer reads
/// related code once. A file with more than `max` findings spans batches.
fn batch_by_file(mut findings: Vec<Finding>, max: usize) -> Vec<Vec<Finding>> {
    assert!(max > 0, "batch size must be positive");
    // Stable, so findings keep their order within a file.
    findings.sort_by(|a, b| a.file().cmp(b.file()));
    let mut groups: Vec<Vec<Finding>> = Vec::new();
    for f in findings {
        match groups.last_mut() {
            Some(group) if group[0].file() == f.file() => group.push(f),
            _ => groups.push(vec![f]),
        }
    }

    let mut batches = Vec::new();
    let mut current: Vec<Finding> = Vec::new();
    for group in groups {
        if !current.is_empty() && current.len() + group.len() > max {
            batches.push(std::mem::take(&mut current));
        }
        for f in group {
            current.push(f);
            if current.len() == max {
                batches.push(std::mem::take(&mut current));
            }
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
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
    // Pretty so the model reads it cleanly; batches are never empty, so the
    // "[]" fallback is unreachable.
    serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".into())
}

/// Pull the reviewer's verdict array out of its (possibly prose-wrapped) output.
fn parse_reviews(stdout: &str) -> Result<Vec<RawReview>> {
    let json = extract_json_block(stdout).context("reviewer output had no json block")?;
    serde_json::from_str(json).context("reviewer output was not a valid review array")
}

/// Pair each finding in a batch with its review. A finding the reviewer
/// omitted is kept (tag-don't-drop) as `needs_review`: it still reaches a
/// human, but is never filed as if it had been confirmed. `corrected_severity`
/// is honored only for `downgraded`, and impact and recommendation only for
/// verdicts that are reported.
fn reconcile(batch: &[Finding], reviews: Vec<RawReview>) -> Vec<Validation> {
    let mut by_id: HashMap<String, RawReview> = reviews
        .into_iter()
        .map(|r| (r.finding_id.clone(), r))
        .collect();

    batch
        .iter()
        .map(|f| match by_id.remove(&f.id) {
            Some(r) => {
                let reported = r.verdict.is_reportable();
                Validation {
                    finding_id: f.id.clone(),
                    corrected_severity: match r.verdict {
                        Verdict::Downgraded => r.corrected_severity,
                        _ => None,
                    },
                    verdict: r.verdict,
                    evidence: r.evidence,
                    impact: if reported { r.impact } else { String::new() },
                    recommendation: if reported {
                        r.recommendation
                    } else {
                        String::new()
                    },
                }
            }
            None => Validation {
                finding_id: f.id.clone(),
                verdict: Verdict::NeedsReview,
                evidence: "reviewer returned no verdict for this finding".into(),
                corrected_severity: None,
                impact: String::new(),
                recommendation: String::new(),
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str) -> Finding {
        at(id, "a.rs:1")
    }

    fn at(id: &str, location: &str) -> Finding {
        Finding {
            id: id.into(),
            task_id: "T".into(),
            title: "t".into(),
            attack_class: "c".into(),
            severity: Severity::High,
            location: location.into(),
            description: "d".into(),
            confidence: 0.5,
            poc_path: None,
        }
    }

    fn review(id: &str, verdict: Verdict) -> RawReview {
        RawReview {
            finding_id: id.into(),
            verdict,
            evidence: "e".into(),
            corrected_severity: None,
            impact: "attacker drains the channel".into(),
            recommendation: "check the bound".into(),
        }
    }

    #[test]
    fn parses_review_array_with_impact_and_recommendation() {
        let out = "```json\n[{\"finding_id\":\"F-1\",\"verdict\":\"confirmed\",\"evidence\":\"e\",\"impact\":\"i\",\"recommendation\":\"r\"}]\n```";
        let reviews = parse_reviews(out).unwrap();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].verdict, Verdict::Confirmed);
        assert_eq!(reviews[0].impact, "i");
        assert_eq!(reviews[0].recommendation, "r");
    }

    #[test]
    fn rejects_non_array_output() {
        assert!(parse_reviews("no json here").is_err());
    }

    #[test]
    fn batches_keep_a_files_findings_together_and_split_oversized_files() {
        let mut input = Vec::new();
        for i in 0..3 {
            input.push(at(&format!("b{i}"), &format!("src/b.rs:{i}")));
            input.push(at(&format!("a{i}"), &format!("src/a.rs:{i}")));
        }
        for i in 0..10 {
            input.push(at(&format!("c{i}"), &format!("src/c.rs:{i}")));
        }
        input.push(at("d0", "src/d.rs:1"));

        let ids = |b: &Vec<Finding>| b.iter().map(|f| f.id.clone()).collect::<Vec<_>>();
        let batches: Vec<Vec<String>> = batch_by_file(input, 8).iter().map(ids).collect();
        assert_eq!(batches.len(), 3);
        // a.rs and b.rs fit together, in file order.
        assert_eq!(batches[0], ["a0", "a1", "a2", "b0", "b1", "b2"]);
        // c.rs has 10: a full batch, then its rest shares with d.rs.
        assert_eq!(batches[1].len(), 8);
        assert_eq!(batches[2], ["c8", "c9", "d0"]);
    }

    #[test]
    fn reconcile_matches_by_id_and_keeps_fields_only_where_they_apply() {
        let batch = vec![finding("F-1"), finding("F-2"), finding("F-3")];
        let mut downgraded = review("F-1", Verdict::Downgraded);
        downgraded.corrected_severity = Some(Severity::Low);
        // Confirmed but the reviewer left a stray severity: must be dropped.
        let mut confirmed = review("F-2", Verdict::Confirmed);
        confirmed.corrected_severity = Some(Severity::Critical);
        let reviews = vec![
            downgraded,
            confirmed,
            review("F-3", Verdict::LikelyFalsePositive),
        ];
        let v = reconcile(&batch, reviews);
        assert_eq!(v[0].verdict, Verdict::Downgraded);
        assert_eq!(v[0].corrected_severity, Some(Severity::Low));
        assert_eq!(v[0].impact, "attacker drains the channel");
        assert_eq!(v[1].verdict, Verdict::Confirmed);
        assert_eq!(v[1].corrected_severity, None);
        // A likely false positive is not reported, so it carries no impact.
        assert_eq!(v[2].verdict, Verdict::LikelyFalsePositive);
        assert!(v[2].impact.is_empty() && v[2].recommendation.is_empty());
    }

    #[test]
    fn unreviewed_finding_is_kept_for_human_review_not_confirmed() {
        // Tag-don't-drop: a finding the reviewer ignored must still be
        // reported, but must not pass as reviewed.
        let batch = vec![finding("F-1"), finding("F-2")];
        let v = reconcile(&batch, vec![review("F-1", Verdict::LikelyFalsePositive)]);
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].finding_id, "F-2");
        assert_eq!(v[1].verdict, Verdict::NeedsReview);
        assert!(v[1].evidence.contains("no verdict"));
    }
}
