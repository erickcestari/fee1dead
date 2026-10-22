//! Validate stage: independent reviewers re-read the code and tag every
//! candidate, writing its impact and recommendation. Nothing is dropped: an
//! unproven bug is `needs_review`.
//!
//! Batches by file keep each reviewer within its timeout. Incremental, so
//! `--resume` reviews only what failed batches left.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn};

use super::salvage::run_parsed;
use super::wishlist::{self, RawWish};
use super::{StageCtx, prompt};
use crate::artifacts::names;
use crate::config::Stage;
use crate::domain::{Finding, Severity, Validation, Verdict, Wish};
use crate::json_block;
use crate::provider::AgentRequest;

const PROMPT: &str = include_str!("../../prompts/validate.md");

/// Enough to share reading across a file, few enough that verifying each
/// fits the agent timeout.
const BATCH_SIZE: usize = 8;

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
    #[serde(default)]
    wish: Option<RawWish>,
}

pub async fn run(ctx: &StageCtx) -> Result<()> {
    ctx.artifacts.ensure_jsonl(names::VALIDATED)?;
    let reviewed: HashSet<String> = ctx
        .artifacts
        .read_jsonl::<Validation>(names::VALIDATED)?
        .into_iter()
        .map(|v| v.finding_id)
        .collect();
    let pending: Vec<Finding> = ctx
        .artifacts
        .read_jsonl::<Finding>(names::CANDIDATES)?
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
            let out = run_parsed(runner.as_ref(), req, |r| {
                json_block::parse::<Vec<RawReview>>(&r.stdout, "review array")
            })
            .await;
            (batch, out)
        });
    }

    let mut counts: HashMap<Verdict, usize> = HashMap::new();
    let (mut failed, mut unreviewed, mut wishes) = (0, 0, 0);
    while let Some(done) = running.join_next().await {
        let (batch, out) = done.context("review task panicked")?;
        match out {
            Ok(mut reviews) => {
                for wish in review_wishes(&batch, &mut reviews) {
                    ctx.artifacts.append_jsonl(names::WISHLIST, &wish)?;
                    wishes += 1;
                }
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
        wishes,
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

/// Keyed by the batch's first finding id, unique across runs.
fn review_request(ctx: &StageCtx, batch: &[Finding]) -> Result<AgentRequest> {
    let cfg = &ctx.config;
    let prompt = review_prompt(&cfg.run.target_dir.to_string_lossy(), batch)
        + &prompt::reference_note(cfg)
        + prompt::skills_directive(cfg);
    Ok(AgentRequest {
        working_dir: cfg.run.target_dir.clone(),
        ..ctx.agent_request(Stage::Validate, &batch[0].id, prompt)?
    })
}

fn review_prompt(target_dir: &str, batch: &[Finding]) -> String {
    PROMPT
        .replace("{target_dir}", target_dir)
        .replace("{wish_kinds}", wishlist::KINDS)
        .replace("{severity_scale}", prompt::severity_scale())
        // Last, so no placeholder in a finding's text is ever substituted.
        .replace("{findings_json}", &review_input(batch))
}

/// Split into batches of at most `max`, keeping each file's findings together
/// and neighbouring files adjacent, so a reviewer reads related code once.
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

/// The hunter's confidence is withheld: it is not needed for any verdict and
/// would anchor the reviewer. Severity stays, since a downgrade is against it.
fn review_input(batch: &[Finding]) -> String {
    let items: Vec<_> = batch
        .iter()
        .map(|f| {
            let mut item = json!({
                "finding_id": f.id,
                "title": f.title,
                "attack_class": f.attack_class,
                "severity": f.severity,
                "location": f.location,
                "description": f.description,
                "attack_scenario": f.attack_scenario,
            });
            if !f.trace.is_empty() {
                item["trace"] = json!(f.trace);
            }
            item
        })
        .collect();
    serde_json::to_string_pretty(&items).expect("a json array always serializes")
}

/// Take the reviewers' wishes, each tied to the finding it would settle. A
/// review of a finding outside the batch is ignored, as in [`reconcile`].
fn review_wishes(batch: &[Finding], reviews: &mut [RawReview]) -> Vec<Wish> {
    let tasks: HashMap<&str, &str> = batch
        .iter()
        .map(|f| (f.id.as_str(), f.task_id.as_str()))
        .collect();
    reviews
        .iter_mut()
        .filter_map(|r| {
            let task_id = tasks.get(r.finding_id.as_str())?;
            r.wish.take()?.into_wish(task_id, Some(&r.finding_id))
        })
        .collect()
}

/// Pair each finding with its review. One the reviewer omitted is kept as
/// `needs_review`: it reaches a human, but never as if confirmed.
/// `corrected_severity` holds only for `downgraded`, and impact and
/// recommendation only for reported verdicts.
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
                    corrected_severity: r
                        .corrected_severity
                        .filter(|_| r.verdict == Verdict::Downgraded),
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
    use crate::domain::fixtures::finding;

    fn at(id: &str, location: &str) -> Finding {
        Finding {
            location: location.into(),
            ..finding(id)
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
            wish: None,
        }
    }

    #[test]
    fn parses_a_review_array() {
        let out = "```json\n[{\"finding_id\":\"F-1\",\"verdict\":\"confirmed\",\"evidence\":\"e\",\"impact\":\"i\",\"recommendation\":\"r\"}]\n```";
        let reviews: Vec<RawReview> = json_block::parse(out, "review array").unwrap();
        assert_eq!(reviews[0].verdict, Verdict::Confirmed);
        assert_eq!(reviews[0].impact, "i");
        assert!(json_block::parse::<Vec<RawReview>>("{\"finding_id\":1}", "review array").is_err());
    }

    #[test]
    fn review_prompt_fills_the_severity_scale() {
        let text = review_prompt("/t", &[finding("F-1")]);
        assert!(text.contains(prompt::severity_scale()));
        assert!(!text.contains("{severity_scale}"));
    }

    #[test]
    fn review_input_withholds_the_hunters_confidence() {
        let input: Vec<serde_json::Value> =
            serde_json::from_str(&review_input(&[finding("F-1")])).unwrap();
        assert_eq!(input[0]["finding_id"], "F-1");
        assert_eq!(input[0]["severity"], "high");
        assert!(input[0].get("confidence").is_none());
        assert!(input[0].get("trace").is_none());
    }

    #[test]
    fn review_input_carries_the_trace() {
        let f = Finding {
            trace: serde_json::from_str(r#"[{"kind": "sink", "location": "a.rs:9"}]"#).unwrap(),
            ..finding("F-1")
        };
        let input: Vec<serde_json::Value> = serde_json::from_str(&review_input(&[f])).unwrap();
        assert_eq!(input[0]["trace"][0]["kind"], "sink");
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
        assert_eq!(batches[0], ["a0", "a1", "a2", "b0", "b1", "b2"]);
        assert_eq!(batches[1].len(), 8);
        assert_eq!(batches[2], ["c8", "c9", "d0"]);
    }

    #[test]
    fn reconcile_keeps_fields_only_where_they_apply() {
        let batch = vec![finding("F-1"), finding("F-2"), finding("F-3")];
        let reviews = vec![
            RawReview {
                corrected_severity: Some(Severity::Low),
                ..review("F-1", Verdict::Downgraded)
            },
            // A stray severity on a confirmed finding is dropped.
            RawReview {
                corrected_severity: Some(Severity::Critical),
                ..review("F-2", Verdict::Confirmed)
            },
            review("F-3", Verdict::LikelyFalsePositive),
        ];
        let v = reconcile(&batch, reviews);
        assert_eq!(v[0].corrected_severity, Some(Severity::Low));
        assert_eq!(v[0].impact, "attacker drains the channel");
        assert_eq!(v[1].corrected_severity, None);
        assert!(v[2].impact.is_empty() && v[2].recommendation.is_empty());
    }

    #[test]
    fn a_wish_is_tied_to_the_finding_it_would_settle() {
        let batch = vec![Finding {
            task_id: "T-0004".into(),
            ..finding("F-1")
        }];
        let wish = || serde_json::from_str(r#"{"kind": "source", "need": "the codec"}"#).ok();
        let mut reviews = vec![
            RawReview {
                wish: wish(),
                ..review("F-1", Verdict::NeedsReview)
            },
            RawReview {
                wish: wish(),
                ..review("not-in-batch", Verdict::NeedsReview)
            },
        ];
        let wishes = review_wishes(&batch, &mut reviews);
        assert_eq!(wishes.len(), 1);
        assert_eq!(wishes[0].task_id, "T-0004");
        assert_eq!(wishes[0].finding_id.as_deref(), Some("F-1"));
        assert_eq!(reconcile(&batch, reviews)[0].verdict, Verdict::NeedsReview);
    }

    #[test]
    fn an_unreviewed_finding_is_kept_for_human_review_not_confirmed() {
        let batch = vec![finding("F-1"), finding("F-2")];
        let v = reconcile(&batch, vec![review("F-1", Verdict::LikelyFalsePositive)]);
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].finding_id, "F-2");
        assert_eq!(v[1].verdict, Verdict::NeedsReview);
        assert!(v[1].evidence.contains("no verdict"));
    }
}
