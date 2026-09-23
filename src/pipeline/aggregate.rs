//! Aggregate stage: compile every hunter's raw output into one reviewable JSON
//! document.
//!
//! Hunters append findings to `candidates.jsonl` and uncovered areas to
//! `gaps.jsonl` one line at a time, and the recon task that surfaced each
//! finding lives separately in `queue.jsonl`. Reviewing that means cross-
//! referencing several files. This stage joins them into a single
//! `findings.json`: findings ordered by severity (then confidence), each enriched
//! with its task's hypothesis and targets and, once validate has run, its
//! review (verdict, evidence, impact, recommendation), plus the gap list, the
//! findings Dedupe collapsed, and a summary.
//!
//! It is pure file IO and shaping with no agent call, so it always runs to
//! completion even when a run spends its whole token budget hunting. Run it as
//! the last pipeline stage so the reviews are in, or on its own with
//! `fee1dead aggregate` after a partial run.

use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;
use tracing::info;

use super::StageCtx;
use crate::artifacts::{Artifacts, names};
use crate::domain::{Duplicate, Finding, GapMarker, Severity, Task, Validation, Verdict};

pub async fn run(ctx: &StageCtx) -> Result<()> {
    write_report(&ctx.artifacts)
}

/// Read the hunters' artifacts, shape them into the report, and write
/// `findings.json`. Takes only [`Artifacts`] (no runner, target, or scratch) so
/// it can be invoked standalone against a partial run's `out_dir`.
pub fn write_report(artifacts: &Artifacts) -> Result<()> {
    let candidates: Vec<Finding> = artifacts.read_jsonl(names::CANDIDATES)?;
    let gaps: Vec<GapMarker> = artifacts.read_jsonl(names::GAPS)?;
    let tasks: Vec<Task> = artifacts.read_jsonl(names::QUEUE)?;
    let duplicates: Vec<Duplicate> = artifacts.read_jsonl(names::DUPLICATES)?;
    let validations: Vec<Validation> = artifacts.read_jsonl(names::VALIDATED)?;

    let report = aggregate(candidates, gaps, tasks, duplicates, validations);
    let json = serde_json::to_string_pretty(&report)?;
    artifacts.write_text(names::REPORT_JSON, &json)?;

    info!(
        findings = report.summary.findings,
        gaps = report.summary.gaps,
        file = names::REPORT_JSON,
        "aggregate complete"
    );
    Ok(())
}

/// The aggregated document written to `findings.json`.
#[derive(Debug, Serialize)]
struct Report {
    summary: Summary,
    findings: Vec<EnrichedFinding>,
    gaps: Vec<GapMarker>,
    /// Findings Dedupe folded into one of `findings`, for spotting a bad merge.
    duplicates: Vec<Duplicate>,
}

#[derive(Debug, Serialize)]
struct Summary {
    findings: usize,
    gaps: usize,
    duplicates: usize,
    /// By effective severity: the reviewer's correction where it made one.
    by_severity: SeverityCounts,
    /// Present once validate has run.
    #[serde(skip_serializing_if = "Option::is_none")]
    by_verdict: Option<VerdictCounts>,
}

#[derive(Debug, Default, Serialize)]
struct VerdictCounts {
    confirmed: usize,
    downgraded: usize,
    needs_review: usize,
    likely_false_positive: usize,
    /// Not yet reviewed, e.g. its review batch failed; `run --resume` retries.
    unreviewed: usize,
}

impl VerdictCounts {
    fn bump(&mut self, verdict: Option<Verdict>) {
        match verdict {
            Some(Verdict::Confirmed) => self.confirmed += 1,
            Some(Verdict::Downgraded) => self.downgraded += 1,
            Some(Verdict::NeedsReview) => self.needs_review += 1,
            Some(Verdict::LikelyFalsePositive) => self.likely_false_positive += 1,
            None => self.unreviewed += 1,
        }
    }
}

/// Per-severity finding tallies, ordered most-severe first for at-a-glance triage.
#[derive(Debug, Default, Serialize)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

impl SeverityCounts {
    fn bump(&mut self, sev: Severity) {
        match sev {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }
}

/// A finding flattened with the recon task context a reviewer needs, so the
/// finding can be triaged without opening `queue.jsonl` to recover its lead.
#[derive(Debug, Serialize)]
struct EnrichedFinding {
    #[serde(flatten)]
    finding: Finding,
    /// The task's lead, present only when the originating task is still in the
    /// queue (gapfill can re-queue, but a finding's task is normally present).
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<TaskContext>,
    /// The reviewer's verdict, present once validate has reviewed the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    review: Option<ReviewContext>,
}

impl EnrichedFinding {
    /// The severity that ships: the reviewer's correction, else the hunter's.
    fn severity(&self) -> Severity {
        self.review
            .as_ref()
            .and_then(|r| r.corrected_severity)
            .unwrap_or(self.finding.severity)
    }

    fn is_likely_false_positive(&self) -> bool {
        self.review
            .as_ref()
            .is_some_and(|r| r.verdict == Verdict::LikelyFalsePositive)
    }
}

/// A [`Validation`] without the finding id it sits under.
#[derive(Debug, Serialize)]
struct ReviewContext {
    verdict: Verdict,
    evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    corrected_severity: Option<Severity>,
    #[serde(skip_serializing_if = "String::is_empty")]
    impact: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    recommendation: String,
}

impl From<&Validation> for ReviewContext {
    fn from(v: &Validation) -> Self {
        Self {
            verdict: v.verdict,
            evidence: v.evidence.clone(),
            corrected_severity: v.corrected_severity,
            impact: v.impact.clone(),
            recommendation: v.recommendation.clone(),
        }
    }
}

/// The slice of a [`Task`] worth carrying alongside its findings.
#[derive(Debug, Serialize)]
struct TaskContext {
    hypothesis: String,
    targets: Vec<String>,
    tags: Vec<String>,
}

/// Join hunter output and reviews into one document: findings enriched with
/// their task's lead and review, plus gaps and a summary. Ordered for triage:
/// likely false positives last, then most severe (effective severity) first,
/// then the hunter's confidence. Pure so it is unit-testable without a
/// [`StageCtx`].
fn aggregate(
    candidates: Vec<Finding>,
    gaps: Vec<GapMarker>,
    tasks: Vec<Task>,
    duplicates: Vec<Duplicate>,
    validations: Vec<Validation>,
) -> Report {
    let tasks_by_id: HashMap<&str, &Task> = tasks.iter().map(|t| (t.id.as_str(), t)).collect();
    let reviews: HashMap<&str, &Validation> = validations
        .iter()
        .map(|v| (v.finding_id.as_str(), v))
        .collect();

    let mut findings: Vec<EnrichedFinding> = candidates
        .into_iter()
        .map(|f| EnrichedFinding {
            task: tasks_by_id.get(f.task_id.as_str()).map(|t| TaskContext {
                hypothesis: t.hypothesis.clone(),
                targets: t.targets.clone(),
                tags: t.tags.clone(),
            }),
            review: reviews.get(f.id.as_str()).map(|v| ReviewContext::from(*v)),
            finding: f,
        })
        .collect();

    let mut by_severity = SeverityCounts::default();
    let mut by_verdict = VerdictCounts::default();
    for f in &findings {
        by_severity.bump(f.severity());
        by_verdict.bump(f.review.as_ref().map(|r| r.verdict));
    }

    // Stable, so equal-rank findings keep candidates.jsonl order.
    findings.sort_by(|a, b| {
        a.is_likely_false_positive()
            .cmp(&b.is_likely_false_positive())
            .then(b.severity().cmp(&a.severity()))
            .then(
                b.finding
                    .confidence
                    .partial_cmp(&a.finding.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });

    Report {
        summary: Summary {
            findings: findings.len(),
            gaps: gaps.len(),
            duplicates: duplicates.len(),
            by_severity,
            by_verdict: (!validations.is_empty()).then_some(by_verdict),
        },
        findings,
        gaps,
        duplicates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Priority, TaskOrigin};

    fn finding(id: &str, task_id: &str, sev: Severity, confidence: f64) -> Finding {
        Finding {
            id: id.into(),
            task_id: task_id.into(),
            title: id.into(),
            attack_class: "c".into(),
            severity: sev,
            location: "a.rs:1".into(),
            description: "d".into(),
            confidence,
            poc_path: None,
        }
    }

    fn task(id: &str, hypothesis: &str) -> Task {
        Task {
            id: id.into(),
            attack_class: "c".into(),
            scope_hint: "s".into(),
            scope_paths: Vec::new(),
            hypothesis: hypothesis.into(),
            targets: vec!["a.rs:1".into()],
            suggested_skills: Vec::new(),
            tags: vec!["crypto".into()],
            priority: Priority::default(),
            origin: TaskOrigin::Recon,
        }
    }

    #[test]
    fn orders_by_severity_then_confidence() {
        let candidates = vec![
            finding("low", "T-1", Severity::Low, 0.9),
            finding("high-weak", "T-1", Severity::High, 0.2),
            finding("high-strong", "T-1", Severity::High, 0.8),
        ];
        let report = aggregate(candidates, vec![], vec![task("T-1", "h")], vec![], vec![]);
        let order: Vec<&str> = report
            .findings
            .iter()
            .map(|f| f.finding.id.as_str())
            .collect();
        assert_eq!(order, ["high-strong", "high-weak", "low"]);
    }

    #[test]
    fn enriches_with_task_context_and_counts_severities() {
        let candidates = vec![
            finding("f1", "T-1", Severity::High, 0.5),
            finding("f2", "T-1", Severity::High, 0.5),
            finding("f3", "T-2", Severity::Critical, 0.5),
        ];
        let report = aggregate(
            candidates,
            vec![],
            vec![task("T-1", "len unchecked")],
            vec![],
            vec![],
        );
        assert_eq!(report.summary.findings, 3);
        assert_eq!(report.summary.by_severity.high, 2);
        assert_eq!(report.summary.by_severity.critical, 1);
        // f1/f2 carry T-1's lead; f3's task is absent from the queue → no context.
        let f1 = report
            .findings
            .iter()
            .find(|f| f.finding.id == "f1")
            .unwrap();
        assert_eq!(f1.task.as_ref().unwrap().hypothesis, "len unchecked");
        let f3 = report
            .findings
            .iter()
            .find(|f| f.finding.id == "f3")
            .unwrap();
        assert!(
            f3.task.is_none(),
            "finding with no queued task has no context"
        );
    }

    #[test]
    fn collapsed_duplicates_are_listed_and_counted() {
        let dup = Duplicate {
            duplicate_of: "f1".into(),
            finding: finding("f2", "T-1", Severity::Low, 0.5),
        };
        let report = aggregate(
            vec![finding("f1", "T-1", Severity::High, 0.5)],
            vec![],
            vec![],
            vec![dup],
            vec![],
        );
        assert_eq!(report.summary.duplicates, 1);
        assert_eq!(report.duplicates[0].duplicate_of, "f1");
        assert_eq!(report.findings.len(), 1, "duplicates are not findings");
    }

    fn review(id: &str, verdict: Verdict, corrected: Option<Severity>) -> Validation {
        Validation {
            finding_id: id.into(),
            verdict,
            evidence: "e".into(),
            corrected_severity: corrected,
            impact: "i".into(),
            recommendation: "r".into(),
        }
    }

    #[test]
    fn reviews_attach_and_rank_by_effective_severity_with_false_positives_last() {
        let candidates = vec![
            finding("fp", "T-1", Severity::Critical, 0.9),
            finding("cut", "T-1", Severity::High, 0.9),
            finding("real", "T-1", Severity::Medium, 0.5),
            finding("pending", "T-1", Severity::Low, 0.5),
        ];
        let validations = vec![
            review("fp", Verdict::LikelyFalsePositive, None),
            review("cut", Verdict::Downgraded, Some(Severity::Info)),
            review("real", Verdict::Confirmed, None),
        ];
        let report = aggregate(candidates, vec![], vec![], vec![], validations);
        let order: Vec<&str> = report
            .findings
            .iter()
            .map(|f| f.finding.id.as_str())
            .collect();
        assert_eq!(order, ["real", "pending", "cut", "fp"]);
        let real = &report.findings[0];
        assert_eq!(real.review.as_ref().unwrap().impact, "i");
        let verdicts = report.summary.by_verdict.as_ref().unwrap();
        assert_eq!(
            (
                verdicts.confirmed,
                verdicts.downgraded,
                verdicts.likely_false_positive,
                verdicts.unreviewed
            ),
            (1, 1, 1, 1)
        );
        // Counted at the reviewer's corrected severity.
        assert_eq!(report.summary.by_severity.info, 1);
        assert_eq!(report.summary.by_severity.high, 0);
    }

    #[test]
    fn before_validate_there_is_no_verdict_summary() {
        let report = aggregate(
            vec![finding("f1", "T-1", Severity::Low, 0.5)],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("by_verdict") && !json.contains("\"review\""),
            "{json}"
        );
    }

    #[test]
    fn missing_task_context_is_omitted_from_json() {
        let report = aggregate(
            vec![finding("f1", "gone", Severity::Low, 0.5)],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("\"task\""),
            "absent context must not serialize: {json}"
        );
    }
}
