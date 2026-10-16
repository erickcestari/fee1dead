//! Aggregate stage: join findings, their task leads and reviews, gaps,
//! duplicates, and wishes into one reviewable `findings.json`. No agent call,
//! so it completes even after a run spent its budget.

use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;
use tracing::info;

use super::StageCtx;
use crate::artifacts::{Artifacts, names};
use crate::domain::{Duplicate, Finding, GapMarker, Severity, Task, Validation, Verdict, Wish};

pub fn run(ctx: &StageCtx) -> Result<()> {
    write_report(&ctx.artifacts)
}

/// Needs only [`Artifacts`], so it runs standalone against a partial run.
pub fn write_report(artifacts: &Artifacts) -> Result<()> {
    let report = aggregate(Inputs {
        candidates: artifacts.read_jsonl(names::CANDIDATES)?,
        gaps: artifacts.read_jsonl(names::GAPS)?,
        tasks: artifacts.read_jsonl(names::QUEUE)?,
        duplicates: artifacts.read_jsonl(names::DUPLICATES)?,
        validations: artifacts.read_jsonl(names::VALIDATED)?,
        wishes: artifacts.read_jsonl(names::WISHLIST)?,
    });
    let json = serde_json::to_string_pretty(&report)?;
    artifacts.write_text(names::REPORT_JSON, &json)?;

    info!(
        findings = report.summary.findings,
        gaps = report.summary.gaps,
        wishes = report.summary.wishes,
        file = names::REPORT_JSON,
        "aggregate complete"
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct Report {
    summary: Summary,
    findings: Vec<EnrichedFinding>,
    gaps: Vec<GapMarker>,
    duplicates: Vec<Duplicate>,
    /// Grouped by kind, so each lever's wishes can be granted together.
    wishes: Vec<Wish>,
}

#[derive(Debug, Serialize)]
struct Summary {
    findings: usize,
    gaps: usize,
    duplicates: usize,
    wishes: usize,
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
    /// E.g. its review batch failed; `run --resume` retries it.
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

/// Most severe first, for at-a-glance triage.
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

/// A finding with its task's lead and its review, so it can be triaged
/// without cross-referencing the queue.
#[derive(Debug, Serialize)]
struct EnrichedFinding {
    #[serde(flatten)]
    finding: Finding,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<TaskContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    review: Option<ReviewContext>,
}

impl EnrichedFinding {
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

#[derive(Debug, Serialize)]
struct TaskContext {
    hypothesis: String,
    targets: Vec<String>,
    tags: Vec<String>,
}

#[derive(Default)]
struct Inputs {
    candidates: Vec<Finding>,
    gaps: Vec<GapMarker>,
    tasks: Vec<Task>,
    duplicates: Vec<Duplicate>,
    validations: Vec<Validation>,
    wishes: Vec<Wish>,
}

/// Ordered for triage: likely false positives last, then by effective
/// severity, then by the hunter's confidence.
fn aggregate(inputs: Inputs) -> Report {
    let Inputs {
        candidates,
        gaps,
        tasks,
        duplicates,
        validations,
        mut wishes,
    } = inputs;
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

    // Stable, so equal ranks keep candidates.jsonl order.
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
    // Stable, so each kind keeps wishlist.jsonl order.
    wishes.sort_by_key(|w| w.kind);

    Report {
        summary: Summary {
            findings: findings.len(),
            gaps: gaps.len(),
            duplicates: duplicates.len(),
            wishes: wishes.len(),
            by_severity,
            by_verdict: (!validations.is_empty()).then_some(by_verdict),
        },
        findings,
        gaps,
        duplicates,
        wishes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{WishKind, fixtures};

    fn finding(id: &str, task_id: &str, severity: Severity, confidence: f64) -> Finding {
        Finding {
            task_id: task_id.into(),
            severity,
            confidence,
            ..fixtures::finding(id)
        }
    }

    fn task(id: &str, hypothesis: &str) -> Task {
        Task {
            hypothesis: hypothesis.into(),
            targets: vec!["a.rs:1".into()],
            tags: vec!["crypto".into()],
            ..fixtures::task(id)
        }
    }

    #[test]
    fn orders_by_severity_then_confidence() {
        let candidates = vec![
            finding("low", "T-1", Severity::Low, 0.9),
            finding("high-weak", "T-1", Severity::High, 0.2),
            finding("high-strong", "T-1", Severity::High, 0.8),
        ];
        let report = aggregate(Inputs {
            candidates,
            tasks: vec![task("T-1", "h")],
            ..Inputs::default()
        });
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
        let report = aggregate(Inputs {
            candidates,
            tasks: vec![task("T-1", "len unchecked")],
            ..Inputs::default()
        });
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
        let report = aggregate(Inputs {
            candidates: vec![finding("f1", "T-1", Severity::High, 0.5)],
            duplicates: vec![dup],
            ..Inputs::default()
        });
        assert_eq!(report.summary.duplicates, 1);
        assert_eq!(report.duplicates[0].duplicate_of, "f1");
        assert_eq!(report.findings.len(), 1, "duplicates are not findings");
    }

    fn review(id: &str, verdict: Verdict, corrected: Option<Severity>) -> Validation {
        Validation {
            corrected_severity: corrected,
            ..fixtures::validation(id, verdict)
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
        let report = aggregate(Inputs {
            candidates,
            validations,
            ..Inputs::default()
        });
        let order: Vec<&str> = report
            .findings
            .iter()
            .map(|f| f.finding.id.as_str())
            .collect();
        assert_eq!(order, ["real", "pending", "cut", "fp"]);
        let real = &report.findings[0];
        assert_eq!(
            real.review.as_ref().unwrap().impact,
            "attacker crashes the node"
        );
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
    fn wishes_are_grouped_by_kind_and_counted() {
        let wish = |need: &str, kind| Wish {
            task_id: "T-1".into(),
            finding_id: None,
            kind,
            need: need.into(),
            unblocks: String::new(),
        };
        let report = aggregate(Inputs {
            wishes: vec![
                wish("a FreeBSD VM", WishKind::Environment),
                wish("proxy.golang.org", WishKind::Network),
                wish("a regtest bitcoind", WishKind::Environment),
            ],
            ..Inputs::default()
        });
        let needs: Vec<&str> = report.wishes.iter().map(|w| w.need.as_str()).collect();
        assert_eq!(
            needs,
            ["proxy.golang.org", "a FreeBSD VM", "a regtest bitcoind"]
        );
        assert_eq!(report.summary.wishes, 3);
    }

    #[test]
    fn before_validate_there_is_no_verdict_summary() {
        let report = aggregate(Inputs {
            candidates: vec![finding("f1", "T-1", Severity::Low, 0.5)],
            ..Inputs::default()
        });
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("by_verdict") && !json.contains("\"review\""),
            "{json}"
        );
    }

    #[test]
    fn missing_task_context_is_omitted_from_json() {
        let report = aggregate(Inputs {
            candidates: vec![finding("f1", "gone", Severity::Low, 0.5)],
            ..Inputs::default()
        });
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("\"task\""),
            "absent context must not serialize: {json}"
        );
    }
}
