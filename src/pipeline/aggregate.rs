//! Aggregate stage: compile every hunter's raw output into one reviewable JSON
//! document.
//!
//! Hunters append findings to `candidates.jsonl` and uncovered areas to
//! `gaps.jsonl` one line at a time, and the recon task that surfaced each
//! finding lives separately in `queue.jsonl`. Reviewing that means cross-
//! referencing three files. This stage joins them into a single `findings.json`:
//! findings ordered by severity (then confidence), each enriched with its task's
//! hypothesis and targets, plus the gap list and a severity summary.
//!
//! It is pure file IO and shaping with no agent call, so unlike the review
//! stages (dedupe/validate/report) it always runs to completion even when a run
//! spends its whole token budget hunting. Run it on its own with
//! `fee1dead aggregate` after a partial run, or as the trailing pipeline stage.

use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;
use tracing::info;

use super::StageCtx;
use crate::artifacts::{Artifacts, names};
use crate::domain::{Finding, GapMarker, Severity, Task};

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

    let report = aggregate(candidates, gaps, tasks);
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
}

#[derive(Debug, Serialize)]
struct Summary {
    findings: usize,
    gaps: usize,
    by_severity: SeverityCounts,
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
}

/// The slice of a [`Task`] worth carrying alongside its findings.
#[derive(Debug, Serialize)]
struct TaskContext {
    hypothesis: String,
    targets: Vec<String>,
    tags: Vec<String>,
}

/// Join hunter output into one document: findings (enriched with their task's
/// lead and ordered severity-desc then confidence-desc) plus gaps and a summary.
/// Pure so it is unit-testable without a [`StageCtx`].
fn aggregate(candidates: Vec<Finding>, gaps: Vec<GapMarker>, tasks: Vec<Task>) -> Report {
    let by_id: HashMap<&str, &Task> = tasks.iter().map(|t| (t.id.as_str(), t)).collect();

    let mut by_severity = SeverityCounts::default();
    let mut findings: Vec<EnrichedFinding> = candidates
        .iter()
        .map(|f| {
            by_severity.bump(f.severity);
            EnrichedFinding {
                finding: f.clone(),
                task: by_id.get(f.task_id.as_str()).map(|t| TaskContext {
                    hypothesis: t.hypothesis.clone(),
                    targets: t.targets.clone(),
                    tags: t.tags.clone(),
                }),
            }
        })
        .collect();

    // Most severe first; within a severity, the hunter's own confidence ranks.
    // Stable order otherwise, so equal-rank findings keep candidates.jsonl order.
    findings.sort_by(|a, b| {
        b.finding.severity.cmp(&a.finding.severity).then(
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
            by_severity,
        },
        findings,
        gaps,
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
        let report = aggregate(candidates, vec![], vec![task("T-1", "h")]);
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
        let report = aggregate(candidates, vec![], vec![task("T-1", "len unchecked")]);
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
    fn missing_task_context_is_omitted_from_json() {
        let report = aggregate(
            vec![finding("f1", "gone", Severity::Low, 0.5)],
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
