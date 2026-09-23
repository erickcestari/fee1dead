//! Dedupe stage: collapse findings that share a root cause into a single
//! record, so variant analysis stays a feature rather than a way to inflate the
//! queue with duplicates.
//!
//! Two findings share a root cause when they sit in the same file under the
//! same attack class AND either cite the same location or restate the same
//! title. File + class alone is too coarse: a finding inherits its hunter's
//! attack class, so one hunter's distinct bugs in one file would all collapse.
//! The highest-severity finding survives as the representative; the others go
//! to `duplicates.jsonl` with the id they duplicate, never silently deleted.

use anyhow::Result;
use tracing::info;

use super::StageCtx;
use super::similarity::{jaccard, tokenize};
use crate::artifacts::names;
use crate::domain::{Duplicate, Finding};

/// Title token overlap at or above which two findings at different lines of the
/// same file and class are the same bug restated.
const SAME_TITLE: f64 = 0.5;

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    let before = candidates.len();
    let (representatives, duplicates) = dedupe_findings(candidates);
    ctx.artifacts
        .write_jsonl(names::CANDIDATES, &representatives)?;
    // Appended, not rewritten: dedupe may run more than once per run.
    for d in &duplicates {
        ctx.artifacts.append_jsonl(names::DUPLICATES, d)?;
    }
    info!(
        before,
        after = representatives.len(),
        collapsed = duplicates.len(),
        "dedupe complete"
    );
    Ok(())
}

fn same_root_cause(a: &Finding, b: &Finding) -> bool {
    a.file().eq_ignore_ascii_case(b.file())
        && a.attack_class.to_lowercase() == b.attack_class.to_lowercase()
        && (a.location.trim().eq_ignore_ascii_case(b.location.trim())
            || jaccard(&tokenize(&a.title), &tokenize(&b.title)) >= SAME_TITLE)
}

/// Cluster findings by root cause and keep one representative per cluster
/// (highest severity, first seen on ties) in first-occurrence order. Returns
/// the representatives and every other cluster member as a [`Duplicate`].
fn dedupe_findings(findings: Vec<Finding>) -> (Vec<Finding>, Vec<Duplicate>) {
    let mut clusters: Vec<Vec<Finding>> = Vec::new();
    for finding in findings {
        match clusters
            .iter_mut()
            .find(|c| c.iter().any(|m| same_root_cause(m, &finding)))
        {
            Some(cluster) => cluster.push(finding),
            None => clusters.push(vec![finding]),
        }
    }

    let mut kept = Vec::new();
    let mut duplicates = Vec::new();
    for mut cluster in clusters {
        let best = (1..cluster.len()).fold(0, |best, i| {
            if cluster[i].severity > cluster[best].severity {
                i
            } else {
                best
            }
        });
        let representative = cluster.remove(best);
        duplicates.extend(cluster.into_iter().map(|finding| Duplicate {
            duplicate_of: representative.id.clone(),
            finding,
        }));
        kept.push(representative);
    }
    (kept, duplicates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Severity;

    fn finding(id: &str, title: &str, location: &str, class: &str, sev: Severity) -> Finding {
        Finding {
            id: id.into(),
            task_id: "T".into(),
            title: title.into(),
            attack_class: class.into(),
            severity: sev,
            location: location.into(),
            description: "d".into(),
            confidence: 0.5,
            poc_path: None,
        }
    }

    #[test]
    fn restated_bug_collapses_to_highest_severity_and_is_recorded() {
        let input = vec![
            finding(
                "a",
                "Unbounded resize in decode",
                "src/p.rs:10",
                "dos",
                Severity::Low,
            ),
            finding(
                "b",
                "Unbounded resize in decode payload",
                "src/p.rs:42",
                "dos",
                Severity::High,
            ),
            finding(
                "c",
                "Unbounded resize in decode",
                "src/other.rs:1",
                "dos",
                Severity::Medium,
            ),
        ];
        let (kept, dups) = dedupe_findings(input);
        let ids: Vec<&str> = kept.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["b", "c"]);
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].finding.id, "a");
        assert_eq!(dups[0].duplicate_of, "b");
    }

    #[test]
    fn distinct_bugs_one_hunter_found_in_one_file_are_kept() {
        // Same file and (inherited) class, different lines and titles.
        let input = vec![
            finding(
                "a",
                "Length overflow before alloc",
                "src/p.rs:10",
                "c",
                Severity::High,
            ),
            finding(
                "b",
                "Signature checked after state write",
                "src/p.rs:90",
                "c",
                Severity::High,
            ),
        ];
        let (kept, dups) = dedupe_findings(input);
        assert_eq!(kept.len(), 2);
        assert!(dups.is_empty());
    }

    #[test]
    fn same_location_and_class_collapse_even_when_retitled() {
        let input = vec![
            finding("a", "Overflow", "src/p.rs:10", "c", Severity::Low),
            finding(
                "b",
                "Wraparound in length math",
                "src/p.rs:10",
                "c",
                Severity::Low,
            ),
        ];
        let (kept, dups) = dedupe_findings(input);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].id, "a", "first seen wins a severity tie");
        assert_eq!(dups[0].duplicate_of, "a");
    }

    #[test]
    fn different_attack_class_not_merged() {
        let input = vec![
            finding("a", "t", "src/p.rs:10", "overflow", Severity::Low),
            finding("b", "t", "src/p.rs:10", "path traversal", Severity::Low),
        ];
        let (kept, dups) = dedupe_findings(input);
        assert_eq!(kept.len(), 2);
        assert!(dups.is_empty());
    }
}
