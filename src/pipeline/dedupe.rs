//! Dedupe stage: collapse findings that share a root cause into one record.
//!
//! Same root cause means the same file, and the same root-cause line, or the
//! same sink, or a restated title under the same attack class. A finding
//! inherits its task's free-form class, so class cannot gate the line or sink
//! match (one bug two tasks found carries two classes), but it must gate the
//! title match (one hunter's distinct bugs in a file share a class). The most
//! severe survives; the rest go to `duplicates.jsonl`, never deleted.

use anyhow::Result;
use tracing::info;

use super::StageCtx;
use super::similarity::{jaccard, tokenize};
use crate::artifacts::names;
use crate::domain::{Duplicate, Finding};

/// Title overlap at which two findings at different lines are one bug restated.
const SAME_TITLE: f64 = 0.5;

pub fn run(ctx: &StageCtx) -> Result<()> {
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    let before = candidates.len();
    let (representatives, duplicates) = dedupe_findings(candidates);
    ctx.artifacts
        .write_jsonl(names::CANDIDATES, &representatives)?;
    // Appended: dedupe may run more than once per run.
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
    let same = |x: &str, y: &str| x.trim().eq_ignore_ascii_case(y.trim());
    a.file().eq_ignore_ascii_case(b.file())
        && (same(&a.location, &b.location)
            || a.sink().zip(b.sink()).is_some_and(|(x, y)| same(x, y))
            || (same(&a.attack_class, &b.attack_class)
                && jaccard(&tokenize(&a.title), &tokenize(&b.title)) >= SAME_TITLE))
}

/// One representative per cluster (most severe, first seen on ties), in
/// first-occurrence order, plus every other member as a [`Duplicate`].
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
    use crate::domain::{Severity, TraceKind, TraceStep, fixtures};

    fn finding(id: &str, title: &str, location: &str, class: &str, sev: Severity) -> Finding {
        Finding {
            title: title.into(),
            location: location.into(),
            attack_class: class.into(),
            severity: sev,
            ..fixtures::finding(id)
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

    fn sinking_at(f: Finding, sink: &str) -> Finding {
        let step = |kind, location: &str| TraceStep {
            kind,
            location: location.into(),
            what: String::new(),
            assumed: false,
        };
        Finding {
            trace: vec![
                step(TraceKind::Entrypoint, "src/wire.rs:3"),
                step(TraceKind::Sink, sink),
            ],
            ..f
        }
    }

    #[test]
    fn one_bug_two_tasks_found_collapses_despite_their_classes() {
        let input = vec![
            finding(
                "a",
                "Length wraps",
                "src/p.rs:10",
                "integer-overflow",
                Severity::High,
            ),
            finding(
                "b",
                "Remote panic",
                "src/p.rs:10",
                "panic-dos",
                Severity::Medium,
            ),
        ];
        let (kept, dups) = dedupe_findings(input);
        assert_eq!(kept.len(), 1);
        assert_eq!(dups[0].duplicate_of, "a");
    }

    #[test]
    fn a_shared_sink_collapses_only_within_one_file() {
        let a = finding(
            "a",
            "Length wraps",
            "src/p.rs:10",
            "overflow",
            Severity::High,
        );
        let b = finding(
            "b",
            "Remote panic",
            "src/p.rs:14",
            "panic-dos",
            Severity::Low,
        );
        let c = finding("c", "Unchecked count", "src/q.rs:7", "dos", Severity::Low);
        let input = vec![
            sinking_at(a, "src/p.rs:20"),
            sinking_at(b, "src/p.rs:20"),
            sinking_at(c, "src/p.rs:20"),
        ];
        let (kept, dups) = dedupe_findings(input);
        let ids: Vec<&str> = kept.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["a", "c"]);
        assert_eq!(dups[0].finding.id, "b");
    }

    #[test]
    fn a_restated_title_under_another_class_is_kept() {
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
                "Unbounded resize in decode",
                "src/p.rs:40",
                "auth",
                Severity::Low,
            ),
        ];
        let (kept, dups) = dedupe_findings(input);
        assert_eq!(kept.len(), 2);
        assert!(dups.is_empty());
    }
}
