//! Dedupe stage: collapse findings that share a root cause into a single
//! record, so variant analysis stays a feature rather than a way to inflate the
//! queue with duplicates.
//!
//! Root cause is approximated by (source file, attack class): multiple line-
//! level hits of the same bug class in the same file are almost always the same
//! underlying defect. The highest-severity finding survives as the
//! representative; the rest are dropped.

use std::collections::HashMap;

use anyhow::Result;
use tracing::info;

use super::StageCtx;
use crate::artifacts::names;
use crate::domain::Finding;

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    let before = candidates.len();
    let (representatives, collapsed) = dedupe_findings(candidates);
    ctx.artifacts.write_jsonl(names::CANDIDATES, &representatives)?;
    info!(before, after = representatives.len(), collapsed, "dedupe complete");
    Ok(())
}

/// The root-cause key: source file (line stripped) + attack class.
fn root_cause_key(f: &Finding) -> (String, String) {
    let file = f
        .location
        .rsplit_once(':')
        .map(|(file, _line)| file)
        .unwrap_or(&f.location)
        .to_lowercase();
    (file, f.attack_class.to_lowercase())
}

/// Keep one representative (highest severity, first seen on ties) per root
/// cause, preserving first-occurrence order. Returns `(kept, collapsed_count)`.
fn dedupe_findings(findings: Vec<Finding>) -> (Vec<Finding>, usize) {
    // key -> index into `kept`.
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    let mut kept: Vec<Finding> = Vec::new();
    let mut collapsed = 0usize;

    for finding in findings {
        let key = root_cause_key(&finding);
        match index.get(&key) {
            Some(&i) => {
                collapsed += 1;
                if finding.severity > kept[i].severity {
                    // Preserve the representative's slot/order, upgrade content.
                    kept[i] = finding;
                }
            }
            None => {
                index.insert(key, kept.len());
                kept.push(finding);
            }
        }
    }
    (kept, collapsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Severity;

    fn finding(id: &str, location: &str, class: &str, sev: Severity) -> Finding {
        Finding {
            id: id.into(),
            task_id: "T".into(),
            title: id.into(),
            attack_class: class.into(),
            severity: sev,
            location: location.into(),
            description: "d".into(),
            poc_path: None,
        }
    }

    #[test]
    fn collapses_same_file_same_class_keeps_highest_severity() {
        let input = vec![
            finding("a", "src/p.rs:10", "overflow", Severity::Low),
            finding("b", "src/p.rs:42", "overflow", Severity::High),
            finding("c", "src/other.rs:1", "overflow", Severity::Medium),
        ];
        let (kept, collapsed) = dedupe_findings(input);
        assert_eq!(collapsed, 1);
        assert_eq!(kept.len(), 2);
        // The high-severity finding in p.rs is the survivor for that cluster.
        let p = kept.iter().find(|f| f.location.starts_with("src/p.rs")).unwrap();
        assert_eq!(p.id, "b");
    }

    #[test]
    fn different_attack_class_not_merged() {
        let input = vec![
            finding("a", "src/p.rs:10", "overflow", Severity::Low),
            finding("b", "src/p.rs:10", "path traversal", Severity::Low),
        ];
        let (kept, collapsed) = dedupe_findings(input);
        assert_eq!(collapsed, 0);
        assert_eq!(kept.len(), 2);
    }
}
