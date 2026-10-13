//! Feedback stage: distil this run into durable seed tasks for the next run
//! against the same target:
//!   - bugs review judged real -> hunt their *variants* nearby;
//!   - unresolved gaps         -> cover the area a hunter skipped.
//!
//! The next run's recon reads the seeds as leads and consumes the file. The
//! list is deduped and capped at `feedback.max_seeds`, newest first.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use tracing::info;

use super::StageCtx;
use crate::artifacts::names;
use crate::domain::{Finding, GapMarker, Priority, Task, TaskOrigin, Validation};

pub fn run(ctx: &StageCtx) -> Result<()> {
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    let validations: Vec<Validation> = ctx.artifacts.read_jsonl(names::VALIDATED)?;
    let gaps: Vec<GapMarker> = ctx.artifacts.read_jsonl(names::GAPS)?;
    // Unconsumed seeds, from a `--resume` or a run whose recon never ran.
    let existing: Vec<Task> = ctx.artifacts.read_jsonl(names::SEEDS)?;

    let by_id: HashMap<&str, &Finding> = candidates.iter().map(|f| (f.id.as_str(), f)).collect();
    let variants = validations
        .iter()
        .filter(|v| v.verdict.is_real_bug())
        .filter_map(|v| by_id.get(v.finding_id.as_str()))
        .map(|f| variant_seed(f));
    let uncovered = gaps
        .iter()
        .map(|g| g.to_task(String::new(), TaskOrigin::Feedback));
    let merged = merge_and_cap(
        variants.chain(uncovered).collect(),
        existing,
        ctx.config.feedback.max_seeds,
    );

    info!(seeds = merged.len(), "feedback updated cross-run memory");
    ctx.artifacts.write_jsonl(names::SEEDS, &merged)
}

/// A variant hunt around a bug review judged real: a strong lead.
fn variant_seed(f: &Finding) -> Task {
    Task {
        attack_class: f.attack_class.clone(),
        scope_hint: format!(
            "variants of confirmed bug \"{}\" near {}",
            f.title, f.location
        ),
        hypothesis: format!("a variant of \"{}\" exists nearby", f.title),
        targets: vec![f.location.clone()],
        suggested_skills: vec!["variant-analysis".to_string()],
        priority: Priority::High,
        origin: TaskOrigin::Feedback,
        ..Task::default()
    }
}

/// New seeds first, deduped by (attack class, scope hint), capped to `max`,
/// with fresh ids.
fn merge_and_cap(new_seeds: Vec<Task>, existing: Vec<Task>, max: usize) -> Vec<Task> {
    let mut seen = HashSet::new();
    let mut out: Vec<Task> = new_seeds
        .into_iter()
        .chain(existing)
        .filter(|seed| {
            seen.insert((
                seed.attack_class.to_lowercase(),
                seed.scope_hint.to_lowercase(),
            ))
        })
        .take(max)
        .collect();
    for (i, task) in out.iter_mut().enumerate() {
        task.id = format!("F-{:04}", i + 1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::fixtures;

    fn seed(class: &str, hint: &str) -> Task {
        Task {
            attack_class: class.into(),
            scope_hint: hint.into(),
            ..fixtures::task("")
        }
    }

    #[test]
    fn dedupes_and_prefers_new() {
        let new = vec![seed("overflow", "fileA"), seed("Overflow", "FILEA")];
        let existing = vec![seed("overflow", "fileA"), seed("traversal", "fileB")];
        let merged = merge_and_cap(new, existing, 100);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].id, "F-0001");
        assert_eq!(merged[1].attack_class, "traversal");
        assert_eq!(merged[1].id, "F-0002");
    }

    #[test]
    fn caps_growth() {
        let new: Vec<Task> = (0..300).map(|i| seed("c", &format!("hint{i}"))).collect();
        assert_eq!(merge_and_cap(new, vec![], 200).len(), 200);
    }

    #[test]
    fn a_variant_seed_targets_the_confirmed_bug_site() {
        let s = variant_seed(&fixtures::finding("F-1"));
        assert_eq!(s.targets, vec!["a.rs:1"]);
        assert_eq!(s.priority, Priority::High);
        assert_eq!(s.suggested_skills, vec!["variant-analysis"]);
    }
}
