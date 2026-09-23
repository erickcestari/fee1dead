//! Feedback stage: distil this run into durable seed tasks for the next run.
//!
//! There are no consumer repositories here; feedback is a memory within the
//! same target. It turns two signals into seeds:
//!   - bugs review judged real -> a task to hunt *variants* of that bug nearby;
//!   - unresolved gaps         -> a task to cover the area a hunter skipped.
//!
//! Seeds are written to `feedback-seeds.jsonl` (preserved across runs). The
//! next run's Recon reads them as leads, puts each through its admission bar
//! like any task it derives itself, and consumes the file, so a seed is judged
//! once against the code as it then stands. The list is deduped and capped at
//! `feedback.max_seeds`, newest first, so the memory stays bounded.

use std::collections::HashMap;
use std::collections::HashSet;

use anyhow::Result;
use tracing::info;

use super::StageCtx;
use crate::artifacts::names;
use crate::domain::{Finding, GapMarker, Priority, Task, TaskOrigin, Validation};

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    let validations: Vec<Validation> = ctx.artifacts.read_jsonl(names::VALIDATED)?;
    let gaps: Vec<GapMarker> = ctx.artifacts.read_jsonl(names::GAPS)?;

    let by_id: HashMap<&str, &Finding> = candidates.iter().map(|f| (f.id.as_str(), f)).collect();

    // New seeds from this run, freshest signal first.
    let mut new_seeds: Vec<Task> = Vec::new();

    // Variant hunts around bugs review judged real (confirmed or downgraded);
    // an unsettled finding is no basis for hunting its variants.
    for v in validations.iter().filter(|v| v.verdict.is_real_bug()) {
        if let Some(f) = by_id.get(v.finding_id.as_str()) {
            new_seeds.push(Task {
                id: String::new(), // assigned after dedupe
                attack_class: f.attack_class.clone(),
                scope_hint: format!(
                    "variants of confirmed bug \"{}\" near {}",
                    f.title, f.location
                ),
                scope_paths: Vec::new(),
                // Point next run's hunter straight at the confirmed bug site.
                hypothesis: format!("a variant of \"{}\" exists nearby", f.title),
                targets: vec![f.location.clone()],
                suggested_skills: vec!["variant-analysis".to_string()],
                tags: Vec::new(),
                // A variant of a bug review judged real is a strong lead.
                priority: Priority::High,
                origin: TaskOrigin::Feedback,
            });
        }
    }

    // Carry forward areas hunters left uncovered.
    for g in &gaps {
        new_seeds.push(g.to_task(String::new(), TaskOrigin::Feedback));
    }

    // Unconsumed seeds: from a `--resume`, or a run whose recon never ran.
    let existing: Vec<Task> = ctx.artifacts.read_jsonl(names::SEEDS)?;
    let merged = merge_and_cap(new_seeds, existing, ctx.config.feedback.max_seeds);

    info!(seeds = merged.len(), "feedback updated cross-run memory");
    ctx.artifacts.write_jsonl(names::SEEDS, &merged)?;
    Ok(())
}

/// Combine new (freshest) seeds with existing ones, dedupe by (attack class,
/// scope hint), cap to `max`, and assign stable ids.
fn merge_and_cap(new_seeds: Vec<Task>, existing: Vec<Task>, max: usize) -> Vec<Task> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out: Vec<Task> = Vec::new();

    for seed in new_seeds.into_iter().chain(existing) {
        if out.len() >= max {
            break;
        }
        let key = (
            seed.attack_class.to_lowercase(),
            seed.scope_hint.to_lowercase(),
        );
        if seen.insert(key) {
            out.push(seed);
        }
    }

    for (i, task) in out.iter_mut().enumerate() {
        task.id = format!("F-{:04}", i + 1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(class: &str, hint: &str) -> Task {
        Task {
            id: String::new(),
            attack_class: class.into(),
            scope_hint: hint.into(),
            scope_paths: Vec::new(),
            hypothesis: String::new(),
            targets: Vec::new(),
            suggested_skills: Vec::new(),
            tags: Vec::new(),
            priority: Priority::default(),
            origin: TaskOrigin::Feedback,
        }
    }

    #[test]
    fn dedupes_and_prefers_new() {
        let new = vec![seed("overflow", "fileA"), seed("overflow", "fileA")];
        let existing = vec![seed("overflow", "fileA"), seed("traversal", "fileB")];
        let merged = merge_and_cap(new, existing, 100);
        // One "overflow/fileA" survives, plus the distinct existing one.
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].id, "F-0001");
        assert_eq!(merged[1].id, "F-0002");
    }

    #[test]
    fn caps_growth() {
        let new: Vec<Task> = (0..300).map(|i| seed("c", &format!("hint{i}"))).collect();
        let merged = merge_and_cap(new, vec![], 200);
        assert_eq!(merged.len(), 200);
    }
}
