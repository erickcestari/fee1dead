//! Feedback stage: distil this run into durable seed tasks for the next run.
//!
//! There are no consumer repositories here; feedback is a memory within the
//! same target. It turns two signals into seeds:
//!   - confirmed findings  -> a task to hunt *variants* of that bug nearby;
//!   - unresolved gaps      -> a task to cover the area a hunter skipped.
//!
//! Seeds are written to `feedback-seeds.jsonl` (preserved across runs); the
//! next run's Recon merges them into the hunt queue (keeping the seed's id). The
//! list is deduped and capped at `feedback.max_seeds`, newest first, so the
//! memory stays bounded and self-cleaning: a bug that gets fixed stops being
//! confirmed and its seed ages out.
//!
//! A carried seed that this run actually hunted (its id is in `hunted.jsonl`) is
//! dropped from the persisted list: it did its job, so re-persisting it would
//! only make the next run re-hunt an already-done task. Fresh signal for the
//! same area re-enters as a new seed.

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

    // Variant hunts around bugs that survived review (confirmed or downgraded).
    for v in validations.iter().filter(|v| v.verdict.is_reportable()) {
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
                // A variant of an already-confirmed bug is a strong lead; hunt it
                // ahead of the speculative carried-forward gaps.
                priority: Priority::High,
                origin: TaskOrigin::Feedback,
            });
        }
    }

    // Carry forward areas hunters left uncovered.
    for g in &gaps {
        new_seeds.push(Task {
            id: String::new(),
            attack_class: "uncovered area".to_string(),
            scope_hint: format!("{} — {}", g.area, g.reason),
            scope_paths: Vec::new(),
            hypothesis: String::new(),
            targets: Vec::new(),
            suggested_skills: Vec::new(),
            tags: Vec::new(),
            priority: Priority::default(),
            origin: TaskOrigin::Feedback,
        });
    }

    let existing: Vec<Task> = ctx.artifacts.read_jsonl(names::SEEDS)?;
    // Task ids hunted this run: a carried seed among them is done and must not
    // be carried forward again.
    let done: HashSet<String> = ctx
        .artifacts
        .read_jsonl::<String>(names::HUNTED)?
        .into_iter()
        .collect();
    let merged = merge_and_cap(new_seeds, existing, &done, ctx.config.feedback.max_seeds);

    info!(seeds = merged.len(), "feedback updated cross-run memory");
    ctx.artifacts.write_jsonl(names::SEEDS, &merged)?;
    Ok(())
}

/// Combine new (freshest) seeds with existing ones, drop carried seeds already
/// hunted (`done`), dedupe by (attack class, scope hint), cap to `max`, and
/// assign stable ids.
///
/// `done` holds task ids hunted this run; a carried seed whose id is listed is
/// dropped so the next run does not re-hunt it. New seeds have no id yet, so the
/// done check never touches them.
fn merge_and_cap(
    new_seeds: Vec<Task>,
    existing: Vec<Task>,
    done: &HashSet<String>,
    max: usize,
) -> Vec<Task> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out: Vec<Task> = Vec::new();

    for seed in new_seeds.into_iter().chain(existing) {
        if out.len() >= max {
            break;
        }
        // A carried seed that was hunted this run is done; drop it.
        if !seed.id.is_empty() && done.contains(&seed.id) {
            continue;
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
        seed_with_id("", class, hint)
    }

    fn seed_with_id(id: &str, class: &str, hint: &str) -> Task {
        Task {
            id: id.into(),
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
        let merged = merge_and_cap(new, existing, &HashSet::new(), 100);
        // One "overflow/fileA" survives, plus the distinct existing one.
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].id, "F-0001");
        assert_eq!(merged[1].id, "F-0002");
    }

    #[test]
    fn caps_growth() {
        let new: Vec<Task> = (0..300).map(|i| seed("c", &format!("hint{i}"))).collect();
        let merged = merge_and_cap(new, vec![], &HashSet::new(), 200);
        assert_eq!(merged.len(), 200);
    }

    #[test]
    fn drops_carried_seed_already_hunted() {
        // F-0001 was hunted this run: it must not be carried forward. F-0002 was
        // not hunted and survives. New seeds (no id) are never dropped by `done`.
        let new = vec![seed("overflow", "fileNew")];
        let existing = vec![
            seed_with_id("F-0001", "traversal", "fileDone"),
            seed_with_id("F-0002", "auth", "fileTodo"),
        ];
        let done: HashSet<String> = ["F-0001".to_string()].into_iter().collect();
        let merged = merge_and_cap(new, existing, &done, 100);
        assert_eq!(merged.len(), 2);
        // Reassigned ids are positional; match on the distinguishing scope hint.
        assert!(merged.iter().any(|t| t.scope_hint == "fileNew"));
        assert!(merged.iter().any(|t| t.scope_hint == "fileTodo"));
        assert!(
            !merged.iter().any(|t| t.scope_hint == "fileDone"),
            "the hunted seed must be dropped"
        );
    }
}
