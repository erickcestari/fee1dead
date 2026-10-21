//! Feedback stage: distil this run into seed tasks for the next one: variant
//! hunts around real bugs, and the gaps hunters left that no follow-up hunt
//! covered. The next recon reads them as leads. Deduped and capped at
//! `feedback.max_seeds`, newest first.

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
    let queue: Vec<Task> = ctx.artifacts.read_jsonl(names::QUEUE)?;
    let hunted: HashSet<String> = ctx
        .artifacts
        .read_jsonl(names::HUNTED)?
        .into_iter()
        .collect();
    // Unconsumed seeds, from a `--resume` or a run whose recon never ran.
    let existing: Vec<Task> = ctx.artifacts.read_jsonl(names::SEEDS)?;

    let by_id: HashMap<&str, &Finding> = candidates.iter().map(|f| (f.id.as_str(), f)).collect();
    let variants = validations
        .iter()
        .filter(|v| v.verdict.is_real_bug())
        .filter_map(|v| by_id.get(v.finding_id.as_str()))
        .map(|f| variant_seed(f));
    let uncovered = unhunted_gaps(&gaps, &queue, &hunted)
        .map(|g| g.to_task(String::new(), TaskOrigin::Feedback));
    let merged = merge_and_cap(
        variants.chain(uncovered).collect(),
        existing,
        ctx.config.feedback.max_seeds,
    );

    info!(seeds = merged.len(), "feedback updated cross-run memory");
    ctx.artifacts.write_jsonl(names::SEEDS, &merged)
}

/// Gaps no hunted gapfill task covers. The task a gap came from does not
/// count: its hunter is the one that reported the area as uncovered.
fn unhunted_gaps<'a>(
    gaps: &'a [GapMarker],
    queue: &'a [Task],
    hunted: &'a HashSet<String>,
) -> impl Iterator<Item = &'a GapMarker> {
    let followed_up: Vec<&Task> = queue
        .iter()
        .filter(|t| t.origin == TaskOrigin::Gapfill && hunted.contains(&t.id))
        .collect();
    gaps.iter().filter(move |gap| {
        !followed_up
            .iter()
            .any(|t| t.id != gap.task_id && t.covers(gap))
    })
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
    fn only_gaps_without_a_hunted_follow_up_are_seeded() {
        let gap = |task_id: &str, area: &str, class: &str| GapMarker {
            task_id: task_id.into(),
            area: area.into(),
            attack_class: class.into(),
            reason: "r".into(),
        };
        let task = |id: &str, area: &str, class: &str, origin| Task {
            attack_class: class.into(),
            scope_hint: area.into(),
            origin,
            ..fixtures::task(id)
        };
        let queue = vec![
            task("T-0001", "src", "overflow", TaskOrigin::Recon),
            task("G-0002", "src/a.rs", "dos", TaskOrigin::Gapfill),
            task("G-0003", "src/b.rs", "auth", TaskOrigin::Gapfill),
            task("T-0004", "src/c.rs", "panic", TaskOrigin::Recon),
        ];
        let hunted: HashSet<String> = ["T-0001", "G-0002", "T-0004"].map(String::from).into();
        let gaps = vec![
            // Re-queued as G-0002, which was hunted.
            gap("T-0001", "src/a.rs", "dos"),
            // Re-queued as G-0003, which a usage limit left unhunted.
            gap("T-0001", "src/b.rs", "auth"),
            // Reported by the follow-up hunt itself.
            gap("G-0002", "src/a.rs:parse", "dos"),
            // Covered by a recon task only, never followed up.
            gap("T-0001", "src/c.rs", "panic"),
        ];
        let areas: Vec<&str> = unhunted_gaps(&gaps, &queue, &hunted)
            .map(|g| g.area.as_str())
            .collect();
        assert_eq!(areas, ["src/b.rs", "src/a.rs:parse", "src/c.rs"]);
    }

    #[test]
    fn a_variant_seed_targets_the_confirmed_bug_site() {
        let s = variant_seed(&fixtures::finding("F-1"));
        assert_eq!(s.targets, vec!["a.rs:1"]);
        assert_eq!(s.priority, Priority::High);
        assert_eq!(s.suggested_skills, vec!["variant-analysis"]);
    }
}
