//! Gapfill stage: turn the areas hunters flagged as under-covered into fresh
//! hunt tasks, appended to the queue for another pass.
//!
//! This counteracts the model's drift toward attack classes it has already had
//! success with. Hunt is incremental (see `hunt.rs`), so only the appended
//! tasks trigger new work.

use anyhow::Result;
use tracing::info;

use super::StageCtx;
use crate::artifacts::names;
use crate::domain::{GapMarker, Task, TaskOrigin};

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let gaps: Vec<GapMarker> = ctx.artifacts.read_jsonl(names::GAPS)?;
    if gaps.is_empty() {
        info!("no gaps to fill");
        return Ok(());
    }

    let queue: Vec<Task> = ctx.artifacts.read_jsonl(names::QUEUE)?;
    let new_tasks = plan_gapfill(&queue, gaps);

    for task in &new_tasks {
        ctx.artifacts.append_jsonl(names::QUEUE, task)?;
    }

    info!(added = new_tasks.len(), "gapfill re-queued uncovered areas");
    Ok(())
}

/// Turn gap markers into fresh hunt tasks, skipping a gap only when an existing
/// task already hunts the same attack class over that area. The class is part of
/// the key because a gap's whole point is usually a *different* class in an area
/// a hunter already covered. Areas match by path containment either way; gaps
/// planned earlier in this batch count as covered, so two markers for the same
/// (area, class) produce one task. Ids continue the queue's numbering with a
/// `G-` prefix.
fn plan_gapfill(queue: &[Task], gaps: Vec<GapMarker>) -> Vec<Task> {
    // (attack class, scope) pairs already hunted or planned, lowercased.
    let mut covered: Vec<(String, String)> = queue
        .iter()
        .flat_map(|t| {
            let class = t.attack_class.to_lowercase();
            scopes(t).map(move |scope| (class.clone(), scope))
        })
        .collect();
    let mut next = queue.len() + 1;
    let mut new_tasks = Vec::new();

    for gap in gaps {
        let class = gap.follow_up_class().to_lowercase();
        let area = gap.area.trim().to_lowercase();
        if covered
            .iter()
            .any(|(c, scope)| *c == class && overlaps(scope, &area))
        {
            continue;
        }
        new_tasks.push(gap.to_task(format!("G-{next:04}"), TaskOrigin::Gapfill));
        covered.push((class, area));
        next += 1;
    }

    new_tasks
}

/// A task's non-empty scopes, lowercased: recon's path prefixes, else the
/// free-form hint (a gap task's hint is its area).
fn scopes(task: &Task) -> impl Iterator<Item = String> + '_ {
    let hint = task.scope_paths.is_empty().then_some(&task.scope_hint);
    task.scope_paths
        .iter()
        .chain(hint)
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
}

/// Whether one scope lies within the other. Both are non-empty for scopes; an
/// empty area overlaps nothing, so it is never silently dropped.
fn overlaps(scope: &str, area: &str) -> bool {
    !area.is_empty() && (area.starts_with(scope) || scope.starts_with(area))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Priority;

    fn task(id: &str, class: &str, hint: &str) -> Task {
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
            origin: TaskOrigin::Recon,
        }
    }

    fn gap(area: &str, class: &str, reason: &str) -> GapMarker {
        GapMarker {
            task_id: "T".into(),
            area: area.into(),
            attack_class: class.into(),
            reason: reason.into(),
        }
    }

    #[test]
    fn requeues_uncovered_areas_with_continued_ids_and_the_gaps_class() {
        let queue = vec![task("T-0001", "overflow", "src/a.rs")];
        let plan = plan_gapfill(&queue, vec![gap("src/b.rs", "auth-bypass", "untouched")]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].id, "G-0002");
        assert_eq!(plan[0].attack_class, "auth-bypass");
        assert!(matches!(plan[0].origin, TaskOrigin::Gapfill));
        assert_eq!(plan[0].scope_hint, "src/b.rs");
        assert_eq!(plan[0].hypothesis, "untouched");
    }

    #[test]
    fn classless_gap_falls_back_to_uncovered_area() {
        let plan = plan_gapfill(&[], vec![gap("src/b.rs", "", "untouched")]);
        assert_eq!(plan[0].attack_class, "uncovered area");
    }

    #[test]
    fn skips_same_class_already_scoped_either_direction() {
        let queue = vec![task("T-0001", "Overflow", "src/auth/login.rs")];
        let plan = plan_gapfill(
            &queue,
            vec![
                gap("src/auth", "overflow", "x"),
                gap("src/auth/login.rs:40", "overflow", "y"),
            ],
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn keeps_a_different_class_inside_an_already_scoped_area() {
        // The case gapfill exists for: a hunter in lnwallet/ flags an auth
        // issue it could not chase.
        let mut t = task("T-0001", "overflow", "");
        t.scope_paths = vec!["lnwallet/".into()];
        let plan = plan_gapfill(
            &[t],
            vec![gap("lnwallet/channel.go:Foo", "auth-bypass", "x")],
        );
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn a_task_with_no_scope_covers_nothing() {
        // An empty scope used to "contain" every area and drop all gaps.
        let queue = vec![task("T-0001", "overflow", "")];
        let plan = plan_gapfill(&queue, vec![gap("src/x.rs", "overflow", "a")]);
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn dedupes_repeated_gaps_within_one_batch() {
        let plan = plan_gapfill(
            &[],
            vec![gap("src/x.rs", "dos", "a"), gap("src/x.rs", "dos", "b")],
        );
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].id, "G-0001");
    }

    #[test]
    fn a_later_pass_skips_gaps_an_earlier_gap_task_covers() {
        let first = plan_gapfill(&[], vec![gap("src/x.rs", "dos", "a")]);
        let again = plan_gapfill(&first, vec![gap("src/x.rs", "dos", "b")]);
        assert!(again.is_empty());
    }
}
