//! Gapfill stage: re-queue the areas hunters flagged as under-covered, for
//! the next hunt pass to pick up.

use anyhow::Result;
use tracing::info;

use super::StageCtx;
use crate::artifacts::names;
use crate::domain::{GapMarker, Task, TaskOrigin};

pub fn run(ctx: &StageCtx) -> Result<()> {
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

/// One task per gap, unless a task already hunts the same class over an
/// overlapping area. The class is part of the key because a gap usually names
/// a *different* class in an area a hunter covered. Ids continue the queue's
/// numbering with a `G-` prefix.
fn plan_gapfill(queue: &[Task], gaps: Vec<GapMarker>) -> Vec<Task> {
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

/// A task's non-empty scopes, lowercased: recon's path prefixes, else the hint.
fn scopes(task: &Task) -> impl Iterator<Item = String> + '_ {
    let hint = task.scope_paths.is_empty().then_some(&task.scope_hint);
    task.scope_paths
        .iter()
        .chain(hint)
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
}

/// An empty area overlaps nothing, so it is never silently dropped.
fn overlaps(scope: &str, area: &str) -> bool {
    !area.is_empty() && (area.starts_with(scope) || scope.starts_with(area))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::fixtures;

    fn task(id: &str, class: &str, hint: &str) -> Task {
        Task {
            attack_class: class.into(),
            scope_hint: hint.into(),
            ..fixtures::task(id)
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
        assert_eq!(plan[0].origin, TaskOrigin::Gapfill);
        assert_eq!(plan[0].hypothesis, "untouched");
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
        let t = Task {
            scope_paths: vec!["lnwallet/".into()],
            ..task("T-0001", "overflow", "")
        };
        let plan = plan_gapfill(
            &[t],
            vec![gap("lnwallet/channel.go:Foo", "auth-bypass", "x")],
        );
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn a_task_with_no_scope_covers_nothing() {
        let queue = vec![task("T-0001", "overflow", "")];
        let plan = plan_gapfill(&queue, vec![gap("src/x.rs", "overflow", "a")]);
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn repeated_gaps_yield_one_task_within_and_across_passes() {
        let plan = plan_gapfill(
            &[],
            vec![gap("src/x.rs", "dos", "a"), gap("src/x.rs", "dos", "b")],
        );
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].id, "G-0001");
        assert!(plan_gapfill(&plan, vec![gap("src/x.rs", "dos", "c")]).is_empty());
    }
}
