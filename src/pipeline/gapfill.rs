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

/// One task per gap, unless a queued or newly planned task already covers it
/// ([`Task::covers`]). Ids continue the queue's numbering with a `G-` prefix.
fn plan_gapfill(queue: &[Task], gaps: Vec<GapMarker>) -> Vec<Task> {
    let mut next = queue.len() + 1;
    let mut new_tasks: Vec<Task> = Vec::new();
    for gap in gaps {
        if queue.iter().chain(&new_tasks).any(|t| t.covers(&gap)) {
            continue;
        }
        // Only recon routes skills; a gap lies where its hunter was sent, so
        // that task's skills carry over rather than leaving none.
        let skills = queue
            .iter()
            .chain(&new_tasks)
            .find(|t| t.id == gap.task_id)
            .map(|t| t.suggested_skills.clone())
            .unwrap_or_default();
        new_tasks.push(Task {
            suggested_skills: skills,
            ..gap.to_task(format!("G-{next:04}"), TaskOrigin::Gapfill)
        });
        next += 1;
    }
    new_tasks
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
            task_id: "T-0001".into(),
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
    fn a_gap_task_inherits_the_skills_of_the_task_that_raised_it() {
        let routed = Task {
            suggested_skills: vec!["ln-model".into()],
            ..task("T-0001", "overflow", "src/a.rs")
        };
        let plan = plan_gapfill(&[routed], vec![gap("src/b.rs", "dos", "x")]);
        assert_eq!(plan[0].suggested_skills, ["ln-model"]);
        // Across passes too: a gap raised by a gapfill hunter.
        let next = plan_gapfill(
            &plan,
            vec![GapMarker {
                task_id: plan[0].id.clone(),
                ..gap("src/c.rs", "race", "y")
            }],
        );
        assert_eq!(next[0].suggested_skills, ["ln-model"]);
        let orphan = GapMarker {
            task_id: "T-9999".into(),
            ..gap("src/d.rs", "dos", "z")
        };
        assert!(
            plan_gapfill(&[], vec![orphan])[0]
                .suggested_skills
                .is_empty()
        );
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
    fn a_gap_without_an_area_does_not_swallow_later_gaps_of_its_class() {
        let plan = plan_gapfill(&[], vec![gap("", "dos", "a"), gap("src/x.rs", "dos", "b")]);
        assert_eq!(plan.len(), 2);
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
