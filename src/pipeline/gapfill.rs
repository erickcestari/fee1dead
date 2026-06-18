//! Gapfill stage: turn the areas hunters flagged as under-covered into fresh
//! hunt tasks, appended to the queue for another pass.
//!
//! This counteracts the model's drift toward attack classes it has already had
//! success with. Hunt is incremental (see `hunt.rs`), so only the appended
//! tasks trigger new work.

use std::collections::HashSet;

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

/// Turn gap markers into fresh hunt tasks, skipping any area an existing queue
/// task already scopes. Cheap bidirectional textual containment is enough to
/// stop obvious duplicates; already-planned gaps in this batch also count as
/// covered, so two markers for the same area produce one task. Ids continue the
/// queue's numbering with a `G-` prefix.
fn plan_gapfill(queue: &[Task], gaps: Vec<GapMarker>) -> Vec<Task> {
    let mut covered: HashSet<String> = queue.iter().map(|t| t.scope_hint.to_lowercase()).collect();
    let mut next = queue.len() + 1;
    let mut new_tasks = Vec::new();

    for gap in gaps {
        let area_key = gap.area.to_lowercase();
        if covered
            .iter()
            .any(|c| c.contains(&area_key) || area_key.contains(c.as_str()))
        {
            continue;
        }
        new_tasks.push(Task {
            id: format!("G-{next:04}"),
            attack_class: "uncovered area".to_string(),
            scope_hint: format!("{} — {}", gap.area, gap.reason),
            hypothesis: String::new(),
            targets: Vec::new(),
            suggested_skills: Vec::new(),
            origin: TaskOrigin::Gapfill,
        });
        covered.insert(area_key);
        next += 1;
    }

    new_tasks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str, hint: &str) -> Task {
        Task {
            id: id.into(),
            attack_class: "c".into(),
            scope_hint: hint.into(),
            hypothesis: String::new(),
            targets: Vec::new(),
            suggested_skills: Vec::new(),
            origin: TaskOrigin::Recon,
        }
    }

    fn gap(area: &str, reason: &str) -> GapMarker {
        GapMarker {
            task_id: "T".into(),
            area: area.into(),
            reason: reason.into(),
        }
    }

    #[test]
    fn requeues_uncovered_areas_with_continued_ids() {
        let queue = vec![task("T-0001", "src/a.rs")];
        let plan = plan_gapfill(&queue, vec![gap("src/b.rs", "untouched")]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].id, "G-0002");
        assert_eq!(plan[0].attack_class, "uncovered area");
        assert!(matches!(plan[0].origin, TaskOrigin::Gapfill));
        assert!(plan[0].scope_hint.starts_with("src/b.rs"));
    }

    #[test]
    fn skips_area_already_scoped_by_queue_either_direction() {
        let queue = vec![task("T-0001", "src/auth/login.rs")];
        // Queue hint contains the gap area, and vice versa: both are duplicates.
        let plan = plan_gapfill(
            &queue,
            vec![gap("src/auth", "x"), gap("src/auth/login.rs:40", "y")],
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn dedupes_repeated_gaps_within_one_batch() {
        let plan = plan_gapfill(&[], vec![gap("src/x.rs", "a"), gap("src/x.rs", "b")]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].id, "G-0001");
    }
}
