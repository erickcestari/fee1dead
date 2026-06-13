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

    // Avoid re-queuing an area an existing task already scopes. Cheap textual
    // containment is enough to stop obvious duplicates.
    let mut covered: HashSet<String> = queue
        .iter()
        .map(|t| t.scope_hint.to_lowercase())
        .collect();

    let mut next = queue.len() + 1;
    let mut added = 0usize;
    for gap in gaps {
        let area_key = gap.area.to_lowercase();
        if covered.iter().any(|c| c.contains(&area_key) || area_key.contains(c.as_str())) {
            continue;
        }
        let task = Task {
            id: format!("G-{next:04}"),
            attack_class: "uncovered area".to_string(),
            scope_hint: format!("{} — {}", gap.area, gap.reason),
            origin: TaskOrigin::Gapfill,
        };
        ctx.artifacts.append_jsonl(names::QUEUE, &task)?;
        covered.insert(area_key);
        next += 1;
        added += 1;
    }

    info!(added, "gapfill re-queued uncovered areas");
    Ok(())
}
