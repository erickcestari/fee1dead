//! Critic stage: one agent reviews the queue against the threat model after a
//! hunt pass and queues tasks for attack surface no task covered. Gapfill
//! only re-queues what hunters reported themselves; recon's blind spots would
//! otherwise reach every hunter. Run `hunt` again after it.

use std::collections::HashSet;

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::info;

use super::StageCtx;
use super::recon::{self, HuntTask};
use super::salvage::run_parsed;
use crate::artifacts::names;
use crate::config::Stage;
use crate::domain::{GapMarker, Task, TaskOrigin};
use crate::json_block;
use crate::provider::ResumeSession;

const PROMPT: &str = include_str!("../../prompts/critic.md");

/// A ceiling, not a target: each task costs a hunter.
const MAX_TASKS: usize = 10;

/// What a forked critic gets instead of recon's report.
const FORKED_CONTEXT: &str = "You built this audit's threat model as the recon agent earlier \
     in this session, so its entry points, trust boundaries, and invariants are already in \
     your context.";

#[derive(Debug, Default, Deserialize)]
struct CriticAnswer {
    #[serde(default)]
    hunt_tasks: Vec<HuntTask>,
}

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let queue: Vec<Task> = ctx.artifacts.read_jsonl(names::QUEUE)?;
    // Once per run: a `--resume` must not queue a second round.
    if queue.iter().any(|t| t.origin == TaskOrigin::Critic) {
        info!("the critic already ran this run");
        return Ok(());
    }
    let hunted: HashSet<String> = ctx
        .artifacts
        .read_jsonl(names::HUNTED)?
        .into_iter()
        .collect();
    let gaps: Vec<GapMarker> = ctx.artifacts.read_jsonl(names::GAPS)?;
    let session = recon::forkable_session(ctx, Stage::Critic);
    let context = match session {
        Some(_) => FORKED_CONTEXT.to_string(),
        None => format!(
            "<threat_model>\n{}\n</threat_model>",
            ctx.artifacts
                .read_text(names::RECON_REPORT)
                .context("the critic needs recon's threat model")?
        ),
    };
    let prompt = PROMPT
        .replace("{target_dir}", &ctx.config.run.target_dir.to_string_lossy())
        .replace("{max_tasks}", &MAX_TASKS.to_string())
        .replace("{context}", &context)
        // Agent-written text last, so every template placeholder is filled first.
        .replace("{gaps}", &gaps_block(&gaps))
        .replace("{queue}", &queue_lines(&queue, &hunted));

    let mut req = ctx.agent_request(Stage::Critic, "critic", prompt)?;
    req.resume = session.map(|session_id| ResumeSession {
        session_id,
        project_dir: ctx.config.run.target_dir.clone(),
    });
    let answer = run_parsed(ctx.runner.as_ref(), req, |r| {
        json_block::parse::<CriticAnswer>(&r.stdout, "critic answer")
    })
    .await
    .context("critic agent failed")?;

    let tasks = plan(&queue, answer.hunt_tasks);
    for task in &tasks {
        ctx.artifacts.append_jsonl(names::QUEUE, task)?;
    }
    info!(
        added = tasks.len(),
        "critic queued uncovered attack surface"
    );
    Ok(())
}

/// At most [`MAX_TASKS`], with ids continuing the queue's numbering under a
/// `C-` prefix.
fn plan(queue: &[Task], proposed: Vec<HuntTask>) -> Vec<Task> {
    proposed
        .into_iter()
        .take(MAX_TASKS)
        .enumerate()
        .map(|(i, t)| t.into_task(format!("C-{:04}", queue.len() + i + 1), TaskOrigin::Critic))
        .collect()
}

fn queue_lines(queue: &[Task], hunted: &HashSet<String>) -> String {
    if queue.is_empty() {
        return "(empty)".to_string();
    }
    queue
        .iter()
        .map(|t| {
            let mark = if hunted.contains(&t.id) {
                " [hunted]"
            } else {
                ""
            };
            format!(
                "- {}{mark}: {} in {}: {}",
                t.id, t.attack_class, t.scope_hint, t.hypothesis
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Hunters' gaps, which gapfill re-queues on its own; nothing when none.
fn gaps_block(gaps: &[GapMarker]) -> String {
    if gaps.is_empty() {
        return String::new();
    }
    let lines: Vec<String> = gaps
        .iter()
        .map(|g| format!("- {} ({}): {}", g.area, g.follow_up_class(), g.reason))
        .collect();
    format!(
        "<gaps>\nAreas hunters flagged as under-covered. Gapfill re-queues each of these, so \
         do not propose them again.\n{}\n</gaps>\n\n",
        lines.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::fixtures;

    #[test]
    fn plan_caps_and_continues_the_queue_numbering() {
        let queue = vec![fixtures::task("T-0001"), fixtures::task("G-0002")];
        let proposed: CriticAnswer = serde_json::from_str(&format!(
            "{{\"hunt_tasks\": [{}]}}",
            vec![r#"{"attack_class": "auth-bypass", "scope_paths": ["rpc/"]}"#; MAX_TASKS + 3]
                .join(",")
        ))
        .unwrap();
        let tasks = plan(&queue, proposed.hunt_tasks);
        assert_eq!(tasks.len(), MAX_TASKS);
        assert_eq!(tasks[0].id, "C-0003");
        assert_eq!(tasks[0].scope_hint, "rpc/");
        assert!(tasks.iter().all(|t| t.origin == TaskOrigin::Critic));
    }

    #[test]
    fn the_queue_shows_what_was_hunted() {
        let t = |id: &str| Task {
            hypothesis: "h".into(),
            ..fixtures::task(id)
        };
        let hunted = HashSet::from(["T-0001".to_string()]);
        assert_eq!(
            queue_lines(&[t("T-0001"), t("G-0002")], &hunted),
            "- T-0001 [hunted]: c in s: h\n- G-0002: c in s: h"
        );
    }

    #[test]
    fn no_gaps_leave_no_section() {
        assert!(gaps_block(&[]).is_empty());
        let gap = GapMarker {
            task_id: "T-0001".into(),
            area: "src/a.rs".into(),
            attack_class: String::new(),
            reason: "error path".into(),
        };
        assert!(gaps_block(&[gap]).contains("- src/a.rs (uncovered area): error path"));
    }
}
