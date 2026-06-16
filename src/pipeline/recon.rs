//! Recon stage: read the repo top-down, emit an architecture document and seed
//! the hunt queue. Runs as a single agent over the target directory.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::info;

use super::StageCtx;
use crate::artifacts::{extract_json_block, names};
use crate::domain::{Task, TaskOrigin};
use crate::provider::AgentRequest;
use crate::skills;

const PROMPT: &str = include_str!("../../prompts/recon.md");

/// The agent emits tasks without ids/origin; we assign those.
#[derive(Debug, Deserialize)]
struct SeedTask {
    attack_class: String,
    scope_hint: String,
}

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let target = &ctx.config.run.target_dir;
    let prompt = PROMPT.replace("{target_dir}", &target.to_string_lossy());

    let req = AgentRequest {
        prompt,
        system: None,
        working_dir: target.clone(),
        allowed_tools: Vec::new(),
        skills: skills::skills_for("recon")
            .iter()
            .map(|s| s.to_string())
            .collect(),
        timeout: Duration::from_secs(ctx.config.run.agent_timeout_secs),
        max_turns: None,
        resume: None,
    };

    let result = ctx.runner.run(req).await.context("recon agent failed")?;
    ctx.cost.record("recon", "recon", result.cost_usd);

    // The whole response is the architecture document.
    ctx.artifacts
        .write_text(names::ARCHITECTURE, &result.stdout)?;

    // Persist recon's session id so hunters can fork from its codebase context.
    // Providers without a session concept leave this unset; hunters then fall
    // back to the architecture doc alone.
    if let Some(session_id) = &result.session_id {
        ctx.artifacts.write_text(names::RECON_SESSION, session_id)?;
    }

    // Parse the task queue from the embedded json block.
    let json = extract_json_block(&result.stdout).context("recon output had no json task block")?;
    let seeds: Vec<SeedTask> =
        serde_json::from_str(json).context("recon task block was not a valid task array")?;

    let mut tasks = assign_ids(seeds);

    let fresh = tasks.len();
    let carried = merge_feedback_seeds(ctx, &mut tasks)?;

    info!(
        fresh,
        carried,
        total = tasks.len(),
        "recon assembled hunt queue"
    );
    ctx.artifacts.write_jsonl(names::QUEUE, &tasks)?;
    Ok(())
}

/// Assign stable, ordered ids to recon's seed tasks. Recon emits attack
/// class + scope only; ids and origin are the harness's to set.
fn assign_ids(seeds: Vec<SeedTask>) -> Vec<Task> {
    seeds
        .into_iter()
        .enumerate()
        .map(|(i, s)| Task {
            id: format!("T-{:04}", i + 1),
            attack_class: s.attack_class,
            scope_hint: s.scope_hint,
            origin: TaskOrigin::Recon,
        })
        .collect()
}

/// Merge durable feedback seeds from past runs into this run's queue, skipping
/// any whose (attack class, scope hint) recon already produced. Returns the
/// number of seeds carried in.
fn merge_feedback_seeds(ctx: &StageCtx, tasks: &mut Vec<Task>) -> Result<usize> {
    let seeds: Vec<Task> = ctx.artifacts.read_jsonl(names::SEEDS)?;
    if seeds.is_empty() {
        return Ok(0);
    }
    let mut seen: HashSet<(String, String)> = tasks
        .iter()
        .map(|t| (t.attack_class.to_lowercase(), t.scope_hint.to_lowercase()))
        .collect();

    let mut carried = 0;
    for seed in seeds {
        let key = (
            seed.attack_class.to_lowercase(),
            seed.scope_hint.to_lowercase(),
        );
        if seen.insert(key) {
            tasks.push(seed);
            carried += 1;
        }
    }
    Ok(carried)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(class: &str, hint: &str) -> SeedTask {
        SeedTask {
            attack_class: class.into(),
            scope_hint: hint.into(),
        }
    }

    #[test]
    fn assigns_padded_sequential_ids_and_recon_origin() {
        let tasks = assign_ids(vec![seed("overflow", "src/a.rs"), seed("auth", "src/b.rs")]);
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].id, "T-0001");
        assert_eq!(tasks[1].id, "T-0002");
        assert_eq!(tasks[0].attack_class, "overflow");
        assert_eq!(tasks[1].scope_hint, "src/b.rs");
        assert!(tasks.iter().all(|t| matches!(t.origin, TaskOrigin::Recon)));
    }

    #[test]
    fn empty_seeds_yield_no_tasks() {
        assert!(assign_ids(Vec::new()).is_empty());
    }

    #[test]
    fn parses_seed_array_from_agent_json_block() {
        let out = "prose\n```json\n[{\"attack_class\":\"x\",\"scope_hint\":\"y\"}]\n```";
        let json = extract_json_block(out).unwrap();
        let seeds: Vec<SeedTask> = serde_json::from_str(json).unwrap();
        let tasks = assign_ids(seeds);
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].attack_class, "x");
    }
}
