//! Recon stage: one agent builds the threat model every hunter forks from.
//! Its whole answer is a JSON threat model, persisted verbatim as
//! `recon.json`; the harness only parses `hunt_tasks` out of it, into the queue.
//!
//! Feedback seeds from past runs enter as leads, not tasks: a seed is only a
//! hypothesis and the code may have changed, so it passes recon's admission
//! bar like anything recon derives. Recon then consumes the seed file.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::info;

use super::salvage::run_parsed;
use super::{StageCtx, loc, prompt};
use crate::artifacts::names;
use crate::config::Stage;
use crate::domain::{Priority, Task, TaskOrigin};
use crate::json_block;
use crate::provider::{AgentRequest, Effort};

const PROMPT: &str = include_str!("../../prompts/recon.md");

/// LOC boundaries of the prompt's size tiers, pre-computed so the caps are
/// deterministic and the agent spends no turns measuring.
const MEDIUM_LOC: u64 = 10_000;
const LARGE_LOC: u64 = 100_000;

/// The slice of the threat model the harness consumes; serde drops the rest.
#[derive(Debug, Default, Deserialize)]
struct ReconReport {
    #[serde(default)]
    hunt_tasks: Vec<HuntTask>,
}

/// A task as recon emits it; any `id` it adds is ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HuntTask {
    attack_class: String,
    scope_paths: Vec<String>,
    targets: Vec<String>,
    hypothesis: String,
    suggested_skills: Vec<String>,
    priority: Priority,
}

impl HuntTask {
    fn into_task(self, id: String) -> Task {
        Task {
            id,
            attack_class: self.attack_class,
            // Derived so cross-stage dedupe, which keys on the hint, still works.
            scope_hint: self.scope_paths.join(", "),
            scope_paths: self.scope_paths,
            hypothesis: self.hypothesis,
            targets: self.targets,
            suggested_skills: self.suggested_skills,
            priority: self.priority,
            origin: TaskOrigin::Recon,
            ..Task::default()
        }
    }
}

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let cfg = &ctx.config;
    let target = &cfg.run.target_dir;
    let loc = loc::count(target);
    let seeds: Vec<Task> = ctx.artifacts.read_jsonl(names::SEEDS)?;
    let spec_path = cfg
        .reference
        .active_dir()
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_default();
    let prompt = PROMPT
        .replace("$REPO_PATH", &target.to_string_lossy())
        .replace("$REPO_NAME", &repo_name(cfg.target.repo.as_deref(), target))
        .replace("$REPO_SIZE", size_tier(loc))
        .replace("$LOC", &loc.to_string())
        .replace("$SPEC_PATH", &spec_path)
        .replace("$LEADS", &leads_block(&seeds))
        + &prompt::reference_recon_directive(cfg)
        + prompt::skills_directive(cfg);

    let req = AgentRequest {
        working_dir: target.clone(),
        // Every hunter forks this session; its prefix must outlive the 5m TTL
        // until the last one launches.
        cache_1h: true,
        ..ctx.agent_request(Stage::Recon, "recon", prompt, Effort::High)?
    };
    let (json, report, session_id) = run_parsed(ctx.runner.as_ref(), req, |result| {
        let json =
            json_block::extract(&result.stdout).context("no JSON threat model in the answer")?;
        let report: ReconReport =
            serde_json::from_str(json).context("the answer is not a valid threat model")?;
        Ok((json.to_string(), report, result.session_id.clone()))
    })
    .await
    .context("recon agent failed")?;

    ctx.artifacts.write_text(names::RECON_REPORT, &json)?;
    if let Some(session_id) = &session_id {
        ctx.artifacts.write_text(names::RECON_SESSION, session_id)?;
    }
    let tasks = into_queue(report.hunt_tasks);
    info!(
        loc,
        tasks = tasks.len(),
        leads = seeds.len(),
        "recon assembled hunt queue"
    );
    ctx.artifacts.write_jsonl(names::QUEUE, &tasks)?;
    // Every lead was judged against the code; the ones that passed are queued.
    ctx.artifacts.write_jsonl::<Task>(names::SEEDS, &[])?;
    Ok(())
}

fn into_queue(hunt_tasks: Vec<HuntTask>) -> Vec<Task> {
    hunt_tasks
        .into_iter()
        .enumerate()
        .map(|(i, t)| t.into_task(format!("T-{:04}", i + 1)))
        .collect()
}

fn size_tier(loc: u64) -> &'static str {
    match loc {
        LARGE_LOC.. => "large",
        MEDIUM_LOC.. => "medium",
        _ => "small",
    }
}

/// One line per feedback seed, or nothing, so a first run carries no empty
/// section.
fn leads_block(seeds: &[Task]) -> String {
    if seeds.is_empty() {
        return String::new();
    }
    let lines: Vec<String> = seeds
        .iter()
        .map(|s| {
            let mut parts = vec![format!("- {}: {}", s.attack_class, s.scope_hint)];
            if !s.hypothesis.is_empty() {
                parts.push(format!("hypothesis: {}", s.hypothesis));
            }
            if !s.targets.is_empty() {
                parts.push(format!("targets: {}", s.targets.join(", ")));
            }
            parts.join("; ")
        })
        .collect();
    format!(
        "<leads>\nLeads carried over from earlier runs against this repository: variants \
         of bugs a reviewer judged real, and areas a hunter flagged but could not finish. \
         They are hypotheses, not findings, and the code may have changed since.\n{}\n</leads>\n",
        lines.join("\n")
    )
}

/// The clone URL's basename when a repo is configured, else the dir's name.
fn repo_name(repo: Option<&str>, target_dir: &Path) -> String {
    let from_url = repo.and_then(|repo| {
        let trimmed = repo.trim_end_matches('/');
        let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
        trimmed.rsplit('/').next().filter(|name| !name.is_empty())
    });
    match from_url {
        Some(name) => name.to_string(),
        None => target_dir.file_name().map_or_else(
            || "target".to_string(),
            |n| n.to_string_lossy().into_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::GapMarker;

    fn queue(json: &str) -> Vec<Task> {
        let report: ReconReport = json_block::parse(json, "threat model").unwrap();
        into_queue(report.hunt_tasks)
    }

    #[test]
    fn assigns_padded_ids_and_derives_the_scope_hint() {
        let tasks = queue(
            r#"{"hunt_tasks":[
                {"attack_class":"overflow","scope_paths":["src/a.rs","src/b.rs"]},
                {"attack_class":"auth","scope_paths":["src/auth/"]}
            ]}"#,
        );
        assert_eq!(tasks.len(), 2);
        assert_eq!(
            (tasks[0].id.as_str(), tasks[1].id.as_str()),
            ("T-0001", "T-0002")
        );
        assert_eq!(tasks[0].scope_hint, "src/a.rs, src/b.rs");
        assert_eq!(tasks[1].scope_hint, "src/auth/");
        assert!(tasks.iter().all(|t| t.origin == TaskOrigin::Recon));
    }

    #[test]
    fn carries_the_task_body_and_ignores_the_agents_id_and_extra_fields() {
        let tasks = queue(
            r#"{"product_summary":"A parser.","invariants":[{"id":"INV-1"}],"hunt_tasks":[{
                "id":"T-99",
                "attack_class":"overflow",
                "scope_paths":["src/a.rs"],
                "hypothesis":"len added without bounds check",
                "targets":["src/a.rs:decode","src/a.rs:42"],
                "suggested_skills":["sharp-edges"],
                "priority":"high"
            }]}"#,
        );
        assert_eq!(tasks[0].id, "T-0001");
        assert_eq!(tasks[0].hypothesis, "len added without bounds check");
        assert_eq!(tasks[0].targets, vec!["src/a.rs:decode", "src/a.rs:42"]);
        assert_eq!(tasks[0].suggested_skills, vec!["sharp-edges"]);
        assert_eq!(tasks[0].priority, Priority::High);
        assert_eq!(
            queue(r#"{"hunt_tasks":[{"attack_class":"c"}]}"#)[0].priority,
            Priority::Medium
        );
        assert!(queue(r#"{"hunt_tasks":[]}"#).is_empty());
    }

    #[test]
    fn size_tier_tracks_loc_thresholds() {
        assert_eq!(size_tier(0), "small");
        assert_eq!(size_tier(9_999), "small");
        assert_eq!(size_tier(10_000), "medium");
        assert_eq!(size_tier(99_999), "medium");
        assert_eq!(size_tier(100_000), "large");
    }

    #[test]
    fn leads_render_one_line_per_seed_and_vanish_without_seeds() {
        assert_eq!(leads_block(&[]), "");
        let seed = GapMarker {
            task_id: "T-0003".into(),
            area: "src/net.rs:decode".into(),
            attack_class: "panic-dos".into(),
            reason: "truncated frames not traced".into(),
        }
        .to_task("F-0001".into(), TaskOrigin::Feedback);
        let block = leads_block(&[seed]);
        assert!(block.starts_with("<leads>\n"));
        assert!(block.contains(
            "- panic-dos: src/net.rs:decode; hypothesis: truncated frames not traced; \
             targets: src/net.rs:decode\n</leads>"
        ));
    }

    #[test]
    fn repo_name_prefers_the_clone_url() {
        let dir = Path::new("/work/target");
        assert_eq!(repo_name(Some("https://github.com/o/lnd.git/"), dir), "lnd");
        assert_eq!(repo_name(Some("https://github.com/o/lnd"), dir), "lnd");
        assert_eq!(repo_name(None, dir), "target");
        assert_eq!(repo_name(Some(""), Path::new("/")), "target");
    }
}
