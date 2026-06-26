//! Recon stage: build the shared threat model every hunter forks from.
//!
//! Runs as a single agent over the target directory. The agent emits ONE
//! structured JSON threat model as its entire final answer; the harness reads it
//! back (via the provider's final-output file), persists it verbatim as
//! `recon.json`, and turns its `hunt_tasks` into the hunt queue. Forked hunters
//! inherit recon's session, so they never re-read the report; only cold hunters
//! (non-forking providers) load `recon.json` as their threat-model context.
//!
//! The harness pre-computes the repo's LOC and size tier and substitutes them
//! into the prompt, so the prompt's size-adaptive caps are deterministic and the
//! agent spends no turns measuring the repo.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::info;

use super::StageCtx;
use crate::artifacts::{extract_json_block, names};
use crate::domain::{Priority, Task, TaskOrigin};
use crate::provider::{AgentRequest, Effort};

const PROMPT: &str = include_str!("../../prompts/recon.md");

/// LOC tier boundaries the prompt's caps key on: `<MEDIUM` is small,
/// `[MEDIUM, LARGE)` is medium, `>=LARGE` is large.
const MEDIUM_LOC: u64 = 10_000;
const LARGE_LOC: u64 = 100_000;

/// The slice of recon's threat model the harness consumes: the hunt queue.
///
/// Recon emits a much richer object (product summary, trust boundaries, entry
/// points, invariants, priority targets, ...). That whole object is persisted
/// verbatim to `recon.json` and is what a cold hunter reads; the harness itself
/// only needs `hunt_tasks` to build the queue, so it deserializes just that and
/// lets serde drop the rest. `#[serde(default)]` keeps a terse response parsing.
#[derive(Debug, Default, Deserialize)]
struct ReconReport {
    #[serde(default)]
    hunt_tasks: Vec<HuntTask>,
}

/// A hunt task as recon emits it. The agent may include an `id`; the harness
/// ignores it and assigns its own (serde drops unknown fields).
#[derive(Debug, Default, Deserialize)]
struct HuntTask {
    #[serde(default)]
    attack_class: String,
    #[serde(default)]
    scope_paths: Vec<String>,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    hypothesis: String,
    #[serde(default)]
    suggested_skills: Vec<String>,
    #[serde(default)]
    priority: Priority,
}

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let target = &ctx.config.run.target_dir;
    let (loc, size) = repo_stats(target);
    let repo_name = repo_name(ctx);
    // The reference repo (a cloned spec) doubles as the prompt's `$SPEC_PATH`;
    // empty when no reference is configured, so Phase E's spec-doc lookup is a
    // no-op.
    let spec_path = ctx
        .config
        .reference
        .active_dir()
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_default();

    let prompt = PROMPT
        .replace("$REPO_PATH", &target.to_string_lossy())
        .replace("$REPO_NAME", &repo_name)
        .replace("$REPO_SIZE", size)
        .replace("$LOC", &loc.to_string())
        .replace("$SPEC_PATH", &spec_path)
        + &ctx.config.reference.recon_directive()
        + &ctx.config.run.skills_directive();

    let req = AgentRequest {
        prompt,
        system: None,
        working_dir: target.clone(),
        extra_dirs: ctx
            .config
            .reference
            .active_dir()
            .map(|d| vec![d.to_path_buf()])
            .unwrap_or_default(),
        allowed_tools: Vec::new(),
        // Recon runs as a single agent: the shared deny-list drops sub-agent
        // fan-out (each child re-explores the repo for little extra coverage)
        // along with the tools no stage uses.
        disallowed_tools: super::disabled_tools(),
        timeout: Duration::from_secs(ctx.config.run.agent_timeout_secs),
        // Bound recon's turns: each turn re-reads its growing context, and that
        // context is replayed into every forked hunter, so an unbounded recon is
        // a run's worst-case cost. The prompt's orient discipline keeps the work
        // inside this budget.
        max_turns: Some(ctx.config.run.recon_max_turns),
        resume: None,
        // Recon is the one session every later stage forks. Its prefix must
        // survive past the default 5m TTL until the last forked agent launches,
        // so it alone takes the 1h cache; leaf stages leave it off.
        cache_1h: true,
        // Threat modeling is high-leverage reasoning, but recon's turns are the
        // most cost-amplified in a run (re-read each turn, forked into hunters),
        // so it sits a notch below the open-ended tracing hunters do.
        effort: Effort::High,
        stream_log_path: Some(ctx.artifacts.log_path("recon-recon.jsonl")),
    };

    let result = ctx.runner.run(req).await.context("recon agent failed")?;

    // The agent's whole final answer is the JSON threat model. Pull it back out
    // (tolerating a stray prose wrapper) and parse out the queue.
    let json =
        extract_json_block(&result.stdout).context("recon output had no json threat model")?;
    let report: ReconReport =
        serde_json::from_str(json).context("recon output was not a valid threat-model object")?;

    // Persist the threat model verbatim: it is the run's auditable record and the
    // context a cold hunter loads. Forked hunters skip it (they have recon's
    // session), so the harness never re-parses the prose fields it dropped above.
    ctx.artifacts.write_text(names::RECON_REPORT, json)?;

    // Persist recon's session id so hunters can fork from its codebase context.
    // Providers without a session concept leave this unset; hunters then fall
    // back to the architecture doc alone.
    if let Some(session_id) = &result.session_id {
        ctx.artifacts.write_text(names::RECON_SESSION, session_id)?;
    }

    let mut tasks = assign_ids(report.hunt_tasks);

    let fresh = tasks.len();
    let carried = merge_feedback_seeds(ctx, &mut tasks)?;

    info!(
        loc,
        size,
        fresh,
        carried,
        total = tasks.len(),
        "recon assembled hunt queue"
    );
    ctx.artifacts.write_jsonl(names::QUEUE, &tasks)?;
    Ok(())
}

/// Assign stable, ordered ids to recon's hunt tasks and derive the legacy
/// `scope_hint` (joined `scope_paths`) so cross-stage dedupe keeps working.
/// Recon emits the task body; ids, origin, and scope_hint are the harness's.
fn assign_ids(seeds: Vec<HuntTask>) -> Vec<Task> {
    seeds
        .into_iter()
        .enumerate()
        .map(|(i, s)| Task {
            id: format!("T-{:04}", i + 1),
            attack_class: s.attack_class,
            scope_hint: s.scope_paths.join(", "),
            scope_paths: s.scope_paths,
            hypothesis: s.hypothesis,
            targets: s.targets,
            suggested_skills: s.suggested_skills,
            tags: Vec::new(),
            priority: s.priority,
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

/// Repo name for the prompt context: the clone URL's basename when a target
/// repo is configured, else the target dir's own name.
fn repo_name(ctx: &StageCtx) -> String {
    if let Some(repo) = &ctx.config.target.repo {
        let trimmed = repo.trim_end_matches('/');
        let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
        if let Some(name) = trimmed.rsplit('/').next()
            && !name.is_empty()
        {
            return name.to_string();
        }
    }
    ctx.config
        .run
        .target_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "target".to_string())
}

/// Rough LOC count and the matching size tier for the target. Approximate by
/// design: it only needs to select the right cap tier, not an exact SLOC. A
/// line walk over source files, skipping VCS / vendor / build directories.
fn repo_stats(dir: &Path) -> (u64, &'static str) {
    let loc = count_loc(dir);
    let size = if loc >= LARGE_LOC {
        "large"
    } else if loc >= MEDIUM_LOC {
        "medium"
    } else {
        "small"
    };
    (loc, size)
}

/// Directories never worth counting: VCS, dependency vendoring, and build output.
/// Any dot-directory is skipped on top of these.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    "__pycache__",
];

/// Source-file extensions counted toward LOC. A representative spread across the
/// languages the harness targets; a missing one only nudges the tier estimate.
const SRC_EXTS: &[&str] = &[
    "rs", "go", "py", "js", "ts", "tsx", "jsx", "mjs", "cjs", "c", "cc", "cpp", "cxx", "h", "hh",
    "hpp", "java", "rb", "php", "sol", "swift", "kt", "scala", "sh", "ml", "ex", "exs", "erl",
    "cs",
];

fn count_loc(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            // Don't follow symlinks: they can escape the tree or cycle.
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with('.') || SKIP_DIRS.contains(&name.as_ref()) {
                    continue;
                }
                stack.push(entry.path());
            } else if ft.is_file() {
                let path = entry.path();
                let counts = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|ext| SRC_EXTS.contains(&ext));
                if counts && let Ok(content) = std::fs::read_to_string(&path) {
                    total += content.lines().count() as u64;
                }
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(out: &str) -> ReconReport {
        let json = extract_json_block(out).unwrap();
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn assigns_padded_ids_origin_and_derives_scope_hint() {
        let report = parse(
            r#"{"hunt_tasks":[
                {"attack_class":"overflow","scope_paths":["src/a.rs","src/b.rs"]},
                {"attack_class":"auth","scope_paths":["src/auth/"]}
            ]}"#,
        );
        let tasks = assign_ids(report.hunt_tasks);
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].id, "T-0001");
        assert_eq!(tasks[1].id, "T-0002");
        assert_eq!(tasks[0].attack_class, "overflow");
        // scope_hint is the joined scope_paths, so cross-stage dedupe still keys.
        assert_eq!(tasks[0].scope_hint, "src/a.rs, src/b.rs");
        assert_eq!(tasks[0].scope_paths, vec!["src/a.rs", "src/b.rs"]);
        assert_eq!(tasks[1].scope_hint, "src/auth/");
        assert!(tasks.iter().all(|t| matches!(t.origin, TaskOrigin::Recon)));
    }

    #[test]
    fn empty_hunt_tasks_yield_no_tasks() {
        let report = parse(r#"{"product_summary":"x","hunt_tasks":[]}"#);
        assert!(assign_ids(report.hunt_tasks).is_empty());
    }

    #[test]
    fn carries_hypothesis_targets_skills_priority_and_ignores_agent_id() {
        let report = parse(
            r#"{"hunt_tasks":[{
                "id":"T-99",
                "attack_class":"overflow",
                "scope_paths":["src/a.rs"],
                "hypothesis":"len added without bounds check",
                "targets":["src/a.rs:decode","src/a.rs:42"],
                "suggested_skills":["sharp-edges","spec-to-code-compliance"],
                "priority":"high"
            }]}"#,
        );
        let tasks = assign_ids(report.hunt_tasks);
        // The agent's own id is discarded; the harness assigns T-0001.
        assert_eq!(tasks[0].id, "T-0001");
        assert_eq!(tasks[0].hypothesis, "len added without bounds check");
        assert_eq!(tasks[0].targets, vec!["src/a.rs:decode", "src/a.rs:42"]);
        assert_eq!(
            tasks[0].suggested_skills,
            vec!["sharp-edges", "spec-to-code-compliance"]
        );
        assert_eq!(tasks[0].priority, Priority::High);
    }

    #[test]
    fn priority_defaults_to_medium_when_absent() {
        let report = parse(r#"{"hunt_tasks":[{"attack_class":"c","scope_paths":["s"]}]}"#);
        let tasks = assign_ids(report.hunt_tasks);
        assert_eq!(tasks[0].priority, Priority::Medium);
    }

    #[test]
    fn size_tier_tracks_loc_thresholds() {
        assert_eq!(repo_stats_tier(0), "small");
        assert_eq!(repo_stats_tier(9_999), "small");
        assert_eq!(repo_stats_tier(10_000), "medium");
        assert_eq!(repo_stats_tier(99_999), "medium");
        assert_eq!(repo_stats_tier(100_000), "large");
    }

    /// Tier from a LOC count, without walking a filesystem.
    fn repo_stats_tier(loc: u64) -> &'static str {
        if loc >= LARGE_LOC {
            "large"
        } else if loc >= MEDIUM_LOC {
            "medium"
        } else {
            "small"
        }
    }

    #[test]
    fn count_loc_walks_sources_and_skips_vcs_and_vendor() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("a.rs"), "one\ntwo\nthree\n").unwrap();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(root.join("src").join("b.go"), "x\ny\n").unwrap();
        // A non-source file is ignored.
        std::fs::write(root.join("README.md"), "a\nb\nc\nd\n").unwrap();
        // Skipped directories must not contribute.
        std::fs::create_dir(root.join(".git")).unwrap();
        std::fs::write(root.join(".git").join("huge.rs"), "junk\njunk\n").unwrap();
        std::fs::create_dir(root.join("node_modules")).unwrap();
        std::fs::write(root.join("node_modules").join("dep.js"), "z\nz\nz\n").unwrap();

        // 3 (a.rs) + 2 (b.go), nothing else.
        assert_eq!(count_loc(root), 5);
    }

    #[test]
    fn parses_queue_and_ignores_the_richer_report_fields() {
        // Recon emits far more than hunt_tasks; the harness deserializes only the
        // queue and lets serde drop product_summary, invariants, entry_points, ...
        let report = parse(
            r#"{
                "language":"rust",
                "product_summary":"A parser.",
                "invariants":[{"id":"INV-1","statement":"len bounds-checked"}],
                "entry_points":[{"type":"file","handler":"parse::decode"}],
                "hunt_tasks":[{"attack_class":"overflow","scope_paths":["src/parse.rs"]}]
            }"#,
        );
        let tasks = assign_ids(report.hunt_tasks);
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].attack_class, "overflow");
    }
}
