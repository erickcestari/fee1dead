//! Hunt stage: run one hunter per queued task, concurrently, each in its own
//! scratch dir. Hunters emit candidate findings and gap markers.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use super::StageCtx;
use crate::artifacts::{Artifacts, extract_json_block, names};
use crate::domain::{Finding, GapMarker, Severity, Task};
use crate::provider::{AgentRequest, AgentRunner, Effort, ResumeSession, is_usage_limited};

const PROMPT: &str = include_str!("../../prompts/hunt.md");

/// Hunter output shape (findings without harness-assigned ids).
#[derive(Debug, Deserialize)]
struct HunterOutput {
    #[serde(default)]
    findings: Vec<RawFinding>,
    #[serde(default)]
    gaps: Vec<RawGap>,
}

#[derive(Debug, Deserialize)]
struct RawFinding {
    title: String,
    severity: Severity,
    location: String,
    description: String,
    /// Hunter's confidence in [0,1]; defaults mid-scale if the hunter omits it.
    #[serde(default = "half")]
    confidence: f64,
    #[serde(default)]
    poc_path: Option<String>,
}

fn half() -> f64 {
    0.5
}

#[derive(Debug, Deserialize)]
struct RawGap {
    area: String,
    reason: String,
}

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let queue: Vec<Task> = ctx.artifacts.read_jsonl(names::QUEUE)?;
    if queue.is_empty() {
        warn!("hunt queue is empty; did recon run?");
        return Ok(());
    }
    // Cold hunters (non-forking providers) get recon's threat model injected as
    // context; forked hunters already carry it in their inherited session.
    let recon_report = ctx
        .artifacts
        .read_text(names::RECON_REPORT)
        .unwrap_or_default();

    // Hunt incrementally: skip tasks already processed in a previous pass so
    // gapfill re-queues only trigger work on the new tasks. Result files are
    // appended to, never truncated.
    let hunted: HashSet<String> = ctx
        .artifacts
        .read_jsonl::<String>(names::HUNTED)?
        .into_iter()
        .collect();
    ctx.artifacts.ensure_jsonl(names::CANDIDATES)?;
    ctx.artifacts.ensure_jsonl(names::GAPS)?;

    let mut tasks: Vec<Task> = queue
        .into_iter()
        .filter(|t| !hunted.contains(&t.id))
        .collect();
    if tasks.is_empty() {
        info!("no new tasks to hunt; all queue entries already processed");
        return Ok(());
    }
    // Schedule deeper tasks first. Concurrency only runs `concurrency` hunters at
    // once (and a usage limit can truncate the tail), so spawn order is value
    // order: hunter-surfaced tasks (gapfill, feedback) before recon's broad
    // sweep, then recon's own priority within each origin. Stable, so queue order
    // breaks ties.
    tasks.sort_by_key(|t| (t.origin.hunt_priority(), t.priority.hunt_rank()));

    // Fork each hunter from recon's session so it inherits the codebase context
    // recon built up, not just the architecture doc. Absent a recorded session
    // (e.g. a provider without sessions, or forking disabled), hunters run cold.
    let recon_session = if ctx.config.run.fork_hunters {
        ctx.artifacts
            .read_text(names::RECON_SESSION)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    } else {
        None
    };
    if recon_session.is_some() {
        info!("hunters will fork from recon's session");
    }

    // A forked hunter already carries recon's session (threat model and
    // invariants included) as a cached prefix, so re-injecting the report text
    // would re-bill those tokens per hunter — it gets a pointer instead. But
    // recon now orients deliberately shallow (structure-first, few full-file
    // reads), so that pass is NOT a substitute for reading the code: steer the
    // forked hunter at its task's own targets. A cold hunter gets the report.
    let arch_context = if recon_session.is_some() {
        "You explored this repository as the recon agent earlier in this \
         session, so its threat model and invariants are already in your \
         context. That pass was deliberately shallow — it read few files in \
         full — so do not treat it as a substitute for reading the code: open \
         this task's targets and the surrounding code yourself before reporting."
            .to_string()
    } else {
        recon_report
    };

    // PoC confirmation is the most token-hungry part of hunting (compile/run
    // loops). When disabled, hunters substantiate by close reading instead.
    let (poc_intro, poc_rule, poc_step) = if ctx.config.run.require_poc {
        (
            "Write, compile, and run any proof-of-concept code in your private \
             scratch dir `{scratch_dir}`. ",
            "- Confirm with a PoC when you can: write it in the scratch dir, \
             compile and run\n  it, and report only if it behaves as the bug \
             predicts.",
            "- [ ] Attempt a PoC in the scratch dir; compile and run it",
        )
    } else {
        (
            "",
            "- Do not write proof-of-concept code. Substantiate findings by \
             tracing the data\n  flow in the source and citing exact \
             locations; leave `poc_path` unset.",
            "- [ ] Substantiate the hypothesis by close reading; cite exact lines",
        )
    };

    let sem = Arc::new(Semaphore::new(ctx.config.run.concurrency));
    let target = ctx.config.run.target_dir.clone();
    let timeout = Duration::from_secs(ctx.config.run.agent_timeout_secs);
    // Reference repo (spec / known-good impl), if configured: appended to each
    // hunter's prompt and added to its readable dirs.
    let reference_note = ctx.config.reference.prompt_note();
    let reference_dirs: Vec<std::path::PathBuf> = ctx
        .config
        .reference
        .active_dir()
        .map(|d| vec![d.to_path_buf()])
        .unwrap_or_default();

    // Set by the first hunter that hits an account usage/session limit. Once
    // set, spawning more hunters is pointless — every one bounces off the same
    // limit until it resets — so the spawn loop stops and the unspawned tasks
    // (never marked processed) are retried on the next run.
    let limited = Arc::new(AtomicBool::new(false));
    let total = tasks.len();

    // Forked hunters each replay recon's session as their first request; the
    // semaphore would otherwise release the whole concurrency batch at once and
    // fire that burst simultaneously, which the API rejects with server-side
    // rate limiting. Stagger consecutive launches to spread the first requests.
    let stagger = Duration::from_millis(ctx.config.run.hunter_stagger_ms);

    let mut handles = Vec::new();
    let mut spawned = 0usize;
    for task in tasks {
        if limited.load(Ordering::Relaxed) {
            break;
        }
        if spawned > 0 && !stagger.is_zero() {
            tokio::time::sleep(stagger).await;
        }
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let runner = Arc::clone(&ctx.runner);
        let limited = Arc::clone(&limited);
        let scratch_dir = ctx.scratch.for_task(&task.id)?;
        let stream_log_path = ctx.artifacts.log_path(&format!("hunt-{}.jsonl", task.id));
        let prompt = PROMPT
            .replace("{attack_class}", &task.attack_class)
            .replace("{scope}", &scope_line(&task))
            .replace("{hypothesis}", &hypothesis_line(&task))
            .replace("{targets}", &targets_block(&task))
            .replace("{skills}", &skills_line(&task, ctx.config.run.use_skills))
            .replace("{target_dir}", &target.to_string_lossy())
            .replace("{poc_intro}", poc_intro)
            .replace("{poc_rule}", poc_rule)
            .replace("{poc_step}", poc_step)
            // After poc_intro, since it may embed {scratch_dir}.
            .replace("{scratch_dir}", &scratch_dir.to_string_lossy())
            .replace("{architecture}", &arch_context)
            + &reference_note
            + &ctx.config.run.skills_directive();
        let extra_dirs = reference_dirs.clone();
        // A forked hunter runs in recon's project dir (the target), so PoCs go
        // to the scratch dir by absolute path; a cold hunter runs in scratch.
        let resume = recon_session.clone().map(|session_id| ResumeSession {
            session_id,
            project_dir: target.clone(),
        });

        handles.push(tokio::spawn(async move {
            let _permit = permit; // released on drop
            let req = AgentRequest {
                prompt,
                system: None,
                working_dir: scratch_dir,
                extra_dirs,
                allowed_tools: Vec::new(),
                // Shared deny-list: no sub-agent fan-out (the orchestrator
                // already runs hunters in parallel) plus the tools no stage uses.
                disallowed_tools: super::disabled_tools(),
                timeout,
                resume,
                // A leaf agent: nothing forks from a hunter, and its own context
                // is re-read only by its own sub-5m-apart turns, so 1h caching
                // would pay a higher write premium for no reuse. It reads recon's
                // prefix at cache rates regardless (recon owns that 1h cache).
                cache_1h: false,
                // Hunting is open-ended multi-hop tracing source→sink; the
                // deepest thinking earns its keep here, and a hunter's effort is
                // not fork-amplified. This is the stage xhigh is for.
                effort: Effort::Xhigh,
                model: None,
                stream_log_path: Some(stream_log_path),
            };
            info!(task = %task.id, attack_class = %task.attack_class, "hunter started");
            let out = run_hunter(runner.as_ref(), req).await;
            if let Err(e) = &out
                && is_usage_limited(e)
            {
                limited.store(true, Ordering::Relaxed);
            }
            info!(task = %task.id, ok = out.is_ok(), "hunter finished");
            (task, out)
        }));
        spawned += 1;
    }

    let mut total_findings = 0usize;
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut limit_failures = 0usize;
    for handle in handles {
        let (task, out) = handle.await.context("hunter task panicked")?;
        match out {
            Ok((findings, gaps)) => {
                succeeded += 1;
                for (i, rf) in findings.into_iter().enumerate() {
                    let finding = Finding {
                        id: format!("{}-F{:02}", task.id, i + 1),
                        task_id: task.id.clone(),
                        title: rf.title,
                        attack_class: task.attack_class.clone(),
                        severity: rf.severity,
                        location: rf.location,
                        description: rf.description,
                        confidence: rf.confidence,
                        poc_path: rf.poc_path,
                    };
                    append_finding(&ctx.artifacts, &finding)?;
                    total_findings += 1;
                }
                for g in gaps {
                    let marker = GapMarker {
                        task_id: task.id.clone(),
                        area: g.area,
                        reason: g.reason,
                    };
                    ctx.artifacts.append_jsonl(names::GAPS, &marker)?;
                }
                // Record the task as processed only on success, so a failed
                // hunter is retried on the next pass.
                ctx.artifacts.append_jsonl(names::HUNTED, &task.id)?;
            }
            // One hunter failing must not abort the whole stage.
            Err(e) => {
                failed += 1;
                if is_usage_limited(&e) {
                    limit_failures += 1;
                }
                warn!(task = %task.id, error = %e, "hunter failed");
            }
        }
    }

    // `total` is the queue size; `spawned` may be smaller if a usage limit cut
    // the run short. Surface the breakdown so a degraded run is obvious at a
    // glance instead of having to reconstruct it from the per-agent logs.
    let skipped = total - spawned;
    info!(
        total,
        spawned,
        succeeded,
        failed,
        skipped,
        findings = total_findings,
        "hunt complete"
    );
    if limit_failures > 0 {
        warn!(
            limit_failures,
            skipped,
            "hunt stopped early: account usage limit reached; \
             unprocessed tasks will be retried on the next run after it resets"
        );
    }
    Ok(())
}

fn append_finding(artifacts: &Artifacts, finding: &Finding) -> Result<()> {
    artifacts.append_jsonl(names::CANDIDATES, finding)
}

/// The scope shown to the hunter: recon's path-prefix list when present, else
/// the free-form scope hint (gapfill/feedback tasks set only the hint).
fn scope_line(task: &Task) -> String {
    if task.scope_paths.is_empty() {
        task.scope_hint.clone()
    } else {
        task.scope_paths.join(", ")
    }
}

/// The hypothesis line shown to the hunter, with a fallback when recon left it
/// unset so the prompt never renders an empty field.
fn hypothesis_line(task: &Task) -> String {
    if task.hypothesis.trim().is_empty() {
        "(none given — form your own from the attack class and scope)".to_string()
    } else {
        task.hypothesis.clone()
    }
}

/// The starting-points block shown to the hunter, one target per line.
fn targets_block(task: &Task) -> String {
    if task.targets.is_empty() {
        "(none given — locate the relevant code within scope yourself)".to_string()
    } else {
        task.targets
            .iter()
            .map(|t| format!("- {t}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// The Trail of Bits skills the hunter should apply, recon's per-task picks.
/// With skills disabled for the run, the per-task picks are ignored.
fn skills_line(task: &Task, use_skills: bool) -> String {
    if !use_skills {
        "(disabled for this run — use judgment)".to_string()
    } else if task.suggested_skills.is_empty() {
        "(none suggested — use judgment)".to_string()
    } else {
        task.suggested_skills.join(", ")
    }
}

async fn run_hunter(
    runner: &dyn AgentRunner,
    req: AgentRequest,
) -> Result<(Vec<RawFinding>, Vec<RawGap>)> {
    let result = runner.run(req).await?;
    let json = extract_json_block(&result.stdout).context("hunter output had no json block")?;
    let out: HunterOutput =
        serde_json::from_str(json).context("hunter output was not valid json")?;
    Ok((out.findings, out.gaps))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::TaskOrigin;

    fn task(hypothesis: &str, targets: &[&str], skills: &[&str]) -> Task {
        Task {
            id: "T-0001".into(),
            attack_class: "overflow".into(),
            scope_hint: "src/a.rs".into(),
            scope_paths: Vec::new(),
            hypothesis: hypothesis.into(),
            targets: targets.iter().map(|s| s.to_string()).collect(),
            suggested_skills: skills.iter().map(|s| s.to_string()).collect(),
            tags: Vec::new(),
            priority: crate::domain::Priority::default(),
            origin: TaskOrigin::Recon,
        }
    }

    #[test]
    fn steering_uses_given_hypothesis_targets_and_skills() {
        let t = task(
            "len added unchecked",
            &["src/a.rs:decode", "src/a.rs:42"],
            &["sharp-edges", "spec-to-code-compliance"],
        );
        assert_eq!(hypothesis_line(&t), "len added unchecked");
        assert_eq!(targets_block(&t), "- src/a.rs:decode\n- src/a.rs:42");
        assert_eq!(
            skills_line(&t, true),
            "sharp-edges, spec-to-code-compliance"
        );
    }

    #[test]
    fn scope_prefers_paths_then_falls_back_to_hint() {
        let mut t = task("h", &[], &[]);
        // With no scope_paths, the free-form hint is shown.
        assert_eq!(scope_line(&t), "src/a.rs");
        // recon's path prefixes take precedence and render joined.
        t.scope_paths = vec!["lnwallet/".into(), "htlcswitch/".into()];
        assert_eq!(scope_line(&t), "lnwallet/, htlcswitch/");
    }

    #[test]
    fn steering_falls_back_when_unset() {
        let t = task("   ", &[], &[]);
        assert!(hypothesis_line(&t).contains("form your own"));
        assert!(targets_block(&t).contains("locate the relevant code"));
        assert!(skills_line(&t, true).contains("use judgment"));
    }

    #[test]
    fn disabling_skills_ignores_per_task_picks() {
        let t = task("x", &["src/a.rs"], &["sharp-edges"]);
        let line = skills_line(&t, false);
        assert!(line.contains("disabled"));
        assert!(!line.contains("sharp-edges"));
    }

    #[test]
    fn spawn_order_is_origin_then_priority() {
        // Mirrors the sort key in run(): hunter-surfaced origins first, then
        // recon's own priority within an origin, queue order breaking ties.
        let mk = |id: &str, origin: TaskOrigin, priority: crate::domain::Priority| {
            let mut t = task("h", &[], &[]);
            t.id = id.into();
            t.origin = origin;
            t.priority = priority;
            t
        };
        use crate::domain::Priority::{High, Low, Medium};
        let mut tasks = vec![
            mk("recon-low", TaskOrigin::Recon, Low),
            mk("recon-high", TaskOrigin::Recon, High),
            mk("gapfill", TaskOrigin::Gapfill, Medium),
            mk("recon-med", TaskOrigin::Recon, Medium),
        ];
        tasks.sort_by_key(|t| (t.origin.hunt_priority(), t.priority.hunt_rank()));
        let order: Vec<&str> = tasks.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(order, ["gapfill", "recon-high", "recon-med", "recon-low"]);
    }
}
