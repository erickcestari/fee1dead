//! Hunt stage: run one hunter per queued task, concurrently, each in its own
//! scratch dir. Hunters emit candidate findings and gap markers.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use super::StageCtx;
use crate::artifacts::{Artifacts, extract_json_block, names};
use crate::domain::{Finding, GapMarker, Severity, Task};
use crate::provider::{AgentRequest, AgentRunner};
use crate::skills;

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
    #[serde(default)]
    poc_path: Option<String>,
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
    let architecture = ctx
        .artifacts
        .read_text(names::ARCHITECTURE)
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

    let tasks: Vec<Task> = queue
        .into_iter()
        .filter(|t| !hunted.contains(&t.id))
        .collect();
    if tasks.is_empty() {
        info!("no new tasks to hunt; all queue entries already processed");
        return Ok(());
    }

    let sem = Arc::new(Semaphore::new(ctx.config.run.concurrency));
    let target = ctx.config.run.target_dir.clone();
    let timeout = Duration::from_secs(ctx.config.run.agent_timeout_secs);
    let skills: Vec<String> = skills::skills_for("hunt").iter().map(|s| s.to_string()).collect();

    let mut handles = Vec::new();
    for task in tasks {
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let runner = Arc::clone(&ctx.runner);
        let scratch_dir = ctx.scratch.for_task(&task.id)?;
        let prompt = PROMPT
            .replace("{attack_class}", &task.attack_class)
            .replace("{scope_hint}", &task.scope_hint)
            .replace("{target_dir}", &target.to_string_lossy())
            .replace("{architecture}", &architecture);
        let skills = skills.clone();

        handles.push(tokio::spawn(async move {
            let _permit = permit; // released on drop
            let req = AgentRequest {
                prompt,
                system: None,
                working_dir: scratch_dir,
                allowed_tools: Vec::new(),
                skills,
                timeout,
                max_turns: None,
            };
            let out = run_hunter(runner.as_ref(), req).await;
            (task, out)
        }));
    }

    let mut total_findings = 0usize;
    for handle in handles {
        let (task, out) = handle.await.context("hunter task panicked")?;
        match out {
            Ok((findings, gaps)) => {
                for (i, rf) in findings.into_iter().enumerate() {
                    let finding = Finding {
                        id: format!("{}-F{:02}", task.id, i + 1),
                        task_id: task.id.clone(),
                        title: rf.title,
                        attack_class: task.attack_class.clone(),
                        severity: rf.severity,
                        location: rf.location,
                        description: rf.description,
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
            Err(e) => warn!(task = %task.id, error = %e, "hunter failed"),
        }
    }

    info!(findings = total_findings, "hunt complete");
    Ok(())
}

fn append_finding(artifacts: &Artifacts, finding: &Finding) -> Result<()> {
    artifacts.append_jsonl(names::CANDIDATES, finding)
}

async fn run_hunter(
    runner: &dyn AgentRunner,
    req: AgentRequest,
) -> Result<(Vec<RawFinding>, Vec<RawGap>)> {
    let result = runner.run(req).await?;
    let json = extract_json_block(&result.stdout)
        .context("hunter output had no json block")?;
    let out: HunterOutput =
        serde_json::from_str(json).context("hunter output was not valid json")?;
    Ok((out.findings, out.gaps))
}
