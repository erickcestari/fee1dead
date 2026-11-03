//! Hunt stage: one hunter per queued task, concurrently, each in its own
//! scratch dir, emitting candidate findings, the hypotheses it cleared, gap
//! markers, and wishes.
//!
//! Incremental: tasks already in `hunted.jsonl` are skipped and results are
//! appended, so a gapfill re-queue or `--resume` only hunts what is new.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tracing::{info, warn};

use super::ruled_out::{self, RawCleared};
use super::salvage::run_parsed;
use super::similarity::{jaccard, report_signature, tokenize};
use super::skills::Skill;
use super::wishlist::{self, RawWish};
use super::{StageCtx, citation, prompt, recon};
use crate::artifacts::{Artifacts, names};
use crate::config::Stage;
use crate::domain::{Finding, GapMarker, RuledOut, Severity, Task, TraceStep, default_confidence};
use crate::json_block;
use crate::provider::{ResumeSession, is_usage_limited};
use crate::store::{ExistingReport, build_sink};
use crate::target::head_commit;

const PROMPT: &str = include_str!("../../prompts/hunt.md");

/// Filed reports each hunter sees. On lnd, the report a re-found bug
/// duplicated ranked in the top 30 for 67 of 80, for ~1k prompt tokens.
const FILED_SHOWN: usize = 30;

const FILED_INTRO: &str = "Already filed, so do not report these again or a variant with the \
     same root cause and fix. A different defect in the same code is still new; spend your \
     effort there:";

/// Ruled-out claims each hunter sees. Fewer than filed reports: each carries
/// its reason.
const RULED_OUT_SHOWN: usize = 15;

const RULED_OUT_INTRO: &str = "Ruled out by earlier runs, on code unchanged since; each names \
     the code that settled it. Do not report one again unless you show that code does not \
     hold:";

/// What a forked hunter gets instead of recon's report, which is already in
/// its session. Recon's pass is shallow, so it is steered back at the code.
const FORKED_CONTEXT: &str = "You explored this repository as the recon agent earlier in this \
     session, so its threat model and invariants are already in your \
     context. That pass was deliberately shallow — it read few files in \
     full — so do not treat it as a substitute for reading the code: open \
     this task's targets and the surrounding code yourself before reporting.";

#[derive(Debug, Deserialize)]
struct HunterOutput {
    #[serde(default)]
    findings: Vec<RawFinding>,
    #[serde(default)]
    cleared: Vec<RawCleared>,
    #[serde(default)]
    gaps: Vec<RawGap>,
    #[serde(default)]
    wishes: Vec<RawWish>,
}

impl HunterOutput {
    /// Every `file:line` the answer stakes a claim on.
    fn cited(&self) -> impl Iterator<Item = &str> {
        let findings = self.findings.iter().flat_map(|f| {
            std::iter::once(f.location.as_str()).chain(f.trace.iter().map(|s| s.location.as_str()))
        });
        findings.chain(self.cleared.iter().map(|c| c.guard.as_str()))
    }
}

#[derive(Debug, Deserialize)]
struct RawFinding {
    title: String,
    severity: Severity,
    location: String,
    #[serde(default)]
    trace: Vec<TraceStep>,
    description: String,
    #[serde(default)]
    attack_scenario: String,
    #[serde(default = "default_confidence")]
    confidence: f64,
    #[serde(default)]
    poc_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawGap {
    area: String,
    #[serde(default)]
    attack_class: String,
    reason: String,
}

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let tasks = pending_tasks(&ctx.artifacts)?;
    if tasks.is_empty() {
        info!("no tasks left to hunt");
        return Ok(());
    }
    let run_id = ctx
        .artifacts
        .read_line(names::RUN_ID)
        .context("the run has no id")?;
    let recon_session = recon::forkable_session(ctx, Stage::Hunt);
    let target = ctx.config.run.target_dir.clone();
    // Without a commit, a cleared claim could never be checked for change.
    let head = head_commit(&target);
    let prompt = HuntPrompt::new(
        ctx,
        recon_session.is_some(),
        filed_reports(ctx),
        ruled_out_claims(ctx, head.as_deref())?,
    );

    let slots = Arc::new(Semaphore::new(ctx.config.run.concurrency));
    let stagger = Duration::from_millis(ctx.config.run.hunter_stagger_ms);
    // Set on the first usage limit: later hunters would only bounce, so
    // spawning stops and `--resume` picks up the rest.
    let limited = Arc::new(AtomicBool::new(false));
    let total = tasks.len();
    let mut running = JoinSet::new();
    let mut tally = Tally::default();
    let mut spawned = 0;

    'spawn: for task in tasks {
        if limited.load(Ordering::Relaxed) {
            break;
        }
        if spawned > 0 && !stagger.is_zero() {
            tokio::time::sleep(stagger).await;
        }
        // Record finished hunters while waiting for a slot, so a crash loses
        // only the hunters still running.
        let slot = loop {
            tokio::select! {
                slot = Arc::clone(&slots).acquire_owned() => {
                    break slot.expect("hunt semaphore is never closed");
                }
                Some(done) = running.join_next() => {
                    let done = done.context("hunter task panicked")?;
                    record(&ctx.artifacts, &run_id, head.as_deref(), done, &mut tally)?;
                    if limited.load(Ordering::Relaxed) {
                        break 'spawn;
                    }
                }
            }
        };
        let mut req = ctx.agent_request(Stage::Hunt, &task.id, String::new())?;
        let scratch_dir = req.working_dir.clone();
        req.prompt = prompt.render(&task, &scratch_dir);
        req.resume = recon_session.clone().map(|session_id| ResumeSession {
            session_id,
            project_dir: ctx.config.run.target_dir.clone(),
        });
        let runner = Arc::clone(&ctx.runner);
        let limited = Arc::clone(&limited);
        let target = target.clone();
        running.spawn(async move {
            info!(task = %task.id, attack_class = %task.attack_class, "hunter started");
            let out = run_parsed(runner.as_ref(), req, |r| {
                let output = json_block::parse::<HunterOutput>(&r.stdout, "hunter report")?;
                citation::check(&target, output.cited())?;
                Ok(output)
            })
            .await;
            if out.as_ref().is_err_and(is_usage_limited) {
                limited.store(true, Ordering::Relaxed);
            }
            info!(task = %task.id, ok = out.is_ok(), "hunter finished");
            Finished {
                task,
                scratch_dir,
                out,
                _slot: slot,
            }
        });
        spawned += 1;
    }
    while let Some(done) = running.join_next().await {
        let done = done.context("hunter task panicked")?;
        record(&ctx.artifacts, &run_id, head.as_deref(), done, &mut tally)?;
    }

    let skipped = total - spawned;
    info!(
        total,
        spawned,
        succeeded = tally.succeeded,
        failed = tally.failed,
        skipped,
        findings = tally.findings,
        wishes = tally.wishes,
        "hunt complete"
    );
    if tally.limit_failures > 0 {
        warn!(
            limit_failures = tally.limit_failures,
            skipped,
            "hunt stopped early: account usage limit reached; once it resets, \
             `fee1dead run --resume` hunts the unprocessed tasks"
        );
    }
    Ok(())
}

/// Queued tasks not hunted yet, in spawn order.
fn pending_tasks(artifacts: &Artifacts) -> Result<Vec<Task>> {
    let hunted: HashSet<String> = artifacts.read_jsonl(names::HUNTED)?.into_iter().collect();
    artifacts.ensure_jsonl(names::CANDIDATES)?;
    artifacts.ensure_jsonl(names::GAPS)?;
    let mut tasks: Vec<Task> = artifacts
        .read_jsonl::<Task>(names::QUEUE)?
        .into_iter()
        .filter(|t| !hunted.contains(&t.id))
        .collect();
    spawn_order(&mut tasks);
    Ok(tasks)
}

/// Most valuable first, since a usage limit can cut the tail. Stable.
fn spawn_order(tasks: &mut [Task]) {
    tasks.sort_by_key(|t| (t.priority.hunt_rank(), t.origin.hunt_rank()));
}

/// Reports the sink already holds, so hunters skip known bugs instead of
/// re-finding them for skip-reported to prune. Hunting goes on without them
/// when the sink cannot list.
fn filed_reports(ctx: &StageCtx) -> Vec<Precedent> {
    match build_sink(&ctx.config.report).and_then(|sink| sink.existing_reports()) {
        Ok(existing) => existing.iter().map(Precedent::filed).collect(),
        Err(e) => {
            warn!(
                error = format!("{e:#}"),
                "cannot list filed reports; hunters will not see them"
            );
            Vec::new()
        }
    }
}

/// Claims earlier runs ruled out on code unchanged since `head`; none for a
/// target that is no git checkout.
fn ruled_out_claims(ctx: &StageCtx, head: Option<&str>) -> Result<Vec<Precedent>> {
    let Some(head) = head else {
        return Ok(Vec::new());
    };
    let entries: Vec<RuledOut> = ctx.artifacts.read_jsonl(names::RULED_OUT)?;
    let holding = ruled_out::holding(entries, &ctx.config.run.target_dir, head);
    Ok(holding.iter().map(Precedent::ruled_out).collect())
}

/// A past record as a hunter sees it (a filed report, a ruled-out claim),
/// with the tokens it is ranked by.
struct Precedent {
    line: String,
    tokens: HashSet<String>,
}

impl Precedent {
    fn filed(e: &ExistingReport) -> Self {
        let line = if e.location.is_empty() {
            format!("- {}", e.title)
        } else {
            format!("- {} (`{}`)", e.title, e.location)
        };
        Self {
            line,
            tokens: tokenize(&report_signature(e)),
        }
    }

    fn ruled_out(r: &RuledOut) -> Self {
        let mut line = format!("- {} (`{}`)", r.claim, r.location);
        if !r.reason.is_empty() {
            line = format!("{line}: {}", r.reason);
        }
        Self {
            line,
            tokens: tokenize(&format!("{} {}", r.claim, r.location)),
        }
    }
}

/// Under `intro`, the `cap` precedents closest to `task`, most similar first;
/// empty when none overlap it.
fn closest_block(task: &Task, precedents: &[Precedent], cap: usize, intro: &str) -> String {
    let task_tokens = tokenize(&format!(
        "{} {} {} {}",
        task.attack_class,
        task.hypothesis,
        scope_line(task),
        task.targets.join(" ")
    ));
    let mut ranked: Vec<(f64, &str)> = precedents
        .iter()
        .map(|r| (jaccard(&task_tokens, &r.tokens), r.line.as_str()))
        .filter(|&(score, _)| score > 0.0)
        .collect();
    if ranked.is_empty() {
        return String::new();
    }
    ranked.sort_by(|a, b| b.0.total_cmp(&a.0));
    let lines: Vec<&str> = ranked.into_iter().take(cap).map(|(_, line)| line).collect();
    format!("{intro}\n{}\n\n", lines.join("\n"))
}

/// The run-wide parts of a hunter prompt.
struct HuntPrompt {
    target_dir: String,
    /// Recon's report for a cold hunter, or [`FORKED_CONTEXT`].
    architecture: String,
    poc: PocText,
    skills: Vec<Skill>,
    suffix: String,
    filed: Vec<Precedent>,
    ruled_out: Vec<Precedent>,
}

impl HuntPrompt {
    fn new(ctx: &StageCtx, forked: bool, filed: Vec<Precedent>, ruled_out: Vec<Precedent>) -> Self {
        let architecture = if forked {
            FORKED_CONTEXT.to_string()
        } else {
            ctx.artifacts
                .read_text(names::RECON_REPORT)
                .unwrap_or_default()
        };
        Self {
            target_dir: ctx.config.run.target_dir.to_string_lossy().into_owned(),
            architecture,
            poc: PocText::new(ctx.config.run.require_poc),
            skills: ctx.skills.clone(),
            // With skills installed, the task's own skills line says which to use.
            suffix: prompt::reference_note(&ctx.config)
                + if ctx.skills.is_empty() {
                    prompt::NO_SKILLS
                } else {
                    ""
                },
            filed,
            ruled_out,
        }
    }

    fn render(&self, task: &Task, scratch_dir: &Path) -> String {
        PROMPT
            .replace("{attack_class}", &task.attack_class)
            .replace("{scope}", &scope_line(task))
            .replace("{hypothesis}", &hypothesis_line(task))
            .replace("{targets}", &targets_block(task))
            .replace("{skills}", &skills_line(task, &self.skills))
            .replace("{target_dir}", &self.target_dir)
            .replace("{poc_intro}", self.poc.intro)
            .replace("{poc_rule}", self.poc.rule)
            .replace("{poc_step}", self.poc.step)
            .replace("{wish_kinds}", wishlist::KINDS)
            .replace("{severity_scale}", prompt::severity_scale())
            // After poc_intro, which may embed it.
            .replace("{scratch_dir}", &scratch_dir.to_string_lossy())
            .replace("{architecture}", &self.architecture)
            // Last, so no placeholder in a filed title or claim is ever substituted.
            .replace("{precedents}", &self.precedents(task))
            + &self.suffix
    }

    /// The filed reports and ruled-out claims closest to `task`.
    fn precedents(&self, task: &Task) -> String {
        closest_block(task, &self.filed, FILED_SHOWN, FILED_INTRO)
            + &closest_block(task, &self.ruled_out, RULED_OUT_SHOWN, RULED_OUT_INTRO)
    }
}

/// The PoC instructions. Without `require_poc`, hunters substantiate by close
/// reading, skipping the token-hungry compile-and-run loop.
struct PocText {
    intro: &'static str,
    rule: &'static str,
    step: &'static str,
}

impl PocText {
    fn new(require_poc: bool) -> Self {
        if require_poc {
            Self {
                intro: "Write, compile, and run any proof-of-concept code in your private \
                        scratch dir `{scratch_dir}`. ",
                rule: "- Confirm with a PoC when you can: write it in the scratch dir, \
                       compile and run\n  it, and report only if it behaves as the bug \
                       predicts.",
                step: "- [ ] Attempt a PoC in the scratch dir; compile and run it",
            }
        } else {
            Self {
                intro: "",
                rule: "- Do not write proof-of-concept code. Substantiate findings by \
                       tracing the data\n  flow in the source and citing exact \
                       locations; leave `poc_path` unset.",
                step: "- [ ] Substantiate the hypothesis by close reading; cite exact lines",
            }
        }
    }
}

/// Recon's path prefixes, else the free-form hint gapfill/feedback tasks set.
fn scope_line(task: &Task) -> String {
    if task.scope_paths.is_empty() {
        task.scope_hint.clone()
    } else {
        task.scope_paths.join(", ")
    }
}

fn hypothesis_line(task: &Task) -> String {
    if task.hypothesis.trim().is_empty() {
        "(none given — form your own from the attack class and scope)".to_string()
    } else {
        task.hypothesis.clone()
    }
}

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

/// The task's suggested skills that are installed, with where to read each;
/// a name recon made up is dropped rather than sent to the hunter.
fn skills_line(task: &Task, installed: &[Skill]) -> String {
    if installed.is_empty() {
        return "(none installed, use judgment)".to_string();
    }
    let usable: Vec<String> = task
        .suggested_skills
        .iter()
        .filter_map(|name| installed.iter().find(|s| &s.name == name))
        .map(|s| format!("{} (`{}`)", s.name, s.path.display()))
        .collect();
    if usable.is_empty() {
        "(none suggested, use judgment)".to_string()
    } else {
        usable.join(", ")
    }
}

/// One hunter's outcome, handed back to the stage.
struct Finished {
    task: Task,
    scratch_dir: PathBuf,
    out: Result<HunterOutput>,
    /// Held until [`record`] has saved the outcome, so a new hunter never
    /// starts ahead of a finished one's save.
    _slot: OwnedSemaphorePermit,
}

#[derive(Default)]
struct Tally {
    succeeded: usize,
    failed: usize,
    limit_failures: usize,
    findings: usize,
    wishes: usize,
}

/// Persist one hunter's findings (PoCs copied out of scratch), cleared
/// hypotheses (stamped with the `head` commit, if any), gaps, and wishes,
/// then its ledger entry. A failed hunter is not marked, so the next pass
/// retries it.
fn record(
    artifacts: &Artifacts,
    run_id: &str,
    head: Option<&str>,
    done: Finished,
    tally: &mut Tally,
) -> Result<()> {
    let Finished {
        task,
        scratch_dir,
        out,
        ..
    } = done;
    let output = match out {
        Ok(output) => output,
        Err(e) => {
            tally.failed += 1;
            if is_usage_limited(&e) {
                tally.limit_failures += 1;
            }
            warn!(task = %task.id, error = format!("{e:#}"), "hunter failed");
            return Ok(());
        }
    };
    tally.succeeded += 1;
    for (i, rf) in output.findings.into_iter().enumerate() {
        let id = finding_id(run_id, &task.id, i);
        // Keep the hunter's own path if the copy fails, so the lead survives.
        let poc_path = rf
            .poc_path
            .map(|p| persist_poc(artifacts, &scratch_dir, &id, &p).unwrap_or(p));
        let finding = Finding {
            id,
            task_id: task.id.clone(),
            title: rf.title,
            attack_class: task.attack_class.clone(),
            severity: rf.severity,
            location: rf.location,
            trace: rf.trace,
            description: rf.description,
            attack_scenario: rf.attack_scenario,
            confidence: rf.confidence,
            poc_path,
        };
        artifacts.append_jsonl(names::CANDIDATES, &finding)?;
        tally.findings += 1;
    }
    if let Some(head) = head {
        for entry in output
            .cleared
            .into_iter()
            .filter_map(|c| c.into_ruled_out(head))
        {
            artifacts.append_jsonl(names::CLEARED, &entry)?;
        }
    }
    for g in output.gaps {
        let marker = GapMarker {
            task_id: task.id.clone(),
            area: g.area,
            attack_class: g.attack_class,
            reason: g.reason,
        };
        artifacts.append_jsonl(names::GAPS, &marker)?;
    }
    for wish in output
        .wishes
        .into_iter()
        .filter_map(|w| w.into_wish(&task.id, None))
    {
        artifacts.append_jsonl(names::WISHLIST, &wish)?;
        tally.wishes += 1;
    }
    artifacts.append_jsonl(names::HUNTED, &task.id)
}

/// Copy a PoC out of the hunter's scratch dir into `pocs/<finding id>/`,
/// returning its path relative to `out_dir`. `None` when it is missing or
/// lies outside the scratch dir.
fn persist_poc(
    artifacts: &Artifacts,
    scratch_dir: &Path,
    finding_id: &str,
    poc_path: &str,
) -> Option<String> {
    let copy = || -> Result<String> {
        let scratch = scratch_dir.canonicalize()?;
        // Joining an absolute path replaces the base, so both forms resolve.
        let src = scratch.join(poc_path).canonicalize()?;
        anyhow::ensure!(
            src.starts_with(&scratch),
            "outside the scratch dir {}",
            scratch.display()
        );
        let name = src.file_name().context("PoC path has no file name")?;
        let rel = Path::new(names::POCS).join(finding_id).join(name);
        artifacts.import(&rel, &src)?;
        Ok(rel.to_string_lossy().into_owned())
    };
    copy()
        .inspect_err(|e| warn!(finding = finding_id, poc_path, error = %e, "could not keep PoC"))
        .ok()
}

/// Unique across runs: `<run>-<task>-F<nn>`.
fn finding_id(run_id: &str, task_id: &str, index: usize) -> String {
    format!("{run_id}-{task_id}-F{:02}", index + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::fixtures;
    use crate::domain::{Priority, TaskOrigin};

    fn task(hypothesis: &str, targets: &[&str], skills: &[&str]) -> Task {
        Task {
            scope_hint: "src/a.rs".into(),
            hypothesis: hypothesis.into(),
            targets: targets.iter().map(ToString::to_string).collect(),
            suggested_skills: skills.iter().map(ToString::to_string).collect(),
            ..fixtures::task("T-0001")
        }
    }

    #[test]
    fn poc_is_copied_out_of_scratch_relative_or_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().join("scratch").join("T-0001");
        std::fs::create_dir_all(scratch.join("poc")).unwrap();
        std::fs::write(scratch.join("poc").join("main.go"), "package main").unwrap();
        let art = Artifacts::new(dir.path().join("out")).unwrap();

        let rel = persist_poc(&art, &scratch, "R-T-0001-F01", "poc").unwrap();
        assert_eq!(rel, "pocs/R-T-0001-F01/poc");
        assert!(art.path(&rel).join("main.go").exists());

        let abs = scratch.join("poc").join("main.go");
        let rel = persist_poc(&art, &scratch, "R-T-0001-F02", abs.to_str().unwrap()).unwrap();
        assert_eq!(rel, "pocs/R-T-0001-F02/main.go");
    }

    #[test]
    fn poc_outside_scratch_or_missing_is_not_copied() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(dir.path().join("secret"), "s").unwrap();
        let art = Artifacts::new(dir.path().join("out")).unwrap();
        assert!(persist_poc(&art, &scratch, "F", "../secret").is_none());
        assert!(persist_poc(&art, &scratch, "F", "nope.go").is_none());
        assert!(!art.path(names::POCS).exists());
    }

    #[test]
    fn finding_ids_carry_the_run_so_they_never_repeat_across_runs() {
        let a = finding_id("20260901T000000Z", "T-0001", 0);
        assert_eq!(a, "20260901T000000Z-T-0001-F01");
        assert_ne!(a, finding_id("20260902T000000Z", "T-0001", 0));
    }

    fn skill(name: &str) -> Skill {
        Skill {
            name: name.into(),
            description: String::new(),
            path: format!("/skills/{name}/SKILL.md").into(),
        }
    }

    #[test]
    fn steering_uses_given_hypothesis_targets_and_installed_skills() {
        let t = task(
            "len added unchecked",
            &["src/a.rs:decode", "src/a.rs:42"],
            &["unsafe-audit", "made-up", "poc-review"],
        );
        assert_eq!(hypothesis_line(&t), "len added unchecked");
        assert_eq!(targets_block(&t), "- src/a.rs:decode\n- src/a.rs:42");
        assert_eq!(
            skills_line(&t, &[skill("poc-review"), skill("unsafe-audit")]),
            "unsafe-audit (`/skills/unsafe-audit/SKILL.md`), poc-review (`/skills/poc-review/SKILL.md`)"
        );
    }

    #[test]
    fn steering_falls_back_when_unset_or_not_installed() {
        let t = task("   ", &[], &[]);
        assert!(hypothesis_line(&t).contains("form your own"));
        assert!(targets_block(&t).contains("locate the relevant code"));
        assert!(skills_line(&t, &[skill("unsafe-audit")]).contains("none suggested"));
        let t = task("x", &[], &["made-up"]);
        assert!(skills_line(&t, &[skill("unsafe-audit")]).contains("none suggested"));
        let t = task("x", &[], &["unsafe-audit"]);
        let line = skills_line(&t, &[]);
        assert!(line.contains("none installed") && !line.contains("unsafe-audit"));
    }

    #[test]
    fn scope_prefers_paths_then_falls_back_to_hint() {
        let mut t = task("h", &[], &[]);
        assert_eq!(scope_line(&t), "src/a.rs");
        t.scope_paths = vec!["lnwallet/".into(), "htlcswitch/".into()];
        assert_eq!(scope_line(&t), "lnwallet/, htlcswitch/");
    }

    fn filed(title: &str, location: &str) -> Precedent {
        Precedent::filed(&ExistingReport {
            id: String::new(),
            title: title.into(),
            location: location.into(),
            attack_class: String::new(),
            text: String::new(),
        })
    }

    fn filed_block(task: &Task, filed: &[Precedent]) -> String {
        closest_block(task, filed, FILED_SHOWN, FILED_INTRO)
    }

    #[test]
    fn filed_block_ranks_the_closest_first_and_drops_unrelated() {
        let t = Task {
            attack_class: "htlc-dust-overflow".into(),
            hypothesis: "dust sum overflows in lnwallet".into(),
            ..fixtures::task("T-0001")
        };
        let block = filed_block(
            &t,
            &[
                filed("Gossip timestamp skew", "discovery/gossiper.go:10"),
                filed("Dust limit check", "lnwallet/channel.go:5"),
                filed("HTLC dust overflow in lnwallet", "lnwallet/channel.go:9"),
            ],
        );
        assert!(block.starts_with(FILED_INTRO));
        let closest = block.find("- HTLC dust overflow in lnwallet (`lnwallet/channel.go:9`)");
        let next = block.find("- Dust limit check");
        assert!(closest.unwrap() < next.unwrap(), "{block}");
        assert!(!block.contains("Gossip"));
        assert!(filed_block(&t, &[filed("Gossip timestamp skew", "")]).is_empty());
    }

    #[test]
    fn filed_block_is_capped() {
        let t = Task {
            hypothesis: "dust".into(),
            ..fixtures::task("T-0001")
        };
        let many: Vec<Precedent> = (0..FILED_SHOWN + 5)
            .map(|i| filed(&format!("dust bug {i}"), ""))
            .collect();
        let block = filed_block(&t, &many);
        assert_eq!(
            block.lines().filter(|l| l.starts_with("- ")).count(),
            FILED_SHOWN
        );
    }

    #[test]
    fn ruled_out_claims_show_their_settling_code_and_reason() {
        let entry = |reason: &str| RuledOut {
            claim: "dust sum overflows".into(),
            location: "lnwallet/channel.go:88".into(),
            reason: reason.into(),
            commit: "c1".into(),
        };
        let t = Task {
            hypothesis: "dust overflow".into(),
            ..fixtures::task("T-0001")
        };
        let block = closest_block(
            &t,
            &[Precedent::ruled_out(&entry("capped by maxDust"))],
            RULED_OUT_SHOWN,
            RULED_OUT_INTRO,
        );
        assert!(block.starts_with(RULED_OUT_INTRO));
        assert!(
            block.contains("- dust sum overflows (`lnwallet/channel.go:88`): capped by maxDust")
        );
        assert_eq!(
            Precedent::ruled_out(&entry("")).line,
            "- dust sum overflows (`lnwallet/channel.go:88`)"
        );
    }

    #[test]
    fn cited_covers_findings_their_traces_and_cleared_guards() {
        let out: HunterOutput = serde_json::from_str(
            r#"{"findings": [{"title": "t", "severity": "high", "location": "a.go:1",
                "description": "d", "trace": [{"kind": "sink", "location": "b.go:2"}]}],
                "cleared": [{"claim": "c", "guard": "c.go:3"}]}"#,
        )
        .unwrap();
        assert_eq!(
            out.cited().collect::<Vec<_>>(),
            ["a.go:1", "b.go:2", "c.go:3"]
        );
    }

    #[test]
    fn render_fills_the_filed_placeholder_with_or_without_reports() {
        let mut p = HuntPrompt {
            target_dir: "/t".into(),
            architecture: String::new(),
            poc: PocText::new(false),
            skills: Vec::new(),
            suffix: String::new(),
            filed: Vec::new(),
            ruled_out: Vec::new(),
        };
        let t = task("dust overflow", &[], &[]);
        assert!(!p.render(&t, Path::new("/s")).contains("{precedents}"));
        p.filed = vec![filed("Dust overflow", "a.go:1")];
        let rendered = p.render(&t, Path::new("/s"));
        assert!(rendered.contains("- Dust overflow (`a.go:1`)"));
        assert!(!rendered.contains("{precedents}"));
    }

    #[test]
    fn render_fills_the_severity_scale() {
        let p = HuntPrompt {
            target_dir: "/t".into(),
            architecture: String::new(),
            poc: PocText::new(false),
            skills: Vec::new(),
            suffix: String::new(),
            filed: Vec::new(),
            ruled_out: Vec::new(),
        };
        let rendered = p.render(&task("dust overflow", &[], &[]), Path::new("/s"));
        assert!(rendered.contains(prompt::severity_scale()));
        assert!(!rendered.contains("{severity_scale}"));
    }

    /// Prefix-caching providers reuse the architecture across cold hunters only
    /// if it comes before anything task-specific.
    #[test]
    fn architecture_precedes_every_task_specific_part() {
        let p = HuntPrompt {
            target_dir: "/t".into(),
            architecture: "RECON REPORT".into(),
            poc: PocText::new(true),
            skills: vec![skill("unsafe-audit")],
            suffix: String::new(),
            filed: vec![filed("Dust overflow", "a.go:1")],
            ruled_out: Vec::new(),
        };
        let a = p.render(
            &task("overflow", &["a.go:1"], &["unsafe-audit"]),
            Path::new("/s1"),
        );
        let b = p.render(&task("dust overflow", &["b.go:2"], &[]), Path::new("/s2"));
        let shared = a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count();
        assert!(a[..shared].contains("RECON REPORT"), "{}", &a[..shared]);
    }

    #[test]
    fn poc_text_embeds_the_scratch_dir_only_when_pocs_are_required() {
        let with = PocText::new(true);
        assert!(with.intro.contains("{scratch_dir}"));
        let without = PocText::new(false);
        assert!(without.intro.is_empty());
        assert!(without.rule.contains("Do not write proof-of-concept"));
    }

    #[test]
    fn spawn_order_is_priority_then_origin() {
        let mk = |id: &str, origin: TaskOrigin, priority: Priority| Task {
            priority,
            origin,
            ..fixtures::task(id)
        };
        let mut tasks = [
            mk("recon-low", TaskOrigin::Recon, Priority::Low),
            mk("recon-med", TaskOrigin::Recon, Priority::Medium),
            mk("recon-high", TaskOrigin::Recon, Priority::High),
            mk("gapfill", TaskOrigin::Gapfill, Priority::Medium),
        ];
        spawn_order(&mut tasks);
        let order: Vec<&str> = tasks.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(order, ["recon-high", "gapfill", "recon-med", "recon-low"]);
    }
}
