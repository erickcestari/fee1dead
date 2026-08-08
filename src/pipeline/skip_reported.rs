//! skip-reported stage: drop candidate findings already reported in the sink
//! (e.g. filed as GitHub issues) *before* validate, so the run does not spend
//! validation tokens re-reviewing findings a previous run already surfaced.
//!
//! It reads `candidates.jsonl`, removes the ones the sink says are already
//! reported, and writes the reduced set back for validate/aggregate to consume.
//! Sinks that upsert by id (sqlite/jsonl/http) report nothing existing, so this
//! stage is a no-op for them and only bites for the github sink.
//!
//! How a candidate is matched to an already-reported finding:
//!
//! 1. Cheap algorithmic pass: token-set (Jaccard) similarity between the
//!    candidate's signature (title + location + attack class) and every existing
//!    one. A high score is a confident duplicate; a low score is confidently
//!    distinct.
//! 2. Only for the inconclusive middle band does a lightweight model (Haiku by
//!    default) judge the single closest pair — so the expensive call runs just on
//!    the genuinely ambiguous cases, not every candidate.
//!
//! The algorithm never *drops* a finding on its own for a middling score; it
//! either decides confidently or escalates to the judge, which fails open (keep
//! the finding): a stray duplicate issue is cheaper to close than a real finding
//! silently swallowed before it is ever validated.

use anyhow::Result;
use tracing::{info, warn};

use super::StageCtx;
use crate::artifacts::{extract_json_block, names};
use crate::domain::Finding;
use crate::provider::{AgentRequest, Effort};
use crate::store::{ExistingReport, build_sink};

/// At or above this token-overlap, a pair is a confident duplicate.
const DUP_HIGH: f64 = 0.6;
/// Below this, a pair is confidently distinct; between the two is the ambiguous
/// band handed to the model judge.
const DUP_LOW: f64 = 0.2;

const JUDGE_PROMPT: &str = include_str!("../../prompts/report-dedupe.md");

pub async fn run(ctx: &StageCtx) -> Result<()> {
    // The sink knows what has already been reported. Building it here is cheap
    // (the github sink does no I/O at construction) and the report stage builds
    // it again independently, keeping the stages decoupled.
    let existing = build_sink(&ctx.config.report)?.existing_reports()?;
    if existing.is_empty() {
        info!("skip-reported: sink reports nothing already filed; nothing to prune");
        return Ok(());
    }

    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    if candidates.is_empty() {
        return Ok(());
    }
    let before = candidates.len();
    let kept = drop_reported(ctx, candidates, &existing).await?;
    ctx.artifacts.write_jsonl(names::CANDIDATES, &kept)?;
    info!(
        before,
        after = kept.len(),
        pruned = before - kept.len(),
        existing = existing.len(),
        "skip-reported complete"
    );
    Ok(())
}

/// The algorithmic verdict for a candidate against the closest existing finding.
#[derive(Debug, PartialEq)]
enum Band {
    Duplicate,
    Distinct,
    /// Inconclusive — escalate to the model judge against this candidate index.
    Uncertain(usize),
}

/// Keep only the candidates not already reported in `existing`. Ambiguous pairs
/// are resolved by a lightweight model judge; the rest by the token score alone.
async fn drop_reported(
    ctx: &StageCtx,
    candidates: Vec<Finding>,
    existing: &[ExistingReport],
) -> Result<Vec<Finding>> {
    let existing_sigs: Vec<String> = existing.iter().map(signature_of_existing).collect();

    let mut kept = Vec::new();
    for finding in candidates {
        let sig = signature_of_finding(&finding);
        match classify(&sig, &existing_sigs) {
            Band::Distinct => kept.push(finding),
            Band::Duplicate => {
                info!(id = %finding.id, "pruning candidate already reported (algorithmic match)");
            }
            Band::Uncertain(idx) => {
                if judge_is_duplicate(ctx, &finding, &existing[idx]).await? {
                    info!(id = %finding.id, "pruning candidate already reported (model judge)");
                } else {
                    kept.push(finding);
                }
            }
        }
    }
    Ok(kept)
}

/// Band a candidate's best algorithmic match falls into.
fn classify(sig: &str, existing_sigs: &[String]) -> Band {
    let tokens = tokenize(sig);
    let (best_idx, best_score) = existing_sigs
        .iter()
        .map(|e| jaccard(&tokens, &tokenize(e)))
        .enumerate()
        .fold(
            (0usize, 0.0f64),
            |(bi, bs), (i, s)| {
                if s > bs { (i, s) } else { (bi, bs) }
            },
        );
    if best_score >= DUP_HIGH {
        Band::Duplicate
    } else if best_score < DUP_LOW {
        Band::Distinct
    } else {
        Band::Uncertain(best_idx)
    }
}

/// Ask the lightweight judge whether a candidate restates an existing finding.
/// Fails open (returns `false` → keep the candidate) on any judge error, so a
/// flaky judge never silences a real finding before it is validated.
async fn judge_is_duplicate(
    ctx: &StageCtx,
    finding: &Finding,
    candidate: &ExistingReport,
) -> Result<bool> {
    let prompt = JUDGE_PROMPT
        .replace("{new_finding}", &signature_of_finding(finding))
        .replace(
            "{existing_finding}",
            &format!("{}\n{}", candidate.title, candidate.text),
        );

    let req = AgentRequest {
        prompt,
        system: None,
        working_dir: ctx.config.run.out_dir.clone(),
        extra_dirs: Vec::new(),
        allowed_tools: Vec::new(),
        disallowed_tools: super::disabled_tools(),
        timeout: std::time::Duration::from_secs(ctx.config.run.agent_timeout_secs),
        resume: None,
        cache_1h: false,
        // A one-shot yes/no over two short texts: cheap model, shallow thinking.
        effort: Effort::Low,
        model: Some(ctx.config.report.dedupe_model().to_string()),
        stream_log_path: Some(
            ctx.artifacts
                .log_path(&format!("skip-reported-{}.jsonl", finding.id)),
        ),
    };

    match ctx.runner.run(req).await {
        Ok(result) => Ok(parse_duplicate_verdict(&result.stdout)),
        Err(e) => {
            warn!(id = %finding.id, error = %e, "dedup judge failed; keeping candidate");
            Ok(false)
        }
    }
}

/// Parse the judge's `{"duplicate": bool}` reply. Anything unparseable is
/// treated as "not a duplicate" so the candidate survives.
fn parse_duplicate_verdict(stdout: &str) -> bool {
    extract_json_block(stdout)
        .and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok())
        .and_then(|v| v.get("duplicate").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

/// The comparison signature of a candidate: the fields that identify the
/// underlying bug, not its prose.
fn signature_of_finding(f: &Finding) -> String {
    format!("{} {} {}", f.title, f.location, f.attack_class)
}

/// The signature of an already-reported finding, from what the sink recovered.
fn signature_of_existing(e: &ExistingReport) -> String {
    format!("{} {}", e.title, e.text)
}

/// Split text into a lowercased set of alphanumeric word tokens.
fn tokenize(s: &str) -> std::collections::HashSet<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 2)
        .map(str::to_lowercase)
        .collect()
}

/// Jaccard overlap of two token sets: |A ∩ B| / |A ∪ B|, in [0,1].
fn jaccard(a: &std::collections::HashSet<String>, b: &std::collections::HashSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    inter / union
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(title: &str, loc: &str, class: &str) -> String {
        format!("{title} {loc} {class}")
    }

    #[test]
    fn identical_signatures_are_duplicates() {
        let existing = vec![sig(
            "Unbounded alloc",
            "src/net.rs:42",
            "resource exhaustion",
        )];
        let s = sig("Unbounded alloc", "src/net.rs:42", "resource exhaustion");
        assert_eq!(classify(&s, &existing), Band::Duplicate);
    }

    #[test]
    fn unrelated_signatures_are_distinct() {
        let existing = vec![sig("SQL injection in login", "src/auth.rs:10", "injection")];
        let s = sig("Integer overflow in parser", "src/parse.rs:900", "overflow");
        assert_eq!(classify(&s, &existing), Band::Distinct);
    }

    #[test]
    fn partial_overlap_is_uncertain_and_points_at_best_candidate() {
        let existing = vec![
            sig("Totally unrelated thing", "x/y.rs:1", "misc"),
            // Shares the location and some words, but reframed: the ambiguous band.
            sig(
                "Missing bounds check before allocation",
                "src/net.rs:42",
                "dos",
            ),
        ];
        let s = sig(
            "Unbounded allocation from length field",
            "src/net.rs:42",
            "resource exhaustion",
        );
        assert_eq!(classify(&s, &existing), Band::Uncertain(1));
    }

    #[test]
    fn empty_existing_keeps_everything_without_scoring() {
        let s = sig("anything", "a.rs:1", "c");
        // No existing signatures → best score is 0 → distinct.
        assert_eq!(classify(&s, &[]), Band::Distinct);
    }

    #[test]
    fn verdict_parses_duplicate_flag_and_fails_open() {
        assert!(parse_duplicate_verdict("{\"duplicate\": true}"));
        assert!(!parse_duplicate_verdict("{\"duplicate\": false}"));
        // Garbage or missing field → not a duplicate (keep the candidate).
        assert!(!parse_duplicate_verdict("not json"));
        assert!(!parse_duplicate_verdict("{\"other\": 1}"));
    }

    #[test]
    fn signature_uses_identity_fields_only() {
        let f = Finding {
            id: "F-1".into(),
            task_id: "T".into(),
            title: "Bug".into(),
            attack_class: "dos".into(),
            severity: crate::domain::Severity::High,
            location: "a.rs:1".into(),
            description: "long prose that should not dominate the signature".into(),
            confidence: 0.5,
            poc_path: None,
        };
        let s = signature_of_finding(&f);
        assert!(s.contains("Bug"));
        assert!(s.contains("a.rs:1"));
        assert!(s.contains("dos"));
        assert!(!s.contains("prose"));
    }
}
