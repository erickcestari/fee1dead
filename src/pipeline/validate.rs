//! Validate stage: an independent agent re-reads the code and tries to disprove
//! each candidate finding. It emits verdicts only; it cannot add findings.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{info, warn};

use super::StageCtx;
use crate::artifacts::{extract_json_block, names};
use crate::domain::{Finding, Validation, Verdict};
use crate::provider::AgentRequest;
use crate::skills;

const PROMPT: &str = include_str!("../../prompts/validate.md");

#[derive(Debug, Deserialize)]
struct RawVerdict {
    verdict: Verdict,
    evidence: String,
}

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    if candidates.is_empty() {
        warn!("no candidate findings to validate");
        ctx.artifacts
            .write_jsonl::<Validation>(names::VALIDATED, &[])?;
        return Ok(());
    }

    let target = ctx.config.run.target_dir.to_string_lossy().into_owned();
    let timeout = Duration::from_secs(ctx.config.run.agent_timeout_secs);
    let skills: Vec<String> = skills::skills_for("validate")
        .iter()
        .map(|s| s.to_string())
        .collect();

    let mut validations = Vec::new();
    let (mut confirmed, mut refuted) = (0usize, 0usize);

    // Validation re-reads the source, so it runs in the target dir.
    for finding in &candidates {
        let prompt = PROMPT
            .replace("{target_dir}", &target)
            .replace("{finding_id}", &finding.id)
            .replace("{title}", &finding.title)
            .replace("{attack_class}", &finding.attack_class)
            .replace("{location}", &finding.location)
            .replace("{description}", &finding.description);

        let req = AgentRequest {
            prompt,
            system: None,
            working_dir: ctx.config.run.target_dir.clone(),
            allowed_tools: Vec::new(),
            skills: skills.clone(),
            timeout,
            max_turns: None,
            resume: None,
        };

        match validate_one(ctx, req).await {
            Ok((raw, cost_usd)) => {
                ctx.cost.record("validate", &finding.id, cost_usd);
                match raw.verdict {
                    Verdict::TruePositive => confirmed += 1,
                    Verdict::FalsePositive => refuted += 1,
                }
                validations.push(Validation {
                    finding_id: finding.id.clone(),
                    verdict: raw.verdict,
                    evidence: raw.evidence,
                });
            }
            // A validator failure is conservative: drop the finding (no verdict
            // means it does not advance to Report).
            Err(e) => warn!(finding = %finding.id, error = %e, "validation failed; dropping"),
        }
    }

    info!(confirmed, refuted, "validation complete");
    ctx.artifacts.write_jsonl(names::VALIDATED, &validations)?;
    Ok(())
}

async fn validate_one(ctx: &StageCtx, req: AgentRequest) -> Result<(RawVerdict, Option<f64>)> {
    let result = ctx.runner.run(req).await?;
    let raw = parse_verdict(&result.stdout)?;
    Ok((raw, result.cost_usd))
}

/// Pull the validator's verdict out of its (possibly prose-wrapped) output.
fn parse_verdict(stdout: &str) -> Result<RawVerdict> {
    let json = extract_json_block(stdout).context("validator output had no json block")?;
    serde_json::from_str(json).context("validator output was not valid json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_true_positive_verdict_from_fenced_block() {
        let out = "Verdict:\n```json\n{\"verdict\":\"true_positive\",\"evidence\":\"reachable\"}\n```";
        let v = parse_verdict(out).unwrap();
        assert_eq!(v.verdict, Verdict::TruePositive);
        assert_eq!(v.evidence, "reachable");
    }

    #[test]
    fn parses_false_positive_verdict_from_bare_json() {
        let v = parse_verdict("{\"verdict\":\"false_positive\",\"evidence\":\"guarded\"}").unwrap();
        assert_eq!(v.verdict, Verdict::FalsePositive);
    }

    #[test]
    fn rejects_output_without_json() {
        assert!(parse_verdict("I could not decide.").is_err());
    }

    #[test]
    fn rejects_unknown_verdict_value() {
        let err = parse_verdict("{\"verdict\":\"maybe\",\"evidence\":\"\"}").unwrap_err();
        assert!(err.to_string().contains("not valid json"), "got: {err}");
    }
}
