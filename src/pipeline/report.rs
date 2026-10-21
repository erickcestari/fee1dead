//! Report stage: persist a schema-checked record for every finding but
//! `likely_false_positive` through the sink. Each carries its verdict, so a
//! `needs_review` one never passes for confirmed. No agent call.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use jsonschema::JSONSchema;
use serde_json::{Value, json};
use tracing::{error, info, warn};

use super::StageCtx;
use crate::artifacts::names;
use crate::config::ReportConfig;
use crate::domain::{Finding, Validation};
use crate::store::{JsonlSink, ReportRecord, ReportSink, build_sink};

const SCHEMA_SRC: &str = include_str!("../../schema/finding.schema.json");

/// Stated plainly when the reviewer left a reported finding's prose empty,
/// rather than let a missing sentence keep the finding out.
const IMPACT_NOT_ASSESSED: &str = "Not assessed by the reviewer; see the description and evidence.";
const RECOMMENDATION_NOT_ASSESSED: &str = "Not assessed by the reviewer.";

pub fn run(ctx: &StageCtx) -> Result<()> {
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    let validations: Vec<Validation> = ctx.artifacts.read_jsonl(names::VALIDATED)?;
    let records = report_records(&candidates, &validations);
    let schema = compile_schema()?;

    let mut sink = build_sink(&ctx.config.report)?;
    // A jsonl sink already is the findings JSONL; a second writer would clobber it.
    let mut jsonl_tee = match ctx.config.report {
        ReportConfig::Jsonl { .. } => None,
        _ => Some(JsonlSink::open(&ctx.artifacts.path(names::FINDINGS_JSONL))?),
    };

    // The local JSONL goes first and a sink error does not stop the loop, so
    // every record is on disk even when the external sink fails.
    let (mut invalid, mut sink_failures) = (0, 0);
    for record in &records {
        let errors = schema_errors(&schema, &record.payload);
        if !errors.is_empty() {
            // Every field is harness-built, so this is a harness bug.
            invalid += 1;
            error!(id = %record.id, errors = errors.join("; "), "report record fails the schema");
            continue;
        }
        if let Some(tee) = jsonl_tee.as_mut() {
            tee.write(record)?;
        }
        if let Err(e) = sink.write(record) {
            sink_failures += 1;
            warn!(id = %record.id, error = format!("{e:#}"), "sink rejected finding");
        }
    }

    info!(
        written = records.len() - invalid - sink_failures,
        total = sink.count()?,
        "report complete"
    );
    if invalid > 0 || sink_failures > 0 {
        bail!(
            "of {} findings, {invalid} failed the schema and {sink_failures} did not reach \
             the {} sink",
            records.len(),
            ctx.config.report.sink_name()
        );
    }
    Ok(())
}

/// One record per reportable finding, at its effective severity, with the
/// reviewer's verdict, evidence, impact, and recommendation.
fn report_records(candidates: &[Finding], validations: &[Validation]) -> Vec<ReportRecord> {
    let by_id: HashMap<&str, &Finding> = candidates.iter().map(|f| (f.id.as_str(), f)).collect();
    validations
        .iter()
        .filter(|v| v.verdict.is_reportable())
        .filter_map(|v| {
            let f = by_id.get(v.finding_id.as_str())?;
            let mut payload = json!({
                "id": f.id,
                "title": f.title,
                "attack_class": f.attack_class,
                "severity": v.corrected_severity.unwrap_or(f.severity),
                "verdict": v.verdict,
                "location": f.location,
                "description": f.description,
                "impact": or_not_assessed(&v.impact, IMPACT_NOT_ASSESSED),
                "recommendation": or_not_assessed(&v.recommendation, RECOMMENDATION_NOT_ASSESSED),
                "evidence": v.evidence,
            });
            if !f.attack_scenario.is_empty() {
                payload["attack_scenario"] = json!(f.attack_scenario);
            }
            if let Some(poc) = &f.poc_path {
                payload["poc_path"] = json!(poc);
            }
            Some(ReportRecord {
                id: f.id.clone(),
                payload,
            })
        })
        .collect()
}

fn or_not_assessed<'a>(text: &'a str, fallback: &'a str) -> &'a str {
    if text.trim().is_empty() {
        fallback
    } else {
        text
    }
}

fn compile_schema() -> Result<JSONSchema> {
    let value: Value =
        serde_json::from_str(SCHEMA_SRC).context("finding schema is not valid json")?;
    JSONSchema::compile(&value).map_err(|e| anyhow::anyhow!("compiling finding schema: {e}"))
}

/// Empty when the payload is valid.
fn schema_errors(schema: &JSONSchema, payload: &Value) -> Vec<String> {
    schema
        .validate(payload)
        .err()
        .map(|it| it.map(|e| e.to_string()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::fixtures::{finding, validation};
    use crate::domain::{Severity, Verdict};

    #[test]
    fn only_reportable_verdicts_become_records_with_the_reviewers_fields() {
        let candidates = vec![
            finding("F-1"),
            finding("F-2"),
            finding("F-3"),
            Finding {
                attack_scenario: "1. Mallory sends a frame.".into(),
                poc_path: Some("pocs/F-4/poc.go".into()),
                ..finding("F-4")
            },
        ];
        let validations = vec![
            validation("F-1", Verdict::Confirmed),
            Validation {
                corrected_severity: Some(Severity::Low),
                ..validation("F-2", Verdict::Downgraded)
            },
            validation("F-3", Verdict::LikelyFalsePositive),
            validation("F-4", Verdict::NeedsReview),
        ];
        let records = report_records(&candidates, &validations);
        let ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["F-1", "F-2", "F-4"]);
        let p = |i: usize| &records[i].payload;
        assert_eq!(p(0)["severity"], "high");
        assert_eq!(p(0)["impact"], "attacker crashes the node");
        assert_eq!(p(1)["severity"], "low");
        assert_eq!(p(2)["verdict"], "needs_review");
        assert_eq!(p(2)["poc_path"], "pocs/F-4/poc.go");
        assert_eq!(p(2)["attack_scenario"], "1. Mallory sends a frame.");
        assert!(p(0).get("poc_path").is_none() && p(0).get("attack_scenario").is_none());
        let schema = compile_schema().unwrap();
        assert!(
            records
                .iter()
                .all(|r| schema_errors(&schema, &r.payload).is_empty())
        );
    }

    #[test]
    fn missing_reviewer_prose_is_stated_not_left_empty() {
        let skipped = Validation {
            impact: String::new(),
            recommendation: "  ".into(),
            ..validation("F-1", Verdict::NeedsReview)
        };
        let records = report_records(&[finding("F-1")], &[skipped]);
        assert_eq!(records[0].payload["impact"], IMPACT_NOT_ASSESSED);
        assert_eq!(
            records[0].payload["recommendation"],
            RECOMMENDATION_NOT_ASSESSED
        );
        assert!(schema_errors(&compile_schema().unwrap(), &records[0].payload).is_empty());
    }

    #[test]
    fn schema_errors_flags_missing_required_fields() {
        let schema = compile_schema().unwrap();
        assert!(!schema_errors(&schema, &json!({"id": "F-1"})).is_empty());
    }
}
