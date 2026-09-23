//! Report stage: turn every reportable finding into a schema-validated record
//! and persist it through the configured sink. No agent call: the reviewer
//! already wrote each finding's impact and recommendation, so every field is
//! known and assembling the record is plain code.
//!
//! "Reportable" means any verdict but `likely_false_positive`, which stays in
//! the validated artifact. A downgraded finding ships with the reviewer's
//! corrected severity; every record carries its `verdict`, so a `needs_review`
//! one is never mistaken for a confirmed bug.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use jsonschema::JSONSchema;
use serde_json::{Value, json};
use tracing::{error, info, warn};

use super::StageCtx;
use crate::artifacts::names;
use crate::config::SinkKind;
use crate::domain::{Finding, Validation};
use crate::store::{JsonlSink, ReportRecord, ReportSink, build_sink};

const SCHEMA_SRC: &str = include_str!("../../schema/finding.schema.json");

/// Stand-ins when the reviewer left a reported finding's prose empty (e.g. it
/// skipped the finding, which is then `needs_review`). They say so plainly
/// rather than let a missing sentence keep a finding out of the report.
const IMPACT_NOT_ASSESSED: &str = "Not assessed by the reviewer; see the description and evidence.";
const RECOMMENDATION_NOT_ASSESSED: &str = "Not assessed by the reviewer.";

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    let validations: Vec<Validation> = ctx.artifacts.read_jsonl(names::VALIDATED)?;
    let records = report_records(&candidates, &validations);

    let schema_value: Value =
        serde_json::from_str(SCHEMA_SRC).context("finding schema is not valid json")?;
    let schema = JSONSchema::compile(&schema_value)
        .map_err(|e| anyhow::anyhow!("compiling finding schema: {e}"))?;

    let mut sink = build_sink(&ctx.config.report)?;
    // Always emit a machine-readable findings JSONL, whatever the configured
    // sink is. When the sink is already jsonl that file *is* the record, so the
    // tee would be a second writer to the same path (clobbering it on flush);
    // skip it in that case and let the primary sink be the jsonl.
    let mut jsonl_tee = match ctx.config.report.sink {
        SinkKind::Jsonl => None,
        _ => Some(JsonlSink::open(
            &ctx.config.run.out_dir.join(names::FINDINGS_JSONL),
        )?),
    };

    // Findings already reported in the destination (e.g. filed as GitHub issues)
    // were pruned from the candidate set by the `skip-reported` stage before
    // validate, so nothing here should be a re-file; the github sink's per-id
    // marker check is the final idempotency guard.
    //
    // The local JSONL goes first and one sink error does not stop the loop, so
    // every record is on disk even when the external sink fails.
    let (mut invalid, mut sink_failures) = (0usize, 0usize);
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
             the {:?} sink",
            records.len(),
            ctx.config.report.sink
        );
    }
    Ok(())
}

/// One record per reportable finding, carrying its effective severity (the
/// reviewer's correction for downgraded findings) and the reviewer's verdict,
/// evidence, impact, and recommendation.
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

/// Collect schema-validation error messages for a payload (empty == valid).
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
    use crate::domain::{Severity, Verdict};

    fn compiled_schema() -> JSONSchema {
        let value: Value = serde_json::from_str(SCHEMA_SRC).unwrap();
        JSONSchema::compile(&value).unwrap()
    }

    fn finding(id: &str, sev: Severity) -> Finding {
        Finding {
            id: id.into(),
            task_id: "T".into(),
            title: "t".into(),
            attack_class: "c".into(),
            severity: sev,
            location: "a.rs:1".into(),
            description: "d".into(),
            confidence: 0.5,
            poc_path: None,
        }
    }

    fn validation(id: &str, verdict: Verdict, corrected: Option<Severity>) -> Validation {
        Validation {
            finding_id: id.into(),
            verdict,
            evidence: "e".into(),
            corrected_severity: corrected,
            impact: "attacker crashes the node".into(),
            recommendation: "bound the length".into(),
        }
    }

    #[test]
    fn embedded_schema_compiles() {
        let _ = compiled_schema();
    }

    #[test]
    fn only_reportable_verdicts_become_records_with_the_reviewers_fields() {
        let mut with_poc = finding("F-4", Severity::Medium);
        with_poc.poc_path = Some("pocs/F-4/poc.go".into());
        let candidates = vec![
            finding("F-1", Severity::High),
            finding("F-2", Severity::High),
            finding("F-3", Severity::High),
            with_poc,
        ];
        let validations = vec![
            validation("F-1", Verdict::Confirmed, None),
            validation("F-2", Verdict::Downgraded, Some(Severity::Low)),
            validation("F-3", Verdict::LikelyFalsePositive, None),
            validation("F-4", Verdict::NeedsReview, None),
        ];
        let records = report_records(&candidates, &validations);
        let ids: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            ["F-1", "F-2", "F-4"],
            "likely_false_positive must not advance"
        );
        let p = |i: usize| &records[i].payload;
        assert_eq!(p(0)["severity"], "high");
        assert_eq!(p(0)["impact"], "attacker crashes the node");
        assert_eq!(p(0)["recommendation"], "bound the length");
        // Downgrade applied.
        assert_eq!(p(1)["severity"], "low");
        // Unsettled findings advance, carrying their verdict and PoC.
        assert_eq!(p(2)["verdict"], "needs_review");
        assert_eq!(p(2)["poc_path"], "pocs/F-4/poc.go");
        assert!(p(0).get("poc_path").is_none());
        // Every record the stage builds satisfies the schema.
        let schema = compiled_schema();
        assert!(
            records
                .iter()
                .all(|r| schema_errors(&schema, &r.payload).is_empty())
        );
    }

    #[test]
    fn missing_reviewer_prose_is_stated_not_left_empty() {
        let mut skipped = validation("F-1", Verdict::NeedsReview, None);
        skipped.impact.clear();
        skipped.recommendation = "  ".into();
        let records = report_records(&[finding("F-1", Severity::High)], &[skipped]);
        assert_eq!(records[0].payload["impact"], IMPACT_NOT_ASSESSED);
        assert_eq!(
            records[0].payload["recommendation"],
            RECOMMENDATION_NOT_ASSESSED
        );
        assert!(schema_errors(&compiled_schema(), &records[0].payload).is_empty());
    }

    #[test]
    fn schema_errors_flags_missing_required_fields() {
        let schema = compiled_schema();
        assert!(!schema_errors(&schema, &json!({"id": "F-1"})).is_empty());
    }
}
