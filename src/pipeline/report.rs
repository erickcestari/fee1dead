//! Report stage: render every reportable finding into a schema-validated record
//! in one batched agent call, with at most one repair round for any records
//! that fail the schema, then persist through the configured sink.
//!
//! "Reportable" means the reviewer tagged the finding `confirmed` or
//! `downgraded`; a downgraded finding ships with the reviewer's corrected
//! severity. `likely_false_positive` findings stay in the validated artifact
//! and are not reported.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use jsonschema::JSONSchema;
use serde_json::{Value, json};
use tracing::{info, warn};

use super::StageCtx;
use crate::artifacts::{extract_json_block, names};
use crate::config::SinkKind;
use crate::domain::{Finding, Severity, Validation};
use crate::provider::{AgentRequest, Effort};
use crate::store::{JsonlSink, ReportRecord, ReportSink, build_sink};

const PROMPT: &str = include_str!("../../prompts/report.md");
const SCHEMA_SRC: &str = include_str!("../../schema/finding.schema.json");

/// How many batched passes the agent gets to satisfy the schema before we give
/// up on whatever records are still invalid.
const MAX_ATTEMPTS: usize = 3;

/// One finding bound for the report, with the effective (post-review) severity.
#[derive(Debug, Clone)]
struct ReportItem {
    id: String,
    title: String,
    attack_class: String,
    severity: Severity,
    location: String,
    description: String,
    evidence: String,
}

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    let validations: Vec<Validation> = ctx.artifacts.read_jsonl(names::VALIDATED)?;
    let items = reportable_items(&candidates, &validations);

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
    if items.is_empty() {
        info!(written = 0, total = sink.count()?, "report complete");
        return Ok(());
    }

    let timeout = Duration::from_secs(ctx.config.run.agent_timeout_secs);
    let mut pending = items;
    let mut done: Vec<Value> = Vec::new();
    let mut repair_note = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        if pending.is_empty() {
            break;
        }

        let prompt = PROMPT
            .replace("{findings_json}", &report_input(&pending))
            .replace("{schema}", SCHEMA_SRC)
            .replace("{repair_note}", &repair_note);

        let req = AgentRequest {
            prompt,
            system: None,
            working_dir: ctx.config.run.out_dir.clone(),
            extra_dirs: Vec::new(),
            allowed_tools: Vec::new(),
            disallowed_tools: super::disabled_tools(),
            timeout,
            resume: None,
            // Leaf agent: nothing forks from it, so the default 5m cache suffices.
            cache_1h: false,
            // Mechanical transform: reviewed findings → schema-valid JSON, no
            // prose, no tracing. Deep thinking can't improve it, only cost more.
            effort: Effort::Low,
            model: None,
            stream_log_path: Some(
                ctx.artifacts
                    .log_path(&format!("report-batch-{attempt}.jsonl")),
            ),
        };

        let result = ctx.runner.run(req).await?;

        let mut returned = match parse_records(&result.stdout) {
            Ok(r) => r,
            Err(e) => {
                warn!(attempt, error = %e, "report output unparseable; retrying");
                repair_note = "Your previous output was not a JSON array. Return ONLY a \
                    bare JSON array of report objects (no markdown fences), one per finding."
                    .to_string();
                continue;
            }
        };

        let (still_pending, notes) = collect_valid(&mut pending, &mut returned, &schema, &mut done);
        pending = still_pending;
        if pending.is_empty() {
            break;
        }
        repair_note = format!(
            "These findings were missing or failed schema validation; return ALL of them \
             again, fixed:\n- {}",
            notes.join("\n- ")
        );
        warn!(
            attempt,
            remaining = pending.len(),
            "report repairing records"
        );
    }

    // Findings already reported in the destination (e.g. filed as GitHub issues)
    // were pruned from the candidate set by the `skip-reported` stage before
    // validate, so nothing here should be a re-file; the github sink's per-id
    // marker check is the final idempotency guard.
    for payload in &done {
        let id = payload
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let record = ReportRecord {
            id,
            payload: payload.clone(),
        };
        sink.write(&record)?;
        if let Some(tee) = jsonl_tee.as_mut() {
            tee.write(&record)?;
        }
    }
    if !pending.is_empty() {
        warn!(
            count = pending.len(),
            "findings could not be rendered to a valid report"
        );
    }

    info!(
        written = done.len(),
        total = sink.count()?,
        "report complete"
    );
    Ok(())
}

/// Select the findings that advance to the report and stamp each with its
/// effective severity (the reviewer's correction for downgraded findings).
fn reportable_items(candidates: &[Finding], validations: &[Validation]) -> Vec<ReportItem> {
    let by_id: HashMap<&str, &Finding> = candidates.iter().map(|f| (f.id.as_str(), f)).collect();
    validations
        .iter()
        .filter(|v| v.verdict.is_reportable())
        .filter_map(|v| {
            let f = by_id.get(v.finding_id.as_str())?;
            Some(ReportItem {
                id: f.id.clone(),
                title: f.title.clone(),
                attack_class: f.attack_class.clone(),
                severity: v.corrected_severity.unwrap_or(f.severity),
                location: f.location.clone(),
                description: f.description.clone(),
                evidence: v.evidence.clone(),
            })
        })
        .collect()
}

/// Serialize the pending items into the JSON the report agent reads.
fn report_input(items: &[ReportItem]) -> String {
    let arr: Vec<_> = items
        .iter()
        .map(|it| {
            json!({
                "id": it.id,
                "title": it.title,
                "attack_class": it.attack_class,
                "severity": it.severity,
                "location": it.location,
                "description": it.description,
                "evidence": it.evidence,
            })
        })
        .collect();
    serde_json::to_string_pretty(&arr).unwrap_or_else(|_| "[]".into())
}

/// Parse the agent's reply into an array of report objects.
fn parse_records(stdout: &str) -> Result<Vec<Value>> {
    let json = extract_json_block(stdout).context("report output had no json block")?;
    serde_json::from_str(json).context("report output was not a json array")
}

/// Match returned records to pending items by id, enforce the authoritative id
/// and severity, and schema-check each. Valid records move to `done`; the rest
/// stay pending. Returns the still-pending items and a note per failure.
fn collect_valid(
    pending: &mut [ReportItem],
    returned: &mut [Value],
    schema: &JSONSchema,
    done: &mut Vec<Value>,
) -> (Vec<ReportItem>, Vec<String>) {
    let mut by_id: HashMap<String, Value> = returned
        .iter_mut()
        .filter_map(|v| {
            let id = v.get("id").and_then(|i| i.as_str()).map(str::to_string)?;
            Some((id, v.take()))
        })
        .collect();

    let mut still = Vec::new();
    let mut notes = Vec::new();
    for item in pending.iter() {
        match by_id.remove(&item.id) {
            Some(mut payload) => {
                // Harness-authoritative: never trust the model to echo these.
                payload["id"] = Value::String(item.id.clone());
                payload["severity"] = Value::String(severity_str(item.severity));
                let errors = schema_errors(schema, &payload);
                if errors.is_empty() {
                    done.push(payload);
                } else {
                    notes.push(format!("{}: {}", item.id, errors.join("; ")));
                    still.push(item.clone());
                }
            }
            None => {
                notes.push(format!("{}: no record returned", item.id));
                still.push(item.clone());
            }
        }
    }
    (still, notes)
}

fn severity_str(sev: Severity) -> String {
    serde_json::to_value(sev)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "medium".into())
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
    use crate::domain::Verdict;

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
        }
    }

    fn full_record(id: &str, sev: &str) -> Value {
        json!({
            "id": id, "title": "x", "attack_class": "c", "severity": sev,
            "location": "a.rs:1", "description": "d", "impact": "i", "recommendation": "r"
        })
    }

    #[test]
    fn embedded_schema_compiles() {
        let _ = compiled_schema();
    }

    #[test]
    fn only_reportable_verdicts_advance_with_corrected_severity() {
        let candidates = vec![
            finding("F-1", Severity::High),
            finding("F-2", Severity::High),
            finding("F-3", Severity::High),
        ];
        let validations = vec![
            validation("F-1", Verdict::Confirmed, None),
            validation("F-2", Verdict::Downgraded, Some(Severity::Low)),
            validation("F-3", Verdict::LikelyFalsePositive, None),
        ];
        let items = reportable_items(&candidates, &validations);
        assert_eq!(items.len(), 2, "likely_false_positive must not advance");
        assert_eq!(items[0].id, "F-1");
        assert_eq!(items[0].severity, Severity::High);
        // Downgrade applied.
        assert_eq!(items[1].id, "F-2");
        assert_eq!(items[1].severity, Severity::Low);
    }

    #[test]
    fn collect_valid_separates_good_from_bad_and_enforces_id_and_severity() {
        let schema = compiled_schema();
        let pending = [
            ReportItem {
                id: "F-1".into(),
                title: "t".into(),
                attack_class: "c".into(),
                severity: Severity::Low,
                location: "a.rs:1".into(),
                description: "d".into(),
                evidence: "e".into(),
            },
            ReportItem {
                id: "F-2".into(),
                title: "t".into(),
                attack_class: "c".into(),
                severity: Severity::High,
                location: "a.rs:1".into(),
                description: "d".into(),
                evidence: "e".into(),
            },
        ];
        // F-1: agent echoed wrong id+severity → must be overwritten and pass.
        // F-2: missing required fields → must stay pending.
        let mut returned = vec![
            json!({
                "id": "WRONG", "title": "x", "attack_class": "c", "severity": "critical",
                "location": "a.rs:1", "description": "d", "impact": "i", "recommendation": "r"
            }),
            json!({"id": "F-2", "title": "x"}),
        ];
        // The first returned record matches F-1 only if its id matches; the
        // model echoed "WRONG", so F-1 has no match and stays pending while the
        // stray record is ignored. This documents that id echo is required.
        let mut pending_vec = pending.to_vec();
        let mut done = Vec::new();
        let (still, notes) = collect_valid(&mut pending_vec, &mut returned, &schema, &mut done);
        assert_eq!(done.len(), 0);
        assert_eq!(still.len(), 2);
        assert_eq!(notes.len(), 2);
    }

    #[test]
    fn collect_valid_accepts_matching_records_and_overwrites_severity() {
        let schema = compiled_schema();
        let pending = [ReportItem {
            id: "F-1".into(),
            title: "t".into(),
            attack_class: "c".into(),
            severity: Severity::Low, // effective severity wins over the record's
            location: "a.rs:1".into(),
            description: "d".into(),
            evidence: "e".into(),
        }];
        let mut returned = vec![full_record("F-1", "critical")];
        let mut pending_vec = pending.to_vec();
        let mut done = Vec::new();
        let (still, _notes) = collect_valid(&mut pending_vec, &mut returned, &schema, &mut done);
        assert!(still.is_empty());
        assert_eq!(done.len(), 1);
        assert_eq!(done[0]["severity"], "low");
        assert_eq!(done[0]["id"], "F-1");
    }

    #[test]
    fn severity_renders_as_schema_enum_value() {
        assert_eq!(severity_str(Severity::Critical), "critical");
        assert_eq!(severity_str(Severity::Info), "info");
    }

    #[test]
    fn schema_errors_flags_missing_required_fields() {
        let schema = compiled_schema();
        assert!(!schema_errors(&schema, &json!({"id": "F-1"})).is_empty());
        assert!(schema_errors(&schema, &full_record("F-1", "high")).is_empty());
    }
}
