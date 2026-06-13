//! Report stage: render each confirmed finding into a schema-validated record,
//! self-repairing schema errors, then persist through the configured sink.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use jsonschema::JSONSchema;
use serde_json::Value;
use tracing::{info, warn};

use super::StageCtx;
use crate::artifacts::{extract_json_block, names};
use crate::domain::{Finding, Validation, Verdict};
use crate::provider::AgentRequest;
use crate::store::{ReportRecord, build_sink};

const PROMPT: &str = include_str!("../../prompts/report.md");
const SCHEMA_SRC: &str = include_str!("../../schema/finding.schema.json");

/// How many times the agent may self-correct schema errors before we give up.
const MAX_REPAIR_ATTEMPTS: usize = 3;

pub async fn run(ctx: &StageCtx) -> Result<()> {
    let candidates: Vec<Finding> = ctx.artifacts.read_jsonl(names::CANDIDATES)?;
    let validations: Vec<Validation> = ctx.artifacts.read_jsonl(names::VALIDATED)?;

    // Only true positives advance.
    let confirmed: HashMap<&str, &Validation> = validations
        .iter()
        .filter(|v| v.verdict == Verdict::TruePositive)
        .map(|v| (v.finding_id.as_str(), v))
        .collect();

    let schema_value: Value =
        serde_json::from_str(SCHEMA_SRC).context("finding schema is not valid json")?;
    let schema = JSONSchema::compile(&schema_value)
        .map_err(|e| anyhow::anyhow!("compiling finding schema: {e}"))?;

    let mut sink = build_sink(&ctx.config.report)?;
    let timeout = Duration::from_secs(ctx.config.run.agent_timeout_secs);
    let mut written = 0usize;

    for finding in &candidates {
        let Some(validation) = confirmed.get(finding.id.as_str()) else {
            continue;
        };

        match build_report(ctx, finding, validation, &schema, timeout).await {
            Ok(mut payload) => {
                // Authoritative id, regardless of what the agent emitted.
                payload["id"] = Value::String(finding.id.clone());
                sink.write(&ReportRecord {
                    id: finding.id.clone(),
                    payload,
                })?;
                written += 1;
            }
            Err(e) => warn!(finding = %finding.id, error = %e, "could not produce valid report"),
        }
    }

    info!(written, total = sink.count()?, "report complete");
    Ok(())
}

/// Run the report agent, then validate-and-repair against the schema.
async fn build_report(
    ctx: &StageCtx,
    finding: &Finding,
    validation: &Validation,
    schema: &JSONSchema,
    timeout: Duration,
) -> Result<Value> {
    let mut repair_note = String::new();

    for attempt in 0..MAX_REPAIR_ATTEMPTS {
        let prompt = PROMPT
            .replace("{finding_id}", &finding.id)
            .replace("{title}", &finding.title)
            .replace("{attack_class}", &finding.attack_class)
            .replace("{severity}", &severity_str(finding))
            .replace("{location}", &finding.location)
            .replace("{description}", &finding.description)
            .replace("{evidence}", &validation.evidence)
            .replace("{schema}", SCHEMA_SRC)
            .replace("{repair_note}", &repair_note);

        let req = AgentRequest {
            prompt,
            system: None,
            working_dir: ctx.config.run.out_dir.clone(),
            allowed_tools: Vec::new(),
            skills: Vec::new(),
            timeout,
            max_turns: None,
            resume: None,
        };

        let result = ctx.runner.run(req).await?;
        let json = extract_json_block(&result.stdout).context("report output had no json block")?;
        let payload: Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(e) => {
                repair_note = format!(
                    "Your previous output was not valid JSON ({e}). Return only a valid json object."
                );
                continue;
            }
        };

        let errors: Vec<String> = schema
            .validate(&payload)
            .err()
            .map(|it| it.map(|e| e.to_string()).collect())
            .unwrap_or_default();

        if errors.is_empty() {
            return Ok(payload);
        }

        warn!(finding = %finding.id, attempt, ?errors, "report failed schema; repairing");
        repair_note = format!(
            "Your previous output failed schema validation with these errors:\n- {}\nFix them.",
            errors.join("\n- ")
        );
    }

    bail!("report did not validate after {MAX_REPAIR_ATTEMPTS} attempts");
}

fn severity_str(f: &Finding) -> String {
    serde_json::to_value(f.severity)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "medium".into())
}
