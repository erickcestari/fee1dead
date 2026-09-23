//! GitHub issue report sink: file one issue per finding via the REST API.
//!
//! One issue per finding, titled by severity and finding title, bodied from the
//! schema-validated payload. Auth is a GitHub PAT (fine-grained or classic) with
//! `issues:write` on the target repo, read from an env var so the token never
//! lands in config or logs.
//!
//! Re-runnable: the report stage can run more than once, so each issue body
//! carries a hidden marker keyed by the finding id. Before creating an issue the
//! sink searches the repo for that marker and skips findings already filed, so a
//! second run does not duplicate issues.

use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use super::{ExistingReport, ReportRecord, ReportSink};

const API_ROOT: &str = "https://api.github.com";

/// Label every fee1dead-filed issue carries, so listing our own issues never
/// sweeps up unrelated ones in the repo.
const SINK_LABEL: &str = "fee1dead";

pub struct GithubSink {
    /// `owner/repo`.
    repo: String,
    token: String,
    agent: ureq::Agent,
    /// Finding ids confirmed present as issues this session (created or found),
    /// so repeated writes of the same id within a run never re-query or re-file.
    filed: HashSet<String>,
    /// Issues created by this sink (excludes ones that already existed).
    created: usize,
}

impl GithubSink {
    pub fn new(repo: String, token: String) -> Self {
        Self {
            repo,
            token,
            agent: ureq::Agent::new(),
            filed: HashSet::new(),
            created: 0,
        }
    }

    /// Common auth/version headers GitHub's REST API expects.
    fn request(&self, method: &str, url: &str) -> ureq::Request {
        self.agent
            .request(method, url)
            .set("authorization", &format!("Bearer {}", self.token))
            .set("accept", "application/vnd.github+json")
            .set("x-github-api-version", "2022-11-28")
            .set("user-agent", "fee1dead")
    }

    /// Whether an issue for this finding already exists in the repo, matched by
    /// the hidden body marker. Best-effort: a search miss (indexing lag, API
    /// error) means we may file a duplicate rather than drop a finding.
    fn issue_exists(&self, id: &str) -> Result<bool> {
        let query = format!("repo:{} in:body \"{}\"", self.repo, marker(id));
        let resp = self
            .request("GET", &format!("{API_ROOT}/search/issues"))
            .query("q", &query)
            .call()
            .with_context(|| format!("searching {} for existing issue {id}", self.repo))?;
        let body: Value = resp.into_json().context("parsing github search response")?;
        Ok(body.get("total_count").and_then(Value::as_u64).unwrap_or(0) > 0)
    }
}

impl ReportSink for GithubSink {
    fn write(&mut self, record: &ReportRecord) -> Result<()> {
        if self.filed.contains(&record.id) {
            return Ok(());
        }
        if self.issue_exists(&record.id)? {
            self.filed.insert(record.id.clone());
            return Ok(());
        }

        let payload = issue_payload(&record.id, &record.payload);
        let resp = self
            .request("POST", &format!("{API_ROOT}/repos/{}/issues", self.repo))
            .send_json(payload);
        match resp {
            Ok(_) => {
                self.filed.insert(record.id.clone());
                self.created += 1;
                Ok(())
            }
            Err(ureq::Error::Status(code, resp)) => {
                let detail = resp
                    .into_string()
                    .unwrap_or_else(|_| "<unreadable body>".into());
                bail!(
                    "github returned {code} filing issue for finding {}: {detail}",
                    record.id
                )
            }
            Err(e) => Err(e).with_context(|| {
                format!(
                    "filing github issue for finding {} in {}",
                    record.id, self.repo
                )
            }),
        }
    }

    fn count(&self) -> Result<usize> {
        // The sink does not re-query the repo; report the issues it created.
        Ok(self.created)
    }

    fn existing_reports(&self) -> Result<Vec<ExistingReport>> {
        // Paginate our own labeled issues (open and closed) so the report stage
        // can dedup new findings against everything already filed.
        let mut out = Vec::new();
        for page in 1..=MAX_ISSUE_PAGES {
            let resp = self
                .request("GET", &format!("{API_ROOT}/repos/{}/issues", self.repo))
                .query("labels", SINK_LABEL)
                .query("state", "all")
                .query("per_page", "100")
                .query("page", &page.to_string())
                .call()
                .with_context(|| format!("listing existing issues in {}", self.repo))?;
            let issues: Vec<Value> = resp.into_json().context("parsing github issue list")?;
            let count = issues.len();
            for issue in &issues {
                // The issues endpoint also returns PRs; skip them.
                if issue.get("pull_request").is_some() {
                    continue;
                }
                let title = issue.get("title").and_then(Value::as_str).unwrap_or("");
                let body = issue.get("body").and_then(Value::as_str).unwrap_or("");
                out.push(existing_report(title, body));
            }
            if count < 100 {
                break;
            }
        }
        Ok(out)
    }
}

/// Cap on issue-list pages fetched for dedup, so a repo with a huge backlog
/// cannot make the report stage page forever.
const MAX_ISSUE_PAGES: u32 = 20;

/// Recover the finding fields from an issue this sink filed (see
/// [`issue_payload`] for the layout it parses back).
fn existing_report(issue_title: &str, body: &str) -> ExistingReport {
    // Issues edited in the web UI come back with CRLF line endings.
    let body = body.replace("\r\n", "\n");
    let title = issue_title
        .strip_prefix('[')
        .and_then(|rest| rest.split_once("] "))
        .map_or(issue_title, |(_severity, title)| title);
    ExistingReport {
        id: marker_id(&body).unwrap_or_default(),
        title: title.to_string(),
        location: section(&body, "Location").trim_matches('`').to_string(),
        attack_class: section(&body, "Attack class").to_string(),
        text: format!("{issue_title}\n{body}"),
    }
}

/// The text under a `## heading` of an issue body; empty when absent.
fn section<'a>(body: &'a str, heading: &str) -> &'a str {
    let open = format!("## {heading}\n\n");
    let Some(start) = body.find(&open) else {
        return "";
    };
    let rest = &body[start + open.len()..];
    let end = [rest.find("\n\n## "), rest.find("<!--")]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(rest.len());
    rest[..end].trim()
}

/// Recover the finding id fee1dead stamped into an issue body, if present.
fn marker_id(body: &str) -> Option<String> {
    let start = body.find("<!-- fee1dead-finding-id:")?;
    let rest = &body[start..];
    let end = rest.find("-->")?;
    let inner = &rest["<!-- fee1dead-finding-id:".len()..end];
    Some(inner.trim().to_string())
}

/// Hidden HTML comment embedded in every issue body: the idempotency key that
/// lets a re-run find the issue a finding already produced.
fn marker(id: &str) -> String {
    format!("<!-- fee1dead-finding-id: {id} -->")
}

/// Build the GitHub issue creation payload (title, body, labels) from a
/// schema-validated finding. Pure so it is unit-testable without the API.
fn issue_payload(id: &str, finding: &Value) -> Value {
    let get = |k: &str| finding.get(k).and_then(Value::as_str).unwrap_or("");
    let severity = get("severity");
    let title = match get("title") {
        "" => format!("[{severity}] finding {id}"),
        t => format!("[{severity}] {t}"),
    };

    let mut body = String::new();
    let mut section = |heading: &str, value: &str| {
        if !value.is_empty() {
            body.push_str(&format!("## {heading}\n\n{value}\n\n"));
        }
    };
    section("Location", &format!("`{}`", get("location")));
    section("Attack class", get("attack_class"));
    section("Description", get("description"));
    section("Impact", get("impact"));
    section("Recommendation", get("recommendation"));
    section("Evidence", get("evidence"));
    if !get("poc_path").is_empty() {
        section(
            "Proof of concept",
            &format!("`{}` in the run's out dir", get("poc_path")),
        );
    }
    body.push_str(&marker(id));

    let mut labels = vec![SINK_LABEL.to_string()];
    if !severity.is_empty() {
        labels.push(format!("severity:{severity}"));
    }
    // The reviewer could not settle it: flag it so nobody acts on it unverified.
    if get("verdict") == "needs_review" {
        labels.push("needs-review".to_string());
    }

    json!({ "title": title, "body": body, "labels": labels })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding() -> Value {
        json!({
            "id": "F-1",
            "title": "Unbounded allocation",
            "attack_class": "resource exhaustion",
            "severity": "high",
            "location": "src/net.rs:42",
            "description": "length is added without a bounds check",
            "impact": "attacker crashes the node",
            "recommendation": "validate length before alloc",
            "evidence": "trace confirms attacker control"
        })
    }

    #[test]
    fn payload_titles_with_severity_and_carries_marker() {
        let p = issue_payload("F-1", &finding());
        assert_eq!(p["title"], "[high] Unbounded allocation");
        let body = p["body"].as_str().unwrap();
        assert!(body.contains("## Impact"));
        assert!(body.contains("attacker crashes the node"));
        // The idempotency marker must be present and id-keyed.
        assert!(body.contains(&marker("F-1")));
    }

    #[test]
    fn payload_labels_include_severity() {
        let p = issue_payload("F-1", &finding());
        let labels: Vec<&str> = p["labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(labels.contains(&"fee1dead"));
        assert!(labels.contains(&"severity:high"));
    }

    #[test]
    fn unsettled_finding_is_labeled_and_poc_is_linked() {
        let mut f = finding();
        f["verdict"] = json!("needs_review");
        f["poc_path"] = json!("pocs/F-1/poc.go");
        let p = issue_payload("F-1", &f);
        assert!(
            p["labels"]
                .as_array()
                .unwrap()
                .contains(&json!("needs-review"))
        );
        assert!(p["body"].as_str().unwrap().contains("`pocs/F-1/poc.go`"));
        // A confirmed finding carries no such label.
        let p = issue_payload("F-1", &finding());
        assert!(
            !p["labels"]
                .as_array()
                .unwrap()
                .contains(&json!("needs-review"))
        );
    }

    #[test]
    fn marker_id_round_trips_from_body() {
        // The id stamped into a body must be recoverable for dedup.
        let body = issue_payload("F-42", &finding())["body"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(marker_id(&body).as_deref(), Some("F-42"));
        // A body without a marker yields nothing.
        assert_eq!(marker_id("just some issue text"), None);
    }

    #[test]
    fn filed_issue_parses_back_to_the_findings_own_fields() {
        let p = issue_payload("F-1", &finding());
        let e = existing_report(
            p["title"].as_str().unwrap(),
            &p["body"].as_str().unwrap().replace('\n', "\r\n"),
        );
        assert_eq!(e.id, "F-1");
        assert_eq!(e.title, "Unbounded allocation");
        assert_eq!(e.location, "src/net.rs:42");
        assert_eq!(e.attack_class, "resource exhaustion");
        assert!(e.text.contains("attacker crashes the node"));
    }

    #[test]
    fn payload_falls_back_to_id_when_title_missing() {
        let p = issue_payload("F-9", &json!({ "severity": "low" }));
        assert_eq!(p["title"], "[low] finding F-9");
        // Sections with empty values are omitted; the marker still anchors the body.
        let body = p["body"].as_str().unwrap();
        assert!(!body.contains("## Description"));
        assert!(body.contains(&marker("F-9")));
    }
}
