//! One GitHub issue per finding, via the REST API. The PAT comes from an env
//! var so it never lands in config or logs.
//!
//! Re-runnable: each body carries a hidden marker keyed by the finding id, and
//! before the first write the sink lists its labeled issues once and skips
//! findings already filed. Listing beats a per-finding search, which allows
//! only 30 requests a minute and indexes with lag.

use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use super::{ExistingReport, ReportRecord, ReportSink};

const API_ROOT: &str = "https://api.github.com";

/// On every filed issue, so listing ours never sweeps up unrelated ones.
const SINK_LABEL: &str = "fee1dead";

pub struct GithubSink {
    api_root: String,
    /// `owner/name`.
    repo: String,
    token: String,
    agent: ureq::Agent,
    /// Finding ids already filed, listed on the first write.
    filed: Option<HashSet<String>>,
    created: usize,
}

impl GithubSink {
    pub fn new(repo: String, token: String) -> Self {
        Self::with_api_root(API_ROOT.to_string(), repo, token)
    }

    fn with_api_root(api_root: String, repo: String, token: String) -> Self {
        Self {
            api_root,
            repo,
            token,
            agent: ureq::Agent::new(),
            filed: None,
            created: 0,
        }
    }

    fn request(&self, method: &str, url: &str) -> ureq::Request {
        self.agent
            .request(method, url)
            .set("authorization", &format!("Bearer {}", self.token))
            .set("accept", "application/vnd.github+json")
            .set("x-github-api-version", "2022-11-28")
            .set("user-agent", "fee1dead")
    }

    fn filed(&mut self) -> Result<&mut HashSet<String>> {
        if self.filed.is_none() {
            let ids = self
                .existing_reports()?
                .into_iter()
                .map(|r| r.id)
                .filter(|id| !id.is_empty())
                .collect();
            self.filed = Some(ids);
        }
        Ok(self.filed.as_mut().expect("filed ids loaded above"))
    }
}

impl ReportSink for GithubSink {
    fn write(&mut self, record: &ReportRecord) -> Result<()> {
        if self.filed()?.contains(&record.id) {
            return Ok(());
        }

        let payload = issue_payload(&record.id, &record.payload);
        let resp = self
            .request(
                "POST",
                &format!("{}/repos/{}/issues", self.api_root, self.repo),
            )
            .send_json(payload);
        match resp {
            Ok(_) => {
                self.filed()?.insert(record.id.clone());
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
        Ok(self.created)
    }

    fn existing_reports(&self) -> Result<Vec<ExistingReport>> {
        // Open and closed, so nothing already filed is filed again.
        let mut out = Vec::new();
        for page in 1..=MAX_ISSUE_PAGES {
            let resp = self
                .request(
                    "GET",
                    &format!("{}/repos/{}/issues", self.api_root, self.repo),
                )
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

/// So a huge backlog cannot make the sink page forever.
const MAX_ISSUE_PAGES: u32 = 20;

/// Parse back the layout [`issue_payload`] writes.
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

fn marker_id(body: &str) -> Option<String> {
    let start = body.find("<!-- fee1dead-finding-id:")?;
    let rest = &body[start..];
    let end = rest.find("-->")?;
    let inner = &rest["<!-- fee1dead-finding-id:".len()..end];
    Some(inner.trim().to_string())
}

/// The idempotency key hidden in every issue body.
fn marker(id: &str) -> String {
    format!("<!-- fee1dead-finding-id: {id} -->")
}

/// The issue-creation payload (title, body, labels) for a finding.
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
    // Flagged so nobody acts on an unsettled finding unverified.
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

    /// Serves a fake GitHub API: the issue list holds one issue already filed
    /// for `F-1`, issue creation succeeds, and anything else 404s. Returns the
    /// base url and the `METHOD path` of every request received.
    fn fake_github() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{BufRead, BufReader, Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let root = format!("http://{}", listener.local_addr().unwrap());
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        let filed = json!([{ "title": "[high] old", "body": marker("F-1") }]).to_string();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut len = 0;
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = header.to_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                }
                reader.read_exact(&mut vec![0; len]).unwrap();

                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap().to_string();
                let path = parts.next().unwrap().split('?').next().unwrap().to_string();
                let (status, body) = match (method.as_str(), path.as_str()) {
                    ("GET", "/repos/o/r/issues") => ("200 OK", filed.clone()),
                    ("POST", "/repos/o/r/issues") => ("201 Created", "{}".to_string()),
                    _ => ("404 Not Found", "{}".to_string()),
                };
                log.lock().unwrap().push(format!("{method} {path}"));
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        (root, seen)
    }

    #[test]
    fn write_lists_filed_issues_once_and_skips_them() {
        let (root, seen) = fake_github();
        let mut sink = GithubSink::with_api_root(root, "o/r".into(), "t".into());
        let record = |id: &str| ReportRecord {
            id: id.into(),
            payload: finding(),
        };
        for id in ["F-1", "F-2", "F-3", "F-2"] {
            sink.write(&record(id)).unwrap();
        }
        assert_eq!(sink.count().unwrap(), 2);
        // One listing, no per-finding search (rate limited to 30/min), and
        // only the unfiled ids are created, once each.
        assert_eq!(
            *seen.lock().unwrap(),
            [
                "GET /repos/o/r/issues",
                "POST /repos/o/r/issues",
                "POST /repos/o/r/issues",
            ]
        );
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
