//! The report sink: where validated, schema-checked findings land.
//!
//! The Report stage writes through [`ReportSink`]. A local SQLite or JSONL sink
//! is used now; an HTTP ingest sink can be added later behind the same trait
//! without touching the stage.

mod github;
mod http;
mod jsonl;
mod sqlite;

use anyhow::{Result, bail};
use serde_json::Value;

pub use github::GithubSink;
pub use http::HttpSink;
pub use jsonl::JsonlSink;
pub use sqlite::SqliteSink;

use crate::config::{ReportConfig, SinkKind};

/// A record ready to persist: the schema-validated finding payload plus the id
/// used for idempotent upserts.
#[derive(Debug, Clone)]
pub struct ReportRecord {
    pub id: String,
    pub payload: Value,
}

/// A finding already present in the destination, surfaced so new findings can
/// be deduped against it (e.g. issues already filed in GitHub).
///
/// `title`, `location`, and `attack_class` are recovered as the finding had
/// them, so they compare like-for-like with a new finding's same fields; empty
/// when the sink cannot recover one.
#[derive(Debug, Clone)]
pub struct ExistingReport {
    /// Finding id the report was filed under, when recoverable (the github sink
    /// reads it from the issue's hidden marker). Empty when unknown.
    pub id: String,
    pub title: String,
    pub location: String,
    pub attack_class: String,
    /// The full report text (e.g. the issue body), context for the model judge.
    pub text: String,
}

pub trait ReportSink {
    /// Persist one finding. Implementations should upsert on `record.id`.
    fn write(&mut self, record: &ReportRecord) -> Result<()>;

    /// Number of distinct findings currently stored (for verification/logging).
    fn count(&self) -> Result<usize>;

    /// Findings already present in the destination, for semantic dedup before
    /// writing. Defaults to none: id-upsert sinks (sqlite/jsonl/http) can't emit
    /// a duplicate for a re-run of the same id, so only external-state sinks
    /// (github) implement this.
    fn existing_reports(&self) -> Result<Vec<ExistingReport>> {
        Ok(Vec::new())
    }
}

/// Construct the sink selected by config. Field presence is validated at config
/// load, so the `bail!`s here are defensive.
pub fn build_sink(cfg: &ReportConfig) -> Result<Box<dyn ReportSink>> {
    Ok(match cfg.sink {
        SinkKind::Sqlite => {
            let Some(path) = &cfg.path else {
                bail!("sqlite sink requires report.path")
            };
            Box::new(SqliteSink::open(path)?)
        }
        SinkKind::Jsonl => {
            let Some(path) = &cfg.path else {
                bail!("jsonl sink requires report.path")
            };
            Box::new(JsonlSink::open(path)?)
        }
        SinkKind::Http => {
            let Some(url) = &cfg.url else {
                bail!("http sink requires report.url")
            };
            let token = cfg
                .token_env
                .as_ref()
                .and_then(|var| std::env::var(var).ok());
            Box::new(HttpSink::new(url.clone(), token))
        }
        SinkKind::Github => {
            let Some(repo) = &cfg.repo else {
                bail!("github sink requires report.repo (\"owner/repo\")")
            };
            let var = cfg.github_token_env();
            let token = std::env::var(var).map_err(|_| {
                anyhow::anyhow!(
                    "github sink requires a PAT in ${var}; set it or point report.token_env at the env var holding one"
                )
            })?;
            Box::new(GithubSink::new(repo.clone(), token))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(sink: SinkKind, path: Option<&str>, url: Option<&str>) -> ReportConfig {
        ReportConfig {
            sink,
            path: path.map(Into::into),
            url: url.map(Into::into),
            token_env: None,
            repo: None,
        }
    }

    #[test]
    fn builds_file_and_http_sinks() {
        let dir = tempfile::tempdir().unwrap();
        let jsonl = dir.path().join("f.jsonl");
        let db = dir.path().join("f.db");

        let s = build_sink(&cfg(SinkKind::Jsonl, jsonl.to_str(), None)).unwrap();
        assert_eq!(s.count().unwrap(), 0);
        let s = build_sink(&cfg(SinkKind::Sqlite, db.to_str(), None)).unwrap();
        assert_eq!(s.count().unwrap(), 0);
        // The http sink does not connect at construction.
        assert!(build_sink(&cfg(SinkKind::Http, None, Some("https://x/y"))).is_ok());
    }

    #[test]
    fn defensive_bails_when_required_field_missing() {
        // Config validation normally catches these; build_sink guards anyway.
        assert!(build_sink(&cfg(SinkKind::Jsonl, None, None)).is_err());
        assert!(build_sink(&cfg(SinkKind::Sqlite, None, None)).is_err());
        assert!(build_sink(&cfg(SinkKind::Http, None, None)).is_err());
        // github with no repo configured.
        assert!(build_sink(&cfg(SinkKind::Github, None, None)).is_err());
    }

    #[test]
    fn github_sink_bails_when_pat_env_missing() {
        // repo is set, but the PAT env var is absent → build must fail loudly.
        let mut c = cfg(SinkKind::Github, None, None);
        c.repo = Some("owner/repo".into());
        c.token_env = Some("FEE1DEAD_TEST_ABSENT_PAT".into());
        assert!(build_sink(&c).is_err());
    }
}
