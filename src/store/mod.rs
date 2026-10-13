//! Where reportable findings land. The Report stage writes only through
//! [`ReportSink`]; a new sink implements it and is wired into [`build_sink`].

mod github;
mod http;
mod jsonl;
mod sqlite;

use anyhow::{Context, Result};
use serde_json::Value;

pub use github::GithubSink;
pub use http::HttpSink;
pub use jsonl::JsonlSink;
pub use sqlite::SqliteSink;

use crate::config::ReportConfig;

/// A schema-validated finding payload, keyed by the id sinks upsert on.
#[derive(Debug, Clone)]
pub struct ReportRecord {
    pub id: String,
    pub payload: Value,
}

/// A finding already in the destination, so new ones can be deduped against
/// it. Fields are recovered as the finding had them, empty when unrecoverable.
#[derive(Debug, Clone)]
pub struct ExistingReport {
    pub id: String,
    pub title: String,
    pub location: String,
    pub attack_class: String,
    /// The full report text, context for the dedupe judge.
    pub text: String,
}

pub trait ReportSink {
    /// Persist one finding, upserting on `record.id`.
    fn write(&mut self, record: &ReportRecord) -> Result<()>;

    /// Findings stored (or sent), for logging.
    fn count(&self) -> Result<usize>;

    /// Only sinks holding external state need this: an id-upsert sink cannot
    /// duplicate a finding it already holds.
    fn existing_reports(&self) -> Result<Vec<ExistingReport>> {
        Ok(Vec::new())
    }
}

pub fn build_sink(cfg: &ReportConfig) -> Result<Box<dyn ReportSink>> {
    Ok(match cfg {
        ReportConfig::Sqlite { path } => Box::new(SqliteSink::open(path)?),
        ReportConfig::Jsonl { path } => Box::new(JsonlSink::open(path)?),
        ReportConfig::Http { url, token_env } => {
            let token = token_env.as_ref().and_then(|var| std::env::var(var).ok());
            Box::new(HttpSink::new(url.clone(), token))
        }
        ReportConfig::Github { repo, token_env } => {
            let token = std::env::var(token_env).with_context(|| {
                format!(
                    "github sink requires a PAT in ${token_env}; set it or point \
                     report.token_env at the env var holding one"
                )
            })?;
            Box::new(GithubSink::new(repo.clone(), token))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_file_and_http_sinks_without_io() {
        let dir = tempfile::tempdir().unwrap();
        let s = build_sink(&ReportConfig::Jsonl {
            path: dir.path().join("f.jsonl"),
        })
        .unwrap();
        assert_eq!(s.count().unwrap(), 0);
        let s = build_sink(&ReportConfig::Sqlite {
            path: dir.path().join("f.db"),
        })
        .unwrap();
        assert_eq!(s.count().unwrap(), 0);
        assert!(
            build_sink(&ReportConfig::Http {
                url: "https://x/y".into(),
                token_env: None,
            })
            .is_ok()
        );
    }

    #[test]
    fn github_sink_fails_loudly_without_its_pat() {
        let cfg = ReportConfig::Github {
            repo: "owner/repo".into(),
            token_env: "FEE1DEAD_TEST_ABSENT_PAT".into(),
        };
        assert!(build_sink(&cfg).is_err());
    }
}
