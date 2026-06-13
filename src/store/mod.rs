//! The report sink: where validated, schema-checked findings land.
//!
//! The Report stage writes through [`ReportSink`]. A local SQLite or JSONL sink
//! is used now; an HTTP ingest sink can be added later behind the same trait
//! without touching the stage.

mod http;
mod jsonl;
mod sqlite;

use anyhow::{Result, bail};
use serde_json::Value;

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

pub trait ReportSink {
    /// Persist one finding. Implementations should upsert on `record.id`.
    fn write(&mut self, record: &ReportRecord) -> Result<()>;

    /// Number of distinct findings currently stored (for verification/logging).
    fn count(&self) -> Result<usize>;
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
    })
}
