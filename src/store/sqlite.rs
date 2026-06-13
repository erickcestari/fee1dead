//! SQLite report sink. Findings are queryable as structured rows; the full
//! payload is kept as JSON for fidelity.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;

use super::{ReportRecord, ReportSink};

pub struct SqliteSink {
    conn: Connection,
}

impl SqliteSink {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening sqlite db {}", path.display()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS findings (
                id        TEXT PRIMARY KEY,
                title     TEXT,
                severity  TEXT,
                location  TEXT,
                payload   TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;
        Ok(Self { conn })
    }
}

impl ReportSink for SqliteSink {
    fn write(&mut self, record: &ReportRecord) -> Result<()> {
        let p = &record.payload;
        let title = p.get("title").and_then(|v| v.as_str());
        let severity = p.get("severity").and_then(|v| v.as_str());
        let location = p.get("location").and_then(|v| v.as_str());
        self.conn.execute(
            "INSERT INTO findings (id, title, severity, location, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                title=excluded.title,
                severity=excluded.severity,
                location=excluded.location,
                payload=excluded.payload",
            rusqlite::params![record.id, title, severity, location, p.to_string()],
        )?;
        Ok(())
    }

    fn count(&self) -> Result<usize> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?;
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn upserts_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = SqliteSink::open(&dir.path().join("f.db")).unwrap();
        let rec = ReportRecord {
            id: "F-1".into(),
            payload: json!({"title":"t","severity":"high","location":"a.rs:1"}),
        };
        sink.write(&rec).unwrap();
        sink.write(&rec).unwrap(); // idempotent
        assert_eq!(sink.count().unwrap(), 1);
    }
}
