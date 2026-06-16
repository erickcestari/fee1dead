//! JSONL report sink: one finding payload per line. Simple, diffable, and easy
//! to feed into other tools. Upserts are kept in memory and rewritten on flush.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;

use super::{ReportRecord, ReportSink};

pub struct JsonlSink {
    path: PathBuf,
    /// id -> payload, kept ordered for stable output.
    records: BTreeMap<String, Value>,
}

impl JsonlSink {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let mut records = BTreeMap::new();
        if path.exists() {
            let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
            for line in BufReader::new(f).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let v: Value = serde_json::from_str(&line)?;
                if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
                    records.insert(id.to_string(), v);
                }
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            records,
        })
    }

    fn flush(&self) -> Result<()> {
        let mut f =
            File::create(&self.path).with_context(|| format!("writing {}", self.path.display()))?;
        for v in self.records.values() {
            writeln!(f, "{}", serde_json::to_string(v)?)?;
        }
        Ok(())
    }
}

impl ReportSink for JsonlSink {
    fn write(&mut self, record: &ReportRecord) -> Result<()> {
        self.records
            .insert(record.id.clone(), record.payload.clone());
        self.flush()
    }

    fn count(&self) -> Result<usize> {
        Ok(self.records.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(id: &str, title: &str) -> ReportRecord {
        ReportRecord {
            id: id.into(),
            payload: json!({"id": id, "title": title}),
        }
    }

    #[test]
    fn upserts_by_id_and_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.jsonl");

        let mut sink = JsonlSink::open(&path).unwrap();
        sink.write(&rec("F-1", "first")).unwrap();
        sink.write(&rec("F-2", "second")).unwrap();
        sink.write(&rec("F-1", "updated")).unwrap(); // upsert, not append
        assert_eq!(sink.count().unwrap(), 2);

        // Reopen: existing lines are loaded back and keyed by id.
        let reopened = JsonlSink::open(&path).unwrap();
        assert_eq!(reopened.count().unwrap(), 2);
        assert_eq!(reopened.records["F-1"]["title"], "updated");
    }

    #[test]
    fn open_missing_file_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let sink = JsonlSink::open(&dir.path().join("nope.jsonl")).unwrap();
        assert_eq!(sink.count().unwrap(), 0);
    }
}
