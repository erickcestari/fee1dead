//! Stage-to-stage artifact IO.
//!
//! Stages never call each other directly; they exchange data through files in
//! the run's `out_dir`. Lists are stored as JSONL (one record per line) so a
//! stage can append incrementally and a partial run is still readable.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Canonical artifact file names within `out_dir`.
pub mod names {
    /// Recon's structured threat model, persisted verbatim as the agent emitted
    /// it. Forked hunters inherit recon's session and never read this; cold
    /// hunters (non-forking providers) read it back as their threat-model context.
    pub const RECON_REPORT: &str = "recon.json";
    pub const QUEUE: &str = "queue.jsonl";
    pub const CANDIDATES: &str = "candidates.jsonl";
    pub const GAPS: &str = "gaps.jsonl";
    pub const VALIDATED: &str = "validated.jsonl";
    /// Ledger of task ids the Hunt stage has already processed, so hunting is
    /// incremental and re-queued (gapfill) tasks get a fresh pass.
    pub const HUNTED: &str = "hunted.jsonl";
    /// Durable cross-run feedback memory: seed tasks distilled from past runs.
    /// Unlike the others, this artifact is NOT reset between runs.
    pub const SEEDS: &str = "feedback-seeds.jsonl";
    /// The recon agent's session id, so hunters can fork from its context.
    /// Holds a single line of text, not JSONL.
    pub const RECON_SESSION: &str = "recon-session.txt";
    /// Directory of per-agent event-stream transcripts (one JSONL file per agent
    /// run). Each transcript's final `result` event carries that agent's cost,
    /// token usage, and prompt-cache hits, so a run is profiled from here. Cleared
    /// wholesale at the start of a recon-led run.
    pub const LOGS: &str = "logs";

    /// Artifacts produced fresh by a single run (everything except SEEDS).
    /// Cleared at the start of a run that includes recon.
    pub const PER_RUN: &[&str] = &[
        RECON_REPORT,
        QUEUE,
        CANDIDATES,
        GAPS,
        VALIDATED,
        HUNTED,
        RECON_SESSION,
    ];
}

/// Handle to a run's output directory.
#[derive(Debug, Clone)]
pub struct Artifacts {
    out_dir: PathBuf,
}

impl Artifacts {
    pub fn new(out_dir: impl Into<PathBuf>) -> Result<Self> {
        let out_dir = out_dir.into();
        std::fs::create_dir_all(&out_dir)
            .with_context(|| format!("creating out_dir {}", out_dir.display()))?;
        Ok(Self { out_dir })
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.out_dir.join(name)
    }

    /// Path of a per-agent stream-log file, under the [`names::LOGS`] dir.
    pub fn log_path(&self, file: &str) -> PathBuf {
        self.path(names::LOGS).join(file)
    }

    /// Overwrite a JSONL file with `items`.
    pub fn write_jsonl<T: Serialize>(&self, name: &str, items: &[T]) -> Result<()> {
        let path = self.path(name);
        let mut f = File::create(&path).with_context(|| format!("creating {}", path.display()))?;
        for item in items {
            let line = serde_json::to_string(item)?;
            writeln!(f, "{line}")?;
        }
        Ok(())
    }

    /// Append one record to a JSONL file.
    pub fn append_jsonl<T: Serialize>(&self, name: &str, item: &T) -> Result<()> {
        let path = self.path(name);
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {} for append", path.display()))?;
        writeln!(f, "{}", serde_json::to_string(item)?)?;
        Ok(())
    }

    /// Read a JSONL file into a vec. Missing file yields an empty vec.
    pub fn read_jsonl<T: DeserializeOwned>(&self, name: &str) -> Result<Vec<T>> {
        let path = self.path(name);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let f = File::open(&path).with_context(|| format!("opening {}", path.display()))?;
        let mut out = Vec::new();
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let item = serde_json::from_str(&line)
                .with_context(|| format!("parsing {} line {}", path.display(), i + 1))?;
            out.push(item);
        }
        Ok(out)
    }

    /// Create an empty JSONL file if it does not exist, leaving an existing one
    /// untouched. Lets downstream stages always read a present (possibly empty)
    /// artifact without truncating accumulated results.
    pub fn ensure_jsonl(&self, name: &str) -> Result<()> {
        let path = self.path(name);
        if !path.exists() {
            File::create(&path).with_context(|| format!("creating {}", path.display()))?;
        }
        Ok(())
    }

    pub fn write_text(&self, name: &str, contents: &str) -> Result<()> {
        let path = self.path(name);
        std::fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))
    }

    pub fn read_text(&self, name: &str) -> Result<String> {
        let path = self.path(name);
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
    }

    pub fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }

    /// Delete an artifact if present (no error when already absent).
    pub fn remove(&self, name: &str) -> Result<()> {
        let path = self.path(name);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }

    /// Recursively delete a directory artifact if present (no error when absent).
    pub fn remove_dir(&self, name: &str) -> Result<()> {
        let path = self.path(name);
        match std::fs::remove_dir_all(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("removing dir {}", path.display())),
        }
    }
}

/// Best-effort extraction of a fenced ```json ... ``` block from agent text,
/// falling back to the first balanced JSON array/object. Agents wrap structured
/// output in prose; this pulls it back out.
pub fn extract_json_block(text: &str) -> Option<&str> {
    if let Some(start) = text.find("```json") {
        let rest = &text[start + "```json".len()..];
        if let Some(end) = rest.find("```") {
            return Some(rest[..end].trim());
        }
    }
    // Fall back to the outermost array or object.
    let first = text.find(['[', '{'])?;
    let last = text.rfind([']', '}'])?;
    if last > first {
        Some(text[first..=last].trim())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Row {
        a: u32,
    }

    #[test]
    fn jsonl_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let art = Artifacts::new(dir.path()).unwrap();
        art.write_jsonl("x.jsonl", &[Row { a: 1 }, Row { a: 2 }])
            .unwrap();
        art.append_jsonl("x.jsonl", &Row { a: 3 }).unwrap();
        let got: Vec<Row> = art.read_jsonl("x.jsonl").unwrap();
        assert_eq!(got, vec![Row { a: 1 }, Row { a: 2 }, Row { a: 3 }]);
    }

    #[test]
    fn missing_jsonl_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let art = Artifacts::new(dir.path()).unwrap();
        let got: Vec<Row> = art.read_jsonl("nope.jsonl").unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn extracts_fenced_json() {
        let t = "Here is the result:\n```json\n[{\"a\":1}]\n```\nDone.";
        assert_eq!(extract_json_block(t), Some("[{\"a\":1}]"));
    }

    #[test]
    fn extracts_bare_json() {
        let t = "blah [{\"a\":1}] trailing";
        assert_eq!(extract_json_block(t), Some("[{\"a\":1}]"));
    }
}
