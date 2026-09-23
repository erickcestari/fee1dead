//! Stage-to-stage artifact IO.
//!
//! Stages never call each other directly; they exchange data through files in
//! the run's `out_dir`. Lists are stored as JSONL (one record per line) so a
//! stage can append incrementally and a partial run is still readable.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

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
    /// Findings Dedupe collapsed into another with the same root cause, each
    /// with the id it duplicates. Kept so a wrong merge can be spotted.
    pub const DUPLICATES: &str = "duplicates.jsonl";
    pub const VALIDATED: &str = "validated.jsonl";
    /// Single human-reviewable JSON document the Aggregate stage compiles from
    /// the hunters' raw output (`candidates.jsonl` + `gaps.jsonl`), enriched with
    /// each finding's recon task context. Unlike the others this is one JSON
    /// object, not JSONL. Written by pure logic with no agent call, so it lands
    /// even when the token budget is spent before the review stages.
    pub const REPORT_JSON: &str = "findings.json";
    /// Machine-readable findings JSONL, one report payload per line. Always
    /// written by the Report stage regardless of the configured sink, so a
    /// JSONL of findings exists even when reports land in sqlite/http/github.
    /// When `report.sink = "jsonl"` this is the sink's own file.
    pub const FINDINGS_JSONL: &str = "findings.jsonl";
    /// Ledger of task ids the Hunt stage has already processed, so hunting is
    /// incremental and re-queued (gapfill) tasks get a fresh pass.
    pub const HUNTED: &str = "hunted.jsonl";
    /// Durable cross-run feedback memory: seed tasks distilled from past runs.
    /// Unlike the others, this artifact is NOT reset between runs.
    pub const SEEDS: &str = "feedback-seeds.jsonl";
    /// The recon agent's session id, so hunters can fork from its context.
    /// Holds a single line of text, not JSONL.
    pub const RECON_SESSION: &str = "recon-session.txt";
    /// This run's id, prefixed to every finding id. Task ids are positional and
    /// repeat every run, so without it `T-0001-F01` would name a different bug
    /// each run and collide in any sink that outlives a run (github issues, a
    /// reused sqlite db). Single line of text; kept across a `--resume`.
    pub const RUN_ID: &str = "run-id.txt";
    /// Directory of per-agent event-stream transcripts (one JSONL file per agent
    /// run). Each transcript's final `result` event carries that agent's cost,
    /// token usage, and prompt-cache hits, so a run is profiled from here. Cleared
    /// wholesale at the start of a recon-led run.
    pub const LOGS: &str = "logs";
    /// Hunters' proof-of-concept code, copied out of their scratch dirs (which
    /// do not outlive the container) to `pocs/<finding id>/`.
    pub const POCS: &str = "pocs";

    /// Artifacts produced fresh by a single run (everything except SEEDS).
    /// Cleared at the start of a run that includes recon.
    pub const PER_RUN: &[&str] = &[
        RECON_REPORT,
        QUEUE,
        CANDIDATES,
        GAPS,
        DUPLICATES,
        VALIDATED,
        REPORT_JSON,
        FINDINGS_JSONL,
        HUNTED,
        RECON_SESSION,
        RUN_ID,
    ];

    /// Directory artifacts produced fresh by a single run, cleared alongside
    /// [`PER_RUN`].
    pub const PER_RUN_DIRS: &[&str] = &[LOGS, POCS];
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

    /// Copy a file or directory tree into `out_dir/rel`, creating parent dirs.
    /// Symlinks are skipped: an agent-written link could point anywhere.
    pub fn import(&self, rel: &Path, src: &Path) -> Result<()> {
        let dest = self.out_dir.join(rel);
        copy_tree(src, &dest)
            .with_context(|| format!("copying {} to {}", src.display(), dest.display()))
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

fn copy_tree(src: &Path, dest: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(src)?;
    if meta.is_dir() {
        std::fs::create_dir_all(dest)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            copy_tree(&entry.path(), &dest.join(entry.file_name()))?;
        }
    } else if meta.is_file() {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dest)?;
    }
    Ok(())
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
    fn import_copies_a_tree_and_skips_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("poc");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("main.go"), "package main").unwrap();
        std::fs::write(src.join("sub").join("x.txt"), "x").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("leak")).unwrap();

        let art = Artifacts::new(dir.path().join("out")).unwrap();
        art.import(Path::new("pocs/F-1/poc"), &src).unwrap();
        let out = dir.path().join("out/pocs/F-1/poc");
        assert_eq!(
            std::fs::read_to_string(out.join("main.go")).unwrap(),
            "package main"
        );
        assert!(out.join("sub/x.txt").exists());
        assert!(!out.join("leak").exists());
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
