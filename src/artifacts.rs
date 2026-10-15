//! Stage-to-stage artifact IO. Stages exchange data only through files in the
//! run's `out_dir`; lists are JSONL so a stage can append incrementally and a
//! partial run stays readable.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Artifact names within `out_dir`.
pub mod names {
    /// Recon's threat model, verbatim; the context a cold hunter reads.
    pub const RECON_REPORT: &str = "recon.json";
    pub const QUEUE: &str = "queue.jsonl";
    pub const CANDIDATES: &str = "candidates.jsonl";
    pub const GAPS: &str = "gaps.jsonl";
    /// Findings Dedupe collapsed, each with the id it duplicates.
    pub const DUPLICATES: &str = "duplicates.jsonl";
    /// What agents needed but the sandbox lacks, for the operator to grant.
    pub const WISHLIST: &str = "wishlist.jsonl";
    pub const VALIDATED: &str = "validated.jsonl";
    /// The one reviewable JSON document Aggregate compiles (not JSONL).
    pub const REPORT_JSON: &str = "findings.json";
    /// Report payloads, written whatever the configured sink.
    pub const FINDINGS_JSONL: &str = "findings.jsonl";
    /// Task ids Hunt has processed, so hunting is incremental.
    pub const HUNTED: &str = "hunted.jsonl";
    /// Cross-run feedback memory; never reset.
    pub const SEEDS: &str = "feedback-seeds.jsonl";
    /// Recon's session id, for hunters to fork. One line of text.
    pub const RECON_SESSION: &str = "recon-session.txt";
    /// Prefixed to every finding id, since task ids repeat every run and would
    /// collide in a sink that outlives a run. One line of text.
    pub const RUN_ID: &str = "run-id.txt";
    /// Per-agent event-stream transcripts.
    pub const LOGS: &str = "logs";
    /// PoCs copied out of the hunters' scratch dirs, which die with the container.
    pub const POCS: &str = "pocs";

    /// Everything one run produces, cleared when a run starts with recon.
    pub(super) const PER_RUN: &[&str] = &[
        RECON_REPORT,
        QUEUE,
        CANDIDATES,
        GAPS,
        DUPLICATES,
        WISHLIST,
        VALIDATED,
        REPORT_JSON,
        FINDINGS_JSONL,
        HUNTED,
        RECON_SESSION,
        RUN_ID,
    ];
    pub(super) const PER_RUN_DIRS: &[&str] = &[LOGS, POCS];
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

    pub fn log_path(&self, file: &str) -> PathBuf {
        self.path(names::LOGS).join(file)
    }

    pub fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }

    /// Clear the previous run's artifacts, keeping the durable feedback seeds.
    pub fn reset_run(&self) -> Result<()> {
        for name in names::PER_RUN {
            let path = self.path(name);
            ignore_missing(std::fs::remove_file(&path))
                .with_context(|| format!("removing {}", path.display()))?;
        }
        for dir in names::PER_RUN_DIRS {
            let path = self.path(dir);
            ignore_missing(std::fs::remove_dir_all(&path))
                .with_context(|| format!("removing {}", path.display()))?;
        }
        Ok(())
    }

    pub fn write_jsonl<T: Serialize>(&self, name: &str, items: &[T]) -> Result<()> {
        let path = self.path(name);
        let mut f = File::create(&path).with_context(|| format!("creating {}", path.display()))?;
        for item in items {
            writeln!(f, "{}", serde_json::to_string(item)?)?;
        }
        Ok(())
    }

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

    /// A missing file reads as empty.
    pub fn read_jsonl<T: DeserializeOwned>(&self, name: &str) -> Result<Vec<T>> {
        let path = self.path(name);
        let f = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
        };
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

    /// Create an empty JSONL file unless one exists, so downstream stages
    /// always find it without truncating accumulated results.
    pub fn ensure_jsonl(&self, name: &str) -> Result<()> {
        let path = self.path(name);
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
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

    /// A one-line text artifact, trimmed; `None` when missing or blank.
    pub fn read_line(&self, name: &str) -> Option<String> {
        let line = self.read_text(name).ok()?.trim().to_string();
        (!line.is_empty()).then_some(line)
    }

    /// Copy the text files of a file or tree into `out_dir/rel`, failing when
    /// there are none. Binaries are build output, not source worth keeping;
    /// symlinks are skipped since an agent-written link could point anywhere.
    pub fn import(&self, rel: &Path, src: &Path) -> Result<()> {
        let dest = self.out_dir.join(rel);
        let copied = copy_tree(src, &dest)
            .with_context(|| format!("copying {} to {}", src.display(), dest.display()))?;
        ensure!(copied > 0, "no text files in {}", src.display());
        Ok(())
    }
}

fn ignore_missing(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Returns the number of files copied. Directories are created only on the
/// way to a copied file, so a tree of binaries leaves nothing behind.
fn copy_tree(src: &Path, dest: &Path) -> io::Result<usize> {
    let meta = std::fs::symlink_metadata(src)?;
    let mut copied = 0;
    if meta.is_dir() {
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            copied += copy_tree(&entry.path(), &dest.join(entry.file_name()))?;
        }
    } else if meta.is_file() && !is_binary(src)? {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dest)?;
        copied = 1;
    }
    Ok(copied)
}

/// Git's heuristic: a NUL byte in the first 8000 bytes.
fn is_binary(path: &Path) -> io::Result<bool> {
    let mut head = Vec::with_capacity(8000);
    File::open(path)?.take(8000).read_to_end(&mut head)?;
    Ok(head.contains(&0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Row {
        a: u32,
    }

    fn artifacts() -> (tempfile::TempDir, Artifacts) {
        let dir = tempfile::tempdir().unwrap();
        let art = Artifacts::new(dir.path().join("out")).unwrap();
        (dir, art)
    }

    #[test]
    fn jsonl_round_trip() {
        let (_dir, art) = artifacts();
        art.write_jsonl("x.jsonl", &[Row { a: 1 }, Row { a: 2 }])
            .unwrap();
        art.append_jsonl("x.jsonl", &Row { a: 3 }).unwrap();
        art.ensure_jsonl("x.jsonl").unwrap();
        let got: Vec<Row> = art.read_jsonl("x.jsonl").unwrap();
        assert_eq!(got, vec![Row { a: 1 }, Row { a: 2 }, Row { a: 3 }]);
    }

    #[test]
    fn missing_jsonl_is_empty() {
        let (_dir, art) = artifacts();
        let got: Vec<Row> = art.read_jsonl("nope.jsonl").unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn read_line_trims_and_treats_blank_as_missing() {
        let (_dir, art) = artifacts();
        assert_eq!(art.read_line(names::RUN_ID), None);
        art.write_text(names::RUN_ID, "  \n").unwrap();
        assert_eq!(art.read_line(names::RUN_ID), None);
        art.write_text(names::RUN_ID, "20260901T000000Z\n").unwrap();
        assert_eq!(
            art.read_line(names::RUN_ID).as_deref(),
            Some("20260901T000000Z")
        );
    }

    #[test]
    fn reset_clears_the_run_but_keeps_the_seeds() {
        let (_dir, art) = artifacts();
        art.write_text(names::QUEUE, "{}").unwrap();
        art.write_text(names::SEEDS, "{}").unwrap();
        std::fs::create_dir_all(art.log_path("x").parent().unwrap()).unwrap();
        art.reset_run().unwrap();
        assert!(!art.exists(names::QUEUE));
        assert!(!art.exists(names::LOGS));
        assert!(art.exists(names::SEEDS));
    }

    #[test]
    fn import_copies_a_trees_text_and_skips_binaries_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("poc");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::create_dir_all(src.join("bin")).unwrap();
        std::fs::write(src.join("main.go"), "package main").unwrap();
        std::fs::write(src.join("sub").join("x.txt"), "x").unwrap();
        std::fs::write(src.join("poc"), b"\x7fELF\x02\x01\x01\0").unwrap();
        std::fs::write(src.join("bin").join("poc.test"), b"\x7fELF\0").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("leak")).unwrap();

        let art = Artifacts::new(dir.path().join("out")).unwrap();
        art.import(Path::new("pocs/F-1/poc"), &src).unwrap();
        let out = dir.path().join("out/pocs/F-1/poc");
        assert_eq!(
            std::fs::read_to_string(out.join("main.go")).unwrap(),
            "package main"
        );
        assert!(out.join("sub/x.txt").exists());
        assert!(!out.join("poc").exists());
        assert!(!out.join("bin").exists());
        assert!(!out.join("leak").exists());
    }

    #[test]
    fn import_of_only_binaries_fails_and_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("poc");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("poc"), b"\x7fELF\0").unwrap();

        let art = Artifacts::new(dir.path().join("out")).unwrap();
        let err = art.import(Path::new("pocs/F-1/poc"), &src).unwrap_err();
        assert!(err.to_string().contains("no text files"), "{err}");
        assert!(!art.path("pocs").exists());
    }
}
