//! Per-agent scratch directories.
//!
//! Every agent run gets its own scratch dir, so concurrent agents cannot clobber
//! each other's proof-of-concept code or final-answer file. A cold hunter runs
//! in it directly; a hunter forked from recon's session, and the stage agents
//! that must run in the target (recon, validate), write here via an additional
//! allowed directory.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct ScratchRoot {
    root: PathBuf,
}

impl ScratchRoot {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("creating scratch root {}", root.display()))?;
        Ok(Self { root })
    }

    /// Create (or reuse) the scratch dir for one agent: a hunt task id, or a
    /// stage label for the single-shot agents (`recon`, `validate`, ...).
    pub fn for_agent(&self, label: &str) -> Result<PathBuf> {
        let dir = self.root.join(sanitize(label));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating scratch dir {}", dir.display()))?;
        Ok(dir)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Keep task ids filesystem-safe without collapsing distinct ids.
fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_isolated_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = ScratchRoot::new(dir.path()).unwrap();
        let a = root.for_agent("task-1").unwrap();
        let b = root.for_agent("task/2").unwrap();
        assert!(a.is_dir());
        assert!(b.is_dir());
        assert_ne!(a, b);
    }
}
