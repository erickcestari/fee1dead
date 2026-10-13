//! Per-agent scratch directories, so concurrent agents never share PoC code
//! or an answer file.

use std::path::PathBuf;

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

    /// Create (or reuse) the scratch dir for the agent named `label`.
    pub fn for_agent(&self, label: &str) -> Result<PathBuf> {
        let dir = self.root.join(sanitize(label));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating scratch dir {}", dir.display()))?;
        Ok(dir)
    }
}

fn sanitize(label: &str) -> String {
    label
        .chars()
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
        assert!(a.is_dir() && b.is_dir());
        assert_ne!(a, b);
        assert!(b.starts_with(dir.path()), "a label cannot escape the root");
    }
}
