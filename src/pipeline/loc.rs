//! A rough line count of a repo's source. Approximate by design: it only has
//! to pick recon's size tier and rank modules for wildcard tasks.

use std::path::{Path, PathBuf};

/// Never counted, on top of any dot-directory: dependencies and build output.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    "__pycache__",
];

/// A missing language only nudges the estimate.
const SRC_EXTS: &[&str] = &[
    "rs", "go", "py", "js", "ts", "tsx", "jsx", "mjs", "cjs", "c", "cc", "cpp", "cxx", "h", "hh",
    "hpp", "java", "rb", "php", "sol", "swift", "kt", "scala", "sh", "ml", "ex", "exs", "erl",
    "cs",
];

/// Each source file under `root`, relative to it, with its line count.
pub(super) fn files(root: &Path) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let path = entry.path();
            // Symlinks are not followed: they can escape the tree or cycle.
            if ft.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_ref()) {
                    stack.push(path);
                }
            } else if ft.is_file()
                && is_source(&path)
                && let Ok(content) = std::fs::read_to_string(&path)
                && let Ok(relative) = path.strip_prefix(root)
            {
                out.push((relative.to_path_buf(), content.lines().count() as u64));
            }
        }
    }
    out
}

pub(super) fn total(files: &[(PathBuf, u64)]) -> u64 {
    files.iter().map(|(_, lines)| lines).sum()
}

fn is_source(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| SRC_EXTS.contains(&ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_sources_and_skips_vcs_vendor_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("a.rs"), "one\ntwo\nthree\n").unwrap();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(root.join("src").join("b.go"), "x\ny\n").unwrap();
        std::fs::write(root.join("README.md"), "a\nb\nc\nd\n").unwrap();
        std::fs::create_dir(root.join(".git")).unwrap();
        std::fs::write(root.join(".git").join("huge.rs"), "junk\njunk\n").unwrap();
        std::fs::create_dir(root.join("node_modules")).unwrap();
        std::fs::write(root.join("node_modules").join("dep.js"), "z\nz\nz\n").unwrap();
        std::os::unix::fs::symlink(root.join("src"), root.join("loop")).unwrap();

        let mut found = files(root);
        found.sort();
        assert_eq!(
            found,
            [(PathBuf::from("a.rs"), 3), (PathBuf::from("src/b.go"), 2)]
        );
        assert_eq!(total(&found), 5);
    }
}
