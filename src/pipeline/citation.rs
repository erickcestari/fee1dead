//! Checks that each `file:line` an agent cites exists in the target, so a
//! made-up or mistyped location goes back to the agent for repair before a
//! reviewer spends a turn on it, or a later run trusts it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::domain::split_location;

/// Fails naming every location in `cited` the target lacks: a missing file,
/// or a line past its end. An absolute path outside `target` (a dependency,
/// the reference) is not checked.
pub(super) fn check<'a>(target: &Path, cited: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut line_counts = HashMap::new();
    let bad: Vec<String> = cited
        .into_iter()
        .filter_map(|location| {
            problem(target, location, &mut line_counts).map(|p| format!("`{location}` ({p})"))
        })
        .collect();
    if bad.is_empty() {
        return Ok(());
    }
    bail!(
        "these cited locations are not in the target repository `{}`: {}. Correct each to \
         a line you read, or drop a finding whose code you cannot find",
        target.display(),
        bad.join(", ")
    )
}

/// What is wrong with `location`, or `None` when it holds. `line_counts`
/// caches each file's line count (`None`: unreadable) across a check.
fn problem(
    target: &Path,
    location: &str,
    line_counts: &mut HashMap<PathBuf, Option<usize>>,
) -> Option<String> {
    let (file, line) = split_location(location);
    if file.is_empty() {
        return Some("no file".to_string());
    }
    let path = Path::new(file);
    if path.is_absolute() && !path.starts_with(target) {
        return None;
    }
    // Joining an absolute path replaces the base, so both forms resolve.
    let path = target.join(path);
    let lines = *line_counts
        .entry(path)
        .or_insert_with_key(|path| std::fs::read(path).ok().map(|b| line_count(&b)));
    match (lines, line) {
        (None, _) => Some("no such file".to_string()),
        (Some(n), Some(l)) if l == 0 || l > n => Some(format!("the file has {n} lines")),
        _ => None,
    }
}

/// Bytes, not UTF-8, so a source file in another encoding still counts.
fn line_count(bytes: &[u8]) -> usize {
    let newlines = bytes.iter().filter(|&&b| b == b'\n').count();
    newlines + usize::from(bytes.last().is_some_and(|&b| b != b'\n'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/a.go"), "one\ntwo\nthree\n").unwrap();
        dir
    }

    #[test]
    fn real_locations_pass_in_any_form() {
        let dir = target();
        let abs = format!("{}/src/a.go:3", dir.path().display());
        let cited = [
            "src/a.go:3",
            "src/a.go:Decode",
            "src/a.go",
            "src/a.go:2:7",
            &abs,
        ];
        check(dir.path(), cited).unwrap();
        // Code outside the target, such as a dependency, is not ours to check.
        check(dir.path(), ["/root/go/pkg/mod/x/y.go:900"]).unwrap();
    }

    #[test]
    fn a_missing_file_or_line_past_the_end_fails_naming_each() {
        let dir = target();
        let err = check(
            dir.path(),
            ["src/a.go:4", "src/a.go:0", "src/b.go:1", ":5", "src/a.go:1"],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("`src/a.go:4` (the file has 3 lines)"), "{err}");
        assert!(err.contains("`src/a.go:0`"), "{err}");
        assert!(err.contains("`src/b.go:1` (no such file)"), "{err}");
        assert!(err.contains("`:5` (no file)"), "{err}");
        assert!(!err.contains("`src/a.go:1`"), "{err}");
    }

    #[test]
    fn line_count_handles_a_missing_final_newline() {
        assert_eq!(line_count(b""), 0);
        assert_eq!(line_count(b"a\nb\n"), 2);
        assert_eq!(line_count(b"a\nb"), 2);
    }
}
