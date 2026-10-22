//! Wildcard tasks: harness-made exploration of the modules no queued task
//! scopes. Recon queues only tasks with a concrete lead, so whatever its
//! shallow threat model missed would otherwise never be hunted.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::domain::{Priority, Task, TaskOrigin};

/// The hunter's brief, given as its hypothesis.
const BRIEF: &str = "No lead was given here: hunt what the threat model missed. Start from \
     the strangest code in scope: half-finished, experimental, compatibility, and fallback \
     features; comments that claim something is safe (verify the claim); code named temp, \
     hack, or legacy; and the edge cases the tests skip. Hold a finding to the same bar as any \
     other task.";

/// A module with less untasked code than this is not worth a hunter.
const MIN_LINES: u64 = 100;

/// Path components and file-name marks of code that is no attack surface.
const NOT_SURFACE_DIRS: &[&str] = &[
    "test",
    "tests",
    "testdata",
    "testing",
    "testutil",
    "testutils",
    "mock",
    "mocks",
    "fixtures",
    "example",
    "examples",
    "docs",
    "bench",
    "benches",
    "fuzz",
    "scripts",
];
const NOT_SURFACE_MARKS: &[&str] = &["_test.", ".test.", ".spec.", "test_", "_mock."];

/// Up to `n` tasks, one per module (a directory's own source files) holding
/// the most code no task in `queue` scopes, largest first. Ids continue the
/// queue's numbering with a `W-` prefix.
pub(super) fn plan(files: &[(PathBuf, u64)], queue: &[Task], n: usize) -> Vec<Task> {
    let mut untasked: BTreeMap<String, u64> = BTreeMap::new();
    for (path, lines) in files {
        let Some(path) = path.to_str() else { continue };
        if !is_surface(path) || queue.iter().any(|t| t.touches(path)) {
            continue;
        }
        let module = path.rsplit_once('/').map_or("", |(dir, _)| dir);
        *untasked.entry(module.to_string()).or_default() += lines;
    }
    let mut modules: Vec<(String, u64)> = untasked
        .into_iter()
        .filter(|&(_, lines)| lines >= MIN_LINES)
        .collect();
    // Stable, so equal modules keep their path order.
    modules.sort_by_key(|m| std::cmp::Reverse(m.1));
    modules
        .into_iter()
        .take(n)
        .enumerate()
        .map(|(i, (module, _))| task(format!("W-{:04}", queue.len() + i + 1), &module))
        .collect()
}

fn task(id: String, module: &str) -> Task {
    let (scope_hint, scope_paths) = if module.is_empty() {
        ("the repository's top-level files".to_string(), Vec::new())
    } else {
        let scope = format!("{module}/");
        (scope.clone(), vec![scope])
    };
    Task {
        id,
        attack_class: "wildcard".to_string(),
        scope_hint,
        scope_paths,
        hypothesis: BRIEF.to_string(),
        priority: Priority::Medium,
        origin: TaskOrigin::Wildcard,
        ..Task::default()
    }
}

fn is_surface(path: &str) -> bool {
    let lower = path.to_lowercase();
    let (dirs, name) = lower.rsplit_once('/').unwrap_or(("", &lower));
    !dirs.split('/').any(|d| NOT_SURFACE_DIRS.contains(&d))
        && !NOT_SURFACE_MARKS.iter().any(|m| name.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::fixtures;

    fn files(list: &[(&str, u64)]) -> Vec<(PathBuf, u64)> {
        list.iter().map(|&(p, n)| (PathBuf::from(p), n)).collect()
    }

    fn scoped(id: &str, scope: &str) -> Task {
        Task {
            scope_paths: vec![scope.into()],
            ..fixtures::task(id)
        }
    }

    #[test]
    fn picks_the_largest_untasked_modules_and_skips_tests() {
        let files = files(&[
            ("lnwallet/channel.go", 900),
            ("htlcswitch/switch.go", 400),
            ("htlcswitch/link.go", 300),
            ("htlcswitch/switch_test.go", 5000),
            ("internal/testutil/net.go", 5000),
            ("rpcserver.go", 500),
            ("tiny/x.go", 50),
        ]);
        let queue = vec![scoped("T-0001", "lnwallet/")];
        let plan = plan(&files, &queue, 5);
        let scopes: Vec<&str> = plan.iter().map(|t| t.scope_hint.as_str()).collect();
        assert_eq!(scopes, ["htlcswitch/", "the repository's top-level files"]);
        assert_eq!(plan[0].id, "W-0002");
        assert_eq!(plan[0].scope_paths, ["htlcswitch/"]);
        assert!(plan[1].scope_paths.is_empty());
        assert!(plan.iter().all(|t| t.origin == TaskOrigin::Wildcard));
    }

    #[test]
    fn a_partly_tasked_module_counts_only_its_untasked_files() {
        let files = files(&[
            ("src/parse.rs", 400),
            ("src/net.rs", 50),
            ("src/rpc.rs", 30),
        ]);
        let queue = vec![scoped("T-0001", "src/parse.rs")];
        assert!(plan(&files, &queue, 1).is_empty());
        assert_eq!(plan(&files, &[], 1)[0].scope_hint, "src/");
    }

    #[test]
    fn zero_asks_for_none() {
        assert!(plan(&files(&[("a/b.go", 1000)]), &[], 0).is_empty());
    }
}
