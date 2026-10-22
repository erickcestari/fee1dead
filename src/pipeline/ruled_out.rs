//! The cross-run memory of claims code settled as not bugs
//! (`ruled-out.jsonl`): hunters' disproved hypotheses and reviewers' likely
//! false positives. Feedback keeps it; each hunter sees the entries closest to
//! its task. An entry holds only while the file that settled it is unchanged.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Deserialize;
use tracing::warn;

use crate::domain::{Finding, RuledOut, Validation, Verdict, split_location};
use crate::target::changed_since;

/// A disproved hypothesis as a hunter writes it. Every field defaults, so a
/// sloppy entry is dropped instead of failing the answer it rides in.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct RawCleared {
    claim: String,
    pub(super) guard: String,
    reason: String,
}

impl RawCleared {
    /// `None` when it names no claim or no guard.
    pub(super) fn into_ruled_out(self, commit: &str) -> Option<RuledOut> {
        let claim = self.claim.trim();
        let guard = self.guard.trim();
        (!claim.is_empty() && !guard.is_empty()).then(|| RuledOut {
            claim: claim.to_string(),
            location: guard.to_string(),
            reason: self.reason.trim().to_string(),
            commit: commit.to_string(),
        })
    }
}

/// The findings review judged likely false positives, with the reviewer's
/// evidence as the reason.
pub(super) fn false_positives(
    candidates: &[Finding],
    validations: &[Validation],
    commit: &str,
) -> Vec<RuledOut> {
    let by_id: HashMap<&str, &Finding> = candidates.iter().map(|f| (f.id.as_str(), f)).collect();
    validations
        .iter()
        .filter(|v| v.verdict == Verdict::LikelyFalsePositive)
        .filter_map(|v| {
            let f = by_id.get(v.finding_id.as_str())?;
            Some(RuledOut {
                claim: f.title.clone(),
                location: f.location.clone(),
                reason: v.evidence.clone(),
                commit: commit.to_string(),
            })
        })
        .collect()
}

/// The entries whose file did not change between their commit and `head`,
/// restamped to `head` so the next check diffs from there. An entry whose
/// commit the checkout lacks cannot be checked, so it is dropped.
pub(super) fn holding(entries: Vec<RuledOut>, target: &Path, head: &str) -> Vec<RuledOut> {
    let mut changed: HashMap<String, Option<HashSet<String>>> = HashMap::new();
    entries
        .into_iter()
        .filter(|e| {
            if e.commit == head {
                return true;
            }
            let files = changed.entry(e.commit.clone()).or_insert_with(|| {
                changed_since(target, &e.commit)
                    .inspect_err(|err| {
                        warn!(
                            commit = e.commit,
                            error = format!("{err:#}"),
                            "cannot diff a ruled-out entry's commit; dropping its entries"
                        )
                    })
                    .ok()
            });
            files
                .as_ref()
                .is_some_and(|files| !files.contains(repo_path(target, &e.location)))
        })
        .map(|e| RuledOut {
            commit: head.to_string(),
            ..e
        })
        .collect()
}

/// The file of `location`, relative to `target` as git reports it.
fn repo_path<'a>(target: &Path, location: &'a str) -> &'a str {
    let file = split_location(location).0;
    let relative = Path::new(file)
        .strip_prefix(target)
        .ok()
        .and_then(Path::to_str)
        .unwrap_or(file);
    relative.trim_start_matches("./")
}

/// The first of each claim at a location, up to `max`; put the newest first.
pub(super) fn dedupe_and_cap(entries: Vec<RuledOut>, max: usize) -> Vec<RuledOut> {
    let mut seen = HashSet::new();
    entries
        .into_iter()
        .filter(|e| seen.insert((e.claim.to_lowercase(), e.location.to_lowercase())))
        .take(max)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::fixtures::{finding, validation};
    use std::process::Command;

    fn entry(claim: &str, location: &str, commit: &str) -> RuledOut {
        RuledOut {
            claim: claim.into(),
            location: location.into(),
            reason: String::new(),
            commit: commit.into(),
        }
    }

    fn git(repo: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn commit(repo: &Path, file: &str, contents: &str) -> String {
        std::fs::write(repo.join(file), contents).unwrap();
        git(repo, &["add", file]);
        git(repo, &["commit", "-qm", contents]);
        git(repo, &["rev-parse", "HEAD"])
    }

    #[test]
    fn a_change_to_the_settling_file_reopens_its_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        git(repo, &["init", "-q"]);
        commit(repo, "a.go", "a");
        let first = commit(repo, "b.go", "b");
        let head = commit(repo, "b.go", "b changed");

        let abs = format!("{}/a.go:3", repo.display());
        let entries = vec![
            entry("unchanged file", "a.go:1", &first),
            entry("absolute path", &abs, &first),
            entry("changed file", "b.go:1", &first),
            entry(
                "unknown commit",
                "a.go:1",
                "0000000000000000000000000000000000000000",
            ),
            entry("already at head", "b.go:1", &head),
        ];
        let kept = holding(entries, repo, &head);
        let claims: Vec<&str> = kept.iter().map(|e| e.claim.as_str()).collect();
        assert_eq!(
            claims,
            ["unchanged file", "absolute path", "already at head"]
        );
        assert!(kept.iter().all(|e| e.commit == head));
    }

    #[test]
    fn dedupe_keeps_the_first_and_caps() {
        let entries = vec![
            entry("Len unchecked", "a.go:1", "c2"),
            entry("len unchecked", "A.go:1", "c1"),
            entry("other", "b.go:1", "c1"),
            entry("third", "c.go:1", "c1"),
        ];
        let merged = dedupe_and_cap(entries, 2);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].commit, "c2");
        assert_eq!(merged[1].claim, "other");
    }

    #[test]
    fn only_likely_false_positives_are_ruled_out() {
        let candidates = vec![finding("F-1"), finding("F-2")];
        let validations = vec![
            validation("F-1", Verdict::LikelyFalsePositive),
            validation("F-2", Verdict::Confirmed),
        ];
        let out = false_positives(&candidates, &validations, "c1");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].location, "a.rs:1");
        assert_eq!(out[0].reason, "e");
    }

    #[test]
    fn a_cleared_entry_needs_a_claim_and_a_guard() {
        let raw = |claim: &str, guard: &str| RawCleared {
            claim: claim.into(),
            guard: guard.into(),
            reason: " bounded ".into(),
        };
        let kept = raw("len overflows", "a.go:9").into_ruled_out("c1").unwrap();
        assert_eq!(
            (kept.location.as_str(), kept.reason.as_str()),
            ("a.go:9", "bounded")
        );
        assert!(raw("", "a.go:9").into_ruled_out("c1").is_none());
        assert!(raw("len overflows", " ").into_ruled_out("c1").is_none());
    }
}
