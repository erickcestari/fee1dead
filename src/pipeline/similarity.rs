//! Token overlap between short finding texts, so dedupe, skip-reported, and
//! hunt measure "same bug" the same way.

use std::collections::HashSet;

use crate::domain::Finding;
use crate::store::ExistingReport;

/// The fields that identify a bug, not its prose. Scoring against a whole
/// issue body would dilute every overlap toward zero.
pub fn signature(title: &str, location: &str, attack_class: &str) -> String {
    format!("{title} {location} {attack_class}")
}

pub fn finding_signature(f: &Finding) -> String {
    signature(&f.title, &f.location, &f.attack_class)
}

pub fn report_signature(e: &ExistingReport) -> String {
    signature(&e.title, &e.location, &e.attack_class)
}

/// Lowercased alphanumeric words, ignoring those of two chars or fewer
/// (line numbers, `rs`, `go`).
pub fn tokenize(s: &str) -> HashSet<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 2)
        .map(str::to_lowercase)
        .collect()
}

/// |A ∩ B| / |A ∪ B|, in [0,1].
pub fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    inter / union
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_uses_identity_fields_only() {
        let f = Finding {
            title: "Bug".into(),
            attack_class: "dos".into(),
            description: "long prose that should not dominate the signature".into(),
            ..crate::domain::fixtures::finding("F-1")
        };
        let s = finding_signature(&f);
        assert!(s.contains("Bug") && s.contains("a.rs:1") && s.contains("dos"));
        assert!(!s.contains("prose"));
    }

    #[test]
    fn overlap_ignores_case_punctuation_and_short_tokens() {
        let a = tokenize("Unbounded alloc in src/net.rs:42");
        let b = tokenize("unbounded ALLOC, in SRC/net.rs");
        assert_eq!(jaccard(&a, &b), 1.0);
        assert_eq!(jaccard(&tokenize(""), &tokenize("")), 0.0);
        assert_eq!(
            jaccard(&tokenize("alpha beta"), &tokenize("gamma delta")),
            0.0
        );
    }
}
