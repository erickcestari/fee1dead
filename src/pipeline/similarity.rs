//! Token overlap between short finding texts, so dedupe and skip-reported
//! measure "same bug" the same way.

use std::collections::HashSet;

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
