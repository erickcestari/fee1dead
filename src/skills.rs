//! Stage-to-skill mapping.
//!
//! Each stage loads a set of Trail of Bits skills (shipped under `./skills/`)
//! that encode the right methodology for that stage. Centralizing the mapping
//! keeps the stage code free of skill-name strings and makes the policy easy to
//! audit and tune.

/// The skills a stage should ask the agent to load.
pub fn skills_for(stage: &str) -> &'static [&'static str] {
    match stage {
        // Recon builds architectural context and enumerates entry points.
        "recon" => &["audit-context-building", "entry-point-analyzer"],
        // Hunters lean on attack-surface and insecure-default heuristics.
        "hunt" => &["sharp-edges", "insecure-defaults"],
        // Validation is disprove-only false-positive checking.
        "validate" => &["fp-check"],
        // Gapfill and dedupe both reason about variants of a finding.
        "gapfill" => &["variant-analysis"],
        "dedupe" => &["variant-analysis"],
        // Feedback traces reachability across repos; differential review fits.
        "feedback" => &["differential-review"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_uses_fp_check() {
        assert_eq!(skills_for("validate"), &["fp-check"]);
    }

    #[test]
    fn unknown_stage_has_no_skills() {
        assert!(skills_for("report").is_empty());
    }
}
