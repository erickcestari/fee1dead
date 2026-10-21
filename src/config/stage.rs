use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// A pipeline stage, as named in `stages.enabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Recon,
    Hunt,
    Gapfill,
    Dedupe,
    SkipReported,
    Validate,
    Report,
    Feedback,
    Aggregate,
}

impl Stage {
    pub const ALL: [Stage; 9] = [
        Stage::Recon,
        Stage::Hunt,
        Stage::Gapfill,
        Stage::Dedupe,
        Stage::SkipReported,
        Stage::Validate,
        Stage::Report,
        Stage::Feedback,
        Stage::Aggregate,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Stage::Recon => "recon",
            Stage::Hunt => "hunt",
            Stage::Gapfill => "gapfill",
            Stage::Dedupe => "dedupe",
            Stage::SkipReported => "skip-reported",
            Stage::Validate => "validate",
            Stage::Report => "report",
            Stage::Feedback => "feedback",
            Stage::Aggregate => "aggregate",
        }
    }

    /// Whether the stage runs an agent, and so may take a `stages.models` entry.
    pub fn runs_agent(self) -> bool {
        matches!(
            self,
            Stage::Recon | Stage::Hunt | Stage::Validate | Stage::SkipReported
        )
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagesConfig {
    /// Stages in run order; a stage may repeat (e.g. hunt after gapfill).
    pub enabled: Vec<Stage>,
    /// Per-stage model override, in the provider's own id form.
    #[serde(default)]
    pub models: BTreeMap<Stage, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_the_config_spelling() {
        for stage in Stage::ALL {
            let parsed: Stage = serde_json::from_value(stage.name().into()).unwrap();
            assert_eq!(parsed, stage);
        }
    }
}
