use std::path::PathBuf;

use anyhow::{Result, ensure};
use serde::Deserialize;

/// The `[report]` block; `sink` selects where reportable findings land.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "sink", rename_all = "lowercase", deny_unknown_fields)]
pub enum ReportConfig {
    Sqlite {
        path: PathBuf,
    },
    Jsonl {
        path: PathBuf,
    },
    /// One POST per finding to an ingest API.
    Http {
        url: String,
        /// Env var holding a bearer token.
        #[serde(default)]
        token_env: Option<String>,
    },
    /// One GitHub issue per finding.
    Github {
        /// `owner/name` slug the issues are filed into.
        repo: String,
        /// Env var holding a PAT with `issues:write`.
        #[serde(default = "default_github_token_env")]
        token_env: String,
    },
}

fn default_github_token_env() -> String {
    "GITHUB_PAT".to_string()
}

impl ReportConfig {
    pub fn sink_name(&self) -> &'static str {
        match self {
            ReportConfig::Sqlite { .. } => "sqlite",
            ReportConfig::Jsonl { .. } => "jsonl",
            ReportConfig::Http { .. } => "http",
            ReportConfig::Github { .. } => "github",
        }
    }

    pub(super) fn validate(&self) -> Result<()> {
        if let ReportConfig::Github { repo, .. } = self {
            let slug = matches!(repo.split_once('/'), Some((owner, name))
                if !owner.is_empty() && !name.is_empty() && !name.contains('/'));
            ensure!(
                slug,
                "report.repo must be in \"owner/repo\" form for the github sink, got {repo:?}"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> Result<ReportConfig> {
        Ok(toml::from_str(toml)?)
    }

    #[test]
    fn each_sink_requires_its_own_field() {
        for (toml, field) in [
            ("sink = \"sqlite\"", "path"),
            ("sink = \"jsonl\"", "path"),
            ("sink = \"http\"", "url"),
            ("sink = \"github\"", "repo"),
        ] {
            let err = parse(toml).unwrap_err().to_string();
            assert!(
                err.contains(&format!("missing field `{field}`")),
                "got: {err}"
            );
        }
    }

    #[test]
    fn rejects_a_field_the_sink_does_not_take() {
        assert!(parse("sink = \"sqlite\"\npath = \"/x\"\nurl = \"https://y\"").is_err());
    }

    #[test]
    fn github_sink_defaults_token_env_and_checks_the_slug() {
        let cfg = parse("sink = \"github\"\nrepo = \"lightningnetwork/lnd\"").unwrap();
        cfg.validate().unwrap();
        let ReportConfig::Github { token_env, .. } = cfg else {
            panic!("expected github");
        };
        assert_eq!(token_env, "GITHUB_PAT");

        for bad in ["not-a-slug", "/lnd", "o/r/x"] {
            let cfg = parse(&format!("sink = \"github\"\nrepo = {bad:?}")).unwrap();
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("owner/repo"), "{bad}: {err}");
        }
    }
}
