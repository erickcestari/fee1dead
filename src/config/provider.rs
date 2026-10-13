use anyhow::{Result, ensure};
use serde::Deserialize;

/// A `[providers.<name>]` block; `type` selects the adapter.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ProviderConfig {
    ClaudeCode(ClaudeCodeConfig),
    #[serde(rename = "opencode")]
    OpenCode(OpenCodeConfig),
    /// Any other CLI, described by a command template.
    Exec(ExecConfig),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClaudeCodeConfig {
    pub model: Option<String>,
    pub extra_args: Vec<String>,
    /// Stop starting agents once the account's weekly usage reaches this
    /// percentage. Read from the CLI's `rate_limit_event`.
    pub max_weekly_usage_pct: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpenCodeConfig {
    /// opencode's `provider/model` id, e.g. `anthropic/claude-opus-5`.
    pub model: Option<String>,
    /// A configured opencode agent (`--agent`).
    pub agent: Option<String>,
    /// Provider-specific reasoning effort (`--variant`).
    pub variant: Option<String>,
    /// Auto-approve permissions (`--auto`); without it the agent cannot write
    /// its answer file.
    pub auto: bool,
    pub extra_args: Vec<String>,
}

impl Default for OpenCodeConfig {
    fn default() -> Self {
        Self {
            model: None,
            agent: None,
            variant: None,
            auto: true,
            extra_args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecConfig {
    pub command: String,
    /// Argv template; `{prompt}` and `{working_dir}` are substituted per run.
    pub args: Vec<String>,
    #[serde(default)]
    pub output: ExecOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExecOutput {
    #[default]
    Text,
    Json,
}

impl ProviderConfig {
    pub(super) fn validate(&self, name: &str) -> Result<()> {
        match self {
            ProviderConfig::ClaudeCode(c) => {
                if let Some(pct) = c.max_weekly_usage_pct {
                    ensure!(
                        (1..=100).contains(&pct),
                        "providers.{name}.max_weekly_usage_pct = {pct} must be between 1 and 100"
                    );
                }
            }
            // opencode rejects a bare model id deep in its server with an
            // opaque "Unexpected server error", so catch it here.
            ProviderConfig::OpenCode(c) => {
                if let Some(model) = &c.model {
                    ensure!(
                        is_provider_qualified_model(model),
                        "providers.{name}.model = {model:?} is not an opencode model id; \
                         use the \"provider/model\" form (e.g. \"anthropic/claude-opus-5\", \
                         \"moonshotai/kimi-k3\"). Run `opencode models` to list them."
                    );
                }
            }
            ProviderConfig::Exec(_) => {}
        }
        Ok(())
    }
}

/// Is this an opencode `provider/model` id? The model half may itself contain
/// slashes (e.g. `fireworks-ai/accounts/…`).
pub(super) fn is_provider_qualified_model(model: &str) -> bool {
    matches!(model.split_once('/'), Some((provider, rest))
        if !provider.is_empty() && !rest.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> ProviderConfig {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn opencode_auto_defaults_on_and_is_overridable() {
        let ProviderConfig::OpenCode(c) = parse("type = \"opencode\"\nmodel = \"a/b\"") else {
            panic!("expected opencode");
        };
        assert!(c.auto);
        assert_eq!(c.agent, None);

        let ProviderConfig::OpenCode(c) =
            parse("type = \"opencode\"\nauto = false\nvariant = \"high\"")
        else {
            panic!("expected opencode");
        };
        assert!(!c.auto);
        assert_eq!(c.variant.as_deref(), Some("high"));
    }

    #[test]
    fn rejects_unknown_keys_inside_a_provider_block() {
        assert!(toml::from_str::<ProviderConfig>("type = \"opencode\"\nmodle = \"x\"").is_err());
        assert!(toml::from_str::<ProviderConfig>("type = \"claude-code\"\nmax_turns = 9").is_err());
    }

    #[test]
    fn opencode_model_needs_a_provider_prefix() {
        let err = parse("type = \"opencode\"\nmodel = \"kimi-k3\"")
            .validate("oc")
            .unwrap_err()
            .to_string();
        assert!(err.contains("providers.oc.model"), "got: {err}");
        assert!(err.contains("provider/model"), "got: {err}");
        let nested = parse("type = \"opencode\"\nmodel = \"fireworks-ai/accounts/f/models/k\"");
        assert!(nested.validate("oc").is_ok());
    }

    #[test]
    fn weekly_usage_cap_is_range_checked() {
        let with_cap = |pct: u32| {
            parse(&format!(
                "type = \"claude-code\"\nmax_weekly_usage_pct = {pct}"
            ))
            .validate("c")
        };
        assert!(with_cap(1).is_ok());
        assert!(with_cap(100).is_ok());
        assert!(with_cap(0).is_err());
        assert!(
            toml::from_str::<ProviderConfig>("type = \"claude-code\"\nmax_weekly_usage_pct = 300")
                .is_err()
        );
        assert!(with_cap(101).is_err());
    }
}
