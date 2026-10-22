//! Per-run TOML configuration, validated once at load: the operator-input
//! trust boundary, so code below it can assume a well-formed config.

mod provider;
mod report;
mod stage;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

pub use provider::{ClaudeCodeConfig, ExecConfig, ExecOutput, OpenCodeConfig, ProviderConfig};
pub use report::ReportConfig;
pub use stage::{Stage, StagesConfig};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub run: RunConfig,
    #[serde(default)]
    pub target: TargetConfig,
    #[serde(default)]
    pub reference: ReferenceConfig,
    pub provider: ProviderSelection,
    /// Keyed by the name `provider.default` refers to.
    pub providers: BTreeMap<String, ProviderConfig>,
    pub firewall: FirewallConfig,
    pub report: ReportConfig,
    pub stages: StagesConfig,
    #[serde(default)]
    pub feedback: FeedbackConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunConfig {
    pub target_dir: PathBuf,
    pub scratch_root: PathBuf,
    pub out_dir: PathBuf,
    /// Max agents (hunters, or review batches) running at once.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_timeout_secs")]
    pub agent_timeout_secs: u64,
    /// Fork each hunter, and the critic, from recon's session so it inherits
    /// recon's context as a cached prefix instead of reading `recon.json`.
    #[serde(default = "enabled")]
    pub fork_hunters: bool,
    /// Have hunters write and run proof-of-concept code. Off by default: the
    /// PoC loop is the most token-hungry part of hunting.
    #[serde(default)]
    pub require_poc: bool,
    /// Delay between hunter launches, so forked hunters replaying recon's
    /// session do not hit the API as one rate-limited burst.
    #[serde(default = "default_hunter_stagger_ms")]
    pub hunter_stagger_ms: u64,
    /// Whether agents may use the vendored skills.
    #[serde(default = "enabled")]
    pub use_skills: bool,
}

impl RunConfig {
    pub fn agent_timeout(&self) -> Duration {
        Duration::from_secs(self.agent_timeout_secs)
    }
}

fn default_concurrency() -> usize {
    50
}

fn default_timeout_secs() -> u64 {
    1800
}

fn default_hunter_stagger_ms() -> u64 {
    750
}

fn enabled() -> bool {
    true
}

/// Where the target comes from and how its environment is readied. Without
/// `repo`, the target is expected mounted at `run.target_dir`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TargetConfig {
    /// Cloned into `run.target_dir`; the git host must be in `[firewall].allow`.
    pub repo: Option<String>,
    /// Branch, tag, or commit; defaults to the repo's default branch.
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
    /// A bash script the container runs as root before the firewall comes up,
    /// in the checked-out target, to install toolchains or build it. A failure
    /// stops the run, since agents would otherwise hunt a half-built target.
    pub setup: Option<String>,
    /// Shell commands run once in the target before any stage, e.g. to warm a
    /// package cache while the network is reachable. A failure only warns.
    pub prepare: Vec<String>,
}

/// A spec or known-good implementation cloned into `dir` and given to the
/// code-reading agents as ground truth. Disabled while `repo` is unset.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReferenceConfig {
    pub repo: Option<String>,
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
    pub dir: PathBuf,
}

impl Default for ReferenceConfig {
    fn default() -> Self {
        Self {
            repo: None,
            git_ref: None,
            dir: PathBuf::from("/work/reference"),
        }
    }
}

impl ReferenceConfig {
    /// The clone directory iff a reference repo is configured.
    pub fn active_dir(&self) -> Option<&Path> {
        self.repo.as_ref().map(|_| self.dir.as_path())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSelection {
    pub default: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    /// Hosts allowed for egress; read by `docker/init-firewall.sh`.
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FeedbackConfig {
    /// Cap on persisted seeds, so the cross-run memory stays bounded.
    pub max_seeds: usize,
    /// Cap on persisted ruled-out claims, likewise.
    pub max_ruled_out: usize,
}

impl Default for FeedbackConfig {
    fn default() -> Self {
        Self {
            max_seeds: 200,
            max_ruled_out: 300,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.run.concurrency >= 1, "run.concurrency must be >= 1");
        ensure!(
            self.providers.contains_key(&self.provider.default),
            "provider.default = \"{}\" is not defined under [providers]",
            self.provider.default
        );
        for (name, provider) in &self.providers {
            provider.validate(name)?;
        }
        ensure!(
            !self.firewall.allow.is_empty(),
            "firewall.allow must list at least one host (default-deny egress)"
        );
        ensure!(
            !self.stages.enabled.is_empty(),
            "stages.enabled must list at least one stage"
        );
        ensure!(
            self.feedback.max_seeds >= 1,
            "feedback.max_seeds must be >= 1"
        );
        ensure!(
            self.feedback.max_ruled_out >= 1,
            "feedback.max_ruled_out must be >= 1"
        );
        for (stage, model) in &self.stages.models {
            ensure!(
                stage.runs_agent(),
                "stages.models.{stage}: only stages that run an agent take a model ({})",
                agent_stage_names()
            );
            ensure!(!model.trim().is_empty(), "stages.models.{stage} is empty");
            if matches!(self.default_provider(), ProviderConfig::OpenCode(_)) {
                ensure!(
                    provider::is_provider_qualified_model(model),
                    "stages.models.{stage} = {model:?} is not an opencode model id; \
                     use the \"provider/model\" form"
                );
            }
        }
        self.report.validate()
    }

    pub fn default_provider(&self) -> &ProviderConfig {
        &self.providers[&self.provider.default]
    }

    /// The model a stage's agents run on; `None` means the provider's `model`.
    /// The skip-reported judge answers yes/no over two short texts, so on
    /// claude-code it defaults to Haiku.
    pub fn stage_model(&self, stage: Stage) -> Option<String> {
        debug_assert!(stage.runs_agent(), "{stage} runs no agent");
        if let Some(model) = self.stages.models.get(&stage) {
            return Some(model.clone());
        }
        match (stage, self.default_provider()) {
            (Stage::SkipReported, ProviderConfig::ClaudeCode(_)) => {
                Some("claude-haiku-4-5".to_string())
            }
            _ => None,
        }
    }
}

fn agent_stage_names() -> String {
    Stage::ALL
        .iter()
        .filter(|s| s.runs_agent())
        .map(|s| s.name())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const VALID: &str = r#"
[run]
target_dir = "/work/target"
scratch_root = "/work/scratch"
out_dir = "/work/out"
concurrency = 8

[provider]
default = "claude-code"

[providers.claude-code]
type = "claude-code"
model = "claude-opus-5"
extra_args = ["--dangerously-skip-permissions"]

[providers.opencode]
type = "opencode"
model = "anthropic/claude-opus-5"

[providers.codex]
type = "exec"
command = "codex"
args = ["exec", "--cd", "{working_dir}", "{prompt}"]
output = "json"

[firewall]
allow = ["api.anthropic.com"]

[report]
sink = "sqlite"
path = "/work/out/findings.db"

[stages]
enabled = ["recon", "hunt", "validate", "report"]
"#;

    fn load(toml: &str) -> Result<Config> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        Config::load(f.path())
    }

    /// The full error chain, so serde's cause under the load context shows.
    fn load_err(toml: &str) -> String {
        format!("{:#}", load(toml).unwrap_err())
    }

    #[test]
    fn parses_valid_config_and_applies_defaults() {
        let cfg = load(VALID).unwrap();
        assert_eq!(cfg.run.concurrency, 8);
        assert!(matches!(
            cfg.default_provider(),
            ProviderConfig::ClaudeCode(_)
        ));
        assert!(matches!(cfg.providers["codex"], ProviderConfig::Exec(_)));
        assert!(matches!(cfg.report, ReportConfig::Sqlite { .. }));
        assert_eq!(
            cfg.stages.enabled,
            [Stage::Recon, Stage::Hunt, Stage::Validate, Stage::Report]
        );
        assert_eq!(cfg.run.agent_timeout_secs, 1800);
        assert!(cfg.run.fork_hunters);
        assert!(!cfg.run.require_poc);
        assert!(cfg.run.use_skills);
        assert_eq!(cfg.run.hunter_stagger_ms, 750);
        assert_eq!(cfg.feedback.max_seeds, 200);
        assert_eq!(cfg.feedback.max_ruled_out, 300);
        assert!(cfg.target.prepare.is_empty());
        assert!(cfg.target.setup.is_none());
        assert!(cfg.reference.active_dir().is_none());
    }

    #[test]
    fn rejects_unknown_keys_instead_of_ignoring_them() {
        let bad = VALID.replace("concurrency = 8", "concurrency = 8\nmax_turns = 60");
        assert!(load_err(&bad).contains("max_turns"));
    }

    #[test]
    fn a_misconfigured_alternative_provider_fails_before_it_is_selected() {
        let bad = VALID.replace("\"anthropic/claude-opus-5\"", "\"kimi-k3\"");
        assert!(load_err(&bad).contains("providers.opencode.model"));
    }

    #[test]
    fn rejects_unknown_default_provider() {
        let bad = VALID.replace("default = \"claude-code\"", "default = \"ghost\"");
        assert!(load_err(&bad).contains("not defined"));
    }

    #[test]
    fn rejects_empty_firewall_allowlist() {
        let bad = VALID.replace("allow = [\"api.anthropic.com\"]", "allow = []");
        assert!(load_err(&bad).contains("default-deny"));
    }

    #[test]
    fn rejects_zero_concurrency() {
        let bad = VALID.replace("concurrency = 8", "concurrency = 0");
        assert!(load_err(&bad).contains("concurrency"));
    }

    #[test]
    fn rejects_unknown_and_empty_stage_lists() {
        let bad = VALID.replace("\"report\"]", "\"report\", \"teleport\"]");
        assert!(load_err(&bad).contains("teleport"));
        let bad = VALID.replace(
            "enabled = [\"recon\", \"hunt\", \"validate\", \"report\"]",
            "enabled = []",
        );
        assert!(load_err(&bad).contains("at least one stage"));
    }

    #[test]
    fn report_sink_fields_are_checked_at_load() {
        let bad = VALID.replace(
            "sink = \"sqlite\"\npath = \"/work/out/findings.db\"",
            "sink = \"github\"\nrepo = \"not-a-slug\"",
        );
        assert!(load_err(&bad).contains("owner/repo"));
    }

    #[test]
    fn reference_parses_with_a_default_dir() {
        let cfg = load(&format!(
            "{VALID}\n[reference]\nrepo = \"https://github.com/lightning/bolts.git\"\nref = \"master\"\n"
        ))
        .unwrap();
        assert_eq!(cfg.reference.git_ref.as_deref(), Some("master"));
        assert_eq!(
            cfg.reference.active_dir(),
            Some(Path::new("/work/reference"))
        );
        let cfg = load(&format!(
            "{VALID}\n[reference]\nrepo = \"https://x/y.git\"\ndir = \"/work/spec\"\n"
        ))
        .unwrap();
        assert_eq!(cfg.reference.active_dir(), Some(Path::new("/work/spec")));
    }

    #[test]
    fn target_prepare_and_setup_parse() {
        let cfg = load(&format!(
            "{VALID}\n[target]\nprepare = [\"go mod download\"]\nsetup = '''\napt-get install -y jq\ngo build ./...\n'''\n"
        ))
        .unwrap();
        assert_eq!(cfg.target.prepare, vec!["go mod download"]);
        assert_eq!(
            cfg.target.setup.as_deref(),
            Some("apt-get install -y jq\ngo build ./...\n")
        );
    }

    #[test]
    fn stage_models_override_the_provider_model_per_stage() {
        let cfg = load(VALID).unwrap();
        assert_eq!(cfg.stage_model(Stage::Hunt), None);
        assert_eq!(
            cfg.stage_model(Stage::SkipReported).as_deref(),
            Some("claude-haiku-4-5")
        );

        let cfg = load(&format!(
            "{VALID}\n[stages.models]\nvalidate = \"claude-sonnet-5\"\nskip-reported = \"x\"\n"
        ))
        .unwrap();
        assert_eq!(
            cfg.stage_model(Stage::Validate).as_deref(),
            Some("claude-sonnet-5")
        );
        assert_eq!(cfg.stage_model(Stage::SkipReported).as_deref(), Some("x"));
    }

    #[test]
    fn stage_models_are_checked_at_load() {
        let bad = format!("{VALID}\n[stages.models]\nreport = \"claude-opus-5\"\n");
        assert!(load_err(&bad).contains("stages.models.report"));

        let opencode = VALID.replace("default = \"claude-code\"", "default = \"opencode\"");
        let bad = format!("{opencode}\n[stages.models]\nhunt = \"kimi-k3\"\n");
        assert!(load_err(&bad).contains("provider/model"));
        // opencode keeps its own model for the judge.
        let cfg = load(&opencode).unwrap();
        assert_eq!(cfg.stage_model(Stage::SkipReported), None);
    }
}
