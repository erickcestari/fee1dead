//! Per-run configuration, loaded from a TOML file.
//!
//! Validation happens once at load (`Config::load`) so the rest of the harness
//! can assume the config is well-formed. This is the trust boundary for
//! operator input: fail fast and loud here rather than deep in a stage.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub run: RunConfig,
    /// Optional: clone the target into `run.target_dir` at startup instead of
    /// expecting it to be mounted there.
    #[serde(default)]
    pub target: TargetConfig,
    pub provider: ProviderSelection,
    /// Named provider definitions, keyed by the name referenced in `provider.default`.
    pub providers: BTreeMap<String, ProviderConfig>,
    pub firewall: FirewallConfig,
    pub report: ReportConfig,
    pub stages: StagesConfig,
    #[serde(default)]
    pub feedback: FeedbackConfig,
}

/// Controls the cross-run feedback memory. The Feedback stage distils each
/// run's confirmed findings and unresolved gaps into durable seed tasks
/// (`feedback-seeds.jsonl` in `out_dir`); the next run's Recon merges them into
/// the hunt queue, so each run starts a little smarter.
#[derive(Debug, Clone, Deserialize)]
pub struct FeedbackConfig {
    /// Cap on persisted seeds, so the memory cannot grow without bound.
    #[serde(default = "default_max_seeds")]
    pub max_seeds: usize,
}

fn default_max_seeds() -> usize {
    200
}

impl Default for FeedbackConfig {
    fn default() -> Self {
        Self {
            max_seeds: default_max_seeds(),
        }
    }
}

/// Optional source for the target repository. When `repo` is set, the harness
/// clones it into `run.target_dir` before recon (the git host must be in
/// `[firewall].allow`). When unset, `run.target_dir` is expected to already
/// contain the code (e.g. mounted into the container).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TargetConfig {
    /// Git URL to clone (https recommended so the firewall can scope it).
    #[serde(default)]
    pub repo: Option<String>,
    /// Branch, tag, or commit SHA to check out. Defaults to the repo's default branch.
    #[serde(default, rename = "ref")]
    pub git_ref: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RunConfig {
    pub target_dir: PathBuf,
    pub scratch_root: PathBuf,
    pub out_dir: PathBuf,
    /// Max hunters running concurrently.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// Per-agent wall-clock timeout in seconds.
    #[serde(default = "default_timeout_secs")]
    pub agent_timeout_secs: u64,
    /// Fork each hunter from the recon agent's session so it inherits recon's
    /// codebase context instead of re-reading the architecture doc. Only the
    /// claude-code provider supports this; others ignore it. Forks run in
    /// recon's directory, so recon's history is a shared, cached prefix across
    /// hunters (cache-read rates) when they start within the cache window.
    #[serde(default = "default_fork_hunters")]
    pub fork_hunters: bool,
    /// Whether hunters write, compile, and run proof-of-concept code to confirm
    /// findings. The PoC loop is the most token-hungry part of hunting, so it is
    /// off by default: hunters substantiate by close reading instead, trading
    /// confirmation strength for far lower token cost. Enable it to have hunters
    /// produce runnable PoCs at higher cost.
    #[serde(default = "default_require_poc")]
    pub require_poc: bool,
}

fn default_concurrency() -> usize {
    50
}

fn default_fork_hunters() -> bool {
    true
}

fn default_require_poc() -> bool {
    false
}

fn default_timeout_secs() -> u64 {
    1800
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderSelection {
    pub default: String,
}

/// A provider definition. `type` selects the adapter; remaining fields are
/// adapter-specific. The `exec` type is the zero-code path for adding any CLI.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ProviderConfig {
    ClaudeCode {
        #[serde(default)]
        model: Option<String>,
        #[serde(default)]
        extra_args: Vec<String>,
    },
    /// Config-driven command template. `args` may contain the placeholders
    /// `{prompt}` and `{working_dir}`, substituted at run time.
    Exec {
        command: String,
        args: Vec<String>,
        #[serde(default)]
        output: ExecOutput,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExecOutput {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirewallConfig {
    /// Hostnames allowed for egress. Consumed by docker/init-firewall.sh.
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReportConfig {
    pub sink: SinkKind,
    /// Path for file-backed sinks (sqlite db / jsonl file).
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Ingest endpoint for the http sink (one POST per finding).
    #[serde(default)]
    pub url: Option<String>,
    /// Env var holding a bearer token for the http sink, if auth is required.
    #[serde(default)]
    pub token_env: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SinkKind {
    Sqlite,
    Jsonl,
    Http,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StagesConfig {
    /// Ordered list of stages to run, e.g. ["recon", "hunt", "validate", "report"].
    pub enabled: Vec<String>,
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

    /// Boundary validation: catch operator mistakes before any stage runs.
    fn validate(&self) -> Result<()> {
        if self.run.concurrency == 0 {
            bail!("run.concurrency must be >= 1");
        }
        if !self.providers.contains_key(&self.provider.default) {
            bail!(
                "provider.default = \"{}\" is not defined under [providers]",
                self.provider.default
            );
        }
        if self.firewall.allow.is_empty() {
            bail!("firewall.allow must list at least one host (default-deny egress)");
        }
        if self.stages.enabled.is_empty() {
            bail!("stages.enabled must list at least one stage");
        }
        if self.feedback.max_seeds == 0 {
            bail!("feedback.max_seeds must be >= 1");
        }
        for stage in &self.stages.enabled {
            if !KNOWN_STAGES.contains(&stage.as_str()) {
                bail!(
                    "unknown stage \"{}\"; known stages: {}",
                    stage,
                    KNOWN_STAGES.join(", ")
                );
            }
        }
        // The report sink needs the field appropriate to its kind.
        match self.report.sink {
            SinkKind::Sqlite | SinkKind::Jsonl => {
                if self.report.path.is_none() {
                    bail!(
                        "report.path is required for the {:?} sink",
                        self.report.sink
                    );
                }
            }
            SinkKind::Http => {
                if self.report.url.is_none() {
                    bail!("report.url is required for the http sink");
                }
            }
        }
        Ok(())
    }

    /// The provider definition selected by `provider.default`.
    pub fn default_provider(&self) -> &ProviderConfig {
        // Safe: validated at load.
        &self.providers[&self.provider.default]
    }
}

pub const KNOWN_STAGES: &[&str] = &[
    "recon", "hunt", "validate", "gapfill", "dedupe", "feedback", "report",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

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
model = "claude-opus-4-8"
extra_args = ["--dangerously-skip-permissions"]

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

    #[test]
    fn parses_valid_config() {
        let f = write_tmp(VALID);
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.run.concurrency, 8);
        assert_eq!(cfg.provider.default, "claude-code");
        assert!(matches!(
            cfg.default_provider(),
            ProviderConfig::ClaudeCode { .. }
        ));
        assert!(matches!(
            cfg.providers["codex"],
            ProviderConfig::Exec { .. }
        ));
    }

    #[test]
    fn rejects_unknown_default_provider() {
        let bad = VALID.replace("default = \"claude-code\"", "default = \"ghost\"");
        let f = write_tmp(&bad);
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("not defined"), "got: {err}");
    }

    #[test]
    fn rejects_empty_firewall_allowlist() {
        let bad = VALID.replace("allow = [\"api.anthropic.com\"]", "allow = []");
        let f = write_tmp(&bad);
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("default-deny"), "got: {err}");
    }

    #[test]
    fn http_sink_requires_url() {
        let bad = VALID.replace(
            "sink = \"sqlite\"\npath = \"/work/out/findings.db\"",
            "sink = \"http\"",
        );
        let f = write_tmp(&bad);
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("report.url is required"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_stage() {
        let bad = VALID.replace("\"report\"]", "\"report\", \"teleport\"]");
        let f = write_tmp(&bad);
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("unknown stage"), "got: {err}");
    }

    #[test]
    fn rejects_zero_concurrency() {
        let bad = VALID.replace("concurrency = 8", "concurrency = 0");
        let f = write_tmp(&bad);
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("concurrency"), "got: {err}");
    }

    #[test]
    fn rejects_empty_stage_list() {
        let bad = VALID.replace(
            "enabled = [\"recon\", \"hunt\", \"validate\", \"report\"]",
            "enabled = []",
        );
        let f = write_tmp(&bad);
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("at least one stage"), "got: {err}");
    }

    #[test]
    fn jsonl_sink_requires_path() {
        let bad = VALID.replace(
            "sink = \"sqlite\"\npath = \"/work/out/findings.db\"",
            "sink = \"jsonl\"",
        );
        let f = write_tmp(&bad);
        let err = Config::load(f.path()).unwrap_err().to_string();
        assert!(err.contains("report.path is required"), "got: {err}");
    }

    #[test]
    fn applies_documented_defaults() {
        // concurrency is set in VALID; the rest fall back to their defaults.
        let f = write_tmp(VALID);
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.run.agent_timeout_secs, 1800);
        assert!(cfg.run.fork_hunters);
        assert!(!cfg.run.require_poc);
        assert_eq!(cfg.feedback.max_seeds, 200);
    }
}
