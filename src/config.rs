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
    /// Optional reference repository (a spec or known-good implementation)
    /// cloned at startup and exposed to the agents as ground truth.
    #[serde(default)]
    pub reference: ReferenceConfig,
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

/// Optional reference repository: a specification or known-good implementation
/// cloned at startup (into `dir`) and added to every hunting agent's readable
/// dirs, so findings can be checked against ground truth (e.g. the BOLT specs
/// for a Lightning implementation, for spec-to-code compliance). Disabled when
/// `repo` is unset. Like the target clone, the git host must be in
/// `[firewall].allow`.
#[derive(Debug, Clone, Deserialize)]
pub struct ReferenceConfig {
    /// Git URL to clone. Unset disables the reference.
    #[serde(default)]
    pub repo: Option<String>,
    /// Branch, tag, or commit SHA to check out. Defaults to the repo's default branch.
    #[serde(default, rename = "ref")]
    pub git_ref: Option<String>,
    /// Where to clone it (a container path the agents can read).
    #[serde(default = "default_reference_dir")]
    pub dir: PathBuf,
}

fn default_reference_dir() -> PathBuf {
    PathBuf::from("/work/reference")
}

impl Default for ReferenceConfig {
    fn default() -> Self {
        Self {
            repo: None,
            git_ref: None,
            dir: default_reference_dir(),
        }
    }
}

impl ReferenceConfig {
    /// The clone directory iff a reference repo is configured.
    pub fn active_dir(&self) -> Option<&Path> {
        self.repo.as_ref().map(|_| self.dir.as_path())
    }

    /// A sentence appended to hunt/validate prompts: where the reference is and
    /// how to use it. Empty when no reference is configured.
    pub fn prompt_note(&self) -> String {
        match self.active_dir() {
            Some(dir) => format!(
                "\n\nA reference spec / known-good implementation is checked out at `{}`. \
                 Treat it as ground truth. For a `spec-to-code-compliance` task, use the \
                 spec-to-code-compliance skill: locate the governing clause in the reference \
                 and prove whether the code honors or violates it.",
                dir.display()
            ),
            None => String::new(),
        }
    }

    /// A directive appended to the recon prompt so it generates
    /// `spec-to-code-compliance` hunt tasks against the reference. Empty when no
    /// reference is configured, so recon never invents spec tasks without a spec.
    pub fn recon_directive(&self) -> String {
        match self.active_dir() {
            Some(dir) => format!(
                "\n\n## Reference spec / known-good implementation\n\n\
                 A reference is checked out at `{}`. Beyond the tasks above, emit \
                 `spec-to-code-compliance` hunt tasks: pick concrete MUST/SHALL/REQUIRED \
                 clauses (or known-good behaviors) from the reference, find the code that \
                 implements each, and write the `hypothesis` as the specific way the code \
                 may deviate. For each, set `attack_class` to \"spec-to-code-compliance\", \
                 set `suggested_skills` to [\"spec-to-code-compliance\"], put BOTH the \
                 reference location and the implementing code in `targets`, and prefer \
                 clauses whose violation has security impact. Cover the security-critical \
                 clauses; skip trivial ones.",
                dir.display()
            ),
            None => String::new(),
        }
    }
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
    ///
    /// The amortized win shrinks now that recon orients shallow (`recon_max_turns`,
    /// structure-first prompt): the shared prefix is mostly the threat model plus
    /// orient output, not deep file reads a hunter would otherwise repeat. Forking
    /// still spares every hunter from re-orienting, but with good per-task `targets`
    /// a cold hunter reads only what it needs — so which regime is cheaper per
    /// confirmed finding is now an empirical call. Compare both on a target before
    /// trusting either default; each agent's stream-log `result` event records its
    /// cost/usage, so a run profiles from the logs dir.
    #[serde(default = "default_fork_hunters")]
    pub fork_hunters: bool,
    /// Whether hunters write, compile, and run proof-of-concept code to confirm
    /// findings. The PoC loop is the most token-hungry part of hunting, so it is
    /// off by default: hunters substantiate by close reading instead, trading
    /// confirmation strength for far lower token cost. Enable it to have hunters
    /// produce runnable PoCs at higher cost.
    #[serde(default = "default_require_poc")]
    pub require_poc: bool,
    /// Cap on a hunter's agent turns. Cost scales with turns (each turn re-reads
    /// the whole cached context), and a long tail of runaway hunters dominates
    /// spend, so this bounds the worst case. Set very high to effectively
    /// disable. Only the claude-code provider enforces it.
    #[serde(default = "default_hunter_max_turns")]
    pub hunter_max_turns: u32,
    /// Cap on recon's agent turns. Recon's job is to orient (structure-first)
    /// and emit the threat model, not to read the whole repo: every turn re-reads
    /// recon's growing context, and a bloated recon session is then replayed into
    /// every forked hunter, so an unbounded recon dominates a run's cost. Keeping
    /// recon compact also keeps its context under the long-context pricing tier.
    /// Only the claude-code provider enforces it.
    #[serde(default = "default_recon_max_turns")]
    pub recon_max_turns: u32,
    /// Delay between launching consecutive hunters, in milliseconds. Forked
    /// hunters each replay recon's (often large) session as their first request;
    /// releasing the whole concurrency batch at once fires that burst
    /// simultaneously and the API rejects it with server-side rate limiting.
    /// Staggering spreads the first requests out. 0 disables the delay.
    #[serde(default = "default_hunter_stagger_ms")]
    pub hunter_stagger_ms: u64,
    /// Whether agents may use the vendored Trail of Bits skills at all. On by
    /// default. When false, every stage prompt is told to ignore the skills and
    /// rely on its own analysis, and recon emits no `suggested_skills` — useful
    /// to isolate the skills' effect on token cost and bug yield, or to run
    /// against a target the skills don't fit.
    #[serde(default = "default_use_skills")]
    pub use_skills: bool,
}

impl RunConfig {
    /// A directive appended to every stage prompt when skills are disabled,
    /// countermanding the in-prompt instructions to use specific skills. Empty
    /// when skills are enabled.
    pub fn skills_directive(&self) -> String {
        if self.use_skills {
            String::new()
        } else {
            "\n\nSkills are disabled for this run. Do not invoke any skill; ignore \
             any earlier instruction to use one and rely on your own analysis. If \
             you emit hunt tasks, leave every `suggested_skills` empty."
                .to_string()
        }
    }
}

fn default_concurrency() -> usize {
    50
}

fn default_hunter_max_turns() -> u32 {
    60
}

fn default_recon_max_turns() -> u32 {
    60
}

fn default_hunter_stagger_ms() -> u64 {
    750
}

fn default_fork_hunters() -> bool {
    true
}

fn default_require_poc() -> bool {
    false
}

fn default_use_skills() -> bool {
    true
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
        if self.run.hunter_max_turns == 0 {
            bail!("run.hunter_max_turns must be >= 1");
        }
        if self.run.recon_max_turns == 0 {
            bail!("run.recon_max_turns must be >= 1");
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
    "recon", "hunt", "validate", "gapfill", "dedupe", "feedback", "aggregate", "report",
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
    fn reference_absent_means_disabled() {
        let cfg = Config::load(write_tmp(VALID).path()).unwrap();
        assert!(cfg.reference.repo.is_none());
        assert!(cfg.reference.active_dir().is_none());
        assert!(cfg.reference.prompt_note().is_empty());
        // Without a reference, recon must not be told to emit spec tasks.
        assert!(cfg.reference.recon_directive().is_empty());
    }

    #[test]
    fn reference_drives_spec_compliance_directive() {
        let with_ref =
            format!("{VALID}\n[reference]\nrepo = \"https://x/y.git\"\ndir = \"/work/spec\"\n");
        let cfg = Config::load(write_tmp(&with_ref).path()).unwrap();
        let directive = cfg.reference.recon_directive();
        assert!(directive.contains("spec-to-code-compliance"));
        assert!(directive.contains("/work/spec"));
        // Hunt/validate get the skill-usage note pointing at the same dir.
        assert!(cfg.reference.prompt_note().contains("/work/spec"));
        assert!(
            cfg.reference
                .prompt_note()
                .contains("spec-to-code-compliance")
        );
    }

    #[test]
    fn reference_parsed_with_default_dir_and_note() {
        let with_ref = format!(
            "{VALID}\n[reference]\nrepo = \"https://github.com/lightning/bolts.git\"\nref = \"master\"\n"
        );
        let cfg = Config::load(write_tmp(&with_ref).path()).unwrap();
        assert_eq!(
            cfg.reference.repo.as_deref(),
            Some("https://github.com/lightning/bolts.git")
        );
        assert_eq!(cfg.reference.git_ref.as_deref(), Some("master"));
        // dir defaults when omitted; active_dir/prompt_note reflect it.
        assert_eq!(
            cfg.reference.active_dir().unwrap(),
            Path::new("/work/reference")
        );
        assert!(cfg.reference.prompt_note().contains("/work/reference"));
    }

    #[test]
    fn reference_dir_is_overridable() {
        let with_ref =
            format!("{VALID}\n[reference]\nrepo = \"https://x/y.git\"\ndir = \"/work/spec\"\n");
        let cfg = Config::load(write_tmp(&with_ref).path()).unwrap();
        assert_eq!(cfg.reference.active_dir().unwrap(), Path::new("/work/spec"));
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
        assert_eq!(cfg.run.hunter_max_turns, 60);
        assert_eq!(cfg.run.recon_max_turns, 30);
        assert_eq!(cfg.run.hunter_stagger_ms, 750);
        assert_eq!(cfg.feedback.max_seeds, 200);
    }
}
