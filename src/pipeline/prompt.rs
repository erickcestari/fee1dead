//! Prompt fragments shared by several stages, appended to their templates.

use crate::config::Config;

/// For the code-reading reviewers and hunters: where the reference is and how
/// to use it. Empty without one.
pub(super) fn reference_note(cfg: &Config) -> String {
    match cfg.reference.active_dir() {
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

/// For recon: emit spec-compliance tasks. Empty without a reference, so recon
/// never invents spec tasks without a spec.
pub(super) fn reference_recon_directive(cfg: &Config) -> String {
    match cfg.reference.active_dir() {
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

/// The scale hunters rate on and reviewers correct against, in one place so
/// both judge severity alike.
pub(super) fn severity_scale() -> &'static str {
    include_str!("../../prompts/severity.md").trim_end()
}

/// Countermands the templates' skill instructions when skills are disabled.
pub(super) fn skills_directive(cfg: &Config) -> &'static str {
    if cfg.run.use_skills {
        ""
    } else {
        "\n\nSkills are disabled for this run. Do not invoke any skill; ignore \
         any earlier instruction to use one and rely on your own analysis. If \
         you emit hunt tasks, leave every `suggested_skills` empty."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> Config {
        toml::from_str(&format!(
            r#"
[run]
target_dir = "/t"
scratch_root = "/s"
out_dir = "/o"
{extra}
[provider]
default = "c"
[providers.c]
type = "claude-code"
[firewall]
allow = ["x"]
[report]
sink = "jsonl"
path = "/o/f.jsonl"
[stages]
enabled = ["recon"]
"#
        ))
        .unwrap()
    }

    #[test]
    fn without_a_reference_no_spec_text_is_added() {
        let cfg = config("");
        assert!(reference_note(&cfg).is_empty());
        assert!(reference_recon_directive(&cfg).is_empty());
    }

    #[test]
    fn a_reference_points_both_notes_at_its_dir() {
        let cfg = config("[reference]\nrepo = \"https://x/y.git\"\ndir = \"/work/spec\"");
        for text in [reference_note(&cfg), reference_recon_directive(&cfg)] {
            assert!(text.contains("/work/spec"));
            assert!(text.contains("spec-to-code-compliance"));
        }
    }

    #[test]
    fn skills_directive_only_when_disabled() {
        assert!(skills_directive(&config("")).is_empty());
        assert!(skills_directive(&config("use_skills = false")).contains("disabled"));
    }
}
