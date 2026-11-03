//! Prompt fragments shared by several stages, appended to their templates.

use super::skills::Skill;
use crate::config::Config;

/// For the code-reading reviewers and hunters: where the reference is and how
/// to use it. Empty without one.
pub(super) fn reference_note(cfg: &Config) -> String {
    match cfg.reference.active_dir() {
        Some(dir) => format!(
            "\n\nA reference spec / known-good implementation is checked out at `{}`. \
             Treat it as ground truth. For a `spec-compliance` task, locate the \
             governing clause in the reference and prove whether the code honors or \
             violates it.",
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
             `spec-compliance` hunt tasks: pick concrete MUST/SHALL/REQUIRED \
             clauses (or known-good behaviors) from the reference, find the code that \
             implements each, and write the `hypothesis` as the specific way the code \
             may deviate. For each, set `attack_class` to \"spec-compliance\", \
             suggest an installed skill that checks code against a spec if one is \
             listed, put BOTH the reference location and the implementing code in \
             `targets`, and prefer \
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

/// Countermands the templates' skill instructions when no skill is installed.
pub(super) const NO_SKILLS: &str = "\n\nNo skills are installed for this run. Do not \
     invoke any skill; ignore any earlier instruction to use one and rely on your own \
     analysis. If you emit hunt tasks, leave every `suggested_skills` empty.";

/// The installed skills an agent may pick from, or [`NO_SKILLS`].
pub(super) fn skills_note(skills: &[Skill]) -> String {
    if skills.is_empty() {
        return NO_SKILLS.to_string();
    }
    let lines: Vec<String> = skills
        .iter()
        .map(|s| format!("- `{}` (`{}`): {}", s.name, s.path.display(), s.description))
        .collect();
    format!(
        "\n\n## Installed skills\n\nThe only skills available. Invoke one by name, or \
         read its `SKILL.md`, when it fits; refer to them by these names.\n{}",
        lines.join("\n")
    )
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
            assert!(text.contains("spec-compliance"));
        }
    }

    #[test]
    fn skills_note_lists_installed_skills_or_forbids_any() {
        assert_eq!(skills_note(&[]), NO_SKILLS);
        let note = skills_note(&[Skill {
            name: "unsafe-audit".into(),
            description: "Audits unsafe code.".into(),
            path: "/skills/unsafe-audit/SKILL.md".into(),
        }]);
        assert!(
            note.contains(
                "- `unsafe-audit` (`/skills/unsafe-audit/SKILL.md`): Audits unsafe code."
            )
        );
        assert!(!note.contains("No skills"));
    }
}
