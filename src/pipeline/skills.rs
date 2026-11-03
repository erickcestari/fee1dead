//! The skills the operator brings in `run.skills_dir`, one `<name>/SKILL.md`
//! each. Agents hear only of skills found there, so none is assumed to exist.

use std::fs;
use std::path::{Path, PathBuf};

/// Enough for recon to match a skill to a task without the menu costing more
/// than the skills save.
const DESCRIPTION_CHARS: usize = 300;

#[derive(Debug, Clone, PartialEq)]
pub(super) struct Skill {
    pub name: String,
    pub description: String,
    /// The `SKILL.md`, so an agent whose CLI does not load skills can read it.
    pub path: PathBuf,
}

/// Every skill under `dir`, by name; none when `dir` is unset or unreadable.
pub(super) fn installed(dir: Option<&Path>) -> Vec<Skill> {
    let Some(entries) = dir.and_then(|d| fs::read_dir(d).ok()) else {
        return Vec::new();
    };
    let mut skills: Vec<Skill> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path().join("SKILL.md");
            let text = fs::read_to_string(&path).ok()?;
            let dir_name = entry.file_name().to_string_lossy().into_owned();
            let name = frontmatter(&text, "name").unwrap_or(dir_name);
            let description = truncate(&frontmatter(&text, "description").unwrap_or_default());
            Some(Skill {
                name,
                description,
                path,
            })
        })
        .collect();
    skills.sort_by(|a, b| a.name.cmp(&b.name));
    skills
}

/// A scalar from the leading `---` block, including a `>`/`|` block scalar
/// folded onto one line. Not a YAML parser: SKILL.md frontmatter is this flat.
fn frontmatter(text: &str, key: &str) -> Option<String> {
    let mut lines = text.lines();
    if lines.next()?.trim() != "---" {
        return None;
    }
    let block: Vec<&str> = lines.take_while(|l| l.trim() != "---").collect();
    let prefix = format!("{key}:");
    let at = block.iter().position(|l| l.starts_with(&prefix))?;
    let value = block[at][prefix.len()..].trim();
    let value = if value.starts_with(['>', '|']) {
        block[at + 1..]
            .iter()
            .take_while(|l| l.starts_with([' ', '\t']) || l.trim().is_empty())
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        value.trim_matches(['"', '\'']).to_string()
    };
    (!value.is_empty()).then_some(value)
}

fn truncate(text: &str) -> String {
    match text.char_indices().nth(DESCRIPTION_CHARS) {
        Some((at, _)) => format!("{}...", text[..at].trim_end()),
        None => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_skill(root: &Path, dir: &str, skill_md: &str) {
        fs::create_dir_all(root.join(dir)).unwrap();
        fs::write(root.join(dir).join("SKILL.md"), skill_md).unwrap();
    }

    #[test]
    fn finds_skills_sorted_with_their_frontmatter() {
        let tmp = tempfile::tempdir().unwrap();
        write_skill(
            tmp.path(),
            "b",
            "---\nname: unsafe-audit\ndescription: \"Audits unsafe code.\"\n---\nbody",
        );
        write_skill(
            tmp.path(),
            "a",
            "---\nname: poc-review\ndescription: >\n  Checks a finding\n  end to end.\nallowed-tools: Read\n---\n",
        );
        fs::create_dir(tmp.path().join("not-a-skill")).unwrap();

        let skills = installed(Some(tmp.path()));
        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["poc-review", "unsafe-audit"]);
        assert_eq!(skills[0].description, "Checks a finding end to end.");
        assert_eq!(skills[1].description, "Audits unsafe code.");
        assert_eq!(skills[1].path, tmp.path().join("b/SKILL.md"));
    }

    #[test]
    fn a_skill_without_frontmatter_is_named_after_its_dir() {
        let tmp = tempfile::tempdir().unwrap();
        write_skill(tmp.path(), "manual-audit", "# Manual audit\n");
        let skills = installed(Some(tmp.path()));
        assert_eq!(skills[0].name, "manual-audit");
        assert_eq!(skills[0].description, "");
    }

    #[test]
    fn no_dir_or_a_missing_one_means_no_skills() {
        assert!(installed(None).is_empty());
        assert!(installed(Some(Path::new("/nonexistent/skills"))).is_empty());
    }

    #[test]
    fn long_descriptions_are_cut_on_a_char_boundary() {
        let long = "é".repeat(DESCRIPTION_CHARS + 10);
        let cut = truncate(&long);
        assert_eq!(cut.chars().count(), DESCRIPTION_CHARS + 3);
        assert!(cut.ends_with("..."));
        assert_eq!(truncate("short"), "short");
    }
}
