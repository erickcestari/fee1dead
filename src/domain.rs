//! The data contract between stages: what each stage reads from the previous
//! one's artifacts and writes for the next. Fields added after the first runs
//! default, so older artifacts still load.

use serde::{Deserialize, Serialize};

/// One unit of hunting work: an attack class pointed at a scope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub attack_class: String,
    /// Free-form scope. Recon derives it from `scope_paths`; gapfill and
    /// feedback tasks set only this. Keys queue dedupe across stages.
    pub scope_hint: String,
    /// Repo-relative path prefixes recon confined the task to.
    #[serde(default)]
    pub scope_paths: Vec<String>,
    /// A falsifiable one-line hypothesis, so the hunter tests a suspected
    /// defect instead of sweeping a whole class.
    #[serde(default)]
    pub hypothesis: String,
    /// `file:func` or `file:line` starting points.
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub suggested_skills: Vec<String>,
    /// Risk tags (e.g. "crypto", "funds"), so a run can be sliced by area.
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub priority: Priority,
    #[serde(default)]
    pub origin: TaskOrigin,
}

/// Set by recon. Hunters spawn in priority order, and a usage limit can cut
/// the tail, so the most critical tasks must go first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    High,
    #[default]
    Medium,
    Low,
}

impl Priority {
    /// Lower is scheduled first.
    pub fn hunt_rank(self) -> u8 {
        match self {
            Priority::High => 0,
            Priority::Medium => 1,
            Priority::Low => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TaskOrigin {
    #[default]
    Recon,
    Gapfill,
    Feedback,
}

impl TaskOrigin {
    /// The tiebreak within a [`Priority`]; lower is scheduled first. A task a
    /// hunter surfaced is narrower than recon's sweep, but never outranks a
    /// higher priority, since only recon's tasks passed its admission bar.
    pub fn hunt_rank(self) -> u8 {
        match self {
            TaskOrigin::Gapfill => 0,
            TaskOrigin::Feedback => 1,
            TaskOrigin::Recon => 2,
        }
    }
}

/// A candidate vulnerability emitted by a hunter, before validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub task_id: String,
    pub title: String,
    pub attack_class: String,
    pub severity: Severity,
    /// `path/to/file.rs:120`.
    pub location: String,
    pub description: String,
    /// How an attacker runs the exploit: the actors, the steps, and what the
    /// attack needs and risks. Empty when the hunter gave none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub attack_scenario: String,
    /// The hunter's confidence in [0,1]. A hard-to-reach bug gets a low score
    /// rather than being dropped, so review decides what to surface.
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    /// Relative to `out_dir`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poc_path: Option<String>,
}

pub(crate) fn default_confidence() -> f64 {
    0.5
}

impl Finding {
    /// The file of [`Finding::location`], line stripped.
    pub fn file(&self) -> &str {
        self.location
            .rsplit_once(':')
            .map_or(self.location.as_str(), |(file, _line)| file)
            .trim()
    }
}

/// A finding Dedupe collapsed into another with the same root cause. Kept so a
/// wrong merge can be spotted and undone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Duplicate {
    pub duplicate_of: String,
    pub finding: Finding,
}

/// Declared in ascending order, so the derived `Ord` ranks severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// The reviewer's tag on a finding. Review never deletes: an unproven bug is
/// `NeedsReview`, so it still reaches a human instead of vanishing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validation {
    pub finding_id: String,
    pub verdict: Verdict,
    pub evidence: String,
    /// Set only for `Downgraded`; replaces the hunter's severity in the report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corrected_severity: Option<Severity>,
    /// What an attacker gains; empty for `LikelyFalsePositive`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub impact: String,
    /// The fix; empty for `LikelyFalsePositive`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Confirmed,
    /// Real but overstated; reported at `corrected_severity`.
    Downgraded,
    /// Kept for review, never reported.
    LikelyFalsePositive,
    /// Inconclusive, or the reviewer skipped it; reported, marked unverified.
    NeedsReview,
}

impl Verdict {
    pub fn is_reportable(self) -> bool {
        !matches!(self, Verdict::LikelyFalsePositive)
    }

    /// Stricter than [`Verdict::is_reportable`]: an unsettled finding is
    /// surfaced, but is no basis for e.g. a variant hunt.
    pub fn is_real_bug(self) -> bool {
        matches!(self, Verdict::Confirmed | Verdict::Downgraded)
    }
}

/// An area a hunter touched but did not cover. Gapfill re-queues it, which
/// counters the model's drift toward classes it already had success with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapMarker {
    pub task_id: String,
    pub area: String,
    /// The class worth a follow-up pass; usually not the reporting hunter's.
    #[serde(default)]
    pub attack_class: String,
    pub reason: String,
}

impl GapMarker {
    pub fn follow_up_class(&self) -> &str {
        match self.attack_class.trim() {
            "" => "uncovered area",
            class => class,
        }
    }

    /// The follow-up task: the area as scope and first target, the reason as
    /// the hypothesis to test.
    pub fn to_task(&self, id: String, origin: TaskOrigin) -> Task {
        Task {
            id,
            attack_class: self.follow_up_class().to_string(),
            scope_hint: self.area.clone(),
            hypothesis: self.reason.clone(),
            targets: vec![self.area.clone()],
            origin,
            ..Task::default()
        }
    }
}

/// Something an agent needed but the sandbox lacks, recorded so the agent
/// carries on instead of stalling. The agents' channel back to the operator,
/// who grants wishes between runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wish {
    pub task_id: String,
    /// Set when a reviewer needed it to settle this finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    pub kind: WishKind,
    /// What was missing, concretely ("a FreeBSD VM", "proxy.golang.org").
    pub need: String,
    /// The check it would let the agent run.
    #[serde(default)]
    pub unblocks: String,
}

/// The lever that grants a wish. Declared in grant-cost order, so the derived
/// `Ord` lists the cheap ones first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WishKind {
    /// A host the egress firewall blocks: `[firewall].allow`.
    Network,
    /// Code the checkout lacks (a dependency, submodule, or spec):
    /// `[target].prepare` or `[reference]`.
    Source,
    /// A compiler, tool, or package missing from the image.
    Toolchain,
    /// Config files, fixtures, or credentials.
    Data,
    /// What the container cannot be: another OS, a VM, hardware, a live service.
    Environment,
    /// Also any kind an agent made up, so one odd label never voids its answer.
    #[default]
    #[serde(other)]
    Other,
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub fn task(id: &str) -> Task {
        Task {
            id: id.into(),
            attack_class: "c".into(),
            scope_hint: "s".into(),
            ..Task::default()
        }
    }

    pub fn finding(id: &str) -> Finding {
        Finding {
            id: id.into(),
            task_id: "T".into(),
            title: "t".into(),
            attack_class: "c".into(),
            severity: Severity::High,
            location: "a.rs:1".into(),
            description: "d".into(),
            attack_scenario: String::new(),
            confidence: default_confidence(),
            poc_path: None,
        }
    }

    pub fn validation(id: &str, verdict: Verdict) -> Validation {
        Validation {
            finding_id: id.into(),
            verdict,
            evidence: "e".into(),
            corrected_severity: None,
            impact: "attacker crashes the node".into(),
            recommendation: "bound the length".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_ascending() {
        let mut v = [
            Severity::High,
            Severity::Info,
            Severity::Critical,
            Severity::Medium,
            Severity::Low,
        ];
        v.sort();
        assert_eq!(
            v,
            [
                Severity::Info,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical
            ]
        );
    }

    #[test]
    fn enums_use_their_wire_spelling() {
        let wire = |v: serde_json::Value| v.as_str().unwrap().to_string();
        assert_eq!(wire(serde_json::json!(Severity::Critical)), "critical");
        assert_eq!(wire(serde_json::json!(Priority::High)), "high");
        assert_eq!(
            wire(serde_json::json!(Verdict::LikelyFalsePositive)),
            "likely_false_positive"
        );
        assert_eq!(
            wire(serde_json::json!(Verdict::NeedsReview)),
            "needs_review"
        );
        assert_eq!(
            wire(serde_json::json!(WishKind::Environment)),
            "environment"
        );
    }

    #[test]
    fn an_unknown_wish_kind_reads_as_other() {
        let kind = |s: &str| serde_json::from_str::<WishKind>(s).unwrap();
        assert_eq!(kind("\"network\""), WishKind::Network);
        assert_eq!(kind("\"a vm please\""), WishKind::Other);
    }

    #[test]
    fn only_likely_false_positives_are_held_back_from_the_report() {
        assert!(Verdict::Confirmed.is_reportable());
        assert!(Verdict::Downgraded.is_reportable());
        assert!(Verdict::NeedsReview.is_reportable());
        assert!(!Verdict::LikelyFalsePositive.is_reportable());
        assert!(!Verdict::NeedsReview.is_real_bug());
        assert!(Verdict::Downgraded.is_real_bug());
    }

    #[test]
    fn older_artifacts_load_with_defaults() {
        let t: Task =
            serde_json::from_str("{\"id\":\"T-1\",\"attack_class\":\"c\",\"scope_hint\":\"s\"}")
                .unwrap();
        assert_eq!(t.origin, TaskOrigin::Recon);
        assert_eq!(t.priority, Priority::Medium);
        assert!(t.tags.is_empty());
        let f: Finding = serde_json::from_str(
            "{\"id\":\"F-1\",\"task_id\":\"T\",\"title\":\"t\",\"attack_class\":\"c\",\"severity\":\"low\",\"location\":\"a.rs:1\",\"description\":\"d\"}",
        )
        .unwrap();
        assert_eq!(f.confidence, 0.5);
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("poc_path") && !json.contains("attack_scenario"));
    }

    #[test]
    fn rank_is_priority_first_and_hunter_surfaced_origins_break_ties() {
        assert!(Priority::High.hunt_rank() < Priority::Medium.hunt_rank());
        assert!(Priority::Medium.hunt_rank() < Priority::Low.hunt_rank());
        assert!(TaskOrigin::Gapfill.hunt_rank() < TaskOrigin::Feedback.hunt_rank());
        assert!(TaskOrigin::Feedback.hunt_rank() < TaskOrigin::Recon.hunt_rank());
    }

    #[test]
    fn finding_file_strips_the_line() {
        let mut f = fixtures::finding("F");
        f.location = "src/a.rs:12".into();
        assert_eq!(f.file(), "src/a.rs");
        f.location = "src/a.rs".into();
        assert_eq!(f.file(), "src/a.rs");
    }

    #[test]
    fn a_gap_becomes_a_task_with_its_reason_as_the_hypothesis() {
        let gap = GapMarker {
            task_id: "T-0001".into(),
            area: "src/a.rs:decode".into(),
            attack_class: String::new(),
            reason: "error path not traced".into(),
        };
        let t = gap.to_task("G-0002".into(), TaskOrigin::Gapfill);
        assert_eq!(t.attack_class, "uncovered area");
        assert_eq!(t.scope_hint, "src/a.rs:decode");
        assert_eq!(t.targets, vec!["src/a.rs:decode"]);
        assert_eq!(t.hypothesis, "error path not traced");
        assert_eq!(t.priority, Priority::Medium);
        assert_eq!(t.origin, TaskOrigin::Gapfill);
    }
}
