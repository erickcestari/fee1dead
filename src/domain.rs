//! Core domain types shared across every pipeline stage.
//!
//! These types are the contract between stages: a stage reads the artifacts
//! produced by the previous one and writes its own. Keeping them in one place
//! makes the inter-stage data flow auditable without reading the stages.

use serde::{Deserialize, Serialize};

/// A single unit of hunting work: one attack class pointed at one scope hint.
///
/// The Recon stage seeds the queue with these; Hunt consumes them. Gapfill and
/// Feedback (later phases) append more.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    /// The attack class the hunter should focus on (e.g. "integer overflow").
    pub attack_class: String,
    /// Where to look: a file, module, function, or subsystem description.
    /// Recon-origin tasks derive this from `scope_paths` (joined); gapfill and
    /// feedback tasks set it directly. Used for queue dedupe across stages.
    pub scope_hint: String,
    /// Repo-relative path prefixes recon confined this task to (the structured
    /// successor to `scope_hint`). Recon populates it; gapfill/feedback tasks
    /// leave it empty and rely on `scope_hint`. Shown to the hunter as its
    /// confinement boundary. Empty for older artifacts.
    #[serde(default)]
    pub scope_paths: Vec<String>,
    /// A falsifiable, one-line hypothesis the hunter should test (e.g. "length
    /// is added without bounds check before the alloc"). Steers the hunter at a
    /// specific suspected defect instead of a whole class. Empty when unset.
    #[serde(default)]
    pub hypothesis: String,
    /// Concrete starting points — `file:func` or `file:line` entries the hunter
    /// should read first, so it spends tokens hunting rather than orienting.
    #[serde(default)]
    pub targets: Vec<String>,
    /// Trail of Bits skills the hunter should apply to this task (e.g.
    /// "constant-time-analysis", "spec-to-code-compliance"). Named in the hunter
    /// prompt so it invokes the matching skill; empty means "use judgment".
    #[serde(default)]
    pub suggested_skills: Vec<String>,
    /// Risk tags recon assigns (e.g. "crypto", "funds", "p2p", "auth"). Carried
    /// in the queue so a run can be sliced by risk area; empty when unset.
    #[serde(default)]
    pub tags: Vec<String>,
    /// How urgently to hunt this task. Hunters spawn in queue order under a
    /// concurrency cap, and a usage limit can truncate the tail, so the most
    /// security-critical tasks must spawn first. Defaults to Medium for older
    /// artifacts and tasks recon leaves unranked.
    #[serde(default)]
    pub priority: Priority,
    /// Where the task came from, for debugging the queue's provenance.
    #[serde(default)]
    pub origin: TaskOrigin,
}

/// How urgently a task should be hunted, set by recon. Lower [`Priority::hunt_rank`]
/// schedules first; this is the within-origin tiebreaker for spawn order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    High,
    #[default]
    Medium,
    Low,
}

impl Priority {
    /// Scheduling rank; lower is scheduled first.
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
    /// Hunt scheduling priority; lower is scheduled first.
    ///
    /// Tasks a hunter caused are narrower and higher-value than recon's broad
    /// sweep: a gap marker is an area a hunter touched but could not finish, and
    /// a feedback seed is a lead distilled from a past run's findings. Both took
    /// hunting to surface, so they run ahead of the initial recon tasks when
    /// concurrency forces an order.
    pub fn hunt_priority(self) -> u8 {
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
    /// The task that surfaced this finding.
    pub task_id: String,
    pub title: String,
    pub attack_class: String,
    pub severity: Severity,
    /// Code location: "path/to/file.rs:120" style.
    pub location: String,
    /// What the hunter believes the bug is and why it matters.
    pub description: String,
    /// Hunter's self-assessed confidence in [0,1]. Latent / hard-to-reach bugs
    /// get a low score rather than being discarded, so the review stage (not the
    /// hunter) decides what to surface. Defaults to 0.5 for older artifacts.
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    /// Optional path to a proof-of-concept in the task scratch dir.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poc_path: Option<String>,
}

fn default_confidence() -> f64 {
    0.5
}

/// Variants are declared in ascending order so the derived `Ord` ranks
/// severity: `Info < Low < Medium < High < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Review verdict produced by the (independent) Validate stage.
///
/// The reviewer never deletes a finding; it *tags* it. A latent or
/// defense-in-depth issue is downgraded, not dropped, so a real bug the hunter
/// could not fully prove still reaches a human instead of vanishing. Only
/// `LikelyFalsePositive` is held back from the report (it stays in the
/// validated artifact for review).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validation {
    pub finding_id: String,
    pub verdict: Verdict,
    /// Evidence supporting the verdict (trace, failed assumption, PoC result).
    pub evidence: String,
    /// Set only when `verdict == Downgraded`: the severity the reviewer judges
    /// correct, which the report stage applies in place of the hunter's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corrected_severity: Option<Severity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Data flow holds, attacker control proven; file as-is.
    Confirmed,
    /// Real issue but overstated; file with `corrected_severity`.
    Downgraded,
    /// Unreachable, mis-cited, or operational-not-security; keep for review,
    /// do not report.
    LikelyFalsePositive,
}

impl Verdict {
    /// Whether a finding with this verdict advances to the report. Downgraded
    /// findings still ship (with corrected severity); only likely-false-
    /// positives are held back.
    pub fn is_reportable(self) -> bool {
        matches!(self, Verdict::Confirmed | Verdict::Downgraded)
    }
}

/// An area a hunter touched but did not cover thoroughly.
///
/// Gapfill (later phase) re-queues these as new tasks to counteract the model's
/// drift toward attack classes it has already had success with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapMarker {
    pub task_id: String,
    /// The under-explored area (file/module/function).
    pub area: String,
    /// Why it was left uncovered, and what an attack class might be.
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_ascending() {
        // Dedupe relies on this ordering to pick the representative finding.
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
        let mut v = [
            Severity::High,
            Severity::Info,
            Severity::Critical,
            Severity::Low,
        ];
        v.sort();
        assert_eq!(
            v,
            [
                Severity::Info,
                Severity::Low,
                Severity::High,
                Severity::Critical
            ]
        );
    }

    #[test]
    fn severity_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
        let s: Severity = serde_json::from_str("\"info\"").unwrap();
        assert_eq!(s, Severity::Info);
    }

    #[test]
    fn verdict_uses_snake_case_on_the_wire() {
        assert_eq!(
            serde_json::to_string(&Verdict::Confirmed).unwrap(),
            "\"confirmed\""
        );
        assert_eq!(
            serde_json::to_string(&Verdict::Downgraded).unwrap(),
            "\"downgraded\""
        );
        assert_eq!(
            serde_json::to_string(&Verdict::LikelyFalsePositive).unwrap(),
            "\"likely_false_positive\""
        );
    }

    #[test]
    fn only_confirmed_and_downgraded_are_reportable() {
        assert!(Verdict::Confirmed.is_reportable());
        assert!(Verdict::Downgraded.is_reportable());
        assert!(!Verdict::LikelyFalsePositive.is_reportable());
    }

    #[test]
    fn finding_confidence_defaults_when_absent() {
        let f: Finding = serde_json::from_str(
            "{\"id\":\"F-1\",\"task_id\":\"T\",\"title\":\"t\",\"attack_class\":\"c\",\"severity\":\"low\",\"location\":\"a.rs:1\",\"description\":\"d\"}",
        )
        .unwrap();
        assert_eq!(f.confidence, 0.5);
    }

    #[test]
    fn hunter_surfaced_origins_outrank_recon_for_scheduling() {
        // Deeper tasks (a hunter had to surface them) run before the broad sweep.
        assert!(TaskOrigin::Gapfill.hunt_priority() < TaskOrigin::Recon.hunt_priority());
        assert!(TaskOrigin::Feedback.hunt_priority() < TaskOrigin::Recon.hunt_priority());

        let mut origins = [TaskOrigin::Recon, TaskOrigin::Feedback, TaskOrigin::Gapfill];
        origins.sort_by_key(|o| o.hunt_priority());
        assert_eq!(
            origins,
            [TaskOrigin::Gapfill, TaskOrigin::Feedback, TaskOrigin::Recon]
        );
    }

    #[test]
    fn task_origin_defaults_to_recon_when_absent() {
        // Older queue files predate the `origin` field; they must still load.
        let t: Task =
            serde_json::from_str("{\"id\":\"T-1\",\"attack_class\":\"c\",\"scope_hint\":\"s\"}")
                .unwrap();
        assert!(matches!(t.origin, TaskOrigin::Recon));
    }

    #[test]
    fn task_priority_and_tags_default_when_absent() {
        // Queue files predating these fields must still load with safe defaults.
        let t: Task =
            serde_json::from_str("{\"id\":\"T-1\",\"attack_class\":\"c\",\"scope_hint\":\"s\"}")
                .unwrap();
        assert_eq!(t.priority, Priority::Medium);
        assert!(t.tags.is_empty());
    }

    #[test]
    fn priority_ranks_high_before_low_and_serializes_lowercase() {
        // Spawn order depends on this ranking: high-value tasks first.
        assert!(Priority::High.hunt_rank() < Priority::Medium.hunt_rank());
        assert!(Priority::Medium.hunt_rank() < Priority::Low.hunt_rank());
        assert_eq!(serde_json::to_string(&Priority::High).unwrap(), "\"high\"");
        let p: Priority = serde_json::from_str("\"low\"").unwrap();
        assert_eq!(p, Priority::Low);
    }

    #[test]
    fn finding_omits_poc_path_when_none() {
        let f = Finding {
            id: "F-1".into(),
            task_id: "T".into(),
            title: "t".into(),
            attack_class: "c".into(),
            severity: Severity::Low,
            location: "a.rs:1".into(),
            description: "d".into(),
            confidence: 0.9,
            poc_path: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("poc_path"), "got: {json}");
    }
}
