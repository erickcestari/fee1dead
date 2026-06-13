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
    pub scope_hint: String,
    /// Where the task came from, for debugging the queue's provenance.
    #[serde(default)]
    pub origin: TaskOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TaskOrigin {
    #[default]
    Recon,
    Gapfill,
    Feedback,
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
    /// Optional path to a proof-of-concept in the task scratch dir.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poc_path: Option<String>,
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

/// Validation verdict produced by the (independent) Validate stage.
///
/// The validator can only confirm or refute a hunter's finding; it cannot emit
/// new findings of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validation {
    pub finding_id: String,
    pub verdict: Verdict,
    /// Evidence supporting the verdict (trace, failed assumption, PoC result).
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    TruePositive,
    FalsePositive,
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
