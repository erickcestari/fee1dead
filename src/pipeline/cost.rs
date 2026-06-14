//! Per-run cost accounting across agent spawns.
//!
//! Every stage spends money the same way: each call to the provider returns an
//! [`AgentResult`](crate::provider::AgentResult) carrying an optional
//! `cost_usd`. The meter is the one place that knows how to tally those: stages
//! call [`CostMeter::record`] after each spawn, the orchestrator logs a subtotal
//! at each stage boundary and a grand total at the end of the run.
//!
//! It is shared (`Arc`) and internally synchronized so the concurrent hunters
//! can record into it from their own tasks.

use std::collections::BTreeMap;
use std::sync::Mutex;

use tracing::info;

/// Thread-safe tally of agent-spawn costs, grouped by stage.
#[derive(Default)]
pub struct CostMeter {
    by_stage: Mutex<BTreeMap<String, StageCost>>,
}

#[derive(Default, Clone, Copy)]
struct StageCost {
    spawns: u64,
    cost_usd: f64,
}

impl CostMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one agent spawn under `stage`, logging its individual cost.
    ///
    /// `label` identifies the spawn within the stage (e.g. a task or finding
    /// id). A provider that does not report cost contributes `0.0` but still
    /// counts as a spawn, so spawn counts stay accurate.
    pub fn record(&self, stage: &str, label: &str, cost_usd: Option<f64>) {
        let cost = cost_usd.unwrap_or(0.0);
        let mut by_stage = self.by_stage.lock().unwrap();
        let entry = by_stage.entry(stage.to_string()).or_default();
        entry.spawns += 1;
        entry.cost_usd += cost;
        info!(stage, label, cost_usd = cost, "agent spawn cost");
    }

    /// Log the running subtotal for `stage`. No-op if the stage spawned nothing
    /// (e.g. the pure-logic stages), so the orchestrator can call it blindly.
    pub fn log_stage(&self, stage: &str) {
        let by_stage = self.by_stage.lock().unwrap();
        if let Some(c) = by_stage.get(stage) {
            info!(
                stage,
                spawns = c.spawns,
                cost_usd = c.cost_usd,
                "stage cost"
            );
        }
    }

    /// Total cost across every stage so far.
    pub fn total_usd(&self) -> f64 {
        self.by_stage
            .lock()
            .unwrap()
            .values()
            .map(|c| c.cost_usd)
            .sum()
    }

    /// Total spawns across every stage so far.
    pub fn total_spawns(&self) -> u64 {
        self.by_stage.lock().unwrap().values().map(|c| c.spawns).sum()
    }

    /// Log the grand total for the run.
    pub fn log_total(&self) {
        info!(
            spawns = self.total_spawns(),
            cost_usd = self.total_usd(),
            "run cost"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tallies_by_stage_and_total() {
        let meter = CostMeter::new();
        meter.record("hunt", "T-0001", Some(0.10));
        meter.record("hunt", "T-0002", Some(0.20));
        meter.record("validate", "T-0001-F01", Some(0.05));
        // A missing cost still counts as a spawn but adds nothing.
        meter.record("validate", "T-0002-F01", None);

        assert_eq!(meter.total_spawns(), 4);
        assert!((meter.total_usd() - 0.35).abs() < 1e-9);
    }
}
