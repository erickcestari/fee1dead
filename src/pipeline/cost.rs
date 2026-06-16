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
use std::time::Duration;

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
    /// Summed wall-clock time of the stage's agents. For concurrent stages
    /// (hunt) this is agent-seconds, not elapsed time.
    secs: f64,
}

impl CostMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one finished agent under `stage`, logging its individual cost and
    /// wall-clock duration.
    ///
    /// `label` identifies the spawn within the stage (e.g. a task or finding
    /// id). A provider that does not report cost contributes `0.0` but still
    /// counts as a spawn, so spawn counts stay accurate.
    pub fn record(&self, stage: &str, label: &str, cost_usd: Option<f64>, duration: Duration) {
        let cost = cost_usd.unwrap_or(0.0);
        let secs = duration.as_secs_f64();
        let mut by_stage = self.by_stage.lock().unwrap();
        let entry = by_stage.entry(stage.to_string()).or_default();
        entry.spawns += 1;
        entry.cost_usd += cost;
        entry.secs += secs;
        info!(
            stage,
            label,
            cost_usd = cost,
            duration_secs = secs,
            "agent finished"
        );
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
                agent_secs = c.secs,
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

    /// Total agent wall-clock seconds across every stage so far (summed, so
    /// concurrent agents overlap in real time but add up here).
    pub fn total_secs(&self) -> f64 {
        self.by_stage.lock().unwrap().values().map(|c| c.secs).sum()
    }

    /// Log the grand total for the run.
    pub fn log_total(&self) {
        info!(
            spawns = self.total_spawns(),
            cost_usd = self.total_usd(),
            agent_secs = self.total_secs(),
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
        meter.record("hunt", "T-0001", Some(0.10), Duration::from_secs(3));
        meter.record("hunt", "T-0002", Some(0.20), Duration::from_secs(5));
        meter.record("validate", "T-0001-F01", Some(0.05), Duration::from_secs(2));
        // A missing cost still counts as a spawn but adds nothing.
        meter.record("validate", "T-0002-F01", None, Duration::from_secs(1));

        assert_eq!(meter.total_spawns(), 4);
        assert!((meter.total_usd() - 0.35).abs() < 1e-9);
        // Durations sum across stages (agent-seconds).
        assert!((meter.total_secs() - 11.0).abs() < 1e-9);
    }
}
