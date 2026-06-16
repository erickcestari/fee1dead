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
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::json;
use tracing::{info, warn};

/// Thread-safe tally of agent-spawn costs, grouped by stage.
///
/// Besides the in-memory tally, when built with [`CostMeter::with_log`] it
/// appends one JSONL row per agent run to a file, so a run can be profiled
/// afterwards to find which tasks dominate cost/time.
#[derive(Default)]
pub struct CostMeter {
    by_stage: Mutex<BTreeMap<String, StageCost>>,
    /// Serializes telemetry appends. A row is written with several `write`
    /// calls (serde's `Display` emits the JSON incrementally), so concurrent
    /// hunters sharing the file would interleave partial lines — `O_APPEND`
    /// keeps bytes from being overwritten but does NOT keep a line intact.
    /// Holding this lock for the whole write is what guarantees one line per row.
    writer: Mutex<TelemetryWriter>,
}

/// File sink for per-agent rows; `path: None` disables persistence (tests).
#[derive(Default)]
struct TelemetryWriter {
    path: Option<PathBuf>,
    /// Opened lazily on first row so the open lands after the per-run artifact
    /// reset has cleared any stale file, then reused for the rest of the run.
    file: Option<std::fs::File>,
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

    /// Build a meter that also appends a JSONL telemetry row per agent to
    /// `log_path`.
    pub fn with_log(log_path: PathBuf) -> Self {
        Self {
            by_stage: Mutex::new(BTreeMap::new()),
            writer: Mutex::new(TelemetryWriter {
                path: Some(log_path),
                file: None,
            }),
        }
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
        {
            let mut by_stage = self.by_stage.lock().unwrap();
            let entry = by_stage.entry(stage.to_string()).or_default();
            entry.spawns += 1;
            entry.cost_usd += cost;
            entry.secs += secs;
        }
        info!(
            stage,
            label,
            cost_usd = cost,
            duration_secs = secs,
            "agent finished"
        );
        self.append_row(stage, label, cost, secs);
    }

    /// Append one telemetry row, serialized so concurrent agents cannot
    /// interleave lines. Best-effort: a telemetry write must never abort a run,
    /// so failures are warned and swallowed.
    fn append_row(&self, stage: &str, label: &str, cost_usd: f64, duration_secs: f64) {
        let mut w = self.writer.lock().unwrap();
        let Some(path) = w.path.clone() else {
            return;
        };
        // Open once, after the per-run reset; reuse the handle thereafter.
        if w.file.is_none() {
            match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(f) => w.file = Some(f),
                Err(e) => {
                    warn!(error = %e, path = %path.display(), "failed to open cost telemetry");
                    return;
                }
            }
        }
        let row = json!({
            "stage": stage,
            "label": label,
            "cost_usd": cost_usd,
            "duration_secs": duration_secs,
        });
        if let Some(f) = w.file.as_mut()
            && let Err(e) = writeln!(f, "{row}")
        {
            warn!(error = %e, path = %path.display(), "failed to write cost telemetry row");
        }
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

    #[test]
    fn writes_one_jsonl_row_per_agent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("costs.jsonl");
        let meter = CostMeter::with_log(path.clone());
        meter.record("hunt", "T-0001", Some(0.1), Duration::from_secs(3));
        // A missing cost is persisted as 0.0; sub-second durations are preserved.
        meter.record("report", "batch-0", None, Duration::from_millis(1500));

        let content = std::fs::read_to_string(&path).unwrap();
        let rows: Vec<serde_json::Value> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["stage"], "hunt");
        assert_eq!(rows[0]["label"], "T-0001");
        assert_eq!(rows[0]["cost_usd"], 0.1);
        assert_eq!(rows[0]["duration_secs"], 3.0);
        assert_eq!(rows[1]["cost_usd"], 0.0);
        assert_eq!(rows[1]["duration_secs"], 1.5);
    }

    #[test]
    fn concurrent_records_do_not_interleave_rows() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("costs.jsonl");
        let meter = Arc::new(CostMeter::with_log(path.clone()));

        let handles: Vec<_> = (0..50)
            .map(|i| {
                let m = Arc::clone(&meter);
                thread::spawn(move || {
                    m.record("hunt", &format!("T-{i:04}"), Some(0.01), Duration::from_millis(1));
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 50);
        // Each line must be a complete, parseable object: proof no two writers
        // interleaved their bytes.
        for l in &lines {
            let v: serde_json::Value = serde_json::from_str(l).expect("each line is intact JSON");
            assert_eq!(v["stage"], "hunt");
        }
    }

    #[test]
    fn no_log_path_means_no_file() {
        // The default meter (used in unit tests) must not touch the filesystem.
        let meter = CostMeter::new();
        meter.record("hunt", "T-0001", Some(0.1), Duration::from_secs(1));
        assert_eq!(meter.total_spawns(), 1);
    }
}
