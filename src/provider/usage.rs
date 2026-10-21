//! What an agent run cost, read back from its stream log. Field names follow
//! Claude Code's `result` event, so totals compare with other harnesses' records.

use std::io::BufRead;
use std::ops::AddAssign;

use serde::Serialize;
use serde_json::Value;

use super::{claude_code, opencode};

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize)]
pub struct Usage {
    pub total_cost_usd: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub cache_creation_input_tokens: u64,
}

impl Usage {
    /// The sum of a stream log's usage events; `None` when it has none, e.g.
    /// a claude run killed before its final event.
    pub fn from_log(log: impl BufRead) -> Option<Usage> {
        let mut total = None;
        for line in log.lines().map_while(Result::ok) {
            let Ok(event) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if let Some(usage) = claude_code::usage(&event).or_else(|| opencode::usage(&event)) {
                *total.get_or_insert_default() += usage;
            }
        }
        total
    }
}

impl AddAssign for Usage {
    fn add_assign(&mut self, other: Usage) {
        self.total_cost_usd += other.total_cost_usd;
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.cache_read_input_tokens += other.cache_read_input_tokens;
        self.cache_creation_input_tokens += other.cache_creation_input_tokens;
    }
}

/// A token count at `pointer`, zero when absent.
pub(super) fn tokens(event: &Value, pointer: &str) -> u64 {
    event.pointer(pointer).and_then(Value::as_u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLAUDE_RESULT: &str = r#"{"type":"result","is_error":false,"total_cost_usd":1.5,"usage":{"input_tokens":10,"output_tokens":20,"cache_read_input_tokens":300,"cache_creation_input_tokens":40}}"#;
    const OPENCODE_STEP: &str = r#"{"type":"step_finish","part":{"type":"step-finish","cost":0.25,"tokens":{"input":5,"output":6,"reasoning":4,"cache":{"read":70,"write":8}}}}"#;

    #[test]
    fn sums_each_clis_usage_events_and_skips_the_rest() {
        let log = format!("{OPENCODE_STEP}\nnot json\n{{\"type\":\"text\"}}\n{OPENCODE_STEP}\n");
        let opencode = Usage::from_log(log.as_bytes()).unwrap();
        assert_eq!(
            opencode,
            Usage {
                total_cost_usd: 0.5,
                input_tokens: 10,
                // Reasoning is billed as output.
                output_tokens: 20,
                cache_read_input_tokens: 140,
                cache_creation_input_tokens: 16,
            }
        );
        let claude = Usage::from_log(CLAUDE_RESULT.as_bytes()).unwrap();
        assert_eq!(claude.total_cost_usd, 1.5);
        assert_eq!(claude.cache_read_input_tokens, 300);
        assert_eq!(claude.cache_creation_input_tokens, 40);
    }

    #[test]
    fn a_log_without_usage_events_is_unpriced() {
        let killed = r#"{"type":"assistant","message":{"usage":{"input_tokens":9}}}"#;
        assert_eq!(Usage::from_log(killed.as_bytes()), None);
        assert_eq!(Usage::from_log(&b""[..]), None);
    }
}
