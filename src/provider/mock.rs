//! A deterministic runner for tests and offline end-to-end runs.
//!
//! It returns canned responses keyed by a substring match against the prompt,
//! so a full pipeline can be exercised without any network or API cost.

use std::collections::VecDeque;
use std::sync::Mutex;

use anyhow::{Result, bail};
use async_trait::async_trait;

use super::{AgentRequest, AgentResult, AgentRunner};

/// A canned reply. If `match_substr` is set, the reply is only used when the
/// prompt contains that substring; otherwise it matches any prompt.
#[derive(Debug, Clone)]
pub struct CannedReply {
    pub match_substr: Option<String>,
    pub stdout: String,
}

pub struct MockRunner {
    name: String,
    replies: Vec<CannedReply>,
    /// Records every prompt seen, for assertions.
    pub seen: Mutex<VecDeque<String>>,
}

impl MockRunner {
    pub fn new(replies: Vec<CannedReply>) -> Self {
        Self {
            name: "mock".into(),
            replies,
            seen: Mutex::new(VecDeque::new()),
        }
    }
}

#[async_trait]
impl AgentRunner for MockRunner {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(&self, req: AgentRequest) -> Result<AgentResult> {
        self.seen.lock().unwrap().push_back(req.prompt.clone());
        let reply = self
            .replies
            .iter()
            .find(|r| match &r.match_substr {
                Some(s) => req.prompt.contains(s.as_str()),
                None => true,
            })
            .cloned();
        match reply {
            Some(r) => Ok(AgentResult {
                stdout: r.stdout,
                structured: None,
                exit_code: 0,
                cost_usd: Some(0.0),
            }),
            None => bail!("mock runner has no canned reply for prompt"),
        }
    }
}
