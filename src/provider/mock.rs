//! A deterministic runner for offline end-to-end runs: canned replies keyed by
//! a substring of the prompt.

use std::collections::VecDeque;
use std::sync::Mutex;

use anyhow::{Result, bail};
use async_trait::async_trait;

use super::{AgentRequest, AgentResult, AgentRunner};

/// A canned reply, used for prompts containing `match_substr` (any prompt
/// when unset).
#[derive(Debug, Clone)]
pub struct CannedReply {
    pub match_substr: Option<String>,
    pub stdout: String,
    pub session_id: Option<String>,
    /// Builds the reply from the prompt instead, for replies that must echo
    /// ids the harness assigned at run time.
    pub render: Option<fn(&str) -> String>,
}

pub struct MockRunner {
    name: String,
    replies: Vec<CannedReply>,
    /// Every prompt seen.
    pub seen: Mutex<VecDeque<String>>,
    /// The session each request forked from, if any.
    pub seen_resume: Mutex<Vec<Option<String>>>,
}

impl MockRunner {
    pub fn new(replies: Vec<CannedReply>) -> Self {
        Self {
            name: "mock".into(),
            replies,
            seen: Mutex::new(VecDeque::new()),
            seen_resume: Mutex::new(Vec::new()),
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
        self.seen_resume
            .lock()
            .unwrap()
            .push(req.resume.as_ref().map(|r| r.session_id.clone()));
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
                stdout: r.render.map_or(r.stdout, |render| render(&req.prompt)),
                session_id: r.session_id,
            }),
            None => bail!("mock runner has no canned reply for prompt"),
        }
    }
}
