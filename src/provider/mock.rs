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
    /// Session id this reply reports, mimicking a real provider's envelope.
    pub session_id: Option<String>,
    /// When set, builds the reply from the prompt instead of using `stdout`,
    /// for stages whose reply must echo ids the harness assigned at run time.
    pub render: Option<fn(&str) -> String>,
}

pub struct MockRunner {
    name: String,
    replies: Vec<CannedReply>,
    /// Records every prompt seen, for assertions.
    pub seen: Mutex<VecDeque<String>>,
    /// Records the session id each request asked to fork from (None when not
    /// forking), for assertions about session wiring.
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
                exit_code: 0,
                session_id: r.session_id,
            }),
            None => bail!("mock runner has no canned reply for prompt"),
        }
    }
}
