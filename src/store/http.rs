//! HTTP report sink: POST each finding to an ingest API.
//!
//! One request per finding keeps the contract simple and lets the ingest side
//! upsert on the finding id. The egress firewall must allow the ingest host
//! (`[firewall].allow`).

use anyhow::{Context, Result, bail};

use super::{ReportRecord, ReportSink};

pub struct HttpSink {
    url: String,
    token: Option<String>,
    agent: ureq::Agent,
    sent: usize,
}

impl HttpSink {
    pub fn new(url: String, token: Option<String>) -> Self {
        Self {
            url,
            token,
            agent: ureq::Agent::new(),
            sent: 0,
        }
    }
}

impl ReportSink for HttpSink {
    fn write(&mut self, record: &ReportRecord) -> Result<()> {
        let mut req = self
            .agent
            .post(&self.url)
            .set("content-type", "application/json");
        if let Some(token) = &self.token {
            req = req.set("authorization", &format!("Bearer {token}"));
        }
        let resp = req
            .send_json(&record.payload)
            .with_context(|| format!("posting finding {} to {}", record.id, self.url))?;
        if resp.status() >= 300 {
            bail!(
                "ingest API returned {} for finding {}",
                resp.status(),
                record.id
            );
        }
        self.sent += 1;
        Ok(())
    }

    fn count(&self) -> Result<usize> {
        // The sink does not query the remote store; report what it sent.
        Ok(self.sent)
    }
}
