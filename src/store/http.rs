//! One POST per finding to an ingest API, which upserts on the id. The ingest
//! host must be in `[firewall].allow`.

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
        // The remote store is not queried; this is what was sent.
        Ok(self.sent)
    }
}
