//! Retry wrapper for transient throttling.
//!
//! The CLIs already retry a 429 briefly on their own, so one that reaches the
//! harness means the burst outlasted those retries: back off for longer, then
//! run the request again. An account quota ([`ProviderError::UsageLimited`]) is
//! passed straight through, since retrying it before it resets only bounces.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tracing::warn;

use super::{AgentRequest, AgentResult, AgentRunner, is_rate_limited};

#[cfg(doc)]
use super::ProviderError;

/// Waits before each retry; the run is attempted `len + 1` times in all.
const BACKOFF: &[Duration] = &[
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(240),
];

/// Runs requests through `inner`, retrying the ones that fail on a transient
/// rate limit. A retried agent starts over, so its earlier partial work is lost.
pub struct RetryOnRateLimit {
    inner: Arc<dyn AgentRunner>,
    backoff: &'static [Duration],
}

impl RetryOnRateLimit {
    pub fn new(inner: Arc<dyn AgentRunner>) -> Self {
        Self::with_backoff(inner, BACKOFF)
    }

    fn with_backoff(inner: Arc<dyn AgentRunner>, backoff: &'static [Duration]) -> Self {
        Self { inner, backoff }
    }
}

#[async_trait]
impl AgentRunner for RetryOnRateLimit {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn run(&self, req: AgentRequest) -> Result<AgentResult> {
        for delay in self.backoff {
            match self.inner.run(req.clone()).await {
                Err(e) if is_rate_limited(&e) => {
                    warn!(error = %e, retry_in_secs = delay.as_secs(), "agent rate limited; backing off");
                    tokio::time::sleep(*delay).await;
                }
                other => return other,
            }
        }
        self.inner.run(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Effort, ProviderError};
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// Fails with the queued errors in order, then succeeds.
    struct Flaky {
        errors: Mutex<Vec<ProviderError>>,
        calls: Mutex<usize>,
    }

    #[async_trait]
    impl AgentRunner for Flaky {
        fn name(&self) -> &str {
            "flaky"
        }

        async fn run(&self, _req: AgentRequest) -> Result<AgentResult> {
            *self.calls.lock().unwrap() += 1;
            match self.errors.lock().unwrap().pop() {
                Some(e) => Err(e.into()),
                None => Ok(AgentResult {
                    stdout: "ok".into(),
                    exit_code: 0,
                    session_id: None,
                }),
            }
        }
    }

    fn req() -> AgentRequest {
        AgentRequest {
            prompt: "p".into(),
            system: None,
            working_dir: PathBuf::from("/w"),
            output_dir: PathBuf::from("/w"),
            extra_dirs: Vec::new(),
            allowed_tools: Vec::new(),
            disallowed_tools: Vec::new(),
            timeout: Duration::from_secs(1),
            resume: None,
            cache_1h: false,
            effort: Effort::Low,
            model: None,
            stream_log_path: None,
        }
    }

    const NO_WAIT: &[Duration] = &[Duration::ZERO, Duration::ZERO];

    fn flaky(errors: Vec<ProviderError>) -> Arc<Flaky> {
        Arc::new(Flaky {
            errors: Mutex::new(errors),
            calls: Mutex::new(0),
        })
    }

    #[tokio::test]
    async fn throttled_runs_are_retried_until_they_succeed() {
        let inner = flaky(vec![
            ProviderError::RateLimited("429".into()),
            ProviderError::RateLimited("429".into()),
        ]);
        let runner = RetryOnRateLimit::with_backoff(inner.clone(), NO_WAIT);
        assert_eq!(runner.run(req()).await.unwrap().stdout, "ok");
        assert_eq!(*inner.calls.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn gives_up_after_the_backoff_is_exhausted() {
        let inner = flaky(vec![
            ProviderError::RateLimited("429".into()),
            ProviderError::RateLimited("429".into()),
            ProviderError::RateLimited("429".into()),
        ]);
        let runner = RetryOnRateLimit::with_backoff(inner.clone(), NO_WAIT);
        assert!(is_rate_limited(&runner.run(req()).await.unwrap_err()));
        assert_eq!(*inner.calls.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn an_account_quota_is_not_retried() {
        let inner = flaky(vec![ProviderError::UsageLimited("session limit".into())]);
        let runner = RetryOnRateLimit::with_backoff(inner.clone(), NO_WAIT);
        assert!(runner.run(req()).await.is_err());
        assert_eq!(*inner.calls.lock().unwrap(), 1);
    }
}
