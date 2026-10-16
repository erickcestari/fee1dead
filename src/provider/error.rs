/// A provider failure the orchestrator reacts to differently than a generic
/// error.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The account's quota, or the operator's weekly cap, is spent. Retrying
    /// before it resets only bounces, so a stage stops spawning agents.
    #[error("usage limit reached: {0}")]
    UsageLimited(String),
    /// Transient backend throttling (429 / overloaded); retried after a backoff.
    #[error("rate limited: {0}")]
    RateLimited(String),
    /// Killed at its timeout. `session_id` lets a stage resume it for salvage.
    #[error("agent timed out")]
    TimedOut { session_id: Option<String> },
}

pub fn is_usage_limited(err: &anyhow::Error) -> bool {
    matches!(err.downcast_ref(), Some(ProviderError::UsageLimited(_)))
}

pub fn is_rate_limited(err: &anyhow::Error) -> bool {
    matches!(err.downcast_ref(), Some(ProviderError::RateLimited(_)))
}

pub fn timed_out_session(err: &anyhow::Error) -> Option<String> {
    match err.downcast_ref()? {
        ProviderError::TimedOut { session_id } => session_id.clone(),
        _ => None,
    }
}

/// Classify a CLI's human error message as a quota or a transient throttle.
/// The two need opposite handling, and claude labels server-side throttling
/// "not your usage limit", which must not read as a quota.
pub(super) fn limit_error(msg: &str) -> Option<ProviderError> {
    let m = msg.to_lowercase();
    let quota = !m.contains("not your usage limit")
        && m.contains("limit")
        && ["session", "usage", "weekly", "hit your", "resets"]
            .iter()
            .any(|w| m.contains(w));
    if quota {
        return Some(ProviderError::UsageLimited(msg.to_string()));
    }
    let throttled = [
        "rate limit",
        "rate_limit",
        "too many requests",
        "overloaded",
        "temporarily limiting",
    ]
    .iter()
    .any(|w| m.contains(w));
    throttled.then(|| ProviderError::RateLimited(msg.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_quota(msg: &str) -> bool {
        matches!(limit_error(msg), Some(ProviderError::UsageLimited(_)))
    }

    fn is_throttle(msg: &str) -> bool {
        matches!(limit_error(msg), Some(ProviderError::RateLimited(_)))
    }

    #[test]
    fn separates_account_quota_from_transient_throttling() {
        assert!(is_quota(
            "You've hit your session limit · resets 2:50am (UTC)"
        ));
        assert!(is_quota("Usage limit reached"));
        assert!(is_quota("Weekly limit reached ∙ resets Mon 9am"));
        assert!(is_throttle("rate limit exceeded, please retry"));
        assert!(is_throttle(
            r#"API Error: 429 {"type":"error","error":{"type":"rate_limit_error"}}"#
        ));
        assert!(is_throttle(
            "Server is temporarily limiting requests (not your usage limit)"
        ));
        assert!(is_throttle("overloaded_error"));
        // An ordinary failure must be neither, or one error would stop a stage.
        assert!(limit_error("hunter output was not valid json").is_none());
        assert!(limit_error("").is_none());
    }

    #[test]
    fn errors_are_recognized_through_anyhow_context() {
        let err = anyhow::Error::from(ProviderError::UsageLimited("x".into())).context("running");
        assert!(is_usage_limited(&err));
        assert!(!is_rate_limited(&err));
        assert!(!is_usage_limited(&anyhow::anyhow!("boom")));

        let timed_out: anyhow::Error = ProviderError::TimedOut {
            session_id: Some("s-1".into()),
        }
        .into();
        assert_eq!(timed_out_session(&timed_out).as_deref(), Some("s-1"));
        let early: anyhow::Error = ProviderError::TimedOut { session_id: None }.into();
        assert_eq!(timed_out_session(&early), None);
        assert_eq!(timed_out_session(&anyhow::anyhow!("boom")), None);
    }
}
