//! Agents wrap a JSON answer in prose or a `json` code fence; pull it back out.

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

/// The first `json` code fence, else the outermost JSON array or object.
pub fn extract(text: &str) -> Option<&str> {
    if let Some(start) = text.find("```json") {
        let rest = &text[start + "```json".len()..];
        if let Some(end) = rest.find("```") {
            return Some(rest[..end].trim());
        }
    }
    let first = text.find(['[', '{'])?;
    let last = text.rfind([']', '}'])?;
    (last > first).then(|| text[first..=last].trim())
}

/// Parse the answer's JSON as a `what`. The errors read well in a repair
/// prompt, which quotes them back to the agent.
pub fn parse<T: DeserializeOwned>(text: &str, what: &str) -> Result<T> {
    let json = extract(text).with_context(|| format!("no JSON {what} in the answer"))?;
    serde_json::from_str(json).with_context(|| format!("the answer is not a valid {what}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_fenced_json() {
        let t = "Here is the result:\n```json\n[{\"a\":1}]\n```\nDone.";
        assert_eq!(extract(t), Some("[{\"a\":1}]"));
    }

    #[test]
    fn extracts_bare_json() {
        assert_eq!(extract("blah [{\"a\":1}] trailing"), Some("[{\"a\":1}]"));
        assert_eq!(extract("no json here"), None);
    }

    #[test]
    fn parse_names_what_was_expected() {
        let err = parse::<Vec<u32>>("{\"a\":1}", "review array").unwrap_err();
        assert!(format!("{err:#}").contains("not a valid review array"));
        let err = parse::<Vec<u32>>("nothing", "review array").unwrap_err();
        assert!(err.to_string().contains("no JSON review array"));
        assert_eq!(parse::<Vec<u32>>("[1, 2]", "x").unwrap(), [1, 2]);
    }
}
