//! The wishlist: what hunters and reviewers needed but the sandbox lacks (a
//! blocked host, a missing tool, a VM). An agent records the wish and carries
//! on from the code; the operator grants wishes between runs.

use serde::Deserialize;

use crate::domain::{Wish, WishKind};

/// The `kind` glossary both prompts embed, one entry per [`WishKind`].
pub(super) const KINDS: &str = "`network` (a host the firewall blocks), `source` (code the \
     checkout lacks: a dependency, submodule, or spec), `toolchain` (a compiler, tool, or \
     package), `data` (config files, fixtures, credentials), `environment` (another OS, a \
     VM, hardware, a running service), or `other`";

/// A wish as an agent writes it. Every field defaults, so a sloppy wish is
/// dropped instead of failing the answer it rides in.
#[derive(Debug, Default, Deserialize)]
pub(super) struct RawWish {
    #[serde(default)]
    kind: WishKind,
    #[serde(default)]
    need: String,
    #[serde(default)]
    unblocks: String,
}

impl RawWish {
    /// `None` when it names no need.
    pub(super) fn into_wish(self, task_id: &str, finding_id: Option<&str>) -> Option<Wish> {
        let need = self.need.trim();
        (!need.is_empty()).then(|| Wish {
            task_id: task_id.to_string(),
            finding_id: finding_id.map(str::to_string),
            kind: self.kind,
            need: need.to_string(),
            unblocks: self.unblocks.trim().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_the_prompts_list_parses_as_itself() {
        let listed: Vec<&str> = KINDS.split('`').skip(1).step_by(2).collect();
        assert_eq!(listed.len(), 6);
        for name in listed {
            let kind: WishKind = serde_json::from_value(serde_json::json!(name)).unwrap();
            assert_eq!(serde_json::json!(kind), name);
        }
    }

    #[test]
    fn a_wish_without_a_need_is_dropped() {
        let raw: RawWish = serde_json::from_str(r#"{"kind": "network"}"#).unwrap();
        assert!(raw.into_wish("T-1", None).is_none());
        let raw: RawWish = serde_json::from_str(r#"{"need": "  a FreeBSD VM "}"#).unwrap();
        let wish = raw.into_wish("T-1", Some("F-1")).unwrap();
        assert_eq!(wish.need, "a FreeBSD VM");
        assert_eq!(wish.kind, WishKind::Other);
        assert_eq!(wish.finding_id.as_deref(), Some("F-1"));
    }
}
