//! fee1dead: an AI-CLI-agnostic vulnerability discovery harness. It never
//! hunts bugs itself; it drives AI CLIs through a staged pipeline whose stages
//! communicate only through artifacts, so they stay decoupled and runs resume.

pub mod artifacts;
pub mod config;
pub mod domain;
pub mod json_block;
pub mod pipeline;
pub mod provider;
pub mod scratch;
pub mod store;
pub mod target;
