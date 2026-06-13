//! fee1dead — a modular, AI-CLI-agnostic vulnerability discovery harness.
//!
//! The orchestrator does not hunt bugs itself. It drives AI coding CLIs through
//! a pipeline (Recon -> Hunt -> Validate -> Gapfill -> Dedupe -> Feedback ->
//! Report), running many narrow agent tasks in parallel and turning their
//! output into queryable, schema-validated findings.
//!
//! Stages communicate only through persisted artifacts (see [`artifacts`]), so
//! they stay decoupled and runs are resumable.

pub mod artifacts;
pub mod config;
pub mod domain;
pub mod pipeline;
pub mod provider;
pub mod scratch;
pub mod skills;
pub mod store;
pub mod target;
