//! The parts of the matcher that are not the DCQL engine and not the WASM
//! binary: the credential blob we register with the platform, the match
//! profile that makes the rules configurable, and the sink that emits picker
//! entries.
//!
//! # Status
//!
//! Phase 0 scaffolding. See the repository's `docs/plan.md`.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod profile;
pub mod sink;
