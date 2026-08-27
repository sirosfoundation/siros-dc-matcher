//! A host implementation of the Credential Manager matcher ABI.
//!
//! In production the only thing that implements this ABI is Play Services,
//! which means the only way to exercise a matcher is to install it on a phone
//! and drive a real verifier. That is a poor place to discover that a DCQL
//! `claim_sets` edge case is wrong.
//!
//! This crate implements the same ABI over wasmtime, so the real `.wasm`
//! binary runs against fixtures in ordinary `cargo test`. It also lets the
//! same fixtures be replayed against another implementation for differential
//! testing — see `CONTRIBUTING.md` on how that oracle is obtained, and why it
//! is never vendored into this repository.
//!
//! # Status
//!
//! Phase 0 scaffolding; wasmtime lands in Phase 1. See `docs/plan.md`.

#![deny(missing_docs)]
#![deny(unsafe_code)]

/// Environment variable naming a local matcher binary to use as a
/// differential-testing oracle. Tests skip when it is unset.
pub const ORACLE_ENV: &str = "MULTIPAZ_MATCHER_WASM";
