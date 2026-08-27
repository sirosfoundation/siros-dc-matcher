//! Kotlin and Swift access to the same matching engine the WASM binary uses.
//!
//! Two callers need this. The Kotlin SDK matches again after the user has
//! selected an entry, to decide what to actually present. iOS has no WASM
//! matcher concept at all — when its OS-level Digital Credentials API
//! integration lands, matching happens in-process, and this is what it will
//! call.
//!
//! Both SDKs currently carry their own DCQL implementation. Those become
//! shims over this crate, so there is one engine and one place for a
//! `credential_sets` bug to live.
//!
//! # Status
//!
//! Phase 0 scaffolding; UniFFI is wired in Phase 2. See `docs/plan.md`.

#![deny(missing_docs)]
#![deny(unsafe_code)]
