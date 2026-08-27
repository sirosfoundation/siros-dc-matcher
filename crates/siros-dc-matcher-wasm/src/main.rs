//! The matcher binary.
//!
//! Runs inside the Android credential picker: no network, no filesystem, and a
//! hard time budget. It reads the verifier's request and the credential blob
//! this wallet registered, decides which credentials to offer, and emits picker
//! entries.
//!
//! # A trap is a silent failure
//!
//! If this binary panics, the picker shows no entries — which the user cannot
//! tell apart from "you have no matching credential". There is no error
//! surface. That is why `unwrap` and `expect` are denied below rather than
//! merely discouraged, and why the release profile aborts instead of
//! unwinding.
//!
//! # Status
//!
//! Phase 0 scaffolding: the ABI in [`abi`] is real and verified, the matching
//! is not implemented yet. See the repository's `docs/plan.md`.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::indexing_slicing)]

mod abi;

fn main() {
    let _version = abi::wasm_version();
    let (_package, _origin) = abi::calling_app_info();
    let _request = abi::request_bytes();
    let _credentials = abi::credentials_bytes();

    // Phase 1 lands the emission path and proves the swap on hardware; Phases
    // 3-5 land DCQL, the profile evaluator and entry display. Emitting nothing
    // is the correct behaviour until then: it reads as "no matching
    // credential", which is exactly true of a matcher that cannot match yet.
}
