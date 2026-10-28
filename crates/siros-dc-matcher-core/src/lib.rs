//! The parts of the matcher outside the DCQL engine and the WASM binary: the
//! credential blob a wallet registers with the platform ([`db`]), the match
//! profile and its evaluator ([`profile`], [`evaluator`]), and the
//! capabilities of a registered circuit ([`circuit_capabilities`]).

#![deny(missing_docs)]
#![deny(unsafe_code)]
// Nothing panics outside the tests. scripts/check_panic_sites.py refuses an
// allow of these lints there and finds the panics they cannot see.
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod circuit_capabilities;
pub mod db;

pub mod evaluator;
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures;
pub mod profile;
