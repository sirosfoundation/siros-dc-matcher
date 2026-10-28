//! The FFI's matching: the v1 credential blob ([`db`]), the match profile that configures its
//! rules and their evaluator ([`profile`], [`evaluator`]), and the capabilities of a registered
//! circuit ([`circuit_capabilities`]). The credential picker, `matcher.wasm`, reads the
//! registration of siros-registration and runs the presentation component's matching.

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

pub mod circuit_capabilities;
pub mod db;

pub mod evaluator;
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures;
pub mod profile;
