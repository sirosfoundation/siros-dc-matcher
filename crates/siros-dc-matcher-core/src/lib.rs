//! The parts of the matcher outside the DCQL engine and the WASM binary: the
//! credential blob a wallet registers with the platform ([`db`]), the match
//! profile and its evaluator ([`profile`], [`evaluator`]), and the
//! capabilities of a registered circuit ([`circuit_capabilities`]).

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod circuit_capabilities;
pub mod db;

pub mod evaluator;
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures;
pub mod profile;
