//! The FFI's matching: the v1 credential blob, the match profile that configures its rules,
//! and their evaluator. The credential picker, `matcher.wasm`, reads the registration of
//! siros-registration and runs the presentation component's matching.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod circuit_capabilities;
pub mod db;

pub mod evaluator;
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures;
pub mod profile;
