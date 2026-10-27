//! The parts of the matcher outside the DCQL engine and the WASM binary: the
//! credential blob a wallet registers with the platform ([`db`]), the match
//! profile and its evaluator ([`profile`], [`evaluator`]), the DC API request
//! ([`request`]), purpose lines ([`purpose`]), and the `zkp_req` planner,
//! response check, proof time and circuit capabilities ([`zkp_req`],
//! [`zkp_req_response`], [`proof_time`], [`circuit_capabilities`]).

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod base64url;
pub mod circuit_capabilities;
pub mod db;
pub mod zkp_req;
pub mod zkp_req_response;

pub mod evaluator;
#[cfg(any(test, feature = "test-fixtures"))]
pub mod fixtures;
pub mod profile;
pub mod proof_time;
pub mod purpose;
pub mod request;
