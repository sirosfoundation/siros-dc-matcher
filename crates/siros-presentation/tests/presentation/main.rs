//! The tests of siros-presentation, in one binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    dead_code
)]

mod digest;
mod display;
mod mdoc;
mod nym_request;
mod offers;
mod refusals;
mod sd_jwt;
mod trust;
mod usable;
mod verifier;
mod wallet;
mod zkp;
