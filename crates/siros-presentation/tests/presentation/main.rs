//! The tests of siros-presentation, in one binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    dead_code
)]

use siros_presentation::testing::{host, verifier, wallet};

mod display;
mod nym_request;
mod offers;
mod sd_jwt;
mod seed;
mod transactions;
mod trust;
mod usable;
