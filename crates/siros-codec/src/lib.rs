//! The encodings every SIROS wallet core crate shares: a strict CBOR reader and deterministic
//! writer, unpadded base64url, the padded base64 of JOSE certificates, and the calendar dates
//! and UTC times of CBOR's `full-date` and `tdate`.
//!
//! Nothing here panics on any input: the matcher runs this code inside the credential picker,
//! where a trap reads as "no matching credential".

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

pub mod base64;
pub mod base64url;
pub mod cbor;
pub mod date;
mod sextets;

pub use sextets::Base64Error;
