//! The encodings every SIROS wallet core crate shares: a strict CBOR reader and deterministic
//! writer, a JSON reader that keeps members in document order, unpadded base64url, the padded
//! base64 of JOSE certificates, the calendar dates and UTC times of CBOR's `full-date` and
//! `tdate`, and the ES256 signature value.
//!
//! It also holds the internals several components share: [`MemberFault`](member::MemberFault),
//! the member fault of a decoded structure; the [`position!`] and [`text_value!`] macros that
//! declare value newtypes; and [`CertificateChain`](chain::CertificateChain), the DER
//! certificate chain an mdoc `x5chain` and an `x5c` carry.
//!
//! Nothing here panics on any input: the matcher runs this code inside the credential picker,
//! where a trap reads as "no matching credential".

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod value;

pub mod base64;
pub mod base64url;
pub mod cbor;
pub mod chain;
pub mod date;
pub mod json;
pub mod member;
mod sextets;
pub mod signature;

pub use sextets::Base64Error;
