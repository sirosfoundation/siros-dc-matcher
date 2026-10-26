//! The encodings every SIROS wallet core crate shares: a strict CBOR reader and deterministic
//! writer, unpadded base64url, and the padded base64 of JOSE certificates.
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

pub mod base64;
pub mod base64url;
pub mod cbor;
