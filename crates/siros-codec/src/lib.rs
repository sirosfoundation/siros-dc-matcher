//! The encodings every SIROS wallet core crate shares: a strict CBOR reader and deterministic
//! writer, and unpadded base64url.
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

pub mod base64url;
pub mod cbor;
