//! The registration projection of the SIROS wallet core (§4.15): what the wallet registers with
//! the Android credential picker together with `matcher.wasm`, in one `RegisterCredentialsRequest`.
//!
//! | Requirement | API |
//! | --- | --- |
//! | K1: per credential the entry reference, format and type, holder-key presence, the typed claim tree without the nym_auth undisclosable attributes, the card and claim labels in the wallet's language, presentability without the UI, the issuer facts, and the projected transaction data definitions with their source and rulebook, each definition stored once; the nym_auth systems; the version | [`Registration::read`], [`write()`] (feature `wallet`), [`RegisteredCredential`] |
//! | TR5: the issuer facts at registration time, and the picker's admission from them alone | [`RegisteredCredential::issuer`], the [`siros_presentation::MatchCredential`] of `&RegisteredCredential` |
//! | K2: the picker's transaction data selection over the projected definitions, over the Digital Credentials API, deferring ad-hoc metadata to the wallet | [`Unverified`] |
//! | R-G6: no delivered or derived secret, no undisclosable attribute | [`write()`] reads no auxiliary data and removes the undisclosable attributes |
//!
//! The format is CBOR, read strictly: a reader refuses every version but [`Version::CURRENT`], every
//! member it does not define, and every reference outside its tables. The wallet registers the
//! projection with the matcher it ships, so the two versions are one.
//!
//! Without the feature `wallet` the crate holds the reader the credential picker links. It builds
//! with Rust 1.82 and links no X.509, ECDSA or trust store code.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(unused_results)]
#![deny(clippy::cognitive_complexity)]
#![deny(clippy::let_underscore_must_use, clippy::let_underscore_untyped)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod error;
mod ids;
mod read;
mod registration;
mod selection;
mod wire;
#[cfg(feature = "wallet")]
mod write;

pub use error::{CredentialFault, Member, RegistrationError};
pub use ids::{CredentialIndex, DefinitionIndex, IconIndex};
pub use registration::{
    Diagnostics, Icon, IconEmpty, RegisteredCard, RegisteredCredential, RegisteredType,
    Registration, Version,
};
pub use selection::Unverified;
#[cfg(feature = "wallet")]
pub use write::{write, CredentialIcon, RegistrationInput, WriteError};
