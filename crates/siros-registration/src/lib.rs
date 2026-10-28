//! The registration projection of the SIROS wallet core (§4.15): what the wallet registers with
//! the Android credential picker together with `matcher.wasm`, in one `RegisterCredentialsRequest`.
//!
//! | Requirement | API |
//! | --- | --- |
//! | K1: per credential the entry reference, format and type, holder-key presence, the typed claim tree without the nym_auth undisclosable attributes, the card and claim labels in the wallet's language, presentability without the UI, the issuer facts, and the projected transaction data definitions with their source and rulebook, each definition stored once; the nym_auth systems; the version | [`Registration`], [`write()`] (feature `wallet`), [`RegisteredCredential`] |
//! | TR5: the issuer facts at registration time, and the picker's admission from them alone | [`RegisteredCredential::issuer`], the [`siros_presentation::MatchCredential`] of `&RegisteredCredential` |
//! | K2: the picker's transaction data selection over the projected definitions, over the request's channel, deferring ad-hoc metadata to the wallet. The picker has no clock: its facts hold at registration time, the issuers' admission and certificate validity (TR5), the credentials' validity (C4), and the dates of held transaction metadata and TS12 definitions | [`Unverified`], [`Facts::registered_at`] |
//! | R-G6: no delivered or derived secret, no undisclosable attribute | [`write()`] reads no auxiliary data and removes the undisclosable attributes |
//! | Cards: a title and an issuer line from the display metadata and the host's wording; an icon of every credential, the host's else the wallet's, a PNG or JPEG of 64 to 256 pixels that the host rasterised and resized | [`RegisteredCard`], [`RasterIcon`] (feature `wallet`), [`RegistrationInput`] |
//!
//! The format is binary, laid out for reading at offsets (`docs/registration.md`): a header
//! with a magic number and the version, a directory of sections, an index of the credential
//! types sorted for binary search, the records of each type as one CBOR sequence, and the
//! definitions and icons the records name by span. [`Registration`] reads it through
//! `Read + Seek`: the header, the directory and the facts when it opens, then each part a
//! request needs when asked. It refuses every version but [`Version::CURRENT`], every offset or
//! length past its part, every member a record does not define, and an index out of order on a
//! search's path. The wallet registers the projection with the matcher it ships, so the two
//! versions are one.
//!
//! Without the feature `wallet` the crate holds the reader the credential picker links. It builds
//! with Rust 1.82 and links no X.509, ECDSA or trust store code.

#![deny(missing_docs)]
// Links to the items of `wallet` resolve with it, where rustdoc checks them.
#![cfg_attr(not(feature = "wallet"), allow(rustdoc::broken_intra_doc_links))]
#![deny(unsafe_code)]
#![deny(unused_results)]
#![deny(clippy::cognitive_complexity)]
#![deny(clippy::let_underscore_must_use, clippy::let_underscore_untyped)]
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
        clippy::disallowed_methods,
        clippy::arithmetic_side_effects
    )
)]
// No attribute can allow these lints, in the tests either.
#![forbid(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented
)]

#[cfg(feature = "wallet")]
mod encode;
mod error;
#[cfg(feature = "wallet")]
mod icon;
mod ids;
mod layout;
mod reader;
mod record;
mod registration;
#[cfg(all(test, feature = "wallet"))]
mod round_trip;
mod selection;
mod wire;
#[cfg(feature = "wallet")]
mod write;

#[cfg(feature = "wallet")]
pub use encode::encode;
pub use error::{
    ByteCount, CredentialFault, DefinitionFault, DirectoryFault, FactsFault, IndexFault, Member,
    OutOfBounds, RegistrationError, Within,
};
#[cfg(feature = "wallet")]
pub use icon::{Dimensions, IconFault, RasterIcon, MAX_ICON_PIXELS, MIN_ICON_PIXELS};
pub use ids::{CredentialIndex, KeyIndex, RecordIndex};
pub use layout::SectionKind;
pub use reader::Registration;
pub use registration::{
    DefinitionRef, Diagnostics, Facts, Icon, IconEmpty, IconRef, Projection, RegisteredCard,
    RegisteredCredential, RegisteredType, TypeName, TypeNameEmpty, Version,
};
pub use selection::Unverified;
#[cfg(feature = "wallet")]
pub use write::{project, write, CredentialIcon, RegistrationInput, WriteError};
