//! Display for the SIROS wallet core.
//!
//! | Requirement | API |
//! | --- | --- |
//! | D1: the only metadata merger; `auxiliary_data` leaves the Credential Response's `credential_metadata` before the merge | [`IssuerMetadata::merge`] |
//! | Display metadata: OpenID4VCI `credential_metadata` and SD-JWT VC Type Metadata, held by the host | [`IssuerMetadata`], [`TypeMetadata`], [`DisplayCache`] |
//! | D2: locale choice by exact tag, then primary language, then the first entry | [`Locale`], [`choose`], [`preferred`] |
//! | D3: SD-JWT VC Type Metadata display wins; OpenID4VCI `credential_metadata` is the fallback | [`DisplayCache::card`], [`DisplayCache::claim_rows`] |
//! | D4: values typed for display | [`DisplayValue`] |
//! | D5: bytes shown by their length | [`DisplayValue::Bytes`] |
//! | Credential cards and claim rows | [`Card`], [`ClaimRow`] |
//! | Display text: no control, format, bidi, separator, private-use or unassigned character, and no over-long text | [`DisplayText`] |
//! | Purpose lines (OpenID4VP 1.0, Section 6.2) | [`purpose::line`], [`purpose::display`] |
//! | Proof statement rows of a `zkp_req` option: the picker's, marked as unverified, and a verified request's | [`proof::rows`], [`proof::verified_rows`] |

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
mod locale;
pub mod proof;
pub mod purpose;
mod text;

pub use error::{ColourFault, DisplayError, EntryFault, LogoFault};
pub use locale::{choose, preferred, Locale, LocaleError, Localized};
pub use text::{DisplayText, TextError, LABEL_MAX, VALUE_MAX};

#[cfg(feature = "credential")]
mod cache;
#[cfg(feature = "credential")]
mod card;
#[cfg(feature = "credential")]
mod claims;
#[cfg(feature = "credential")]
mod colour;
#[cfg(feature = "credential")]
mod entry;
#[cfg(feature = "credential")]
mod issuer;
#[cfg(feature = "credential")]
mod json;
#[cfg(feature = "credential")]
mod logo;
#[cfg(feature = "credential")]
mod rows;
#[cfg(feature = "credential")]
mod type_metadata;

#[cfg(feature = "credential")]
pub use cache::DisplayCache;
#[cfg(feature = "credential")]
pub use card::Card;
#[cfg(feature = "credential")]
pub use colour::Colour;
#[cfg(feature = "credential")]
pub use issuer::IssuerMetadata;
#[cfg(feature = "credential")]
pub use logo::{Integrity, Logo, LogoUri};
#[cfg(feature = "credential")]
pub use rows::{ClaimRow, DisplayValue};
#[cfg(feature = "credential")]
pub use type_metadata::TypeMetadata;
