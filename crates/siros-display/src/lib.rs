//! Display for the SIROS wallet core.
//!
//! | Requirement | API |
//! | --- | --- |
//! | D2: locale choice by exact tag, then primary language, then the first entry | [`Locale`], [`choose`] |
//! | Display text: no control, format, bidi, separator, private-use or unassigned character, and no over-long text | [`DisplayText`] |
//! | Purpose lines (OpenID4VP 1.0, Section 6.2) | [`purpose::line`], [`purpose::display`] |
//! | Proof statement rows of a `zkp_req` option | [`proof::rows`] |

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

pub use error::DisplayError;
pub use locale::{choose, Locale, LocaleError, Localized};
pub use text::{DisplayText, TextError, LABEL_MAX, VALUE_MAX};
