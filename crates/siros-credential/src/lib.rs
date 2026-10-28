//! The format-independent credential of the SIROS wallet core.
//!
//! | Requirement | API |
//! | --- | --- |
//! | C1: constructible only by parsing a wallet state entry through the format components | [`Credential::parse`] |
//! | C2: claim values keep their type; the credential reads them from the format's own tree | [`Credential::parse`] refuses a value of none of the ten types; [`TypedValue`], [`Array`], [`Object`] |
//! | C3: claims path pointers, through Q4 for SD-JWT VC and as `[namespace, element]` for mdoc | [`ClaimPointer`], [`Credential::claims`], `impl siros_dcql::Credential` |
//! | C4: validity at a given time | [`UsableCredential::at`] |
//! | C5: the instance used for a batch | [`least_used`] over any [`Instance`] |
//!
//! A credential gives its entry reference, format, type, issuer, configuration id, validity,
//! key identifier and the `auxiliary_data` its issuer delivered. Types that hold claim values
//! or delivered secrets implement no `Debug` (R-G6).

#![deny(missing_docs)]
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
        clippy::disallowed_methods
    )
)]

mod credential;
mod error;
mod instance;
mod pointer;
mod resolve;
mod sd_jwt_vc;
mod usable;
mod value;

pub use credential::{Credential, EntryRef, Format, Parsed};
pub use error::{CredentialError, HolderKeyError, PointerError, ValidityError};
pub use instance::{least_used, Instance};
pub use pointer::ClaimPointer;
pub use usable::{UsableCredential, Validity};
pub use value::{Array, Elements, Members, Object, TypedValue};
