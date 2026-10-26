//! SD-JWT VC for the SIROS wallet core (RFC 9901).
//!
//! | Step | API | Requirement |
//! | --- | --- | --- |
//! | Read a stored credential | [`SdJwt::parse`] | S1: the checks of RFC 9901, Section 7.1 |
//! | Walk its claims | [`SdJwt::claims`], [`Object`], [`Claim`], [`ClaimValue`], [`Element`] | S2: issued array positions |
//! | Resolve a claims path pointer | [`SdJwt::root`] gives the [`Node`] that [`siros_dcql::resolve`] walks | Q4 |
//! | Select disclosures | [`SdJwt::select`] gives a [`Presentation`] | S3 |
//! | Bind the presentation to a key | [`Presentation::key_binding`] gives a [`KeyBinding`] | S4 |
//!
//! The issuer JWT is kept verbatim. Its signature and the validity claims (Section 7.1, steps
//! 2.a to 2.c and 6) are the caller's to check.
//!
//! The host signs [`KeyBinding::signing_input`] with ES256 and returns the raw `r ‖ s`
//! signature, which [`KeyBinding::assemble`] turns into the SD-JWT+KB.
//!
//! Types that hold claim values or salts implement no `Debug`, which keeps them out of logs
//! (R-G6).
//!
//! Nothing here panics on any input.

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

mod alg;
mod error;
mod json;
mod key_binding;
mod node;
mod process;
mod sd_jwt;
mod select;
mod tree;

pub use error::{KeyBindingError, ParseError};
pub use key_binding::{KeyBinding, Presentation};
pub use node::{Children, Node, NodeValue};
pub use process::MAX_DEPTH;
pub use sd_jwt::SdJwt;
pub use tree::{Claim, ClaimValue, DisclosureId, Element, Object};
