//! Digital Credentials Query Language (DCQL), as defined by
//! [OpenID for Verifiable Presentations 1.0][oid4vp] §6.
//!
//! A DCQL query is how a verifier states what it wants. It carries a list of
//! [`CredentialQuery`] entries — each constrained by format, type and claims —
//! and optionally a list of [`CredentialSetQuery`] entries expressing which
//! *combinations* of those would satisfy the request. A query is constructed only by parsing.
//!
//! [`execute`] evaluates such a query against anything implementing
//! [`Credential`], with format and metadata matching delegated to a
//! [`Policy`] — §6.1 defines `meta` per credential format, so a generic
//! engine cannot interpret it. The crate does no I/O and has no opinion about
//! how credentials are stored, which is what lets the same engine run inside
//! a WebAssembly sandbox, in a Kotlin wallet, and in a Swift one.
//!
//! # Layout
//!
//! [`query`] is the wire model (§6.1–6.3), [`authority`] its `trusted_authorities`
//! (§6.1.1), [`path`] resolves claims path pointers (§7), and [`eval`] performs selection
//! (§6.4).
//!
//! [oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub mod authority;
mod combinations;
pub mod eval;
pub mod id;
pub mod path;
pub mod query;
mod result;

pub use authority::{
    AuthorityType, AuthorityValue, TrustedAuthorities, TrustedAuthority, TrustedAuthorityError,
};
pub use combinations::{Combination, Combinations, Dropped};
pub use eval::{execute, select_claims, Credential, CryptographicBinding, ExactFormat, Policy};
pub use id::{ClaimId, ClaimIdError, QueryId, QueryIdError};
pub use path::{
    mdoc_components, resolve, resolve_json, ClaimNode, ComponentIndex, Lookup, PathComponent,
    PathError,
};
pub use query::{
    ClaimsQuery, CredentialFormat, CredentialQuery, CredentialSetQuery, DcqlQuery, HolderBinding,
    Multiplicity, QueryError, SetRequirement,
};
pub use result::{Candidate, QueryMatch, QueryResult, Satisfaction, SelectedClaim};
