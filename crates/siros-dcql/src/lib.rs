//! Digital Credentials Query Language (DCQL), as defined by
//! [OpenID for Verifiable Presentations 1.0][oid4vp] §6.
//!
//! A DCQL query is how a verifier states what it wants. It carries a list of
//! [`CredentialQuery`] entries — each constrained by format, type and claims —
//! and optionally a list of [`CredentialSetQuery`] entries expressing which
//! *combinations* of those would satisfy the request.
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
//! [`query`] is the wire model (§6.1–6.3), [`path`] resolves claims path
//! pointers (§7), and [`eval`] performs selection (§6.4).
//!
//! [oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod eval;
pub mod path;
pub mod query;

pub use eval::{
    execute, Candidate, Combination, Combinations, Credential, ExactFormat, Policy, QueryMatch,
    QueryResult, SelectedClaim,
};
pub use path::{mdoc_components, resolve_json, PathComponent, PathError};
pub use query::{ClaimsQuery, CredentialQuery, CredentialSetQuery, DcqlQuery};
