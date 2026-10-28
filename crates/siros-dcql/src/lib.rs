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
//! [`query`] is the wire model (§6.1–6.3), [`id`] the Credential Query id
//! (§6.1), [`path`] resolves claims path pointers over any claim tree (§7), and
//! [`eval`] performs selection (§6.4).
//!
//! [oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

#![deny(missing_docs)]
#![deny(unsafe_code)]
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
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod eval;
pub mod id;
pub mod path;
pub mod query;

pub use eval::{
    execute, Candidate, Combination, Combinations, Credential, Dropped, ExactFormat, Policy,
    QueryMatch, QueryResult, SelectedClaim,
};
pub use id::{QueryId, QueryIdError};
pub use path::{
    mdoc_components, resolve, resolve_json, ClaimNode, Lookup, PathComponent, PathError,
};
pub use query::{ClaimsQuery, CredentialQuery, CredentialSetQuery, DcqlQuery, QueryError};
