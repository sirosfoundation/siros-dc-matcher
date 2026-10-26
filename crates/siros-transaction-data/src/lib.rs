//! OpenID4VP 1.0 transaction data for the SIROS wallet core: the `transaction_data` request
//! parameter, the transaction data types of EC TS12 v1.0.1, what each binds into a
//! presentation, and its display.
//!
//! | Requirement | API |
//! | --- | --- |
//! | T1: base64url JSON, no duplicate keys, string `type`, non-empty `credential_ids` of DCQL query ids | [`Entry::parse`] |
//! | T2: one implementation per type: parsing, authorizing credentials, display, bindings, extra KB-JWT claims | the crate's `TransactionType` trait and its registry, behind [`Entry`] |
//! | T3: the B.3.3.1 hashes, over each entry as received, one algorithm per credential | [`bind`], [`MemberBinding::kb_jwt_claims`], [`HashAlg`] |
//! | T4: an entry binds to the first of its `credential_ids` the chosen offer answers with a credential the type authorizes | [`bind`], [`Presented`] |
//! | T5: no binding under `require_cryptographic_holder_binding: false` | [`Entry::parse`] refuses such a query (B.3.3) |
//! | T6: the four TS12 types, SD-JWT VC only, typed payloads, hashes plus `jti`, `response_mode`, `amr`, display failing closed | [`Entry::parse`], [`KbJwtInputs`], [`Amr`], [`MemberBinding::views`] |
//! | T7: type metadata and referenced documents as host fetches under H1 | [`TypeMetadata::fetch`], [`Step::Fetch`], [`Fetched`] |
//!
//! Every refusal is a [`TransactionDataError`], which reaches the verifier as
//! `invalid_transaction_data` (Section 8.5).
//!
//! A presentation with transaction data goes through these steps:
//! 1. [`Entry::parse`] each string of the request's `transaction_data` against its DCQL query.
//! 2. For each SD-JWT VC that answers a query some entry names, have the host perform
//!    [`TypeMetadata::fetch`] and read the response with [`TypeMetadata::parse`].
//! 3. For each offer, [`bind`] the entries to the credentials it presents.
//! 4. Show [`MemberBinding::views`], fetching each document it asks for into [`Fetched`].
//! 5. Add [`MemberBinding::kb_jwt_claims`] to the KB-JWT of each bound credential.

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

mod amr;
mod binding;
mod entry;
mod error;
mod hash;
mod integrity;
mod json;
mod kind;
mod labels;
mod metadata;
mod ts12;
mod view;

pub use amr::{Amr, Factor, Inherence, Knowledge, Possession};
pub use binding::{bind, Jti, KbJwtInputs, MemberBinding, Presented};
pub use entry::Entry;
pub use error::TransactionDataError;
pub use hash::HashAlg;
pub use json::MAX_DEPTH;
pub use metadata::{Fetched, Step, TypeMetadata};
pub use view::{Frequency, Level, Row, RowValue, TransactionView};
