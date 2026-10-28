//! Presentation for the SIROS wallet core. Phase 1 maps a request and the wallet state to the
//! plan and its consent view.
//!
//! | Requirement | API |
//! | --- | --- |
//! | A1: the format table, `meta`, holder binding, usable credentials, no undisclosable nym_auth attribute; why a request has no offer | [`Matching::new`] over [`MatchCredential`]s, [`Failure`] |
//! | A2: `zkp_req` matching as one selection, then the usable attestation and the opened seed | [`ZkpQuery`], [`Matching::answer`]; the wallet's tests in [`plan`] |
//! | A3: offers, optional additions (one option per set), an optional set joined to an offer that carries no transaction entry, all-optional sets | [`Offers::of`] over [`EntryCarriers`] |
//! | A4: the digest of what the user consents to | [`ConsentView::digest`] |
//! | A9: the wallet's display | [`WalletDisplay::of`] |
//! | T4: each transaction entry bound to one credential, named by `credentialId` and instance in the view and the digest | [`CredentialView::entry`], [`CredentialView::entries`] |
//! | N2: the nym_auth request of a verified request, its `verifier_id` from the request's certificate | [`siros_zkp_req_nym_auth::request::NymAuthRequest`], built by [`plan`] from [`PlanInput::verifier_id`] |
//!
//! Without the default feature `wallet` the crate holds the matching ([`Matching`], [`Offers`],
//! [`WalletDisplay`]), for the credential picker to run over its registration projection (K2).
//! It builds with Rust 1.82 and links no crypto, prover or display resolution.
//!
//! The crate performs no I/O. The plan asks the host for each fetch, and the time is an input.

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
#![cfg_attr(test, allow(clippy::disallowed_methods))]

mod credential;
mod display_rule;
mod ids;
mod matching;
mod offers;

pub use credential::{KeyHolding, MatchCredential};
pub use display_rule::{Choice, DisplayFacts, Presentability, TransactionData, WalletDisplay};
pub use ids::{CandidateIndex, OptionIndex, QueryIndex, SetIndex};
pub use matching::{
    Answer, Answered, Answers, Asked, AskedError, Candidate, ChoiceError, Claims, Excluded,
    Failure, HolderBinding, Matching, ProofChoice, QueryRefusal, ZkpQuery, ZkpRefusal,
};
pub use offers::{
    Addition, EntryCarriers, EntryQueries, Member, Offer, Offers, Refusal, MAX_ADDITIONS,
    MAX_EXAMINED, MAX_OFFERS,
};

#[cfg(feature = "wallet")]
mod error;
#[cfg(feature = "wallet")]
mod plan;

#[cfg(feature = "wallet")]
pub use error::{Inconsistency, PresentationError};
#[cfg(feature = "wallet")]
pub use plan::{
    plan, AdditionView, ConsentView, CredentialView, EntryPosition, Fetches, JsonCause, MemberView,
    NoSeed, OfferView, OptionRefusal, PlanDigest, PlanInput, PlanStep, Planned, Shown, Unproven,
};
