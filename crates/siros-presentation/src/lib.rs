//! Presentation for the SIROS wallet core. Phase 1 maps a request and the wallet state to the
//! plan and its consent view; phase 2 maps the user's selection to the response and the
//! presentation record.
//!
//! | Requirement | API |
//! | --- | --- |
//! | A1: the format table, `meta`, holder binding, usable credentials, no undisclosable nym_auth attribute; why a request has no offer | [`Matching::new`] over [`MatchCredential`]s, [`Failure`] |
//! | A2: `zkp_req` matching as one selection, then the usable attestation and the opened seed | [`ZkpQuery`], [`Matching::answer`]; the wallet's tests in [`plan`] |
//! | A3: offers, optional additions (one option per set), an optional set joined to an offer that carries no transaction entry, all-optional sets, the subset of a `multiple` member by `credentialId` | [`Offers::of`] over [`EntryCarriers`], [`Selection`] with [`Subset`] |
//! | A4: the digest of what the user consents to; the selection parsed against the recomputed plan | [`ConsentView::digest`], [`PlanDigest::parse`], [`Selection`], [`Planned::choose`] gives a [`Chosen`] |
//! | A5: every signing input a `Sign` effect; the signatures parsed against them, each verifying under its key | [`Chosen::prepare`] gives [`Sign`]s, [`Prepared::finish`] |
//! | A6: the SD-JWT `aud` | [`Chosen::prepare`] |
//! | A7: the SessionTranscript of the request's `Handover` | [`Chosen::prepare`] |
//! | A8: one `vp_token`; `access_denied` on a decline; the record names the instances used | [`Prepared::finish`], [`Planned::decline`] |
//! | A9: the wallet's display, and its refusal in a background fulfilment | [`WalletDisplay::of`], [`Fulfilment`] |
//! | T4: each transaction entry bound to one credential, named by `credentialId` and instance in the view and the digest; a selection that leaves it out refused | [`CredentialView::entry`], [`CredentialView::entries`], [`PresentationError::BoundCredentialOmitted`] |
//! | K3: the selection from the credential picker's picked entries, checked against the plan | [`Pick`], [`Planned::picked`] |
//! | N2: the nym_auth request of a verified request, its `verifier_id` from the request's certificate | [`siros_zkp_req_nym_auth::request::NymAuthRequest`], built by [`plan`] from [`PlanInput::verifier_id`] |
//!
//! Without the default feature `wallet` the crate holds the matching ([`Matching`], [`Offers`],
//! [`WalletDisplay`]): what the credential picker runs over its registration projection. It
//! builds with Rust 1.82 and links no crypto, prover or display resolution.
//!
//! The crate performs no I/O. The plan asks the host for each fetch, phase 2 asks it for each
//! signature, randomness comes from the caller's CSPRNG, and the time is an input.

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

mod credential;
mod display_rule;
mod ids;
mod matching;
mod offers;

pub use credential::{KeyHolding, MatchCredential};
pub use display_rule::{Choice, DisplayFacts, Presentability, TransactionData, WalletDisplay};
pub use ids::{AdditionIndex, CandidateIndex, OfferIndex, OptionIndex, QueryIndex, SetIndex};
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
mod respond;

#[cfg(feature = "wallet")]
pub use error::{Inconsistency, PresentationError};
#[cfg(feature = "wallet")]
pub use plan::{
    plan, refusal, AdditionView, ConsentView, CredentialView, DigestError, EntryPosition, Fetches,
    JsonCause, MemberView, NoSeed, OfferView, OptionRefusal, PlanDigest, PlanInput, PlanStep,
    Planned, Shown, Unproven,
};
#[cfg(feature = "wallet")]
pub use respond::{
    Chosen, Fulfilment, Pick, PickError, Prepared, Response, Selection, Sign, SignId,
    SignatureError, Subset, SubsetError,
};
