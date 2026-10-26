//! Presentation for the SIROS wallet core. Phase 1 maps a request and the wallet state to the
//! plan and its consent view; phase 2 maps the user's selection to the response and the
//! presentation record.
//!
//! | Requirement | API |
//! | --- | --- |
//! | A1: the format table, `meta`, holder binding, usable credentials, no undisclosable nym_auth attribute | [`Matching::new`] over [`MatchCredential`]s |
//! | A2: `zkp_req` matching as one selection, then the usable attestation and the opened seed | [`ZkpQuery`], [`Matching::answer`]; the wallet's tests in [`plan`] |
//! | A3: offers, optional additions (one option per set), optional sets joined for a transaction entry, all-optional sets, the subset of a `multiple` member | [`Offers::of`], [`Selection`] |
//! | A4: the digest of what the user consents to; the selection parsed against the recomputed plan | [`ConsentView::digest`], [`Selection`], [`Planned::choose`] gives a [`Chosen`] |
//! | A5: every signing input a `Sign` effect; the signatures parsed against them, each verifying under its key | [`Chosen::prepare`] gives [`Sign`]s, [`Prepared::finish`] |
//! | A6: the SD-JWT `aud` | [`Chosen::prepare`] |
//! | A7: the SessionTranscript of the request's `Handover` | [`Chosen::prepare`] |
//! | A8: one `vp_token`; `access_denied` on a decline; the record names the instances used | [`Prepared::finish`], [`Planned::decline`] |
//! | A9: the wallet's display, and its refusal in a background fulfilment | [`WalletDisplay::of`], [`Fulfilment`] |
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
mod matching;
mod offers;

pub use credential::MatchCredential;
pub use display_rule::{DisplayFacts, WalletDisplay};
pub use matching::{
    Answer, Answered, Answers, Asked, Candidate, Claims, Matching, ProofChoice, ZkpQuery,
};
pub use offers::{Addition, Member, Offer, Offers, MAX_ADDITIONS, MAX_EXAMINED, MAX_OFFERS};

#[cfg(feature = "wallet")]
mod error;
#[cfg(feature = "wallet")]
mod plan;
#[cfg(feature = "wallet")]
mod respond;

#[cfg(feature = "wallet")]
pub use error::PresentationError;
#[cfg(feature = "wallet")]
pub use plan::{
    plan, refusal, AdditionView, ConsentView, CredentialView, Fetches, MemberView, NoSeed,
    OfferView, PlanInput, PlanStep, Planned, Shown,
};
#[cfg(feature = "wallet")]
pub use respond::{Chosen, Fulfilment, Prepared, Response, Selection, Sign, SignId};
