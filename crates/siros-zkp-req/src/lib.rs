//! The `zkp_req` protocol layer: one implementation for the matcher, the wallet and the
//! verifier.
//!
//! The normative text is `zkp_req.md` of the nym_auth rulebook repository, draft 0.1 at commit
//! `e65861c`. This crate holds what the protocol defines for every function catalogue and
//! every system:
//!
//! | Module | Defines | `zkp_req` |
//! | --- | --- | --- |
//! | [`query`] | The Credential Query, `_req` and `_req_sets` | Sections 1.1, 2, 2.1 |
//! | [`formats`] | `vp_formats_supported.zkp_req` | Section 1.2 |
//! | [`select`] | The usable pair of a system and a proof backend | Section 1.3 |
//! | [`consent`] | Match, one consent screen, prove; the request's error code | Section 5 |
//! | [`presentation`] | `ZkpPresentation`, the backends' `Proof`, the `vp_token` | Sections 3, 4, 6.1 |
//! | [`structure`] | The Verifier's checks of a presentation, steps 1 to 5 | Section 4.1 |
//! | [`vp_token`] | The presentations of a query in a JSON `vp_token` | Section 6.1 |
//! | [`outcome`] | The error codes and the request rules | Section 5 |
//!
//! A function catalogue, such as `siros-zkp-req-nym-auth`, adds its functions and systems.
//! Proving stays outside: a host implements it behind the catalogue's prover interface.
//!
//! Nothing here panics on any input: the matcher runs this code inside the credential picker,
//! where a trap reads as "no matching credential".

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::cognitive_complexity)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub mod consent;
pub mod formats;
pub mod outcome;
pub mod presentation;
pub mod query;
pub mod select;
pub mod structure;
pub mod vp_token;

pub use consent::{failure_code, Candidate, Judged, Match, OptionRefusal, UserInput};
pub use formats::ZkpFormats;
pub use outcome::{ErrorCode, RequestRule};
pub use presentation::{
    vp_token_cbor, vp_token_json, EncodingError, ProofEnvelope, ZkpPresentation,
};
pub use query::{CredentialType, QueryOption, ReqItem, ReturnHandle, ZkpReqQuery};
pub use select::{usable_backend, PairRefusal, System};
pub use structure::{answered_option, StructureRejection};
pub use vp_token::{presentations_of, VpTokenError};
