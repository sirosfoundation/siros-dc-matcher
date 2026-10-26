//! The nym_auth function catalogue of `zkp_req`, its systems, and the presenter and verifier
//! around a host's prover.
//!
//! The normative texts are `nym_auth_rulebook.md` (0.5), `systems/longfellow-nym_auth-v1.md`
//! and `systems/vega-nym_auth-v1.md` of the nym_auth rulebook repository at commit `e65861c`.
//!
//! | Module | Defines | Source |
//! | --- | --- | --- |
//! | [`catalogue`] | `pseudonym`, `age_check`, the query rules | Function catalogue |
//! | [`age`] | `range`, E and C | `age_check` |
//! | [`verifier_id`] | `verifier_id`, `verifier_input`, the `sha-256` pseudonym | `pseudonym` |
//! | [`system`] | The systems and the options each supports | System rulebooks, Sections 1 to 3 |
//! | [`session`] | The `Handover`, the device message, e2 | Binding; system rulebooks, Section 5 |
//! | [`policy`] | Signed requests, encrypted responses | Binding, Response confidentiality |
//! | [`mdoc`] | The ISO/IEC 18013-5 attestation | Attestation |
//! | [`checks`] | The Wallet's tests of a credential | System rulebooks, Section 7 |
//! | [`presenter`] | `match`, then `prove` in phases | `zkp_req`, Sections 1.3, 2.1, 3, 4 |
//! | [`prover`] | The statement and the prover interface | System rulebooks, Sections 3, 4, 7 |
//! | [`verify`] | The Verifier's checks | `zkp_req`, Section 4.1; system rulebooks, Section 9 |
//!
//! The provers stay outside. A host implements [`prover::NymAuthProver`] and
//! [`prover::NymAuthProofVerifier`] with a system's prover and verifier.
//!
//! Without the default feature `credential`, the crate holds the catalogue, the systems, the
//! session binding and the policy: what the credential picker needs.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::cognitive_complexity)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

pub mod age;
pub mod catalogue;
pub mod date;
pub mod outcome;
pub mod policy;
pub mod session;
pub mod system;
pub mod verifier_id;

#[cfg(feature = "credential")]
pub mod checks;
#[cfg(feature = "credential")]
pub mod mdoc;
#[cfg(feature = "credential")]
pub mod presenter;
#[cfg(feature = "credential")]
pub mod prover;
#[cfg(feature = "credential")]
pub mod verify;
#[cfg(feature = "credential")]
pub mod x509;

#[cfg(feature = "test-fixtures")]
pub mod testing;
