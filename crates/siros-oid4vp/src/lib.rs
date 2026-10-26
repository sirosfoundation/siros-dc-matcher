//! OpenID for Verifiable Presentations 1.0 for the SIROS wallet core.
//!
//! | Module | Defines | OpenID4VP 1.0 |
//! | --- | --- | --- |
//! | [`unverified`] | The request as the credential picker reads it (P2) | Appendix A |
//! | [`handover`] | The mdoc `Handover` and `SessionTranscript`, the JWK thumbprint | B.2.6 |
//! | [`intake`] | Intake of redirect and DC API requests to a [`VerifiedRequest`] (P1, P3) | 5, 5.9, 5.10, A |
//! | [`verified`] | The verified request and its verifier | 5, 8.3 |
//! | [`response`] | `vp_token`, submissions, error submissions, the direct post reply (P4, P5) | 8 |
//!
//! Intake and the response need the `crypto` feature. Without it the crate holds what the
//! picker links, and builds with Rust 1.82.
//!
//! The crate performs no I/O. Intake asks the host for each fetch and trust evaluation as an
//! [`intake::Effect`], and randomness comes from the caller's CSPRNG.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::cognitive_complexity)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub mod error_code;
pub mod handover;
pub mod protocol;
pub mod unverified;

#[cfg(feature = "crypto")]
pub mod client_id;
#[cfg(feature = "crypto")]
pub mod fetch;
#[cfg(feature = "crypto")]
mod form;
#[cfg(feature = "crypto")]
pub mod intake;
#[cfg(feature = "crypto")]
mod jose;
#[cfg(feature = "crypto")]
pub mod response;
#[cfg(feature = "crypto")]
pub mod verified;
#[cfg(feature = "crypto")]
mod x509;

pub use error_code::ErrorCode;
pub use handover::{ec_jwk_thumbprint, Handover, HandoverInvalid};
pub use protocol::Protocol;
pub use unverified::{diagnose, NoQuery, UnverifiedQuery, UnverifiedRequest};

#[cfg(feature = "crypto")]
pub use client_id::{ClientId, ClientIdPrefix};
#[cfg(feature = "crypto")]
pub use fetch::{Fetch, FetchResponse, HttpsUrl, Method};
#[cfg(feature = "crypto")]
pub use intake::{
    Effect, EffectResult, IntakeError, IntakeState, KeyMaterial, Step, Trust, TrustAnswer,
    TrustSubject,
};
#[cfg(feature = "crypto")]
pub use response::{
    concat_kdf, cose_kdf, read_reply, Presentation, ResponseError, Submission, VpToken,
};
#[cfg(feature = "crypto")]
pub use verified::{
    AccessCertificate, ContentEncryption, Encryption, ResponseMode, VerifiedRequest, VerifierView,
};
