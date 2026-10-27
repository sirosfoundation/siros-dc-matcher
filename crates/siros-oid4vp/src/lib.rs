//! OpenID for Verifiable Presentations 1.0 for the SIROS wallet core.
//!
//! | Module | Defines | OpenID4VP 1.0 |
//! | --- | --- | --- |
//! | [`unverified`] | The request as the credential picker reads it (P2) | Appendix A |
//! | [`handover`] | The mdoc `Handover` and `SessionTranscript`, the JWK thumbprint | B.2.6 |
//! | [`semantic`] | The semantics identifier of a Wallet-Relying Party's certificate | ETSI TS 119 475, 5.1.3, 5.1.5 |
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

pub mod client_id;
pub mod error_code;
pub mod handover;
pub mod protocol;
mod request;
pub mod semantic;
pub mod unverified;

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
mod values;
#[cfg(feature = "crypto")]
pub mod verified;
#[cfg(feature = "crypto")]
mod x509;

pub use client_id::{ClientId, ClientIdError, ClientIdPrefix};
pub use error_code::ErrorCode;
pub use handover::{ec_jwk_thumbprint, Handover, HandoverInvalid, JwkThumbprint};
pub use protocol::Protocol;
pub use semantic::{Person, SemanticIdError, SemanticIdentifier};
pub use unverified::{diagnose, CompactFault, NoQuery, PayloadFault, UnverifiedRequest};

pub use fetch::{
    BodyLimit, Fetch, FetchResponse, HttpStatus, HttpsUrl, MediaType, Method, Redirects,
};
#[cfg(feature = "crypto")]
pub use intake::{
    AttestationClaim, AttestationFault, ChainFault, ClaimsFault, Coordinate, Effect, EffectResult,
    FormFault, IntakeError, IntakeState, JsonParameter, JwkFault, JwsError, JwsFault, KeyMaterial,
    LeafKeyFault, Step, Trust, TrustAnswer, TrustSubject, Verdict, VerifierInfoRule,
};
pub use request::{
    AttestationFormat, RequestSignature, ResponseMode, TransactionDataInvalid, TransactionDataItem,
};
#[cfg(feature = "crypto")]
pub use response::{
    concat_kdf, cose_kdf, read_reply, ContentKey, EncryptionFault, Presentation, RedirectUri,
    ReplyFault, ResponseError, Submission, VpToken,
};
#[cfg(feature = "crypto")]
pub use values::{AttestationIssuer, Kid, Nonce, Origin, State, TrustChain};
#[cfg(feature = "crypto")]
pub use verified::{
    AccessCertificate, CertificateDer, ContentEncryption, Encryption, VerifiedRequest, VerifierView,
};
