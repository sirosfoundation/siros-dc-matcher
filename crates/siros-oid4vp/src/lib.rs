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

pub mod client_id;
pub mod error_code;
pub mod handover;
pub mod protocol;
pub mod semantic;
pub mod unverified;

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
pub use unverified::{
    diagnose, CompactFault, NoQuery, PayloadFault, UnverifiedQuery, UnverifiedRequest,
};

#[cfg(feature = "crypto")]
pub use fetch::{BodyLimit, Fetch, FetchResponse, HttpStatus, HttpsUrl, MediaType, Method};
#[cfg(feature = "crypto")]
pub use intake::{
    AttestationFault, ChainFault, Effect, EffectResult, FormFault, IntakeError, IntakeState,
    JwsError, JwsFault, KeyMaterial, Step, Trust, TrustAnswer, TrustSubject, Verdict,
    VerifierInfoRule,
};
#[cfg(feature = "crypto")]
pub use response::{
    concat_kdf, cose_kdf, read_reply, ContentKey, EncryptionFault, Presentation, RedirectUri,
    ReplyFault, ResponseError, Submission, VpToken,
};
#[cfg(feature = "crypto")]
pub use values::{AttestationIssuer, Kid, Nonce, Origin, State, TransactionDataItem, TrustChain};
#[cfg(feature = "crypto")]
pub use verified::{
    AccessCertificate, AttestationFormat, CertificateDer, ContentEncryption, Encryption,
    ResponseMode, VerifiedRequest, VerifierView,
};
#[cfg(feature = "crypto")]
pub use x509::X509Chain;
