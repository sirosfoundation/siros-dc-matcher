//! `zkp_req` across the FFI boundary: the session of a request, the `vp_token` of presentations,
//! and the verifier's checks.
//!
//! The rules are those of `siros-zkp-req` and `siros-zkp-req-nym-auth`, at the nym_auth
//! rulebook draft (commit `e65861c`). Codes cross the boundary as their stable identifiers.

use std::sync::Arc;

use serde_json::Value;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::{Date, DateTime};
use siros_dcql::QueryId;
use siros_oid4vp::{ec_jwk_thumbprint, JwkThumbprint, Origin, SemanticIdentifier};
use siros_trust::Certificate;
use siros_zkp_req::{ErrorCode, ReqSetIndex, ResultKey, ZkProof, ZkpPresentation};
use siros_zkp_req_nym_auth::catalogue::MDOC_DOCTYPE;
use siros_zkp_req_nym_auth::presenter::Session;
use siros_zkp_req_nym_auth::prover::{NymAuthProofVerifier, ProofFailure, Statement};
use siros_zkp_req_nym_auth::request_object::{check_request, Channel, Signing};
use siros_zkp_req_nym_auth::verifier_id::{Intermediary, PseudonymValue, VerifierId};
use siros_zkp_req_nym_auth::verify::{verify, Rejection, Tolerance, VerifyInput};

/// Why a `zkp_req` call gave no result. `error_code` is what the wallet sends the verifier
/// for the request (`zkp_req`, Section 5); the rest is for the user and the logs.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ZkpReqError {
    /// The request breaks a rule of `zkp_req` or of the nym_auth catalogue.
    #[error("invalid request ({code})")]
    InvalidRequest {
        /// `invalid_request`.
        error_code: String,
        /// The rule's identifier.
        code: String,
    },
    /// An input of the host is not one the core can use.
    #[error("host input ({code})")]
    Host {
        /// `access_denied`.
        error_code: String,
        /// What is wrong.
        code: String,
    },
    /// The verifier refused a presentation.
    #[error("presentation refused ({code})")]
    Refused {
        /// The system rulebook's code (Section 9), or the step of `zkp_req`, Section 4.1.
        code: String,
        /// The failed check, for the logs. Its wording may change; match on `code`.
        detail: String,
    },
}

fn host(code: &str) -> ZkpReqError {
    ZkpReqError::Host {
        error_code: ErrorCode::AccessDenied.as_str().to_owned(),
        code: code.to_owned(),
    }
}

fn json(text: &str, what: &str) -> Result<Value, ZkpReqError> {
    serde_json::from_str(text).map_err(|_| host(what))
}

/// The channel a request arrived on.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiChannel {
    /// The Digital Credentials API, with the calling origin the platform reports.
    DcApi {
        /// The origin.
        origin: String,
    },
    /// Redirects, including a `request_uri` from a QR code or a link.
    Redirect,
}

/// The form of `verifier_id` the trust framework fixes, with what it is made from.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiVerifierIdForm {
    /// `semantic`: the end Relying Party's semantic identifier, from the registration
    /// certificate when present, else from the access certificate.
    Semantic {
        /// The semantic identifier.
        semantic_identifier: String,
    },
    /// `x509_san_dns`: the Client Identifier.
    X509SanDns {
        /// Whether the registration certificate names an intermediary.
        registration_names_intermediary: bool,
    },
}

/// The session a presentation is bound to.
#[derive(Debug, uniffi::Object)]
pub struct FfiSession(Session);

#[uniffi::export]
impl FfiSession {
    /// The CBOR `Handover` (OpenID4VP 1.0, B.2.6).
    pub fn handover(&self) -> Vec<u8> {
        self.0.handover.as_cbor().to_vec()
    }

    /// `verifier_id`.
    pub fn verifier_id(&self) -> String {
        self.0.verifier_id.as_str().to_owned()
    }
}

fn invalid(code: &str) -> ZkpReqError {
    ZkpReqError::InvalidRequest {
        error_code: ErrorCode::InvalidRequest.as_str().to_owned(),
        code: code.to_owned(),
    }
}

/// The session of a validated Request Object: the policy of signed requests and encrypted
/// responses, the `Handover` for the response-encryption key with this JWK thumbprint, and
/// `verifier_id` in the trust framework's form.
///
/// # Errors
///
/// [`ZkpReqError::InvalidRequest`] for a rule of the policy or of the verifier identity, and
/// [`ZkpReqError::Host`] for a thumbprint of no key in the request.
#[uniffi::export]
pub fn zkp_req_session(
    request_object_json: String,
    signed: bool,
    channel: FfiChannel,
    jwk_thumbprint: Vec<u8>,
    verifier_id: FfiVerifierIdForm,
) -> Result<Arc<FfiSession>, ZkpReqError> {
    let request = json(&request_object_json, "request_object_not_json")?;
    let channel = match channel {
        FfiChannel::DcApi { origin } => Channel::DcApi {
            origin: Origin::new(&origin),
        },
        FfiChannel::Redirect => Channel::Redirect,
    };
    let signing = if signed {
        Signing::Signed
    } else {
        Signing::Unsigned
    };
    let checked = check_request(&request, signing, channel).map_err(|r| invalid(r.code()))?;
    let thumbprint = JwkThumbprint::new(
        jwk_thumbprint
            .try_into()
            .map_err(|_| host("thumbprint_length"))?,
    );
    let handover = checked
        .handover(&thumbprint)
        .map_err(|_| host("thumbprint_not_in_request"))?;
    let verifier_id = match verifier_id {
        FfiVerifierIdForm::Semantic {
            semantic_identifier,
        } => VerifierId::semantic(
            &SemanticIdentifier::parse_stated(&semantic_identifier)
                .map_err(|e| invalid(e.code()))?,
        ),
        FfiVerifierIdForm::X509SanDns {
            registration_names_intermediary,
        } => {
            let client_id = checked.client_id();
            let intermediary = if registration_names_intermediary {
                Intermediary::Named
            } else {
                Intermediary::Absent
            };
            VerifierId::x509_san_dns(client_id, intermediary).map_err(|r| invalid(r.code()))?
        }
    };
    Ok(Arc::new(FfiSession(Session {
        handover,
        verifier_id,
    })))
}

/// The JWK SHA-256 Thumbprint (RFC 7638) of an elliptic-curve JWK.
///
/// # Errors
///
/// [`ZkpReqError::Host`] for text that is no EC JWK.
#[uniffi::export]
pub fn zkp_req_jwk_thumbprint(jwk_json: String) -> Result<Vec<u8>, ZkpReqError> {
    let jwk = json(&jwk_json, "jwk_not_json")?;
    ec_jwk_thumbprint(&jwk)
        .map(|t| t.as_bytes().to_vec())
        .ok_or_else(|| host("jwk_not_ec"))
}

/// The public values of a proof (system rulebooks, Section 4).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiStatement {
    /// The system.
    pub system_id: String,
    /// The proof backend.
    pub proof_backend: String,
    /// The `docType` the circuits check.
    pub doc_type: String,
    /// The Document Signer certificate, DER.
    pub issuer_certificate: Vec<u8>,
    /// The issuer key Q: x, big-endian.
    pub issuer_key_x: Vec<u8>,
    /// The issuer key Q: y, big-endian.
    pub issuer_key_y: Vec<u8>,
    /// T: `YYYY-MM-DDThh:mm:ssZ`.
    pub proof_time: String,
    /// E: `YYYY-MM-DD`; `None` for the system's widest value.
    pub earliest: Option<String>,
    /// C: `YYYY-MM-DD`; `None` for the system's widest value.
    pub cutoff: Option<String>,
    /// `verifier_input`.
    pub verifier_input: Vec<u8>,
    /// The encoded `SessionTranscript`.
    pub session_transcript: Vec<u8>,
    /// e2.
    pub challenge_digest: Vec<u8>,
}

fn full_date(d: Option<Date>) -> Option<String> {
    d.and_then(Date::to_full_date)
}

impl From<&Statement> for FfiStatement {
    fn from(s: &Statement) -> Self {
        Self {
            system_id: s.system.id().as_str().to_owned(),
            proof_backend: s.proof_backend.as_str().to_owned(),
            doc_type: MDOC_DOCTYPE.to_owned(),
            issuer_certificate: s.issuer.certificate().der().to_vec(),
            issuer_key_x: s.issuer.key().x().to_vec(),
            issuer_key_y: s.issuer.key().y().to_vec(),
            proof_time: s.proof_time.to_string(),
            earliest: full_date(s.earliest),
            cutoff: full_date(s.cutoff),
            verifier_input: s.verifier_input.as_bytes().to_vec(),
            session_transcript: s.session_transcript.as_bytes().to_vec(),
            challenge_digest: s.challenge_digest.as_bytes().to_vec(),
        }
    }
}

/// The presentations of one answered query.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiVpTokenEntry {
    /// The Credential Query's `id`.
    pub query_id: String,
    /// The CBOR presentations.
    pub presentations: Vec<Vec<u8>>,
}

fn answers(
    entries: Vec<FfiVpTokenEntry>,
) -> Result<Vec<(QueryId, Vec<ZkpPresentation>)>, ZkpReqError> {
    entries
        .into_iter()
        .map(|e| {
            let query_id = QueryId::parse(&e.query_id).map_err(|e| host(e.code()))?;
            let presentations = e
                .presentations
                .iter()
                .map(|p| ZkpPresentation::decode(p).map_err(|_| host("presentation_not_cbor")))
                .collect::<Result<_, _>>()?;
            Ok((query_id, presentations))
        })
        .collect()
}

/// The `vp_token` of JSON Response Modes (`zkp_req`, Section 6.1): each presentation is the
/// base64url, without padding, of its CBOR.
///
/// # Errors
///
/// [`ZkpReqError::Host`] for bytes that are no presentation.
#[uniffi::export]
pub fn zkp_req_vp_token_json(entries: Vec<FfiVpTokenEntry>) -> Result<String, ZkpReqError> {
    Ok(siros_zkp_req::vp_token_json(&answers(entries)?).to_string())
}

/// The `vp_token` of `direct_post.cwt` (`zkp_req`, Section 6.1), CBOR: each presentation is
/// the map itself.
///
/// # Errors
///
/// [`ZkpReqError::Host`] for bytes that are no presentation.
#[uniffi::export]
pub fn zkp_req_vp_token_cbor(entries: Vec<FfiVpTokenEntry>) -> Result<Vec<u8>, ZkpReqError> {
    Ok(siros_zkp_req::vp_token_cbor(&answers(entries)?).encode())
}

/// What a system's verifier says of a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiProofCheck {
    /// The proof verifies.
    Accepted,
    /// `zk_proof` breaks the backend's format.
    Encoding,
    /// A circuit's proof fails.
    Invalid,
    /// The proof's public values differ from the statement.
    PublicInput,
    /// The verifier failed on its own inputs, artifacts or code, and judged nothing.
    Internal,
}

/// A system's verifier, implemented by the host.
#[uniffi::export(with_foreign)]
pub trait FfiProofVerifier: Send + Sync {
    /// Verifies `zk_proof` against `statement` and the pseudonym of `results`.
    fn verify(
        &self,
        statement: FfiStatement,
        pseudonym: Vec<u8>,
        zk_proof: Vec<u8>,
    ) -> FfiProofCheck;
}

struct ForeignVerifier(Arc<dyn FfiProofVerifier>);

impl NymAuthProofVerifier for ForeignVerifier {
    fn verify(
        &self,
        statement: &Statement,
        pseudonym: &PseudonymValue,
        zk_proof: &ZkProof,
    ) -> Result<(), ProofFailure> {
        match self.0.verify(
            statement.into(),
            pseudonym.as_bytes().to_vec(),
            zk_proof.as_bytes().to_vec(),
        ) {
            FfiProofCheck::Accepted => Ok(()),
            FfiProofCheck::Encoding => Err(ProofFailure::Encoding),
            FfiProofCheck::Invalid => Err(ProofFailure::Invalid),
            FfiProofCheck::PublicInput => Err(ProofFailure::PublicInput),
            FfiProofCheck::Internal => Err(ProofFailure::Internal),
        }
    }
}

/// What an accepted presentation establishes.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiVerified {
    /// The system.
    pub system_id: String,
    /// The proof backend.
    pub proof_backend: String,
    /// The answered option's index in `_req_sets`.
    pub req_set: Option<u64>,
    /// `results`: each handle and its result, CBOR.
    pub results: Vec<FfiResult>,
    /// The Document Signer certificate the proof was made against.
    pub issuer_certificate: Vec<u8>,
    /// The proof time, `YYYY-MM-DDThh:mm:ssZ`.
    pub proof_time: String,
}

/// One entry of `results`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiResult {
    /// The `return` handle.
    pub handle: String,
    /// The result, CBOR: a `bstr` pseudonym or `true`.
    pub value: Vec<u8>,
}

fn rejection(r: &Rejection) -> ZkpReqError {
    ZkpReqError::Refused {
        code: r.code().to_owned(),
        detail: format!("{r:?}"),
    }
}

/// Verifies a presentation against the verifier's own query, session, clock and
/// `trust_anchors` (DER certificates), with the host's proof verifier.
///
/// # Errors
///
/// [`ZkpReqError::Refused`] with the system rulebook's code, and [`ZkpReqError::Host`] with
/// the certificate's code for a trust anchor that does not parse.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn zkp_req_verify(
    query_json: String,
    client_metadata_json: String,
    session: Arc<FfiSession>,
    presentation: Vec<u8>,
    now: i64,
    tolerance_future: i64,
    tolerance_past: i64,
    trust_anchors: Vec<Vec<u8>>,
    verifier: Arc<dyn FfiProofVerifier>,
) -> Result<FfiVerified, ZkpReqError> {
    let query = json(&query_json, "query_not_json")?;
    let metadata = json(&client_metadata_json, "client_metadata_not_json")?;
    let trust_anchors: Vec<Certificate> = trust_anchors
        .iter()
        .map(|der| Certificate::parse(der).map_err(|e| host(e.code())))
        .collect::<Result<_, _>>()?;
    let now = DateTime::from_unix(now).ok_or_else(|| host("now_out_of_range"))?;
    let seconds = |s: i64| u32::try_from(s).map_err(|_| host("tolerance_out_of_range"));
    let tolerance = Tolerance::seconds(seconds(tolerance_future)?, seconds(tolerance_past)?);
    let verified = verify(
        &VerifyInput {
            query: &query,
            client_metadata: &metadata,
            session: &session.0,
            presentation: &presentation,
            now,
            tolerance,
            trust_anchors: &trust_anchors,
        },
        &ForeignVerifier(verifier),
    )
    .map_err(|r| rejection(&r))?;
    Ok(FfiVerified {
        system_id: verified.system.id().as_str().to_owned(),
        proof_backend: verified.proof_backend.as_str().to_owned(),
        req_set: verified.req_set.map(ReqSetIndex::as_u64),
        results: verified
            .results
            .iter()
            .map(|(handle, value): &(ResultKey, Cbor)| FfiResult {
                handle: handle.as_str().to_owned(),
                value: value.encode(),
            })
            .collect(),
        issuer_certificate: verified.issuer.certificate().der().to_vec(),
        proof_time: verified.proof_time.to_string(),
    })
}
