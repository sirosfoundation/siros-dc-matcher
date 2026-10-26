//! The `zkp_req` presenter, across the FFI boundary: match, then the wallet's one consent
//! screen, then prove in phases, and the verifier's checks.
//!
//! Proving stays with the host. The presenter gives the host the data its device key signs and
//! the job a system's prover runs (zk-cred-longfellow, zk-cred-vega), and assembles the
//! presentation from the prover's output. Every call checks everything again: nothing is kept
//! between calls.
//!
//! The rules are those of `siros-zkp-req` and `siros-zkp-req-nym-auth`, at the nym_auth
//! rulebook draft (commit `e65861c`). Codes cross the boundary as their stable identifiers.

use std::sync::Arc;

use serde_json::Value;
use siros_codec::cbor::Value as Cbor;
use siros_oid4vp::ec_jwk_thumbprint;
use siros_zkp_req::{Candidate, ErrorCode, Match, ZkpPresentation};
use siros_zkp_req_nym_auth::date::Date;
use siros_zkp_req_nym_auth::mdoc::StoredCredential;
use siros_zkp_req_nym_auth::outcome::ZkpError;
use siros_zkp_req_nym_auth::policy::{check_request, Channel};
use siros_zkp_req_nym_auth::presenter::{
    match_query, prepare, MatchInput, NymAuthMatch, Prepared, ProveError, ProveInput, Session,
};
use siros_zkp_req_nym_auth::prover::{NymAuthProofVerifier, ProofFailure, ProofOutput, Statement};
use siros_zkp_req_nym_auth::system::{pair_code, NymAuthSystem};
use siros_zkp_req_nym_auth::verifier_id::VerifierId;
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
    /// The credential cannot answer the candidate's option.
    #[error("the credential cannot answer ({errors:?})")]
    Rejected {
        /// `access_denied`.
        error_code: String,
        /// Each failure, with the system rulebook's code.
        errors: Vec<FfiZkpError>,
    },
    /// The candidate's system and backend no longer form a usable pair for its option.
    #[error("unsupported ({code})")]
    Unsupported {
        /// `access_denied`.
        error_code: String,
        /// Why the pair is not usable.
        code: String,
    },
    /// An input of the host, or the prover's output, is not one the presenter can use.
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

/// A credential the wallet stores.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiStoredCredential {
    /// The wallet's identifier.
    pub id: String,
    /// The credential format, `mso_mdoc`.
    pub format: String,
    /// The credential as issued: base64url without padding of an `IssuerSigned`, a `Document`
    /// or a one-document `DeviceResponse`.
    pub data: String,
    /// The identifier of the device key.
    pub kid: String,
}

impl From<FfiStoredCredential> for StoredCredential {
    fn from(c: FfiStoredCredential) -> Self {
        Self {
            id: c.id,
            format: c.format,
            data: c.data,
            kid: c.kid,
        }
    }
}

/// A credential, option, system and proof backend that answer a query.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCandidate {
    /// The wallet's identifier of the credential.
    pub credential_id: String,
    /// The system of the pair.
    pub system_id: String,
    /// The proof backend of the pair.
    pub proof_backend: String,
    /// The option's index in `_req_sets`; `None` without them.
    pub req_set: Option<u64>,
    /// The `_req` indexes of the option.
    pub items: Vec<u64>,
}

/// An index across the boundary: `usize` fits `u64` on every target.
fn index(i: usize) -> u64 {
    i as u64
}

/// An index from the host.
fn from_index(i: u64) -> Result<usize, ZkpReqError> {
    usize::try_from(i).map_err(|_| host("index_out_of_range"))
}

impl From<&Candidate> for FfiCandidate {
    fn from(c: &Candidate) -> Self {
        Self {
            credential_id: c.credential_id.clone(),
            system_id: c.system_id.clone(),
            proof_backend: c.proof_backend.clone(),
            req_set: c.req_set.map(index),
            items: c.items.iter().map(|&i| index(i)).collect(),
        }
    }
}

impl FfiCandidate {
    fn to_candidate(&self) -> Result<Candidate, ZkpReqError> {
        Ok(Candidate {
            credential_id: self.credential_id.clone(),
            system_id: self.system_id.clone(),
            proof_backend: self.proof_backend.clone(),
            req_set: self.req_set.map(from_index).transpose()?,
            items: self
                .items
                .iter()
                .map(|&i| from_index(i))
                .collect::<Result<_, _>>()?,
            inputs: Vec::new(),
        })
    }
}

/// Why a credential cannot answer: an item's failure, or the credential's.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiZkpError {
    /// The system rulebook's code (Section 9): `age_out_of_range`, `seed_mismatch`,
    /// `validity`, `issuer_signature`, `issuer_untrusted`, `device_binding`,
    /// `credential_form`.
    pub code: String,
    /// The `_req` index of a failing item; `None` for the credential's own checks.
    pub item: Option<u64>,
    /// The option's index in `_req_sets` of a failing item.
    pub req_set: Option<u64>,
}

impl From<&ZkpError> for FfiZkpError {
    fn from(e: &ZkpError) -> Self {
        let (item, req_set) = match e {
            ZkpError::Item { option, item, .. } => (Some(index(*item)), option.map(index)),
            ZkpError::Credential(_) => (None, None),
        };
        Self {
            code: e.code().to_owned(),
            item,
            req_set,
        }
    }
}

/// A credential that cannot answer, and why.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiJudged {
    /// The wallet's identifier of the credential.
    pub credential_id: String,
    /// The failures, in the verifier's order of options.
    pub errors: Vec<FfiZkpError>,
}

/// Why a system forms no usable pair for an option.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPairRefusal {
    /// The system.
    pub system_id: String,
    /// `system_not_listed`, `no_listed_backend`, `credential_type`, or the system's
    /// `unsupported` reason.
    pub code: String,
}

/// An option without a usable pair.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiOptionRefusal {
    /// The option's index in `_req_sets`; `None` without them.
    pub req_set: Option<u64>,
    /// Each system's refusal.
    pub systems: Vec<FfiPairRefusal>,
}

/// The outcome of matching one query.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiZkpMatch {
    /// The credentials that can answer, best first: show the consent screen.
    Candidates {
        /// The candidates.
        candidates: Vec<FfiCandidate>,
    },
    /// No credential can answer: send `access_denied`.
    Rejected {
        /// Each credential that matched the query's type, and why it cannot answer.
        rejected: Vec<FfiJudged>,
    },
    /// No option has a usable pair: send `vp_formats_not_supported`.
    Unsupported {
        /// Each option and why.
        options: Vec<FfiOptionRefusal>,
    },
    /// The query breaks a rule: send `invalid_request`.
    Invalid {
        /// The rule's identifier.
        code: String,
    },
}

impl From<NymAuthMatch> for FfiZkpMatch {
    fn from(m: NymAuthMatch) -> Self {
        match m {
            Match::Candidates(c) => Self::Candidates {
                candidates: c.iter().map(FfiCandidate::from).collect(),
            },
            Match::Rejected(judged) => Self::Rejected {
                rejected: judged
                    .iter()
                    .map(|j| FfiJudged {
                        credential_id: j.credential_id.clone(),
                        errors: j.errors.iter().map(FfiZkpError::from).collect(),
                    })
                    .collect(),
            },
            Match::Unsupported(options) => Self::Unsupported {
                options: options
                    .iter()
                    .map(|o| FfiOptionRefusal {
                        req_set: o.req_set.map(index),
                        systems: o
                            .systems
                            .iter()
                            .map(|(system_id, r)| FfiPairRefusal {
                                system_id: system_id.clone(),
                                code: pair_code(r).to_owned(),
                            })
                            .collect(),
                    })
                    .collect(),
            },
            Match::Invalid(rule) => Self::Invalid {
                code: rule.code().to_owned(),
            },
        }
    }
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

fn parse_systems(ids: &[String]) -> Result<Vec<NymAuthSystem>, ZkpReqError> {
    ids.iter()
        .map(|id| NymAuthSystem::from_id(id).ok_or_else(|| host("system_unknown")))
        .collect()
}

/// Matches one `zkp_req` Credential Query against the wallet's credentials.
///
/// `query_json` is the Credential Query, `client_metadata_json` the request's
/// `client_metadata`. `credentials` are those of the query's format and type, a superset is
/// fine. `anchors` are the DER certificates the query's `trusted_authorities` designate,
/// required when it has some. `systems` are the system ids the host proves, in the wallet's
/// order of preference. `now` is the wallet's clock in seconds since the epoch.
///
/// # Errors
///
/// [`ZkpReqError::Host`] for an input the presenter cannot use.
#[uniffi::export]
pub fn zkp_req_match(
    query_json: String,
    client_metadata_json: String,
    credentials: Vec<FfiStoredCredential>,
    anchors: Option<Vec<Vec<u8>>>,
    systems: Vec<String>,
    now: i64,
) -> Result<FfiZkpMatch, ZkpReqError> {
    let query = json(&query_json, "query_not_json")?;
    let metadata = json(&client_metadata_json, "client_metadata_not_json")?;
    let credentials: Vec<StoredCredential> = credentials.into_iter().map(Into::into).collect();
    let systems = parse_systems(&systems)?;
    let matched = match_query(&MatchInput {
        query: &query,
        client_metadata: &metadata,
        credentials: &credentials,
        anchors: anchors.as_deref(),
        systems: &systems,
        now,
    })
    .map_err(|e| host(e.code()))?;
    Ok(matched.into())
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
        FfiChannel::DcApi { origin } => Channel::DcApi { origin },
        FfiChannel::Redirect => Channel::Redirect,
    };
    let checked = check_request(&request, signed, channel).map_err(|r| invalid(r.code()))?;
    let thumbprint: [u8; 32] = jwk_thumbprint
        .try_into()
        .map_err(|_| host("thumbprint_length"))?;
    let handover = checked
        .handover(&thumbprint)
        .map_err(|_| host("thumbprint_not_in_request"))?;
    let verifier_id = match verifier_id {
        FfiVerifierIdForm::Semantic {
            semantic_identifier,
        } => VerifierId::semantic(&semantic_identifier),
        FfiVerifierIdForm::X509SanDns {
            registration_names_intermediary,
        } => VerifierId::x509_san_dns(&checked.client_id, registration_names_intermediary),
    }
    .map_err(|r| invalid(r.code()))?;
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
        .map(|t| t.to_vec())
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
            system_id: s.system.id().to_owned(),
            proof_backend: s.proof_backend.clone(),
            doc_type: s.doc_type.to_owned(),
            issuer_certificate: s.issuer_certificate.clone(),
            issuer_key_x: s.issuer_key.x.to_vec(),
            issuer_key_y: s.issuer_key.y.to_vec(),
            proof_time: s.proof_time.to_string(),
            earliest: full_date(s.earliest),
            cutoff: full_date(s.cutoff),
            verifier_input: s.verifier_input.to_vec(),
            session_transcript: s.session_transcript.clone(),
            challenge_digest: s.challenge_digest.to_vec(),
        }
    }
}

/// What a system's prover needs.
#[derive(Clone, uniffi::Record)]
pub struct FfiProofJob {
    /// The public values.
    pub statement: FfiStatement,
    /// The credential's `IssuerSigned`, as issued.
    pub issuer_signed: Vec<u8>,
    /// The 16-byte `secret_seed`. The host zeroes its copy after proving.
    pub secret_seed: Vec<u8>,
    /// The device signature, `r ‖ s`, verified under the MSO's device key.
    pub device_signature: Vec<u8>,
}

impl std::fmt::Debug for FfiProofJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiProofJob")
            .field("statement", &self.statement)
            .finish_non_exhaustive()
    }
}

fn prove_error(e: ProveError) -> ZkpReqError {
    let access_denied = ErrorCode::AccessDenied.as_str().to_owned();
    match e {
        ProveError::Invalid(rule) => invalid(rule.code()),
        ProveError::Rejected(errors) => ZkpReqError::Rejected {
            error_code: access_denied,
            errors: errors.iter().map(FfiZkpError::from).collect(),
        },
        ProveError::NotUsable(refusal) => ZkpReqError::Unsupported {
            error_code: access_denied,
            code: pair_code(&refusal).to_owned(),
        },
        other => host(other.code()),
    }
}

/// A presentation ready for the device signature, then for the prover.
#[derive(uniffi::Object)]
pub struct FfiPrepared(Prepared);

/// Checks the consented candidate again and builds its statement (system rulebooks,
/// Section 7). The same inputs as [`zkp_req_match`], with the session and the credential's
/// delivered `secret_seed`.
///
/// # Errors
///
/// [`ZkpReqError`]: what fails, with the Section 9 codes.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn zkp_req_prepare(
    candidate: FfiCandidate,
    query_json: String,
    client_metadata_json: String,
    session: Arc<FfiSession>,
    credential: FfiStoredCredential,
    secret_seed: Vec<u8>,
    anchors: Option<Vec<Vec<u8>>>,
    now: i64,
) -> Result<Arc<FfiPrepared>, ZkpReqError> {
    let query = json(&query_json, "query_not_json")?;
    let metadata = json(&client_metadata_json, "client_metadata_not_json")?;
    let credential: StoredCredential = credential.into();
    let prepared = prepare(&ProveInput {
        candidate: &candidate.to_candidate()?,
        query: &query,
        client_metadata: &metadata,
        session: &session.0,
        credential: &credential,
        secret_seed: &secret_seed,
        anchors: anchors.as_deref(),
        now,
    })
    .map_err(prove_error)?;
    Ok(Arc::new(FfiPrepared(prepared)))
}

#[uniffi::export]
impl FfiPrepared {
    /// The data the device key signs with ES256.
    pub fn data_to_sign(&self) -> Vec<u8> {
        self.0.data_to_sign().to_vec()
    }

    /// The identifier of the device key.
    pub fn key_id(&self) -> String {
        self.0.key_id().to_owned()
    }

    /// The statement the proof establishes.
    pub fn statement(&self) -> FfiStatement {
        self.0.statement().into()
    }

    /// The prover's job, once `device_signature` (`r ‖ s`) verifies under the MSO's device key.
    ///
    /// # Errors
    ///
    /// `device_binding`, or [`ZkpReqError::Host`] for a signature that is not 64 bytes.
    pub fn job(&self, device_signature: Vec<u8>) -> Result<FfiProofJob, ZkpReqError> {
        let job = self.0.job(&device_signature).map_err(prove_error)?;
        Ok(FfiProofJob {
            statement: (&job.statement).into(),
            issuer_signed: job.issuer_signed.clone(),
            secret_seed: job.secret_seed.to_vec(),
            device_signature: job.device_signature.to_vec(),
        })
    }

    /// The `ZkpPresentation` (CBOR) of the prover's output.
    ///
    /// # Errors
    ///
    /// [`ZkpReqError::Host`] when the prover's pseudonym is not the catalogue's, or its
    /// `zk_proof` breaks the backend's length rules.
    pub fn assemble(&self, zk_proof: Vec<u8>, pseudonym: Vec<u8>) -> Result<Vec<u8>, ZkpReqError> {
        let pseudonym: [u8; 32] = pseudonym.try_into().map_err(|_| host("pseudonym_length"))?;
        let presentation = self
            .0
            .assemble(&ProofOutput {
                zk_proof,
                pseudonym,
            })
            .map_err(prove_error)?;
        Ok(presentation.encode())
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
) -> Result<Vec<(String, Vec<ZkpPresentation>)>, ZkpReqError> {
    entries
        .into_iter()
        .map(|e| {
            let presentations = e
                .presentations
                .iter()
                .map(|p| ZkpPresentation::decode(p).map_err(|_| host("presentation_not_cbor")))
                .collect::<Result<_, _>>()?;
            Ok((e.query_id, presentations))
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
        pseudonym: &[u8; 32],
        zk_proof: &[u8],
    ) -> Result<(), ProofFailure> {
        match self
            .0
            .verify(statement.into(), pseudonym.to_vec(), zk_proof.to_vec())
        {
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

/// Verifies a presentation against the verifier's own query, session, clock and trust
/// anchors, with the host's proof verifier.
///
/// # Errors
///
/// [`ZkpReqError::Refused`] with the system rulebook's code.
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
    let verified = verify(
        &VerifyInput {
            query: &query,
            client_metadata: &metadata,
            session: &session.0,
            presentation: &presentation,
            now,
            tolerance: Tolerance {
                future: tolerance_future,
                past: tolerance_past,
            },
            trust_anchors: &trust_anchors,
        },
        &ForeignVerifier(verifier),
    )
    .map_err(|r| rejection(&r))?;
    Ok(FfiVerified {
        system_id: verified.system.id().to_owned(),
        proof_backend: verified.proof_backend,
        req_set: verified.req_set.map(index),
        results: verified
            .results
            .iter()
            .map(|(handle, value): &(String, Cbor)| FfiResult {
                handle: handle.clone(),
                value: value.encode(),
            })
            .collect(),
        issuer_certificate: verified.issuer_certificate,
        proof_time: verified.proof_time.to_string(),
    })
}
