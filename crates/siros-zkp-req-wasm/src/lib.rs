//! The `zkp_req` presenter for the browser, built with `wasm-pack build --target web` and run in
//! a Web Worker or the page.
//!
//! It is the presenter behind the wallet frontend's in-page host (`ZkpPresenterInPageHost` of
//! `@sirosfoundation/zkp-req`): `matchQuery`, then the wallet's one consent screen, then
//! `prepare`, the device signature, the job for a system's prover, and `assemble`. Proving
//! stays outside: a host runs the job with a zk-cred prover (zk-cred-longfellow,
//! zk-cred-vega). Every call checks everything again; nothing is kept between calls.
//!
//! Objects cross the boundary with the snake_case names of the frontend's types, bytes as
//! `Uint8Array`. A refusal throws an object `{error_code, kind, code, errors?}`: `error_code` is
//! what the wallet sends the verifier (`zkp_req`, Section 5).

#![deny(missing_docs)]
#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::Value;
use siros_zkp_req::{Candidate, ErrorCode, Match, PairRefusal, ZkpPresentation};
use siros_zkp_req_nym_auth::date::Date;
use siros_zkp_req_nym_auth::mdoc::StoredCredential;
use siros_zkp_req_nym_auth::outcome::ZkpError;
use siros_zkp_req_nym_auth::policy::{check_request, Channel};
use siros_zkp_req_nym_auth::presenter::{
    self, MatchInput, NymAuthMatch, Prepared, ProveError, ProveInput, Session,
};
use siros_zkp_req_nym_auth::prover::{ProofOutput, Statement};
use siros_zkp_req_nym_auth::system::{NymAuthSystem, Unsupported};
use siros_zkp_req_nym_auth::verifier_id::VerifierId;
use wasm_bindgen::prelude::*;

/// A refusal, as thrown to JavaScript.
#[derive(Serialize)]
struct Thrown {
    error_code: &'static str,
    kind: &'static str,
    code: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<JsZkpError>,
}

fn thrown(error_code: ErrorCode, kind: &'static str, code: &str) -> JsValue {
    to_js(&Thrown {
        error_code: error_code.as_str(),
        kind,
        code: code.to_owned(),
        errors: Vec::new(),
    })
}

fn host(code: &str) -> JsValue {
    thrown(ErrorCode::AccessDenied, "host", code)
}

fn to_js<T: Serialize>(value: &T) -> JsValue {
    value
        .serialize(&serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true))
        .unwrap_or_else(|e| JsValue::from_str(&e.to_string()))
}

fn from_js<T: for<'de> Deserialize<'de>>(value: JsValue, what: &str) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(|_| host(what))
}

/// A credential the wallet stores (`StoredCredential` of the frontend's types).
#[derive(Deserialize)]
struct JsStoredCredential {
    id: String,
    format: String,
    data: String,
    kid: String,
}

impl From<JsStoredCredential> for StoredCredential {
    fn from(c: JsStoredCredential) -> Self {
        Self {
            id: c.id,
            format: c.format,
            data: c.data,
            kid: c.kid,
        }
    }
}

#[derive(Deserialize)]
struct JsMatchInput {
    query: Value,
    client_metadata: Value,
    credentials: Vec<JsStoredCredential>,
    #[serde(default)]
    anchors: Option<Vec<ByteBuf>>,
    systems: Vec<String>,
    now: i64,
}

/// A candidate (`Candidate` of the frontend's types, with the draft's option and backend).
#[derive(Serialize, Deserialize)]
struct JsCandidate {
    credential_id: String,
    system_id: String,
    proof_backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    req_set: Option<usize>,
    items: Vec<usize>,
}

impl From<&Candidate> for JsCandidate {
    fn from(c: &Candidate) -> Self {
        Self {
            credential_id: c.credential_id.clone(),
            system_id: c.system_id.clone(),
            proof_backend: c.proof_backend.clone(),
            req_set: c.req_set,
            items: c.items.clone(),
        }
    }
}

impl JsCandidate {
    fn to_candidate(&self) -> Candidate {
        Candidate {
            credential_id: self.credential_id.clone(),
            system_id: self.system_id.clone(),
            proof_backend: self.proof_backend.clone(),
            req_set: self.req_set,
            items: self.items.clone(),
            inputs: Vec::new(),
        }
    }
}

/// `ItemError` or `CredentialError` of the frontend's types.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JsZkpError {
    Item {
        index: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        req_set: Option<usize>,
        code: &'static str,
    },
    Credential {
        code: &'static str,
    },
}

impl From<&ZkpError> for JsZkpError {
    fn from(e: &ZkpError) -> Self {
        match e {
            ZkpError::Item { option, item, code } => Self::Item {
                index: *item,
                req_set: *option,
                code: code.code(),
            },
            ZkpError::Credential(code) => Self::Credential { code: code.code() },
        }
    }
}

#[derive(Serialize)]
struct JsJudged {
    candidate: JsJudgedCredential,
    errors: Vec<JsZkpError>,
}

#[derive(Serialize)]
struct JsJudgedCredential {
    credential_id: String,
}

#[derive(Serialize)]
struct JsOptionRefusal {
    #[serde(skip_serializing_if = "Option::is_none")]
    req_set: Option<usize>,
    systems: Vec<JsPairRefusal>,
}

#[derive(Serialize)]
struct JsPairRefusal {
    system_id: String,
    code: &'static str,
}

/// `Match` of the frontend's types.
#[derive(Serialize)]
#[serde(untagged)]
enum JsMatch {
    Candidates {
        candidates: Vec<JsCandidate>,
    },
    Rejected {
        rejected: Vec<JsJudged>,
    },
    Unsupported {
        refused: &'static str,
        options: Vec<JsOptionRefusal>,
    },
    Invalid {
        refused: &'static str,
        code: &'static str,
    },
}

fn pair_code(r: &PairRefusal<Unsupported>) -> &'static str {
    match r {
        PairRefusal::SystemNotListed => "system_not_listed",
        PairRefusal::NoListedBackend => "no_listed_backend",
        PairRefusal::CredentialType => "credential_type",
        PairRefusal::Unsupported(u) => u.code(),
    }
}

impl From<NymAuthMatch> for JsMatch {
    fn from(m: NymAuthMatch) -> Self {
        match m {
            Match::Candidates(c) => Self::Candidates {
                candidates: c.iter().map(JsCandidate::from).collect(),
            },
            Match::Rejected(judged) => Self::Rejected {
                rejected: judged
                    .iter()
                    .map(|j| JsJudged {
                        candidate: JsJudgedCredential {
                            credential_id: j.credential_id.clone(),
                        },
                        errors: j.errors.iter().map(JsZkpError::from).collect(),
                    })
                    .collect(),
            },
            Match::Unsupported(options) => Self::Unsupported {
                refused: "unsupported",
                options: options
                    .iter()
                    .map(|o| JsOptionRefusal {
                        req_set: o.req_set,
                        systems: o
                            .systems
                            .iter()
                            .map(|(system_id, r)| JsPairRefusal {
                                system_id: system_id.clone(),
                                code: pair_code(r),
                            })
                            .collect(),
                    })
                    .collect(),
            },
            Match::Invalid(rule) => Self::Invalid {
                refused: "invalid",
                code: rule.code(),
            },
        }
    }
}

fn parse_systems(ids: &[String]) -> Result<Vec<NymAuthSystem>, JsValue> {
    ids.iter()
        .map(|id| NymAuthSystem::from_id(id).ok_or_else(|| host("system_unknown")))
        .collect()
}

fn anchor_list(anchors: Option<Vec<ByteBuf>>) -> Option<Vec<Vec<u8>>> {
    anchors.map(|a| a.into_iter().map(ByteBuf::into_vec).collect())
}

/// Matches one `zkp_req` Credential Query: `{query, client_metadata, credentials, anchors?,
/// systems, now}`, `now` in seconds since the epoch. Returns the frontend's `Match`.
///
/// # Errors
///
/// Throws `{kind: "host"}` for an input the presenter cannot use.
#[wasm_bindgen(js_name = matchQuery)]
pub fn match_query(input: JsValue) -> Result<JsValue, JsValue> {
    let input: JsMatchInput = from_js(input, "match_input")?;
    let credentials: Vec<StoredCredential> =
        input.credentials.into_iter().map(Into::into).collect();
    let systems = parse_systems(&input.systems)?;
    let anchors = anchor_list(input.anchors);
    let matched = presenter::match_query(&MatchInput {
        query: &input.query,
        client_metadata: &input.client_metadata,
        credentials: &credentials,
        anchors: anchors.as_deref(),
        systems: &systems,
        now: input.now,
    })
    .map_err(|e| host(&format!("{e:?}")))?;
    Ok(to_js(&JsMatch::from(matched)))
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JsChannel {
    DcApi { origin: String },
    Redirect,
}

#[derive(Deserialize)]
#[serde(tag = "form", rename_all = "snake_case")]
enum JsVerifierIdForm {
    Semantic {
        semantic_identifier: String,
    },
    X509SanDns {
        registration_names_intermediary: bool,
    },
}

#[derive(Deserialize)]
struct JsSessionInput {
    request_object: Value,
    signed: bool,
    channel: JsChannel,
    jwk_thumbprint: ByteBuf,
    verifier_id: JsVerifierIdForm,
}

/// The session a presentation is bound to (`PresentationSession` of the frontend's types).
#[wasm_bindgen]
pub struct ZkpSession(Session);

#[wasm_bindgen]
impl ZkpSession {
    /// The CBOR `Handover` (OpenID4VP 1.0, B.2.6).
    pub fn handover(&self) -> Vec<u8> {
        self.0.handover.as_cbor().to_vec()
    }

    /// `verifier_id`.
    #[wasm_bindgen(js_name = verifierId)]
    pub fn verifier_id(&self) -> String {
        self.0.verifier_id.as_str().to_owned()
    }
}

fn invalid(code: &str) -> JsValue {
    thrown(ErrorCode::InvalidRequest, "invalid_request", code)
}

/// The session of a validated Request Object: `{request_object, signed, channel:
/// {kind: "dc_api", origin} | {kind: "redirect"}, jwk_thumbprint, verifier_id: {form:
/// "semantic", semantic_identifier} | {form: "x509_san_dns", registration_names_intermediary}}`.
///
/// # Errors
///
/// Throws `{kind: "invalid_request"}` for a rule of the policy or of the verifier identity.
#[wasm_bindgen(js_name = session)]
pub fn session(input: JsValue) -> Result<ZkpSession, JsValue> {
    let input: JsSessionInput = from_js(input, "session_input")?;
    let channel = match input.channel {
        JsChannel::DcApi { origin } => Channel::DcApi { origin },
        JsChannel::Redirect => Channel::Redirect,
    };
    let checked = check_request(&input.request_object, input.signed, channel)
        .map_err(|r| invalid(r.code()))?;
    let thumbprint: [u8; 32] = input
        .jwk_thumbprint
        .into_vec()
        .try_into()
        .map_err(|_| host("thumbprint_length"))?;
    let handover = checked
        .handover(&thumbprint)
        .map_err(|_| host("thumbprint_not_in_request"))?;
    let verifier_id = match input.verifier_id {
        JsVerifierIdForm::Semantic {
            semantic_identifier,
        } => VerifierId::semantic(&semantic_identifier),
        JsVerifierIdForm::X509SanDns {
            registration_names_intermediary,
        } => VerifierId::x509_san_dns(&checked.client_id, registration_names_intermediary),
    }
    .map_err(|r| invalid(r.code()))?;
    Ok(ZkpSession(Session {
        handover,
        verifier_id,
    }))
}

#[derive(Deserialize)]
struct JsProveInput {
    candidate: JsCandidate,
    query: Value,
    client_metadata: Value,
    credential: JsStoredCredential,
    secret_seed: ByteBuf,
    #[serde(default)]
    anchors: Option<Vec<ByteBuf>>,
    now: i64,
}

/// The public values of a proof, for a system's prover (system rulebooks, Section 4).
#[derive(Serialize)]
struct JsStatement {
    system_id: &'static str,
    proof_backend: String,
    doc_type: &'static str,
    issuer_certificate: ByteBuf,
    issuer_key_x: ByteBuf,
    issuer_key_y: ByteBuf,
    proof_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    earliest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cutoff: Option<String>,
    verifier_input: ByteBuf,
    session_transcript: ByteBuf,
    challenge_digest: ByteBuf,
}

impl From<&Statement> for JsStatement {
    fn from(s: &Statement) -> Self {
        Self {
            system_id: s.system.id(),
            proof_backend: s.proof_backend.clone(),
            doc_type: s.doc_type,
            issuer_certificate: ByteBuf::from(s.issuer_certificate.clone()),
            issuer_key_x: ByteBuf::from(s.issuer_key.x.to_vec()),
            issuer_key_y: ByteBuf::from(s.issuer_key.y.to_vec()),
            proof_time: s.proof_time.to_string(),
            earliest: s.earliest.and_then(Date::to_full_date),
            cutoff: s.cutoff.and_then(Date::to_full_date),
            verifier_input: ByteBuf::from(s.verifier_input.to_vec()),
            session_transcript: ByteBuf::from(s.session_transcript.clone()),
            challenge_digest: ByteBuf::from(s.challenge_digest.to_vec()),
        }
    }
}

#[derive(Serialize)]
struct JsProofJob {
    statement: JsStatement,
    issuer_signed: ByteBuf,
    secret_seed: ByteBuf,
    device_signature: ByteBuf,
}

fn prove_error(e: ProveError) -> JsValue {
    match e {
        ProveError::Invalid(rule) => invalid(rule.code()),
        ProveError::Rejected(errors) => to_js(&Thrown {
            error_code: ErrorCode::AccessDenied.as_str(),
            kind: "rejected",
            code: "credential".to_owned(),
            errors: errors.iter().map(JsZkpError::from).collect(),
        }),
        ProveError::NotUsable(r) => thrown(ErrorCode::AccessDenied, "unsupported", pair_code(&r)),
        other => host(&format!("{other:?}")),
    }
}

/// A presentation ready for the device signature, then for the prover.
#[wasm_bindgen]
pub struct ZkpPrepared(Prepared);

/// Checks the consented candidate again and builds its statement: `{candidate, query,
/// client_metadata, credential, secret_seed, anchors?, now}` and the session.
///
/// # Errors
///
/// Throws `{kind: "rejected", errors}` with the system rulebook's codes, or another kind.
#[wasm_bindgen(js_name = prepare)]
pub fn prepare(input: JsValue, session: &ZkpSession) -> Result<ZkpPrepared, JsValue> {
    let input: JsProveInput = from_js(input, "prove_input")?;
    let credential: StoredCredential = input.credential.into();
    let anchors = anchor_list(input.anchors);
    let prepared = presenter::prepare(&ProveInput {
        candidate: &input.candidate.to_candidate(),
        query: &input.query,
        client_metadata: &input.client_metadata,
        session: &session.0,
        credential: &credential,
        secret_seed: &input.secret_seed,
        anchors: anchors.as_deref(),
        now: input.now,
    })
    .map_err(prove_error)?;
    Ok(ZkpPrepared(prepared))
}

#[wasm_bindgen]
impl ZkpPrepared {
    /// The data the device key signs with ES256 (`WalletContext.sign(kid, "ES256", data)`).
    #[wasm_bindgen(js_name = dataToSign)]
    pub fn data_to_sign(&self) -> Vec<u8> {
        self.0.data_to_sign().to_vec()
    }

    /// The identifier of the device key.
    #[wasm_bindgen(js_name = keyId)]
    pub fn key_id(&self) -> String {
        self.0.key_id().to_owned()
    }

    /// The statement the proof establishes.
    pub fn statement(&self) -> JsValue {
        to_js(&JsStatement::from(self.0.statement()))
    }

    /// The prover's job, once the signature (`r ‖ s`) verifies under the MSO's device key.
    ///
    /// # Errors
    ///
    /// Throws `device_binding`, or `{kind: "host"}` for a signature that is not 64 bytes.
    pub fn job(&self, device_signature: &[u8]) -> Result<JsValue, JsValue> {
        let job = self.0.job(device_signature).map_err(prove_error)?;
        Ok(to_js(&JsProofJob {
            statement: JsStatement::from(&job.statement),
            issuer_signed: ByteBuf::from(job.issuer_signed.clone()),
            secret_seed: ByteBuf::from(job.secret_seed.to_vec()),
            device_signature: ByteBuf::from(job.device_signature.to_vec()),
        }))
    }

    /// The CBOR `ZkpPresentation` of the prover's output.
    ///
    /// # Errors
    ///
    /// Throws `{kind: "host"}` when the pseudonym is not the catalogue's or `zk_proof` breaks
    /// the backend's length rules.
    pub fn assemble(&self, zk_proof: Vec<u8>, pseudonym: &[u8]) -> Result<Vec<u8>, JsValue> {
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

#[derive(Deserialize)]
struct JsVpTokenEntry {
    query_id: String,
    presentations: Vec<ByteBuf>,
}

/// The `vp_token` of JSON Response Modes (`zkp_req`, Section 6.1), from `[{query_id,
/// presentations}]`.
///
/// # Errors
///
/// Throws `{kind: "host"}` for bytes that are no presentation.
#[wasm_bindgen(js_name = vpTokenJson)]
pub fn vp_token_json(entries: JsValue) -> Result<String, JsValue> {
    let entries: Vec<JsVpTokenEntry> = from_js(entries, "vp_token_entries")?;
    let answers = entries
        .into_iter()
        .map(|e| {
            let presentations = e
                .presentations
                .iter()
                .map(|p| ZkpPresentation::decode(p).map_err(|_| host("presentation_not_cbor")))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((e.query_id, presentations))
        })
        .collect::<Result<Vec<_>, JsValue>>()?;
    Ok(siros_zkp_req::vp_token_json(&answers).to_string())
}
