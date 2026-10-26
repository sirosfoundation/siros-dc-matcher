//! The presenter of nym_auth queries: `match`, then the Wallet's consent, then `prove`.
//!
//! It does no input or output. The host passes what its `WalletContext` holds (credentials,
//! anchors, the clock, the seed), signs the data the presenter gives it with the device key,
//! and runs a system's prover on the [`ProofJob`]. The presenter keeps nothing between calls:
//! `prove` checks everything again.

use std::fmt;

use serde_json::Value;
use siros_codec::cbor::Value as Cbor;
use siros_zkp_req::{
    usable_backend, Candidate, Judged, Match, OptionRefusal, PairRefusal, ProofEnvelope,
    QueryOption, ZkpFormats, ZkpPresentation, ZkpReqQuery,
};
use zeroize::Zeroizing;

use crate::age::{Bound, Bounds};
use crate::catalogue::{Function, Item, NymAuthQuery, Pseudonym, MDOC_DOCTYPE};
use crate::checks::{self, Checked, Credential};
use crate::date::{Date, DateTime};
use crate::mdoc::{P256Key, StoredCredential};
use crate::outcome::{CredentialCode, InvalidRequest, ItemCode, ZkpError};
use crate::prover::{NymAuthProver, ProofJob, ProofOutput, ProverFailure, Statement};
use crate::session::device_message;
use crate::system::{pair_code, NymAuthSystem, Unsupported};
use crate::verifier_id::{pseudonym_sha256, sha256, verifier_input, VerifierId};
use siros_oid4vp::Handover;

/// The outcome of matching one nym_auth query.
pub type NymAuthMatch = Match<InvalidRequest, PairRefusal<Unsupported>, ZkpError>;

/// The largest `zk_proof` the proof backends read (`longfellow-libzk-v1`, `vega-v1`).
pub const MAX_ZK_PROOF: usize = 1 << 20;

/// A host input this presenter cannot use. It is a defect of the host, never of the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostError {
    /// `now` lies outside 0000-01-01T00:00:00Z to 9999-12-31T23:59:59Z.
    Time,
    /// The query names trusted authorities and the host passed no anchors for them.
    AnchorsMissing,
    /// The secret seed is not 16 bytes.
    SeedLength,
    /// The device signature is not 64 bytes, `r ‖ s`.
    SignatureLength,
    /// The candidate names an option, system or proof backend `match` does not give.
    CandidateMismatch,
    /// The credential is not the candidate's.
    CredentialMismatch,
}

impl HostError {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::Time => "time",
            Self::AnchorsMissing => "anchors_missing",
            Self::SeedLength => "seed_length",
            Self::SignatureLength => "signature_length",
            Self::CandidateMismatch => "candidate_mismatch",
            Self::CredentialMismatch => "credential_mismatch",
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "host input: {}", self.code())
    }
}

impl std::error::Error for HostError {}

/// What `match` needs: the request's query and metadata, and what the host's `WalletContext`
/// gives.
#[derive(Debug, Clone, Copy)]
pub struct MatchInput<'a> {
    /// The Credential Query, one element of `dcql_query.credentials`.
    pub query: &'a Value,
    /// The request's `client_metadata`.
    pub client_metadata: &'a Value,
    /// The Wallet's credentials of the query's format and type; a superset is fine.
    pub credentials: &'a [StoredCredential],
    /// DER certificates of the anchors the query's `trusted_authorities` designate. Required
    /// when the query has `trusted_authorities`.
    pub anchors: Option<&'a [Vec<u8>]>,
    /// The systems the host proves, in the Wallet's order of preference.
    pub systems: &'a [NymAuthSystem],
    /// The Wallet's clock: seconds since 1970-01-01T00:00:00Z. The proof time.
    pub now: i64,
}

struct Parsed {
    query: NymAuthQuery,
    formats: ZkpFormats,
}

/// The query and the metadata, validated. `None` when the query asks for another credential
/// type.
fn parse(query: &Value, client_metadata: &Value) -> Result<Option<Parsed>, InvalidRequest> {
    let parsed = ZkpReqQuery::parse(query)?;
    let formats = ZkpFormats::from_client_metadata(client_metadata)?;
    Ok(NymAuthQuery::from_query(parsed)?.map(|query| Parsed { query, formats }))
}

/// The bounds of `option` at `d`: those of its `age_check`, or the widest.
fn option_bounds(query: &NymAuthQuery, option: &QueryOption, d: Date) -> Bounds {
    query
        .option_items(option)
        .find_map(|(_, item)| match &item.function {
            Function::AgeCheck(age) => Some(age.range.bounds(d)),
            Function::Pseudonym(_) => None,
        })
        .unwrap_or(Bounds::WIDEST)
}

/// An option, its bounds, and the first usable pair in the Wallet's order.
struct OptionPlan<'q> {
    option: &'q QueryOption,
    bounds: Bounds,
    pair: Option<(NymAuthSystem, String)>,
    refusals: Vec<(String, PairRefusal<Unsupported>)>,
}

fn plan_option<'q>(
    parsed: &'q Parsed,
    option: &'q QueryOption,
    systems: &[NymAuthSystem],
    d: Date,
) -> OptionPlan<'q> {
    let bounds = option_bounds(&parsed.query, option, d);
    let items: Vec<&Item> = parsed.query.option_items(option).map(|(_, i)| i).collect();
    let mut refusals = Vec::new();
    for &system in systems {
        let ty = &parsed.query.query.credential_type;
        match usable_backend(&parsed.formats, ty, &system, |s| {
            s.supports(items.iter().copied(), &bounds)
        }) {
            Ok(backend) => {
                return OptionPlan {
                    option,
                    bounds,
                    pair: Some((system, backend.to_owned())),
                    refusals,
                }
            }
            Err(refusal) => refusals.push((system.id().to_owned(), refusal)),
        }
    }
    OptionPlan {
        option,
        bounds,
        pair: None,
        refusals,
    }
}

/// The anchors to check the issuer against: required when the query names authorities.
fn anchors_for<'a>(
    query: &NymAuthQuery,
    anchors: Option<&'a [Vec<u8>]>,
) -> Result<Option<&'a [Vec<u8>]>, HostError> {
    match (&query.query.trusted_authorities, anchors) {
        (None, _) => Ok(None),
        (Some(_), Some(anchors)) => Ok(Some(anchors)),
        (Some(_), None) => Err(HostError::AnchorsMissing),
    }
}

/// The items of `option` that fail for `credential`: the `age_check` assertion.
fn item_errors(
    query: &NymAuthQuery,
    plan: &OptionPlan<'_>,
    credential: &Credential,
) -> Vec<ZkpError> {
    query
        .option_items(plan.option)
        .filter_map(|(index, item)| match item.function {
            Function::AgeCheck(_) if !plan.bounds.holds(credential.mdoc.birth_date.value) => {
                Some(ZkpError::Item {
                    option: plan.option.req_set,
                    item: index,
                    code: ItemCode::AgeOutOfRange,
                })
            }
            _ => None,
        })
        .collect()
}

/// Matches one query against the Wallet's credentials (`zkp_req`, Sections 1.3 and 2.1).
///
/// The candidates come in the Verifier's order of options, then in the order of
/// `credentials`. Each answers its option with the first usable pair in the Wallet's order.
///
/// # Errors
///
/// [`HostError`]: an input of the host this presenter cannot use.
pub fn match_query(input: &MatchInput<'_>) -> Result<NymAuthMatch, HostError> {
    let proof_time = DateTime::from_unix(input.now).ok_or(HostError::Time)?;
    let parsed = match parse(input.query, input.client_metadata) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => return Ok(Match::Rejected(Vec::new())),
        Err(rule) => return Ok(Match::Invalid(rule)),
    };
    let d = proof_time.date();
    let plans: Vec<OptionPlan<'_>> = parsed
        .query
        .query
        .options
        .iter()
        .map(|option| plan_option(&parsed, option, input.systems, d))
        .collect();
    if plans.iter().all(|p| p.pair.is_none()) {
        return Ok(Match::Unsupported(unsupported(plans)));
    }
    let anchors = anchors_for(&parsed.query, input.anchors)?;
    let judged: Vec<(&StoredCredential, Checked)> = input
        .credentials
        .iter()
        .filter(|c| c.format == "mso_mdoc")
        .map(|c| (c, checks::check(&c.data, anchors, proof_time)))
        .collect();
    Ok(candidates_or_rejections(&parsed.query, &plans, &judged))
}

fn unsupported(plans: Vec<OptionPlan<'_>>) -> Vec<OptionRefusal<PairRefusal<Unsupported>>> {
    plans
        .into_iter()
        .map(|p| OptionRefusal {
            req_set: p.option.req_set,
            systems: p.refusals,
        })
        .collect()
}

/// The outcome for one credential and one option with a usable pair.
fn judge(
    query: &NymAuthQuery,
    plan: &OptionPlan<'_>,
    checked: &Checked,
) -> Option<Result<(), Vec<ZkpError>>> {
    match checked {
        Checked::OtherDocType => None,
        Checked::Unreadable(_) => Some(Err(vec![ZkpError::Credential(
            CredentialCode::CredentialForm,
        )])),
        Checked::Read(credential, failures) => {
            let mut errors: Vec<ZkpError> =
                failures.iter().map(|c| ZkpError::Credential(*c)).collect();
            errors.extend(item_errors(query, plan, credential));
            Some(if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            })
        }
    }
}

fn candidates_or_rejections(
    query: &NymAuthQuery,
    plans: &[OptionPlan<'_>],
    judged: &[(&StoredCredential, Checked)],
) -> NymAuthMatch {
    let mut candidates = Vec::new();
    let mut rejected: Vec<Judged<ZkpError>> = Vec::new();
    for plan in plans {
        let Some((system, backend)) = &plan.pair else {
            continue;
        };
        for (credential, checked) in judged {
            match judge(query, plan, checked) {
                Some(Ok(())) => candidates.push(Candidate {
                    credential_id: credential.id.clone(),
                    system_id: system.id().to_owned(),
                    proof_backend: backend.clone(),
                    req_set: plan.option.req_set,
                    items: plan.option.items.clone(),
                    inputs: Vec::new(),
                }),
                Some(Err(errors)) => record(&mut rejected, &credential.id, errors),
                None => {}
            }
        }
    }
    if candidates.is_empty() {
        Match::Rejected(rejected)
    } else {
        Match::Candidates(candidates)
    }
}

/// Adds `errors` to the judgement of `credential_id`, each error once.
fn record(rejected: &mut Vec<Judged<ZkpError>>, credential_id: &str, errors: Vec<ZkpError>) {
    let index = match rejected
        .iter()
        .position(|j| j.credential_id == credential_id)
    {
        Some(index) => index,
        None => {
            rejected.push(Judged {
                credential_id: credential_id.to_owned(),
                errors: Vec::new(),
            });
            rejected.len() - 1
        }
    };
    if let Some(judged) = rejected.get_mut(index) {
        for error in errors {
            if !judged.errors.contains(&error) {
                judged.errors.push(error);
            }
        }
    }
}

/// The session a presentation is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The `Handover` of the channel the request arrived on.
    pub handover: Handover,
    /// `verifier_id`, in the form the trust framework fixes.
    pub verifier_id: VerifierId,
}

/// What `prove` needs: the consented candidate, the request again, the session, and what the
/// host's `WalletContext` gives.
#[derive(Debug, Clone, Copy)]
pub struct ProveInput<'a> {
    /// The candidate the User consented to.
    pub candidate: &'a Candidate,
    /// The Credential Query.
    pub query: &'a Value,
    /// The request's `client_metadata`.
    pub client_metadata: &'a Value,
    /// The session.
    pub session: &'a Session,
    /// The candidate's credential.
    pub credential: &'a StoredCredential,
    /// The `secret_seed` delivered with the credential, 16 bytes.
    pub secret_seed: &'a [u8],
    /// The anchors, as for `match`.
    pub anchors: Option<&'a [Vec<u8>]>,
    /// The Wallet's clock, as for `match`. The proof time.
    pub now: i64,
}

/// Why `prove` made no presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveError {
    /// The query breaks a rule (`invalid_request`).
    Invalid(InvalidRequest),
    /// An input of the host.
    Host(HostError),
    /// The candidate's pair is no longer usable for its option.
    NotUsable(PairRefusal<Unsupported>),
    /// The credential fails for the candidate's option.
    Rejected(Vec<ZkpError>),
    /// The device key did not sign.
    Signer(SignFailure),
    /// The prover made no proof.
    Prover(ProverFailure),
    /// The prover's pseudonym differs from the catalogue's.
    PseudonymMismatch,
    /// The prover's `zk_proof` breaks the proof backend's length rules.
    ZkProofLength,
}

impl ProveError {
    /// The error code for the Verifier (`zkp_req`, Section 5).
    pub fn error_code(&self) -> siros_zkp_req::ErrorCode {
        match self {
            Self::Invalid(_) => siros_zkp_req::ErrorCode::InvalidRequest,
            _ => siros_zkp_req::ErrorCode::AccessDenied,
        }
    }

    /// A stable identifier: the code of the rule, the host input, the pair refusal, the signer
    /// or the prover; `credential` for a credential that fails, with its codes in the variant.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(rule) => rule.code(),
            Self::Host(e) => e.code(),
            Self::NotUsable(refusal) => pair_code(refusal),
            Self::Rejected(_) => "credential",
            Self::Signer(e) => e.code(),
            Self::Prover(e) => e.code(),
            Self::PseudonymMismatch => "pseudonym_mismatch",
            Self::ZkProofLength => "zk_proof_length",
        }
    }
}

impl fmt::Display for ProveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ProveError {}

impl From<HostError> for ProveError {
    fn from(e: HostError) -> Self {
        Self::Host(e)
    }
}

/// Why the device key did not sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignFailure {
    /// The User cancelled.
    Cancelled,
    /// The key is not available.
    Unavailable,
}

impl SignFailure {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::Cancelled => "sign_cancelled",
            Self::Unavailable => "sign_unavailable",
        }
    }
}

/// A presentation ready for the device signature, then for the prover.
pub struct Prepared {
    statement: Statement,
    issuer_signed: Vec<u8>,
    secret_seed: Zeroizing<[u8; 16]>,
    device_key: P256Key,
    data_to_sign: Vec<u8>,
    kid: String,
    req_set: Option<usize>,
    results: Vec<(String, Cbor)>,
    pseudonym: [u8; 32],
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("statement", &self.statement)
            .field("req_set", &self.req_set)
            .finish_non_exhaustive()
    }
}

/// Checks the candidate again and builds the statement (system rulebooks, Section 7).
///
/// # Errors
///
/// [`ProveError`]: what fails, as the Section 9 codes name it.
pub fn prepare(input: &ProveInput<'_>) -> Result<Prepared, ProveError> {
    let proof_time = DateTime::from_unix(input.now).ok_or(HostError::Time)?;
    let seed: Zeroizing<[u8; 16]> = Zeroizing::new(
        input
            .secret_seed
            .try_into()
            .map_err(|_| HostError::SeedLength)?,
    );
    let parsed = parse(input.query, input.client_metadata)
        .map_err(ProveError::Invalid)?
        .ok_or(HostError::CandidateMismatch)?;
    let (plan, system) = candidate_plan(&parsed, input.candidate, proof_time.date())?;
    if input.credential.id != input.candidate.credential_id {
        return Err(HostError::CredentialMismatch.into());
    }
    let anchors = anchors_for(&parsed.query, input.anchors)?;
    let credential = checked_credential(
        &parsed.query,
        &plan,
        input.credential,
        anchors,
        proof_time,
        &seed,
    )?;
    let pseudonym_item = pseudonym_of(&parsed.query, &plan)?;
    let session_transcript = input.session.handover.session_transcript();
    let data_to_sign = device_message(&session_transcript, MDOC_DOCTYPE);
    let statement = Statement {
        system,
        proof_backend: input.candidate.proof_backend.clone(),
        doc_type: MDOC_DOCTYPE,
        issuer_certificate: credential.certificate.der.clone(),
        issuer_key: credential.certificate.key,
        proof_time,
        earliest: bound_date(plan.bounds.earliest)?,
        cutoff: bound_date(plan.bounds.cutoff)?,
        verifier_input: verifier_input(pseudonym_item, &input.session.verifier_id),
        session_transcript,
        challenge_digest: sha256(&data_to_sign),
    };
    let pseudonym = pseudonym_sha256(
        &pseudonym_item.config,
        &seed,
        &[0; 32],
        &statement.verifier_input,
    );
    let results = results(&parsed.query, &plan, &pseudonym);
    Ok(Prepared {
        statement,
        issuer_signed: credential.mdoc.issuer_signed.clone(),
        secret_seed: seed,
        device_key: credential.mdoc.device_key,
        data_to_sign,
        kid: input.credential.kid.clone(),
        req_set: plan.option.req_set,
        results,
        pseudonym,
    })
}

/// The candidate's option and pair, usable again at the proof date.
fn candidate_plan<'q>(
    parsed: &'q Parsed,
    candidate: &Candidate,
    d: Date,
) -> Result<(OptionPlan<'q>, NymAuthSystem), ProveError> {
    let option = parsed
        .query
        .query
        .option(candidate.req_set)
        .filter(|o| o.items == candidate.items)
        .ok_or(HostError::CandidateMismatch)?;
    let system =
        NymAuthSystem::from_id(&candidate.system_id).ok_or(HostError::CandidateMismatch)?;
    let plan = plan_option(parsed, option, &[system], d);
    match (&plan.pair, plan.refusals.first()) {
        (Some((_, backend)), _) if *backend == candidate.proof_backend => Ok((plan, system)),
        (Some(_), _) => Err(HostError::CandidateMismatch.into()),
        (None, Some((_, refusal))) => Err(ProveError::NotUsable(refusal.clone())),
        (None, None) => Err(HostError::CandidateMismatch.into()),
    }
}

/// The credential, after every test that needs no device signature, the seed's included.
fn checked_credential(
    query: &NymAuthQuery,
    plan: &OptionPlan<'_>,
    stored: &StoredCredential,
    anchors: Option<&[Vec<u8>]>,
    proof_time: DateTime,
    seed: &[u8; 16],
) -> Result<Credential, ProveError> {
    let (credential, failures) = match checks::check(&stored.data, anchors, proof_time) {
        Checked::Read(credential, failures) => (*credential, failures),
        Checked::Unreadable(_) => {
            return Err(ProveError::Rejected(vec![ZkpError::Credential(
                CredentialCode::CredentialForm,
            )]))
        }
        Checked::OtherDocType => return Err(HostError::CredentialMismatch.into()),
    };
    let mut errors: Vec<ZkpError> = failures.into_iter().map(ZkpError::Credential).collect();
    errors.extend(item_errors(query, plan, &credential));
    if !checks::opens_ssc(&credential.mdoc, seed) {
        errors.extend(query.option_items(plan.option).filter_map(|(index, item)| {
            matches!(item.function, Function::Pseudonym(_)).then_some(ZkpError::Item {
                option: plan.option.req_set,
                item: index,
                code: ItemCode::SeedMismatch,
            })
        }));
    }
    if errors.is_empty() {
        Ok(credential)
    } else {
        Err(ProveError::Rejected(errors))
    }
}

/// The option's `pseudonym`, which every system requires.
fn pseudonym_of<'q>(
    query: &'q NymAuthQuery,
    plan: &OptionPlan<'q>,
) -> Result<&'q Pseudonym, ProveError> {
    query
        .option_items(plan.option)
        .find_map(|(_, item)| match &item.function {
            Function::Pseudonym(p) => Some(p),
            Function::AgeCheck(_) => None,
        })
        .ok_or(ProveError::NotUsable(PairRefusal::Unsupported(
            Unsupported::NoPseudonym,
        )))
}

/// A bound the system encodes.
fn bound_date(bound: Option<Bound>) -> Result<Option<Date>, ProveError> {
    match bound {
        None => Ok(None),
        Some(Bound::Date(d)) => Ok(Some(d)),
        Some(Bound::Unencodable) => Err(ProveError::NotUsable(PairRefusal::Unsupported(
            Unsupported::AgeBounds,
        ))),
    }
}

/// `results`: the pseudonym under its handle, `true` under the handle of a function without a
/// result (`zkp_req`, Section 3).
fn results(
    query: &NymAuthQuery,
    plan: &OptionPlan<'_>,
    pseudonym: &[u8; 32],
) -> Vec<(String, Cbor)> {
    query
        .option_items(plan.option)
        .filter_map(|(_, item)| {
            let handle = item.ret.as_ref()?.as_str().to_owned();
            let value = match item.function {
                Function::Pseudonym(_) => Cbor::Bytes(pseudonym.to_vec()),
                Function::AgeCheck(_) => Cbor::Bool(true),
            };
            Some((handle, value))
        })
        .collect()
}

impl Prepared {
    /// The data the device key signs with ES256: the COSE `Sig_structure` of Section 5.
    pub fn data_to_sign(&self) -> &[u8] {
        &self.data_to_sign
    }

    /// The identifier of the device key, `kid` of the stored credential.
    pub fn key_id(&self) -> &str {
        &self.kid
    }

    /// The statement the proof establishes.
    pub fn statement(&self) -> &Statement {
        &self.statement
    }

    /// The prover's job, once the device signature verifies under the MSO's device key.
    ///
    /// # Errors
    ///
    /// [`ProveError::Host`] for a signature that is not 64 bytes, and `device_binding` for one
    /// that does not verify.
    pub fn job(&self, device_signature: &[u8]) -> Result<ProofJob, ProveError> {
        let signature: [u8; 64] = device_signature
            .try_into()
            .map_err(|_| HostError::SignatureLength)?;
        if !checks::es256_verifies(&self.device_key, &self.data_to_sign, &signature) {
            return Err(ProveError::Rejected(vec![ZkpError::Credential(
                CredentialCode::DeviceBinding,
            )]));
        }
        Ok(ProofJob {
            statement: self.statement.clone(),
            issuer_signed: self.issuer_signed.clone(),
            secret_seed: self.secret_seed.clone(),
            device_signature: signature,
        })
    }

    /// The presentation of the prover's output (`zkp_req`, Section 4, and the proof backends'
    /// `Proof`).
    ///
    /// # Errors
    ///
    /// [`ProveError::PseudonymMismatch`] when the prover's pseudonym is not the catalogue's,
    /// and [`ProveError::ZkProofLength`] for a `zk_proof` the backend would refuse.
    pub fn assemble(&self, output: &ProofOutput) -> Result<ZkpPresentation, ProveError> {
        if output.pseudonym != self.pseudonym {
            return Err(ProveError::PseudonymMismatch);
        }
        let length_ok = output.zk_proof.len() <= MAX_ZK_PROOF
            && self
                .statement
                .system
                .zk_proof_len()
                .is_none_or(|n| n == output.zk_proof.len());
        if !length_ok {
            return Err(ProveError::ZkProofLength);
        }
        let envelope = ProofEnvelope {
            inputs: vec![
                (
                    "issuer_key_set".to_owned(),
                    Cbor::Array(vec![Cbor::Bytes(self.statement.issuer_certificate.clone())]),
                ),
                (
                    "proof_time".to_owned(),
                    Cbor::Tag(
                        0,
                        Box::new(Cbor::Text(self.statement.proof_time.to_string())),
                    ),
                ),
            ],
            zk_proof: output.zk_proof.clone(),
        };
        Ok(ZkpPresentation {
            system_id: self.statement.system.id().to_owned(),
            proof_backend: self.statement.proof_backend.clone(),
            req_set: self.req_set.map(|i| i as u64),
            proof: envelope.encode(),
            results: self.results.clone(),
        })
    }
}

impl Prepared {
    /// The job, the prover and `assemble`, for a host that links a prover.
    ///
    /// # Errors
    ///
    /// [`ProveError`]: the device signature, the prover's failure, or its output.
    pub fn prove(
        &self,
        device_signature: &[u8],
        prover: &dyn NymAuthProver,
    ) -> Result<ZkpPresentation, ProveError> {
        let job = self.job(device_signature)?;
        let output = prover.prove(&job).map_err(|failure| match failure {
            ProverFailure::CredentialForm => {
                ProveError::Rejected(vec![ZkpError::Credential(CredentialCode::CredentialForm)])
            }
            other => ProveError::Prover(other),
        })?;
        self.assemble(&output)
    }
}

/// The device key, as the host's `WalletContext.sign` offers it.
pub trait Signer {
    /// Signs `data` with the key `kid` and the JOSE algorithm `alg`; returns `r ‖ s` for ES256.
    ///
    /// # Errors
    ///
    /// [`SignFailure`]: why the key did not sign.
    fn sign(&self, kid: &str, alg: &str, data: &[u8]) -> Result<Vec<u8>, SignFailure>;
}

/// `prepare`, the signature, the prover and `assemble`, for a host that can call both in turn.
///
/// # Errors
///
/// [`ProveError`]: the first step that fails.
pub fn present(
    input: &ProveInput<'_>,
    signer: &dyn Signer,
    prover: &dyn NymAuthProver,
) -> Result<ZkpPresentation, ProveError> {
    let prepared = prepare(input)?;
    let signature = signer
        .sign(prepared.key_id(), "ES256", prepared.data_to_sign())
        .map_err(ProveError::Signer)?;
    prepared.prove(&signature, prover)
}
