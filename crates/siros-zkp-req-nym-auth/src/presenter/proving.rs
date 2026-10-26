//! `prove`: the candidate checked again, the statement, the device signature, the prover's job
//! and the presentation (system rulebooks, Section 7; `zkp_req`, Section 4).

use std::fmt;

use serde_json::Value;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::{Date, DateTime};
use siros_mdoc::{device_signing_input, es256_verifies, DeviceNameSpaces};
use siros_oid4vp::Handover;
use siros_zkp_req::{Candidate, PairRefusal, ProofEnvelope, ZkpPresentation};
use zeroize::Zeroizing;

use super::{
    anchors_for, credential_errors, item_errors, parse, plan_option, HostError, OptionPlan, Parsed,
    MAX_ZK_PROOF,
};
use crate::age::Bound;
use crate::attestation::{OpenedSeed, SeedMismatch, UsableAttestation};
use crate::catalogue::{Function, NymAuthQuery, Pseudonym, MDOC_DOCTYPE};
use crate::mdoc::StoredCredential;
use crate::outcome::{CredentialCode, InvalidRequest, ItemCode, ZkpError};
use crate::prover::{NymAuthProver, ProofJob, ProofOutput, ProverFailure, Statement};
use crate::system::{pair_code, NymAuthSystem, Unsupported};
use crate::verifier_id::{pseudonym_sha256, sha256, verifier_input, VerifierId};

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
    attestation: UsableAttestation,
    seed: OpenedSeed,
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
    let (pseudonym_index, pseudonym_item) = pseudonym_of(&parsed.query, &plan)?;
    let (attestation, opened) = usable_credential(
        &parsed.query,
        &plan,
        pseudonym_index,
        input.credential,
        anchors,
        proof_time,
        &seed,
    )?;
    let session_transcript = input.session.handover.session_transcript();
    let data_to_sign = device_signing_input(
        &session_transcript,
        MDOC_DOCTYPE,
        &DeviceNameSpaces::empty(),
    );
    let certificate = attestation.credential().certificate();
    let statement = Statement {
        system,
        proof_backend: input.candidate.proof_backend.clone(),
        doc_type: MDOC_DOCTYPE,
        issuer_certificate: certificate.der().to_vec(),
        issuer_key: *certificate.key(),
        proof_time: attestation.proof_time(),
        earliest: bound_date(plan.bounds.earliest)?,
        cutoff: bound_date(plan.bounds.cutoff)?,
        verifier_input: verifier_input(pseudonym_item, &input.session.verifier_id),
        session_transcript,
        challenge_digest: sha256(&data_to_sign),
    };
    let pseudonym = pseudonym_sha256(
        &pseudonym_item.config,
        opened.secret_seed(),
        &[0; 32],
        &statement.verifier_input,
    );
    let results = results(&parsed.query, &plan, &pseudonym);
    Ok(Prepared {
        statement,
        attestation,
        seed: opened,
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
        .query()
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

/// The usable attestation and the opened seed of `stored`, after every test that needs no
/// device signature. The failures of the credential come first, then those of the items: the
/// `age_check` assertion and the `pseudonym` at `pseudonym_index`, whose seed must open `ssc`.
fn usable_credential(
    query: &NymAuthQuery,
    plan: &OptionPlan<'_>,
    pseudonym_index: usize,
    stored: &StoredCredential,
    anchors: Option<&[Vec<u8>]>,
    proof_time: DateTime,
    seed: &[u8; 16],
) -> Result<(UsableAttestation, OpenedSeed), ProveError> {
    let tested = UsableAttestation::new(&stored.data, anchors, proof_time);
    let (mut errors, credential) =
        credential_errors(&tested).ok_or(HostError::CredentialMismatch)?;
    let Some(credential) = credential else {
        return Err(ProveError::Rejected(errors));
    };
    errors.extend(item_errors(query, plan, credential));
    let opened = match OpenedSeed::open(credential, seed) {
        Ok(opened) => Some(opened),
        Err(SeedMismatch) => {
            errors.push(ZkpError::Item {
                option: plan.option.req_set,
                item: pseudonym_index,
                code: ItemCode::SeedMismatch,
            });
            None
        }
    };
    match (tested, opened) {
        (Ok(attestation), Some(opened)) if errors.is_empty() => Ok((attestation, opened)),
        _ => Err(ProveError::Rejected(errors)),
    }
}

/// The option's `pseudonym` and its `_req` index. Every system requires one.
fn pseudonym_of<'q>(
    query: &'q NymAuthQuery,
    plan: &OptionPlan<'q>,
) -> Result<(usize, &'q Pseudonym), ProveError> {
    query
        .option_items(plan.option)
        .find_map(|(index, item)| match &item.function {
            Function::Pseudonym(p) => Some((index, p)),
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
        let device_key = self.attestation.credential().mdoc().device_key();
        if !es256_verifies(device_key, &self.data_to_sign, &signature) {
            return Err(ProveError::Rejected(vec![ZkpError::Credential(
                CredentialCode::DeviceBinding,
            )]));
        }
        Ok(ProofJob::new(
            self.statement.clone(),
            self.attestation.clone(),
            self.seed.clone(),
            signature,
        ))
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
