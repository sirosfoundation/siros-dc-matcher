//! `prove`: the candidate checked again, the statement, the device signature, the prover's job
//! and the presentation (system rulebooks, Section 7; `zkp_req`, Section 4).

use std::fmt;

use serde_json::Value;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::{Date, DateTime};
use siros_mdoc::{device_signing_input, es256_verifies, DeviceNameSpaces};
use siros_oid4vp::Handover;
use siros_zkp_req::{Candidate, PairRefusal, ProofEnvelope, QueryOption, ZkpPresentation};
use zeroize::Zeroizing;

use super::answer::{opened_seed, Answer, Unanswerable};
use super::{anchors_for, parse, HostError, Parsed, MAX_ZK_PROOF};
use crate::age::Bound;
use crate::attestation::{OpenedSeed, SecretSeed, Unusable, UsableAttestation};
use crate::catalogue::{Function, NymAuthQuery, MDOC_DOCTYPE};
use crate::mdoc::StoredCredential;
use crate::outcome::{CredentialCode, InvalidRequest, ZkpError};
use crate::pair::UsablePair;
use crate::prover::{NymAuthProver, ProofJob, ProofOutput, ProverFailure, Statement};
use crate::system::{pair_code, NymAuthSystem, Unsupported};
use crate::verifier_id::{pseudonym_sha256, sha256, verifier_input, VerifierId};

#[cfg(feature = "request")]
use crate::request::NymAuthRequest;
#[cfg(feature = "request")]
use siros_wallet_state::KeyId;

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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum ProveError {
    /// The query breaks a rule (`invalid_request`).
    Invalid(#[source] InvalidRequest),
    /// An input of the host.
    Host(#[from] HostError),
    /// The candidate's pair is no longer usable for its option.
    NotUsable(#[source] PairRefusal<Unsupported>),
    /// The credential fails for the candidate's option.
    Rejected(Vec<ZkpError>),
    /// The device key did not sign.
    Signer(#[source] SignFailure),
    /// The prover made no proof.
    Prover(#[source] ProverFailure),
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

impl From<Unanswerable> for ProveError {
    fn from(e: Unanswerable) -> Self {
        match e {
            Unanswerable::Failed(errors) => Self::Rejected(errors),
        }
    }
}

/// Why the device key did not sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
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
///
/// # Panics
///
/// When the host breaks [`ProveInput`]: a secret seed of other than 16 bytes, a credential
/// other than the candidate's, or no anchors for a query that names trusted authorities.
#[expect(
    clippy::expect_used,
    reason = "ProveInput's secret seed is 16 bytes; another length is a bug of the host, and \
              no seed opens `ssc` from it"
)]
pub fn prepare(input: &ProveInput<'_>) -> Result<Prepared, ProveError> {
    let proof_time = DateTime::from_unix(input.now).ok_or(HostError::Time)?;
    let seed = SecretSeed::new(Zeroizing::new(
        input
            .secret_seed
            .try_into()
            .expect("the secret seed is 16 bytes"),
    ));
    let parsed = parse(input.query, input.client_metadata)
        .map_err(ProveError::Invalid)?
        .ok_or(HostError::CandidateMismatch)?;
    let pair = candidate_pair(&parsed, input.candidate, proof_time.date())?;
    // ProveInput carries the candidate's credential. Another credential is a bug of the host,
    // and the proof would be of a credential the User did not consent to.
    assert!(
        input.credential.id == input.candidate.credential_id,
        "the host passed a credential other than the candidate's"
    );
    let anchors = anchors_for(&parsed.query, input.anchors);
    let answer = answer(pair, input.credential, anchors, proof_time, &seed)?;
    build(answer, input.session, &input.credential.kid)
}

impl Prepared {
    /// The statement of `answer` in the session of `request`, for the device key `key_id`
    /// (system rulebooks, Section 7).
    ///
    /// # Errors
    ///
    /// [`ProveError::NotUsable`] for an `age_check` bound the system does not encode.
    #[cfg(feature = "request")]
    pub fn new(
        answer: Answer<'_>,
        request: &NymAuthRequest<'_>,
        key_id: &KeyId,
    ) -> Result<Self, ProveError> {
        build(answer, request.session(), key_id.as_str())
    }
}

/// The statement of `answer` in `session`, and the data the device key `kid` signs.
fn build(answer: Answer<'_>, session: &Session, kid: &str) -> Result<Prepared, ProveError> {
    let (pair, attestation, seed) = answer.into_parts();
    let (_, pseudonym_item) = pair.pseudonym();
    let session_transcript = session.handover.session_transcript();
    let data_to_sign = device_signing_input(
        &session_transcript,
        MDOC_DOCTYPE,
        &DeviceNameSpaces::empty(),
    );
    let certificate = attestation.credential().certificate();
    let statement = Statement {
        system: pair.system(),
        proof_backend: pair.backend().as_str().to_owned(),
        doc_type: MDOC_DOCTYPE,
        issuer_certificate: certificate.der().to_vec(),
        issuer_key: *certificate.key(),
        proof_time: attestation.proof_time(),
        earliest: bound_date(pair.bounds().earliest)?,
        cutoff: bound_date(pair.bounds().cutoff)?,
        verifier_input: verifier_input(pseudonym_item, &session.verifier_id),
        session_transcript,
        challenge_digest: sha256(&data_to_sign),
    };
    let pseudonym = pseudonym_sha256(
        &pseudonym_item.config,
        seed.secret_seed(),
        &[0; 32],
        &statement.verifier_input,
    );
    let option = pair.option();
    let results = results(option.query(), option.option(), &pseudonym);
    Ok(Prepared {
        statement,
        attestation,
        seed,
        data_to_sign,
        kid: kid.to_owned(),
        req_set: option.option().req_set,
        results,
        pseudonym,
    })
}

/// The candidate's pair, usable again at the proof date.
fn candidate_pair<'q>(
    parsed: &'q Parsed,
    candidate: &Candidate,
    d: Date,
) -> Result<UsablePair<'q>, ProveError> {
    let option = parsed
        .query
        .options()
        .find(|o| o.option().req_set == candidate.req_set && o.option().items == candidate.items)
        .ok_or(HostError::CandidateMismatch)?;
    let system =
        NymAuthSystem::from_id(&candidate.system_id).ok_or(HostError::CandidateMismatch)?;
    let pair = option
        .pair(&parsed.formats, system, d)
        .map_err(ProveError::NotUsable)?;
    if pair.backend().as_str() != candidate.proof_backend {
        return Err(HostError::CandidateMismatch.into());
    }
    Ok(pair)
}

/// The answer of `pair`'s option by `stored` at `proof_time`, opened with `secret_seed`. The
/// failures of the credential come first, then those of the items: the `age_check` assertion
/// and the `pseudonym`, whose seed must open `ssc`.
///
/// # Panics
///
/// When `stored` is an mdoc of another `docType` than nym_auth's.
#[expect(
    clippy::panic,
    reason = "`match` gives candidates of nym_auth credentials only, and ProveInput carries the \
              candidate's credential; another `docType` is a bug of the host"
)]
fn answer<'q>(
    pair: UsablePair<'q>,
    stored: &StoredCredential,
    anchors: Option<&[Vec<u8>]>,
    proof_time: DateTime,
    secret_seed: &SecretSeed,
) -> Result<Answer<'q>, ProveError> {
    match UsableAttestation::new(&stored.data, anchors, proof_time) {
        Ok(attestation) => Ok(Answer::new(pair, attestation, secret_seed)?),
        Err(Unusable::OtherDocType) => {
            panic!("the candidate's credential is an mdoc of another docType")
        }
        Err(unusable) => {
            let tested = unusable
                .codes()
                .iter()
                .map(|&code| ZkpError::Credential(code));
            let items = unusable
                .credential()
                .and_then(|credential| opened_seed(&pair, credential, secret_seed).err())
                .unwrap_or_default();
            Err(ProveError::Rejected(tested.chain(items).collect()))
        }
    }
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
    option: &QueryOption,
    pseudonym: &[u8; 32],
) -> Vec<(String, Cbor)> {
    query
        .option_items(option)
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
    /// `device_binding` for a signature that does not verify.
    ///
    /// # Panics
    ///
    /// When the signature is not the 64 bytes `r ‖ s` of ES256.
    #[expect(
        clippy::expect_used,
        reason = "the host signs `data_to_sign` with ES256 as `r ‖ s`; another length is a bug \
                  of the host, and no proof binds the device key with it"
    )]
    pub fn job(&self, device_signature: &[u8]) -> Result<ProofJob, ProveError> {
        let signature: [u8; 64] = device_signature
            .try_into()
            .expect("the device signature is the 64 bytes r || s");
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
