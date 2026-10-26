//! The statement of an answer, the device signature, the prover's job and the presentation
//! (system rulebooks, Section 7; `zkp_req`, Section 4).

use std::fmt;

use siros_codec::cbor::Value as Cbor;
use siros_codec::date::Date;
use siros_mdoc::{device_signing_input, es256_verifies, DeviceNameSpaces};
use siros_wallet_state::KeyId;
use siros_zkp_req::{PairRefusal, ProofEnvelope, QueryOption, ZkpPresentation};

use super::answer::{Answer, Unanswerable};
use super::{Session, MAX_ZK_PROOF};
use crate::age::Bound;
use crate::attestation::{OpenedSeed, UsableAttestation};
use crate::catalogue::{Function, NymAuthQuery, MDOC_DOCTYPE};
use crate::outcome::{CredentialCode, ZkpError};
use crate::prover::{NymAuthProver, ProofJob, ProofOutput, ProverFailure, Statement};
use crate::request::NymAuthRequest;
use crate::system::{pair_code, Unsupported};
use crate::verifier_id::{pseudonym_sha256, sha256, verifier_input};

/// A host input this presenter cannot use. It is a defect of the host, never of the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostError {
    /// The attestation was tested at another date than the pair's proof date.
    Time,
    /// The device signature is not 64 bytes, `r ‖ s`.
    SignatureLength,
}

impl HostError {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::Time => "time",
            Self::SignatureLength => "signature_length",
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "host input: {}", self.code())
    }
}

impl std::error::Error for HostError {}

/// Why no presentation was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveError {
    /// An input of the host.
    Host(HostError),
    /// The attestation is usable for another query than the answer's.
    OtherQuery,
    /// The pair is no longer usable for its option.
    NotUsable(PairRefusal<Unsupported>),
    /// The credential fails for the option.
    Rejected(Vec<ZkpError>),
    /// The prover made no proof.
    Prover(ProverFailure),
    /// The prover's pseudonym differs from the catalogue's.
    PseudonymMismatch,
    /// The prover's `zk_proof` breaks the proof backend's length rules.
    ZkProofLength,
}

impl ProveError {
    /// The error code for the Verifier (`zkp_req`, Section 5): `access_denied`.
    pub fn error_code(&self) -> siros_zkp_req::ErrorCode {
        siros_zkp_req::ErrorCode::AccessDenied
    }

    /// A stable identifier: the code of the host input, the pair refusal or the prover;
    /// `credential` for a credential that fails, with its codes in the variant.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Host(e) => e.code(),
            Self::OtherQuery => "other_query",
            Self::NotUsable(refusal) => pair_code(refusal),
            Self::Rejected(_) => "credential",
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

impl From<Unanswerable> for ProveError {
    fn from(e: Unanswerable) -> Self {
        match e {
            Unanswerable::OtherQuery => Self::OtherQuery,
            Unanswerable::ProofDate => Self::Host(HostError::Time),
            Unanswerable::Failed(errors) => Self::Rejected(errors),
        }
    }
}

impl From<HostError> for ProveError {
    fn from(e: HostError) -> Self {
        Self::Host(e)
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

impl Prepared {
    /// The statement of `answer` in the session of `request`, for the device key `key_id`
    /// (system rulebooks, Section 7).
    ///
    /// # Errors
    ///
    /// [`ProveError::NotUsable`] for an `age_check` bound the system does not encode.
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
    let signer = attestation.credential().signer();
    let statement = Statement {
        system: pair.system(),
        proof_backend: pair.backend().as_str().to_owned(),
        doc_type: MDOC_DOCTYPE,
        issuer_certificate: signer.certificate().der().to_vec(),
        issuer_key: *signer.key(),
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

    /// The identifier of the device key.
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
