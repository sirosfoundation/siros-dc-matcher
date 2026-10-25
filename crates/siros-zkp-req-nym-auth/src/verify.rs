//! The Verifier's side (`zkp_req`, Section 4.1, and system rulebooks, Sections 4 and 9): it
//! builds the statement from its own request, session, clock and trust configuration, takes
//! only `req_set`, `results` and the prover-supplied values from the presentation, and hands
//! the proof to a system's verifier.

use std::fmt;

use serde_json::Value;
use siros_zkp_req::cbor::Value as Cbor;
use siros_zkp_req::{
    answered_option, EncodingError, ProofEnvelope, QueryOption, StructureRejection, ZkpFormats,
    ZkpPresentation, ZkpReqQuery,
};

use crate::age::{Bound, Bounds};
use crate::catalogue::{has_result, Function, NymAuthQuery, MDOC_DOCTYPE};
use crate::date::{Date, DateTime};
use crate::outcome::InvalidRequest;
use crate::presenter::{Session, MAX_ZK_PROOF};
use crate::prover::{NymAuthProofVerifier, ProofFailure, Statement};
use crate::session::device_message;
use crate::system::{NymAuthSystem, Unsupported};
use crate::verifier_id::{sha256, verifier_input};
use crate::x509::{chains_to, CertificateError, P256Certificate};

/// How far `proof_time` may lie from the Verifier's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tolerance {
    /// Seconds ahead of the clock.
    pub future: i64,
    /// Seconds behind the clock.
    pub past: i64,
}

/// What the Verifier holds.
#[derive(Debug, Clone, Copy)]
pub struct VerifyInput<'a> {
    /// Its Credential Query.
    pub query: &'a Value,
    /// Its `client_metadata`.
    pub client_metadata: &'a Value,
    /// Its session: the `Handover` of the request it sent, and its `verifier_id`.
    pub session: &'a Session,
    /// The presentation, CBOR.
    pub presentation: &'a [u8],
    /// Its clock: seconds since 1970-01-01T00:00:00Z.
    pub now: i64,
    /// Its tolerance for `proof_time`.
    pub tolerance: Tolerance,
    /// Its trust configuration: DER certificates of the anchors it trusts for this query.
    pub trust_anchors: &'a [Vec<u8>],
}

/// What an accepted presentation establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The system.
    pub system: NymAuthSystem,
    /// The proof backend.
    pub proof_backend: String,
    /// The answered option's index in `_req_sets`.
    pub req_set: Option<usize>,
    /// `results`.
    pub results: Vec<(String, Cbor)>,
    /// The Document Signer certificate the proof was made against.
    pub issuer_certificate: Vec<u8>,
    /// The proof time.
    pub proof_time: DateTime,
}

/// Why `issuer_key_set` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssuerKeySetError {
    /// It holds zero or several certificates.
    Count,
    /// The certificate is not one of the systems' form.
    Certificate(CertificateError),
    /// The certificate chains to no trust anchor, or is not valid at the Verifier's clock.
    Untrusted,
}

/// Why `proof_time` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofTimeError {
    /// It is not exactly `YYYY-MM-DDThh:mm:ssZ`, a real UTC second.
    Malformed,
    /// It lies beyond the tolerance of the Verifier's clock.
    Tolerance,
}

/// Why a presentation is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// The Verifier's own query is invalid, or its clock is out of range.
    Request(Option<InvalidRequest>),
    /// The Verifier's own option lies outside the system's Section 2: `request`.
    Unsupported(Unsupported),
    /// The presentation is not a `ZkpPresentation`.
    Presentation(EncodingError),
    /// Steps 1 to 5 of `zkp_req`, Section 4.1.
    Structure(StructureRejection),
    /// `proof` breaks the proof backend's format, or `inputs` breaks Section 3:
    /// `proof_encoding`.
    ProofEncoding,
    /// `issuer_key_set`.
    IssuerKeySet(IssuerKeySetError),
    /// `proof_time`.
    ProofTime(ProofTimeError),
    /// The pseudonym is no 32-byte `bstr`: `results`.
    Results,
    /// The system's verifier refused the proof.
    Proof(ProofFailure),
}

impl Rejection {
    /// The code of the system rulebooks' Section 9 table, or the step of `zkp_req`,
    /// Section 4.1.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Request(_) | Self::Unsupported(_) => "request",
            Self::Presentation(_) => "presentation",
            Self::Structure(_) => "structure",
            Self::ProofEncoding | Self::Proof(ProofFailure::Encoding) => "proof_encoding",
            Self::IssuerKeySet(_) => "issuer_key_set",
            Self::ProofTime(_) => "proof_time",
            Self::Results => "results",
            Self::Proof(ProofFailure::Invalid) => "proof_invalid",
            Self::Proof(ProofFailure::PublicInput) => "public_input",
        }
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl std::error::Error for Rejection {}

/// The prover-supplied values of a presentation, read.
struct Supplied {
    certificate: P256Certificate,
    proof_time: DateTime,
    zk_proof: Vec<u8>,
}

/// Verifies a presentation for one query.
///
/// # Errors
///
/// [`Rejection`]: the first check that fails.
pub fn verify(
    input: &VerifyInput<'_>,
    verifier: &dyn NymAuthProofVerifier,
) -> Result<Verified, Rejection> {
    let now = DateTime::from_unix(input.now).ok_or(Rejection::Request(None))?;
    let (query, formats) = own_query(input.query, input.client_metadata)?;
    let presentation =
        ZkpPresentation::decode(input.presentation).map_err(Rejection::Presentation)?;
    let option = answered_option(
        &query.query,
        &formats,
        &presentation,
        |system, backend| {
            NymAuthSystem::from_id(system).is_some_and(|s| s.backends().contains(&backend))
        },
        |item| has_result(&item.fn_id),
    )
    .map_err(Rejection::Structure)?;
    let system = NymAuthSystem::from_id(&presentation.system_id)
        .ok_or(Rejection::Structure(StructureRejection::SystemNotOnBackend))?;
    let supplied = supplied(&presentation, system, input, now)?;
    let bounds = own_bounds(&query, option, system, supplied.proof_time.date())?;
    let pseudonym = pseudonym_result(&query, option, &presentation)?;
    let session_transcript = input.session.handover.session_transcript();
    let challenge_digest = sha256(&device_message(&session_transcript, MDOC_DOCTYPE));
    let statement = Statement {
        system,
        proof_backend: presentation.proof_backend.clone(),
        doc_type: MDOC_DOCTYPE,
        issuer_certificate: supplied.certificate.der.clone(),
        issuer_key: supplied.certificate.key,
        proof_time: supplied.proof_time,
        earliest: bound(bounds.earliest)?,
        cutoff: bound(bounds.cutoff)?,
        verifier_input: own_verifier_input(&query, option, input.session)?,
        session_transcript,
        challenge_digest,
    };
    verifier
        .verify(&statement, &pseudonym, &supplied.zk_proof)
        .map_err(Rejection::Proof)?;
    Ok(Verified {
        system,
        proof_backend: presentation.proof_backend,
        req_set: option.req_set,
        results: presentation.results,
        issuer_certificate: supplied.certificate.der,
        proof_time: supplied.proof_time,
    })
}

fn own_query(
    query: &Value,
    client_metadata: &Value,
) -> Result<(NymAuthQuery, ZkpFormats), Rejection> {
    let invalid = |rule: InvalidRequest| Rejection::Request(Some(rule));
    let parsed = ZkpReqQuery::parse(query).map_err(|r| invalid(r.into()))?;
    let formats =
        ZkpFormats::from_client_metadata(client_metadata).map_err(|r| invalid(r.into()))?;
    let query = NymAuthQuery::from_query(parsed)
        .map_err(|r| invalid(r.into()))?
        .ok_or(Rejection::Request(None))?;
    Ok((query, formats))
}

/// `inputs` (system rulebooks, Section 3) and `zk_proof`.
fn supplied(
    presentation: &ZkpPresentation,
    system: NymAuthSystem,
    input: &VerifyInput<'_>,
    now: DateTime,
) -> Result<Supplied, Rejection> {
    let envelope =
        ProofEnvelope::decode(&presentation.proof).map_err(|_| Rejection::ProofEncoding)?;
    let length_ok = envelope.zk_proof.len() <= MAX_ZK_PROOF
        && system
            .zk_proof_len()
            .is_none_or(|n| n == envelope.zk_proof.len());
    if !length_ok || envelope.inputs.len() != 2 {
        return Err(Rejection::ProofEncoding);
    }
    let input_of = |name: &str| {
        envelope
            .inputs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
            .ok_or(Rejection::ProofEncoding)
    };
    let certificate = issuer_certificate(input_of("issuer_key_set")?, input, now)?;
    let proof_time = proof_time(input_of("proof_time")?, input, now)?;
    Ok(Supplied {
        certificate,
        proof_time,
        zk_proof: envelope.zk_proof,
    })
}

/// `issuer_key_set`: `[ bstr ]`, exactly one DER certificate the Verifier trusts now.
fn issuer_certificate(
    value: &Cbor,
    input: &VerifyInput<'_>,
    now: DateTime,
) -> Result<P256Certificate, Rejection> {
    let Cbor::Array(set) = value else {
        return Err(Rejection::ProofEncoding);
    };
    if set.iter().any(|c| !matches!(c, Cbor::Bytes(_))) {
        return Err(Rejection::ProofEncoding);
    }
    let [Cbor::Bytes(der)] = set.as_slice() else {
        return Err(Rejection::IssuerKeySet(IssuerKeySetError::Count));
    };
    let certificate = P256Certificate::parse(der)
        .map_err(|e| Rejection::IssuerKeySet(IssuerKeySetError::Certificate(e)))?;
    if !chains_to(&certificate, input.trust_anchors) || !certificate.valid_at(now.unix()) {
        return Err(Rejection::IssuerKeySet(IssuerKeySetError::Untrusted));
    }
    Ok(certificate)
}

/// `proof_time`: `tdate`, exactly 20 characters, within the tolerance.
fn proof_time(value: &Cbor, input: &VerifyInput<'_>, now: DateTime) -> Result<DateTime, Rejection> {
    let Cbor::Tag(0, text) = value else {
        return Err(Rejection::ProofEncoding);
    };
    let Cbor::Text(text) = text.as_ref() else {
        return Err(Rejection::ProofEncoding);
    };
    let time = DateTime::parse(text).ok_or(Rejection::ProofTime(ProofTimeError::Malformed))?;
    let earliest = now.unix().saturating_sub(input.tolerance.past);
    let latest = now.unix().saturating_add(input.tolerance.future);
    if !(earliest..=latest).contains(&time.unix()) {
        return Err(Rejection::ProofTime(ProofTimeError::Tolerance));
    }
    Ok(time)
}

/// E and C of the Verifier's own option at the proof date, which the system must support.
fn own_bounds(
    query: &NymAuthQuery,
    option: &QueryOption,
    system: NymAuthSystem,
    d: Date,
) -> Result<Bounds, Rejection> {
    let bounds = query
        .option_items(option)
        .find_map(|(_, item)| match &item.function {
            Function::AgeCheck(age) => Some(age.range.bounds(d)),
            Function::Pseudonym(_) => None,
        })
        .unwrap_or(Bounds::WIDEST);
    system
        .supports(query.option_items(option).map(|(_, i)| i), &bounds)
        .map_err(Rejection::Unsupported)?;
    Ok(bounds)
}

fn bound(bound: Option<Bound>) -> Result<Option<Date>, Rejection> {
    match bound {
        None => Ok(None),
        Some(Bound::Date(d)) => Ok(Some(d)),
        Some(Bound::Unencodable) => Err(Rejection::Unsupported(Unsupported::AgeBounds)),
    }
}

/// The pseudonym of `results`: a 32-byte `bstr` under the `pseudonym` item's handle.
fn pseudonym_result(
    query: &NymAuthQuery,
    option: &QueryOption,
    presentation: &ZkpPresentation,
) -> Result<[u8; 32], Rejection> {
    let handle = query
        .option_items(option)
        .find_map(|(_, item)| match item.function {
            Function::Pseudonym(_) => item.ret.as_ref(),
            Function::AgeCheck(_) => None,
        })
        .ok_or(Rejection::Unsupported(Unsupported::NoPseudonym))?;
    let value = presentation
        .results
        .iter()
        .find(|(k, _)| k == handle.as_str())
        .map(|(_, v)| v);
    match value {
        Some(Cbor::Bytes(b)) => b.as_slice().try_into().map_err(|_| Rejection::Results),
        _ => Err(Rejection::Results),
    }
}

fn own_verifier_input(
    query: &NymAuthQuery,
    option: &QueryOption,
    session: &Session,
) -> Result<[u8; 32], Rejection> {
    query
        .option_items(option)
        .find_map(|(_, item)| match &item.function {
            Function::Pseudonym(p) => Some(verifier_input(p, &session.verifier_id)),
            Function::AgeCheck(_) => None,
        })
        .ok_or(Rejection::Unsupported(Unsupported::NoPseudonym))
}
