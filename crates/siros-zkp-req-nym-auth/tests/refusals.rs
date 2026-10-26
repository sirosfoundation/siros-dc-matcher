//! G3: one fixture per refusal rule, each with the exact typed error it must give.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod refusal_cases;
mod support;

use serde_json::{json, Value};
use siros_codec::cbor::Value as Cbor;
use siros_zkp_req::{
    EncodingError, Match, PairRefusal, ProofEnvelope, RequestRule, StructureRejection,
    ZkpPresentation,
};
use siros_zkp_req_nym_auth::catalogue::CatalogueRule;
use siros_zkp_req_nym_auth::outcome::{CredentialCode, InvalidRequest, ItemCode, ZkpError};
use siros_zkp_req_nym_auth::policy::{check_request, Channel, PolicyRule};
use siros_zkp_req_nym_auth::presenter::{
    match_query, present, MatchInput, NymAuthMatch, ProveError, ProveInput,
};
use siros_zkp_req_nym_auth::prover::{ProofFailure, ProverFailure};
use siros_zkp_req_nym_auth::system::{NymAuthSystem, Unsupported};
use siros_zkp_req_nym_auth::verifier_id::{VerifierId, VerifierIdRule};
use siros_zkp_req_nym_auth::verify::{
    verify, IssuerKeySetError, ProofTimeError, Rejection, Tolerance, VerifyInput,
};
use support::*;

/// What a fixture gives.
#[derive(Debug, PartialEq)]
enum Got {
    Invalid(InvalidRequest),
    Unsupported(PairRefusal<Unsupported>),
    Rejected(Vec<ZkpError>),
    Prove(ProveError),
    Verify(Rejection),
    Policy(PolicyRule),
    VerifierId(VerifierIdRule),
    Accepted,
}

fn protocol(rule: RequestRule) -> Got {
    Got::Invalid(InvalidRequest::Protocol(rule))
}

fn catalogue(rule: CatalogueRule) -> Got {
    Got::Invalid(InvalidRequest::Catalogue(rule))
}

fn ds() -> Issuer {
    Issuer::root(0x11, "Test Document Signer")
}

fn matched(
    query: &Value,
    metadata: &Value,
    data: String,
    anchors: Option<&[Vec<u8>]>,
) -> NymAuthMatch {
    match_query(&MatchInput {
        query,
        client_metadata: metadata,
        credentials: &[stored("c1", data)],
        anchors,
        systems: &[NymAuthSystem::LongfellowV1],
        now: NOW,
    })
    .unwrap()
}

fn got(m: NymAuthMatch) -> Got {
    match m {
        Match::Invalid(rule) => Got::Invalid(rule),
        Match::Unsupported(options) => Got::Unsupported(options[0].systems[0].1.clone()),
        Match::Rejected(judged) => Got::Rejected(judged[0].errors.clone()),
        Match::Candidates(_) => Got::Accepted,
    }
}

/// Matches `query` against the default credential.
fn match_query_edit(edit: impl FnOnce(&mut Value)) -> Got {
    let mut q = query(Some("18+"), false);
    edit(&mut q);
    got(matched(
        &q,
        &client_metadata(),
        issue(&ds(), &Spec::default()),
        None,
    ))
}

fn match_metadata_edit(edit: impl FnOnce(&mut Value)) -> Got {
    let mut metadata = client_metadata();
    edit(&mut metadata);
    got(matched(
        &query(None, false),
        &metadata,
        issue(&ds(), &Spec::default()),
        None,
    ))
}

fn match_credential(spec: Spec, range: Option<&str>) -> Got {
    got(matched(
        &query(range, false),
        &client_metadata(),
        issue(&ds(), &spec),
        None,
    ))
}

/// Proves the default credential with this seed, device key and prover.
fn prove(seed: [u8; 16], device: u8, fail: Option<ProverFailure>) -> Got {
    let q = query(None, false);
    let metadata = client_metadata();
    let credential = stored("c1", issue(&ds(), &Spec::default()));
    let Match::Candidates(candidates) = matched(&q, &metadata, credential.data.clone(), None)
    else {
        panic!("no candidate");
    };
    let session = session(&q, NONCE);
    let prover = TestProver { fail };
    let result = present(
        &ProveInput {
            candidate: &candidates[0],
            query: &q,
            client_metadata: &metadata,
            session: &session,
            credential: &credential,
            secret_seed: &seed,
            anchors: None,
            now: NOW,
        },
        &DeviceSigner(device),
        &prover,
    );
    match result {
        Ok(_) => Got::Accepted,
        Err(e) => Got::Prove(e),
    }
}

fn policy(edit: impl FnOnce(&mut Value), signed: bool, channel: Channel) -> Got {
    let mut request = request_object(&query(None, false), NONCE);
    edit(&mut request);
    match check_request(&request, signed, channel) {
        Ok(_) => Got::Accepted,
        Err(rule) => Got::Policy(rule),
    }
}

fn verifier_id(result: Result<VerifierId, VerifierIdRule>) -> Got {
    match result {
        Ok(_) => Got::Accepted,
        Err(rule) => Got::VerifierId(rule),
    }
}

/// An honest presentation for a query with two options, made with `system`.
fn honest(system: NymAuthSystem, query: &Value) -> Vec<u8> {
    let metadata = client_metadata();
    let credential = stored("c1", issue(&ds(), &Spec::default()));
    let m = match_query(&MatchInput {
        query,
        client_metadata: &metadata,
        credentials: std::slice::from_ref(&credential),
        anchors: None,
        systems: &[system],
        now: NOW,
    })
    .unwrap();
    let Match::Candidates(candidates) = m else {
        panic!("no candidate")
    };
    present(
        &ProveInput {
            candidate: &candidates[0],
            query,
            client_metadata: &metadata,
            session: &session(query, NONCE),
            credential: &credential,
            secret_seed: &SEED,
            anchors: None,
            now: NOW,
        },
        &DeviceSigner(Spec::default().device),
        &TestProver { fail: None },
    )
    .unwrap()
    .encode()
}

fn sets_query() -> Value {
    let mut q = query(Some("18+"), true);
    q["_req_sets"] = json!([[0, 1], [0]]);
    q
}

struct Verifying {
    query: Value,
    metadata: Value,
    anchors: Vec<Vec<u8>>,
    now: i64,
}

impl Default for Verifying {
    fn default() -> Self {
        Self {
            query: sets_query(),
            metadata: client_metadata(),
            anchors: vec![ds().der],
            now: NOW + 5,
        }
    }
}

fn verified(v: Verifying, bytes: &[u8]) -> Got {
    let result = verify(
        &VerifyInput {
            query: &v.query,
            client_metadata: &v.metadata,
            session: &session(&v.query, NONCE),
            presentation: bytes,
            now: v.now,
            tolerance: Tolerance {
                future: 60,
                past: 600,
            },
            trust_anchors: &v.anchors,
        },
        &TestVerifier,
    );
    match result {
        Ok(_) => Got::Accepted,
        Err(r) => Got::Verify(r),
    }
}

/// Verifies the honest Longfellow presentation after `edit`.
fn verify_edit(edit: impl FnOnce(&mut ZkpPresentation)) -> Got {
    verify_edit_as(NymAuthSystem::LongfellowV1, Verifying::default(), edit)
}

fn verify_edit_as(
    system: NymAuthSystem,
    v: Verifying,
    edit: impl FnOnce(&mut ZkpPresentation),
) -> Got {
    let mut p = ZkpPresentation::decode(&honest(system, &sets_query())).unwrap();
    edit(&mut p);
    verified(v, &p.encode())
}

fn edit_envelope(p: &mut ZkpPresentation, edit: impl FnOnce(&mut ProofEnvelope)) {
    let mut envelope = ProofEnvelope::decode(&p.proof).unwrap();
    edit(&mut envelope);
    p.proof = envelope.encode();
}

fn set_input(envelope: &mut ProofEnvelope, name: &str, value: Cbor) {
    for (k, v) in &mut envelope.inputs {
        if k == name {
            *v = value.clone();
        }
    }
}

fn set_result(p: &mut ZkpPresentation, handle: &str, value: Option<Cbor>) {
    p.results.retain(|(k, _)| k != handle);
    if let Some(value) = value {
        p.results.push((handle.to_owned(), value));
    }
}

fn credential_error(code: CredentialCode) -> Got {
    Got::Rejected(vec![ZkpError::Credential(code)])
}

#[test]
fn every_refusal_rule() {
    let cases = refusal_cases::all();
    // The honest inputs each fixture edits are accepted: each fixture breaks only its rule.
    assert_eq!(match_query_edit(|_| {}), Got::Accepted);
    assert_eq!(prove(SEED, Spec::default().device, None), Got::Accepted);
    assert_eq!(verify_edit(|_| {}), Got::Accepted);
    assert_eq!(policy(|_| {}, true, Channel::Redirect), Got::Accepted);
    let failures: Vec<String> = cases
        .into_iter()
        .filter(|(_, got, want)| got != want)
        .map(|(name, got, want)| format!("{name}: got {got:?}, want {want:?}"))
        .collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// The honest presentation of a query without `_req_sets`, with a `req_set` added.
fn edited_no_sets() -> Vec<u8> {
    let mut p = ZkpPresentation::decode(&honest(
        NymAuthSystem::LongfellowV1,
        &query(Some("18+"), true),
    ))
    .unwrap();
    p.req_set = Some(0);
    p.encode()
}
