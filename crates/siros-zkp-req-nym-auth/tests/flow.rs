//! G1, the honest path, and G5, the tamper cases.
//!
//! The host is a test host: its prover binds every public value and the pseudonym into its
//! `zk_proof`, and its verifier refuses any other value. A real proof is outside this crate.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use ciborium::value::Value as Ciborium;
use serde_json::{json, Value};
use siros_zkp_req::cbor::Value as Cbor;
use siros_zkp_req::{Candidate, Match, ZkpPresentation};
use siros_zkp_req_nym_auth::presenter::{match_query, present, MatchInput, ProveInput};
use siros_zkp_req_nym_auth::prover::ProofFailure;
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::verify::{verify, Rejection, Tolerance, VerifyInput};
use support::*;

const TOLERANCE: Tolerance = Tolerance {
    future: 60,
    past: 600,
};

/// Two options: the pseudonym with an age check, or the pseudonym alone.
fn two_option_query() -> Value {
    let mut q = query(Some("18+"), true);
    q["_req_sets"] = json!([[0, 1], [0]]);
    q
}

struct Presented {
    candidate: Candidate,
    bytes: Vec<u8>,
}

fn present_with(system: NymAuthSystem, query: &Value, anchors: &[Vec<u8>]) -> Presented {
    let ds = Issuer::root(0x11, "Test Document Signer");
    let credential = stored("c1", issue(&ds, &Spec::default()));
    let metadata = client_metadata();
    let matched = match_query(&MatchInput {
        query,
        client_metadata: &metadata,
        credentials: std::slice::from_ref(&credential),
        anchors: Some(anchors),
        systems: &[system],
        now: NOW,
    })
    .unwrap();
    let Match::Candidates(candidates) = matched else {
        panic!("no candidate: {matched:?}");
    };
    let candidate = candidates[0].clone();
    let session = session(query, NONCE);
    let presentation = present(
        &ProveInput {
            candidate: &candidate,
            query,
            client_metadata: &metadata,
            session: &session,
            credential: &credential,
            secret_seed: &SEED,
            anchors: Some(anchors),
            now: NOW,
        },
        &DeviceSigner(Spec::default().device),
        &TestProver { fail: None },
    )
    .unwrap();
    Presented {
        candidate,
        bytes: presentation.encode(),
    }
}

fn verify_with(
    query: &Value,
    nonce: &str,
    bytes: &[u8],
    anchors: &[Vec<u8>],
) -> Result<siros_zkp_req_nym_auth::verify::Verified, Rejection> {
    verify(
        &VerifyInput {
            query,
            client_metadata: &client_metadata(),
            session: &session(query, nonce),
            presentation: bytes,
            now: NOW + 5,
            tolerance: TOLERANCE,
            trust_anchors: anchors,
        },
        &TestVerifier,
    )
}

fn map_get<'a>(map: &'a [(Ciborium, Ciborium)], key: &str) -> &'a Ciborium {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("{key} is missing"))
}

/// The presentation against the draft's CDDL (`zkp_req`, Section 4; the backends' `Proof`;
/// system rulebooks, Section 3), read with ciborium, a decoder independent of this crate.
fn assert_draft_shape(bytes: &[u8], system: NymAuthSystem, ds_der: &[u8]) -> [u8; 32] {
    let top: Ciborium = ciborium::from_reader(bytes).unwrap();
    let top = top.as_map().unwrap();
    let mut keys: Vec<&str> = top.iter().map(|(k, _)| k.as_text().unwrap()).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["proof", "proof_backend", "req_set", "results", "system_id"]
    );
    assert_eq!(map_get(top, "system_id").as_text(), Some(system.id()));
    assert_eq!(
        map_get(top, "proof_backend").as_text(),
        Some(system.backends()[0])
    );
    assert_eq!(map_get(top, "req_set").as_integer(), Some(0.into()));
    let proof: Ciborium =
        ciborium::from_reader(map_get(top, "proof").as_bytes().unwrap().as_slice()).unwrap();
    let proof = proof.as_map().unwrap();
    assert_eq!(proof.len(), 2);
    let inputs = map_get(proof, "inputs").as_map().unwrap();
    assert_eq!(inputs.len(), 2);
    let key_set = map_get(inputs, "issuer_key_set").as_array().unwrap();
    assert_eq!(key_set.len(), 1);
    assert_eq!(key_set[0].as_bytes().unwrap().as_slice(), ds_der);
    let Ciborium::Tag(0, time) = map_get(inputs, "proof_time") else {
        panic!("proof_time is not a tdate");
    };
    assert_eq!(time.as_text(), Some("2026-10-09T12:00:00Z"));
    let zk_proof = map_get(proof, "zk_proof").as_bytes().unwrap();
    if let Some(len) = system.zk_proof_len() {
        assert_eq!(zk_proof.len(), len);
    }
    let results = map_get(top, "results").as_map().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(map_get(results, "adult"), &Ciborium::Bool(true));
    map_get(results, "nym")
        .as_bytes()
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap()
}

/// G1: request, match, the host's signature and prover, the presentation, the Verifier's
/// checks, for each system. The pseudonym is the one the catalogue defines, written out here.
#[test]
fn honest_path_per_system() {
    let query = two_option_query();
    let ds = Issuer::root(0x11, "Test Document Signer");
    let anchors = vec![ds.der.clone()];
    for system in NymAuthSystem::ALL {
        let presented = present_with(system, &query, &anchors);
        assert_eq!(presented.candidate.req_set, Some(0));
        assert_eq!(presented.candidate.system_id, system.id());
        let nym = assert_draft_shape(&presented.bytes, system, &ds.der);
        assert_eq!(nym, expected_pseudonym(&SEED, CLIENT_ID));
        let verified = verify_with(&query, NONCE, &presented.bytes, &anchors).unwrap();
        assert_eq!(verified.system, system);
        assert_eq!(verified.req_set, Some(0));
        assert_eq!(verified.issuer_certificate, ds.der);
    }
}

/// Re-encodes a presentation after `edit`.
fn edited(bytes: &[u8], edit: impl FnOnce(&mut ZkpPresentation)) -> Vec<u8> {
    let mut p = ZkpPresentation::decode(bytes).unwrap();
    edit(&mut p);
    p.encode()
}

/// The `proof` with `proof_time` one second later: still within the tolerance.
fn later_proof_time(p: &mut ZkpPresentation) {
    let mut envelope = siros_zkp_req::ProofEnvelope::decode(&p.proof).unwrap();
    for (name, value) in &mut envelope.inputs {
        if name == "proof_time" {
            *value = Cbor::Tag(0, Box::new(Cbor::text("2026-10-09T12:00:01Z")));
        }
    }
    p.proof = envelope.encode();
}

fn flipped_pseudonym(p: &mut ZkpPresentation) {
    for (handle, value) in &mut p.results {
        if let (true, Cbor::Bytes(nym)) = (handle == "nym", value) {
            nym[0] ^= 1;
        }
    }
}

/// G5: a changed public input, a changed result and a presentation for another request are
/// each refused by the proof check, after every earlier check passed: the Verifier built its
/// statement from the changed value.
#[test]
fn tampering_is_refused_by_the_proof() {
    let query = two_option_query();
    let ds = Issuer::root(0x11, "Test Document Signer");
    let anchors = vec![ds.der.clone()];
    for system in NymAuthSystem::ALL {
        let honest = present_with(system, &query, &anchors).bytes;
        let cases = [
            ("proof_time", edited(&honest, later_proof_time), NONCE),
            ("result", edited(&honest, flipped_pseudonym), NONCE),
            ("other request", honest.clone(), "aNotherNonce-0123456789"),
        ];
        for (name, bytes, nonce) in cases {
            let rejection = verify_with(&query, nonce, &bytes, &anchors).unwrap_err();
            assert_eq!(
                rejection,
                Rejection::Proof(ProofFailure::Invalid),
                "{system:?} {name}"
            );
        }
        verify_with(&query, NONCE, &honest, &anchors).unwrap();
    }
}
