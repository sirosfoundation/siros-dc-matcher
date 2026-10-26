//! The `zkp_req` verifier through the FFI: a presentation made on the plan's path, verified with
//! the statement the prover received.

use std::sync::Arc;

use siros_dc_matcher_ffi::zkp_req::{
    zkp_req_jwk_thumbprint, zkp_req_session, zkp_req_verify, zkp_req_vp_token_json, FfiChannel,
    FfiProofCheck, FfiProofVerifier, FfiStatement, FfiVerifierIdForm, FfiVpTokenEntry, ZkpReqError,
};
use siros_zkp_req_nym_auth::prover::ProofOutput;
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::testing::{
    client_metadata, device_signature, encryption_jwk, expected_pseudonym, issue, prepared, query,
    request_object, verified_request, Issuer, Spec, CLIENT_ID, NONCE, NOW, SEED,
};

/// A verifier that accepts exactly the statement the prover received.
struct Expecting(FfiStatement);

impl FfiProofVerifier for Expecting {
    fn verify(&self, statement: FfiStatement, _: Vec<u8>, _: Vec<u8>) -> FfiProofCheck {
        if self.0 == statement {
            FfiProofCheck::Accepted
        } else {
            FfiProofCheck::Invalid
        }
    }
}

fn session(nonce: &str) -> Arc<siros_dc_matcher_ffi::zkp_req::FfiSession> {
    let thumbprint = zkp_req_jwk_thumbprint(encryption_jwk().to_string()).unwrap();
    zkp_req_session(
        request_object(&query(Some("18+"), true), nonce).to_string(),
        true,
        FfiChannel::Redirect,
        thumbprint,
        FfiVerifierIdForm::X509SanDns {
            registration_names_intermediary: false,
        },
    )
    .unwrap()
}

#[test]
fn a_presentation_verifies_through_the_ffi() {
    let q = query(Some("18+"), true);
    let ds = Issuer::root(0x11, "Test Document Signer");
    let request = verified_request(&q, NONCE);
    let data = issue(&ds, &Spec::default());
    let prepared = prepared(NymAuthSystem::LongfellowV1, &q, &data, &SEED, &request).unwrap();
    let signature = device_signature(Spec::default().device, prepared.data_to_sign());
    let job = prepared.job(&signature).unwrap();
    let pseudonym = expected_pseudonym(&SEED, CLIENT_ID);
    let presentation = prepared
        .assemble(&ProofOutput {
            zk_proof: vec![7; 1024],
            pseudonym,
        })
        .unwrap()
        .encode();
    let vp_token = zkp_req_vp_token_json(vec![FfiVpTokenEntry {
        query_id: "nym".into(),
        presentations: vec![presentation.clone()],
    }])
    .unwrap();
    assert!(vp_token.starts_with("{\"nym\":[\""));

    let verifier = Arc::new(Expecting(FfiStatement::from(job.statement())));
    let verify = |nonce: &str| {
        zkp_req_verify(
            q.to_string(),
            client_metadata().to_string(),
            session(nonce),
            presentation.clone(),
            NOW + 5,
            60,
            600,
            vec![ds.der.clone()],
            verifier.clone(),
        )
    };
    let verified = verify(NONCE).unwrap();
    assert_eq!(verified.system_id, "urn:circuits:longfellow:nym_auth:v1");
    let nym = verified.results.iter().find(|r| r.handle == "nym").unwrap();
    assert_eq!(nym.value, [&[0x58, 0x20][..], &pseudonym].concat());
    // Another request's session gives another statement: the proof check refuses it.
    assert!(matches!(
        verify("aNotherNonce-0123456789"),
        Err(ZkpReqError::Refused { code, .. }) if code == "proof_invalid"
    ));
}
