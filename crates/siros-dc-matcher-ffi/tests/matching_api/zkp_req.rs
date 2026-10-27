//! `zkp_req` over the matching surface: the circuit and the option a query is answered with, and
//! the verifier's lists in `client_metadata`.

use std::collections::HashMap;

use serde_json::json;
use siros_dc_matcher_ffi::matching::{
    match_dc_api_request, match_dcql, match_dcql_with_context, MatchError,
};
use siros_dc_matcher_ffi::{FfiCapability, FfiClaim, FfiCredential, SirosBlobBuilder};

use crate::{age_claim, dcql, wallet};

const NYM: &str = "eu.europa.ec.eudi.nym_auth.1";

/// A blob built the way an SDK builds one: through `SirosBlobBuilder`, with a
/// nym_auth mdoc that holds a claim, and the circuits registered.
fn nym_blob(circuits: &[(&str, &str, Option<&str>)]) -> Vec<u8> {
    let builder = SirosBlobBuilder::new();
    builder.add_credential(FfiCredential {
        id: "nym-1".into(),
        format: "mso_mdoc".into(),
        doctype: Some(NYM.into()),
        vct: None,
        title: "Pseudonym credential".into(),
        subtitle: "Issuer".into(),
        icon_id: None,
        claims: vec![FfiClaim {
            path: vec![NYM.into(), "birth_date".into()],
            value: "1990-01-01".into(),
            display: "Birth date".into(),
            display_value: None,
        }],
    });
    for (system, system_id, functions) in circuits {
        let mut params = HashMap::from([("system_id".to_string(), (*system_id).to_string())]);
        if let Some(functions) = functions {
            params.insert("functions".to_string(), (*functions).to_string());
        }
        builder.add_zkp_req_system(FfiCapability {
            system: (*system).to_string(),
            params,
        });
    }
    builder.build().expect("blob")
}

fn zkp_req_query(req: serde_json::Value) -> serde_json::Value {
    json!({"id": "nym", "format": "zkp_req",
           "meta": {"source_format": "mso_mdoc", "doctype_value": NYM}, "_req": req})
}

fn age_req() -> serde_json::Value {
    json!([{"fn_id": "age_check", "return": "age", "params": {"range": "18+"}}])
}

fn dcql_of(query: serde_json::Value) -> String {
    json!({"credentials": [query]}).to_string()
}

/// The verifier's lists (`zkp_req`, Section 1.2), as JSON text.
fn lists(backends: &[&str], ids: &[&str]) -> Option<String> {
    Some(
        json!({"vp_formats_supported": {"zkp_req": {
            "proof_backend_values": backends, "system_id_values": ids}}})
        .to_string(),
    )
}

/// Matches with the lists of a verifier that accepts the test circuit.
fn match_accepted(
    blob: Vec<u8>,
    query: serde_json::Value,
) -> siros_dc_matcher_ffi::matching::FfiMatchOutcome {
    match_dcql_with_context(
        blob,
        dcql_of(query),
        lists(&["longfellow-libzk-v1"], &["urn:circuit:1"]),
    )
    .expect("matched")
}

#[test]
fn a_zkp_req_match_returns_the_circuit_and_the_option() {
    let blob = nym_blob(&[("longfellow-libzk-v1", "urn:circuit:1", None)]);
    let out = match_accepted(blob, zkp_req_query(age_req()));
    assert!(out.satisfiable);
    let member = &out.combinations[0].members[0];
    assert_eq!(member.credential_id, "nym-1");
    assert!(member.claims.is_empty(), "nothing is disclosed");
    let zk: serde_json::Value =
        serde_json::from_str(member.zkp_req.as_deref().expect("zkp_req")).expect("JSON");
    assert_eq!(zk["circuit"]["system"], "longfellow-libzk-v1");
    assert_eq!(zk["circuit"]["params"]["system_id"], "urn:circuit:1");
    assert_eq!(zk["proof_backend"], "longfellow-libzk-v1");
    assert_eq!(zk["items"], json!([0]));
}

#[test]
fn other_formats_have_no_zkp_req_member() {
    let blob = wallet(None);
    let query = dcql(
        "mso_mdoc",
        age_claim(),
        json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
    );
    let out = match_dcql(blob, query).expect("matched");
    assert!(out.combinations[0].members[0].zkp_req.is_none());
}

/// The bare-query path has no envelope to read `client_metadata` from, so the
/// caller passes it, and the verifier's lists are honoured. Without them a
/// `zkp_req` query is invalid (Section 1.2) and nothing matches.
#[test]
fn match_dcql_with_context_applies_the_verifiers_lists() {
    let blob = nym_blob(&[("longfellow-libzk-v1", "urn:circuit:1", None)]);
    let query = dcql_of(zkp_req_query(age_req()));
    let with = |backends: &[&str], ids: &[&str]| {
        match_dcql_with_context(blob.clone(), query.clone(), lists(backends, ids))
            .expect("matched")
            .satisfiable
    };
    assert!(with(&["longfellow-libzk-v1"], &["urn:circuit:1"]));
    assert!(!with(&["longfellow-libzk-v1"], &["urn:other"]));
    assert!(!with(&["another-backend"], &["urn:circuit:1"]));
    assert!(
        !match_dcql_with_context(blob.clone(), query.clone(), None)
            .expect("matched")
            .satisfiable
    );
    assert!(!match_dcql(blob, query).expect("matched").satisfiable);
}

#[test]
fn unparseable_client_metadata_is_a_request_error() {
    let blob = nym_blob(&[("p", "c", None)]);
    let result = match_dcql_with_context(
        blob,
        dcql_of(zkp_req_query(age_req())),
        Some("{nope".into()),
    );
    assert!(matches!(result, Err(MatchError::Request { .. })));
}

/// DCQL refuses an object under `claims` in every format, `zkp_req` included: both entry points
/// answer with a request error.
#[test]
fn a_zkp_req_query_with_object_claims_is_a_request_error() {
    let blob = nym_blob(&[("longfellow-libzk-v1", "urn:circuit:1", None)]);
    let query = json!({"id": "nym", "format": "zkp_req",
        "meta": {"source_format": "mso_mdoc", "doctype_value": NYM},
        "claims": {"_req": [{"fn_id": "age_check", "return": "age", "params": {"range": "18+"}}]}});

    assert!(matches!(
        match_dcql_with_context(
            blob.clone(),
            dcql_of(query.clone()),
            lists(&["longfellow-libzk-v1"], &["urn:circuit:1"]),
        ),
        Err(MatchError::Request { .. })
    ));

    let envelope = json!({"requests": [{"protocol": "openid4vp-v1-unsigned",
        "data": {"dcql_query": {"credentials": [query]},
                 "client_metadata": {"vp_formats_supported": {"zkp_req": {
                     "proof_backend_values": ["longfellow-libzk-v1"],
                     "system_id_values": ["urn:circuit:1"]}}}}}]})
    .to_string();
    assert!(matches!(
        match_dc_api_request(blob, envelope),
        Err(MatchError::Request { .. })
    ));
}

/// `match_dc_api_request` already has the whole request, so `client_metadata`
/// flows through without the caller passing it again.
#[test]
fn match_dc_api_request_reads_client_metadata_from_the_request() {
    let blob = nym_blob(&[("longfellow-libzk-v1", "urn:circuit:1", None)]);
    let request = |backends: &[&str]| {
        json!({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": {
            "dcql_query": {"credentials": [zkp_req_query(age_req())]},
            "client_metadata": {"vp_formats_supported": {"zkp_req": {
                "proof_backend_values": backends, "system_id_values": ["urn:circuit:1"]}}}
        }}]})
        .to_string()
    };
    assert!(
        match_dc_api_request(blob.clone(), request(&["longfellow-libzk-v1"]))
            .expect("matched")
            .satisfiable
    );
    assert!(
        !match_dc_api_request(blob, request(&["another-backend"]))
            .expect("matched")
            .satisfiable
    );
}

#[test]
fn an_invalid_zkp_req_request_is_not_satisfiable_and_does_not_fall_back_to_claims() {
    let blob = nym_blob(&[("longfellow-libzk-v1", "urn:circuit:1", None)]);
    let mut query = zkp_req_query(age_req());
    // Ordinary DCQL claims, naming a claim the wallet holds.
    query["claims"] = json!([{"path": [NYM, "birth_date"]}]);
    let out = match_accepted(blob.clone(), query);
    assert!(!out.satisfiable);
    assert!(out.combinations.is_empty());

    let dup = zkp_req_query(json!([
        {"fn_id": "age_check", "return": "h", "params": {"range": "18+"}},
        {"fn_id": "age_check", "return": "h", "params": {"range": "18+"}}]));
    assert!(!match_accepted(blob, dup).satisfiable);
}

#[test]
fn a_wallet_without_a_circuit_is_not_offered() {
    let blob = nym_blob(&[]);
    assert!(!match_accepted(blob, zkp_req_query(age_req())).satisfiable);
}

#[test]
fn a_circuit_declaring_functions_is_filtered_across_the_boundary() {
    let blob = nym_blob(&[("longfellow-libzk-v1", "urn:circuit:1", Some("pseudonym"))]);
    assert!(!match_accepted(blob, zkp_req_query(age_req())).satisfiable);
}
