//! `zkp_req` through the shipping binary: the circuit, the option and the verifier's lists.

use crate::*;

fn nym_request(query: Value, client_metadata: Option<Value>) -> Vec<u8> {
    let mut data = json!({"dcql_query": {"credentials": [query]}});
    if let Some(cm) = client_metadata {
        data["client_metadata"] = cm;
    }
    json!({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": data}]})
        .to_string()
        .into_bytes()
}

fn nym_query() -> Value {
    json!({"id": "nym", "format": "zkp_req",
    "meta": {"source_format": "mso_mdoc", "doctype_value": fixtures::NYM_AUTH_DOCTYPE},
    "_req": [
        {"fn_id": "pseudonym", "return": "n",
         "params": {"config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256"}},
        {"fn_id": "age_check", "return": "a", "params": {"range": "13-17"}}
    ]})
}

/// The verifier's lists (`zkp_req`, Section 1.2): one backend and one system.
fn lists(backend: &str, system_id: &str) -> Value {
    json!({"vp_formats_supported": {"zkp_req": {
        "proof_backend_values": [backend], "system_id_values": [system_id]}}})
}

fn nym_db(circuits: Vec<Capability>) -> CredentialDatabase {
    fixtures::nym_wallet(circuits)
}

/// The real binary, end to end: a `zkp_req` match is one entry whose rows
/// come from the answered option, not from the credential's claims, and every
/// row says the request behind it is unverified.
#[test]
fn a_zkp_req_request_is_offered_with_rows_from_the_option() {
    let db = nym_db(vec![fixtures::circuit(
        "longfellow-libzk-v1",
        "urn:circuit:1",
        None,
    )]);
    let captured = invoke(
        &db,
        nym_request(
            nym_query(),
            Some(lists("longfellow-libzk-v1", "urn:circuit:1")),
        ),
    );

    let entry = captured.entry("siros-0", 0).expect("zkp_req entry");
    assert_eq!(entry.credential_id, "nym-1");

    let meta = data(entry);
    assert_eq!(
        meta["claims"],
        json!([]),
        "a zkp_req match carries no claims"
    );
    assert_eq!(meta["zkp_req"]["circuit"]["system"], "longfellow-libzk-v1");
    assert_eq!(meta["zkp_req"]["proof_backend"], "longfellow-libzk-v1");
    assert_eq!(meta["zkp_req"]["items"], json!([0, 1]));

    let names: Vec<&str> = entry.fields.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["Pseudonym", "Age check"]);
    assert!(!names.contains(&"Birth date"), "no claim field: {names:?}");
    for (name, value) in &entry.fields {
        assert!(value.ends_with("(unverified request)"), "{name}: {value}");
    }
}

#[test]
fn a_non_zkp_req_match_has_no_zkp_req_metadata() {
    let captured = invoke(
        &wallet(None),
        request(
            "mso_mdoc",
            json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
        ),
    );
    let entry = captured.entry("siros-0", 0).expect("entry");
    let meta = data(entry);
    assert!(meta["zkp_req"].is_null());
}

#[test]
fn the_verifiers_lists_decide_in_the_binary() {
    let db = nym_db(vec![fixtures::circuit("p", "c", None)]);
    assert!(!invoke(&db, nym_request(nym_query(), Some(lists("p", "c")))).is_empty());
    assert!(invoke(&db, nym_request(nym_query(), Some(lists("q", "c")))).is_empty());
    assert!(invoke(&db, nym_request(nym_query(), Some(lists("p", "d")))).is_empty());
    assert!(invoke(&db, nym_request(nym_query(), None)).is_empty());
}

/// The binary reads the new registration params the way the library does.
#[test]
fn credential_type_and_capabilities_decide_in_the_binary() {
    let with = |params: &[(&str, String)]| {
        let mut c = fixtures::circuit("p", "c", None);
        for (k, v) in params {
            c.params.insert((*k).to_string(), v.clone());
        }
        nym_db(vec![c])
    };
    let offered = |db: &CredentialDatabase| {
        !invoke(db, nym_request(nym_query(), Some(lists("p", "c")))).is_empty()
    };
    let caps = |ty: &str| {
        json!({"schema": 1, "presentation": "zkp_req",
               "credential": {"format": "mso_mdoc", "type": ty},
               "functions": [
                   {"id": "pseudonym", "always": true,
                    "params": {"config": {"enum": ["known-offender-matching-ssc"]},
                               "ver": {"type": "integer"}, "prf": {"enum": ["sha-256"]}}},
                   {"id": "age_check", "max": 1, "params": {"range": {"type": "string"}}}]})
        .to_string()
    };

    assert!(offered(&with(&[])));
    assert!(offered(&with(&[(
        "credential_type",
        fixtures::NYM_AUTH_DOCTYPE.into()
    )])));
    assert!(!offered(&with(&[(
        "credential_type",
        "eu.example.other.1".into()
    )])));
    assert!(offered(&with(&[(
        "capabilities",
        caps(fixtures::NYM_AUTH_DOCTYPE)
    )])));
    assert!(!offered(&with(&[(
        "capabilities",
        caps("eu.example.other.1")
    )])));
    assert!(!offered(&with(&[("capabilities", "{not json".into())])));
}

/// `claims` in any form is not `zkp_req`: an object, which DCQL cannot
/// represent, reaches the protocol crate and is refused as a request for
/// nothing.
#[test]
fn a_zkp_req_request_with_object_claims_offers_nothing() {
    let db = nym_db(vec![fixtures::circuit("p", "c", None)]);
    let query = json!({"id": "nym", "format": "zkp_req",
        "meta": {"source_format": "mso_mdoc", "doctype_value": fixtures::NYM_AUTH_DOCTYPE},
        "claims": {"_req": [{"fn_id": "age_check", "return": "a", "params": {"range": "18+"}}]}});
    assert!(invoke(&db, nym_request(query, Some(lists("p", "c")))).is_empty());
}

#[test]
fn zkp_req_offers_nothing_without_a_circuit_or_with_an_invalid_query() {
    // No circuit registered.
    assert!(invoke(
        &nym_db(vec![]),
        nym_request(nym_query(), Some(lists("p", "c")))
    )
    .is_empty());

    let db = nym_db(vec![fixtures::circuit("p", "c", None)]);
    // Ordinary claims on zkp_req: no fallback to claim matching, although
    // the wallet holds the claim.
    let mut with_claims = nym_query();
    with_claims["claims"] = json!([{"path": [fixtures::NYM_AUTH_DOCTYPE, "birth_date"]}]);
    assert!(invoke(&db, nym_request(with_claims, Some(lists("p", "c")))).is_empty());

    let mut invalid = nym_query();
    invalid["_req"] = json!([{"fn_id": "age_check", "return": "x", "params": {"range": "18"}}]);
    assert!(invoke(&db, nym_request(invalid, Some(lists("p", "c")))).is_empty());
}
