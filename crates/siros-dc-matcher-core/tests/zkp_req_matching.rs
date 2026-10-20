//! Matching `zkp_req` (nym_auth) credentials through the planner.
//!
//! The matcher decides which credentials could answer a `zkp_req` request
//! from the plan, the wallet's registered circuits and the verifier's
//! `client_metadata`. It applies no satisfiability rules: those belong to the
//! wallet, so some tests here pin that a request which is unsatisfiable by the
//! rulebook is still offered.

use serde_json::{json, Value};
use siros_dc_matcher_core::db::CredentialDatabase;
use siros_dc_matcher_core::evaluator::{credentials, resolve, ProfilePolicy};
use siros_dc_matcher_core::fixtures::{circuit, nym_wallet, NYM_AUTH_DOCTYPE};
use siros_dc_matcher_core::request::first_supported_context;
use siros_dcql::execute;

const LONGFELLOW: &str = "longfellow-libzk-v1";
const CIRCUIT: &str = "urn:circuits:longfellow:nym_auth:v1";

fn normative(req: Value) -> Value {
    json!({"id": "nym", "format": "zkp_req",
           "meta": {"source_format": "mso_mdoc", "doctype_value": NYM_AUTH_DOCTYPE},
           "_req": req})
}

fn age() -> Value {
    json!({"fn_id": "age_check", "return": "age", "params": {"ge": "2008-10-10", "le": "2013-10-09"}})
}

fn pseudonym() -> Value {
    json!({"fn_id": "pseudonym", "return": "nym",
           "params": {"config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256"}})
}

fn client_metadata(systems: Option<&[&str]>, ids: Option<&[&str]>) -> Value {
    let mut entry = serde_json::Map::new();
    if let Some(systems) = systems {
        entry.insert("proof_system_values".into(), json!(systems));
    }
    if let Some(ids) = ids {
        entry.insert("system_id_values".into(), json!(ids));
    }
    json!({"vp_formats_supported": {"zkp_req": entry}})
}

fn envelope(query: Value, client_metadata: Option<Value>) -> Vec<u8> {
    let mut data = json!({"dcql_query": {"credentials": [query]}});
    if let Some(cm) = client_metadata {
        data["client_metadata"] = cm;
    }
    json!({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": data}]})
        .to_string()
        .into_bytes()
}

/// What the matcher offers: the candidate credential ids, and for the first
/// one its resolved claims and `zkp_req` selection as JSON.
struct Outcome {
    ids: Vec<String>,
    claims: Vec<Vec<String>>,
    selection: Option<Value>,
}

fn run(db: &CredentialDatabase, request: &[u8]) -> Outcome {
    let none = Outcome {
        ids: vec![],
        claims: vec![],
        selection: None,
    };
    let Some(context) = first_supported_context(request, &db.profile, None) else {
        return none;
    };
    let Some(query) = context.matching_query() else {
        return none;
    };
    let held = credentials(db);
    let policy = ProfilePolicy::new(&db.profile).with_context(&context);
    let result = execute(&query, &held, &policy);
    let Some(matched) = result.query("nym") else {
        return none;
    };
    let first = matched.candidates.first().map(|candidate| {
        let cq = query.credential("nym").expect("query");
        resolve(&policy, cq, candidate)
    });
    Outcome {
        ids: matched
            .candidates
            .iter()
            .map(|c| c.credential_id.clone())
            .collect(),
        claims: first.as_ref().map(|r| r.claims.clone()).unwrap_or_default(),
        selection: first.and_then(|r| r.zkp_req.map(|z| z.to_json())),
    }
}

fn wallet() -> CredentialDatabase {
    nym_wallet(vec![circuit(LONGFELLOW, CIRCUIT, None)])
}

#[test]
fn a_nym_auth_mdoc_matches_in_the_normative_shape() {
    let out = run(
        &wallet(),
        &envelope(normative(json!([pseudonym(), age()])), None),
    );
    assert_eq!(out.ids, ["nym-1"]);
    let selection = out.selection.expect("selection");
    assert_eq!(selection["circuit"]["system"], LONGFELLOW);
    assert_eq!(selection["circuit"]["params"]["system_id"], CIRCUIT);
    let functions = selection["plan"]["functions"].as_array().expect("array");
    assert_eq!(functions.len(), 2);
    assert_eq!(functions[0]["function_id"], "pseudonym");
    assert_eq!(functions[1]["handle"], "age");
}

/// The credential holds a `birth_date` claim. A `zkp_req` match proves
/// things about it and discloses nothing.
#[test]
fn a_zkp_req_match_carries_no_claims() {
    let out = run(&wallet(), &envelope(normative(json!([age()])), None));
    assert_eq!(out.ids, ["nym-1"]);
    assert!(out.claims.is_empty());
}

#[test]
fn no_match_when_the_wallet_has_no_circuit() {
    let out = run(
        &nym_wallet(vec![]),
        &envelope(normative(json!([age()])), None),
    );
    assert!(out.ids.is_empty());
}

#[test]
fn another_doctype_does_not_match() {
    let mut query = normative(json!([age()]));
    query["meta"]["doctype_value"] = json!("org.iso.18013.5.1.mDL");
    assert!(run(&wallet(), &envelope(query, None)).ids.is_empty());
}

#[test]
fn system_id_values_filter_the_wallets_circuits() {
    let db = nym_wallet(vec![
        circuit(LONGFELLOW, "urn:circuits:other", None),
        circuit(LONGFELLOW, CIRCUIT, None),
    ]);
    let wants = |ids: &[&str]| {
        run(
            &db,
            &envelope(
                normative(json!([age()])),
                Some(client_metadata(None, Some(ids))),
            ),
        )
    };
    // The second circuit is the one chosen: the first is ruled out.
    let chosen = wants(&[CIRCUIT]).selection.expect("selection");
    assert_eq!(chosen["circuit"]["params"]["system_id"], CIRCUIT);
    assert!(wants(&["urn:circuits:unknown"]).ids.is_empty());
}

#[test]
fn proof_system_values_filter_the_wallets_circuits() {
    let wants = |systems: &[&str]| {
        run(
            &wallet(),
            &envelope(
                normative(json!([age()])),
                Some(client_metadata(Some(systems), None)),
            ),
        )
    };
    assert_eq!(wants(&[LONGFELLOW]).ids, ["nym-1"]);
    assert_eq!(wants(&["other-proof-system", LONGFELLOW]).ids, ["nym-1"]);
    assert!(wants(&["other-proof-system"]).ids.is_empty());
}

#[test]
fn both_lists_must_hold_for_the_same_circuit() {
    let db = nym_wallet(vec![
        circuit("system-a", "circuit-a", None),
        circuit("system-b", "circuit-b", None),
    ]);
    let out = run(
        &db,
        &envelope(
            normative(json!([age()])),
            Some(client_metadata(Some(&["system-a"]), Some(&["circuit-b"]))),
        ),
    );
    assert!(
        out.ids.is_empty(),
        "system-a with circuit-b is not one circuit"
    );
}

/// The rulebook calls both lists OPTIONAL, so a verifier that sends neither
/// constrains nothing.
#[test]
fn absent_verifier_lists_are_no_constraint() {
    for cm in [
        None,
        Some(json!({})),
        Some(json!({"vp_formats_supported": {}})),
        Some(client_metadata(None, None)),
    ] {
        let out = run(&wallet(), &envelope(normative(json!([age()])), cm));
        assert_eq!(out.ids, ["nym-1"]);
    }
}

#[test]
fn a_circuit_declaring_functions_is_filtered_by_them() {
    let only_age = nym_wallet(vec![circuit(LONGFELLOW, CIRCUIT, Some("age_check"))]);
    let both = nym_wallet(vec![circuit(
        LONGFELLOW,
        CIRCUIT,
        Some("age_check, pseudonym"),
    )]);
    let wants_both = envelope(normative(json!([pseudonym(), age()])), None);
    let wants_age = envelope(normative(json!([age()])), None);

    assert!(run(&only_age, &wants_both).ids.is_empty());
    assert_eq!(run(&only_age, &wants_age).ids, ["nym-1"]);
    assert_eq!(run(&both, &wants_both).ids, ["nym-1"]);
}

#[test]
fn a_circuit_declaring_no_functions_is_not_filtered() {
    let out = run(
        &wallet(),
        &envelope(normative(json!([pseudonym(), age()])), None),
    );
    assert_eq!(out.ids, ["nym-1"]);
    // A function the rulebook does not define is unsatisfiable, whatever the
    // circuit declares.
    let req = json!([age(), {"fn_id": "future_fn", "return": "f"}]);
    assert!(run(&wallet(), &envelope(normative(req), None))
        .ids
        .is_empty());
}

/// A `claims` array is ordinary DCQL, which `zkp_req` does not use. The
/// wallet holds the claim it names, so a fallback to claim matching would
/// offer the credential; it must not.
#[test]
fn a_request_with_claims_as_an_array_has_no_match() {
    let mut query = normative(json!([age()]));
    query["claims"] = json!([{"path": [NYM_AUTH_DOCTYPE, "birth_date"]}]);
    assert!(run(&wallet(), &envelope(query, None)).ids.is_empty());

    let mut only_claims = json!({"id": "nym", "format": "zkp_req",
        "meta": {"doctype_value": NYM_AUTH_DOCTYPE},
        "claims": [{"path": [NYM_AUTH_DOCTYPE, "birth_date"]}]});
    assert!(run(&wallet(), &envelope(only_claims.clone(), None))
        .ids
        .is_empty());
    only_claims["claim_sets"] = json!([["a"]]);
    assert!(run(&wallet(), &envelope(only_claims, None)).ids.is_empty());
}

#[test]
fn an_invalid_plan_has_no_match() {
    let dup = json!([
        {"fn_id": "age_check", "return": "h", "params": {"ge": "2008-10-10"}},
        {"fn_id": "age_check", "return": "h", "params": {"le": "2013-10-09"}}
    ]);
    let bad_date = json!([{"fn_id": "age_check", "return": "h", "params": {"ge": "2026-02-30"}}]);
    let empty = json!([]);
    for req in [dup, bad_date, empty] {
        assert!(run(&wallet(), &envelope(normative(req), None))
            .ids
            .is_empty());
    }
    // Bad client_metadata is a structural defect too.
    let cm = json!({"vp_formats_supported": {"zkp_req": ["x"]}});
    assert!(
        run(&wallet(), &envelope(normative(json!([age()])), Some(cm)))
            .ids
            .is_empty()
    );
}

/// Requests the rulebook calls unsatisfiable are never offered, one rule at a
/// time (the codes are pinned in `vectors/zkp_req_unsat`).
#[test]
fn an_unsatisfiable_request_is_not_offered() {
    let ok = |req: Value| run(&wallet(), &envelope(normative(req), None)).ids;
    assert_eq!(ok(json!([pseudonym(), age()])), ["nym-1"]);
    // le before ge
    assert!(ok(json!([{"fn_id": "age_check", "return": "a",
        "params": {"ge": "2013-10-09", "le": "2008-10-10"}}]))
    .is_empty());
    // no bound
    assert!(ok(json!([{"fn_id": "age_check", "return": "b", "params": {}}])).is_empty());
    // unknown config, missing ver, missing prf, ver 2
    for params in [
        json!({"config": "no-such-config", "ver": 1, "prf": "sha-256"}),
        json!({"config": "known-offender-matching-ssc", "prf": "sha-256"}),
        json!({"config": "known-offender-matching-ssc", "ver": 1}),
        json!({"config": "known-offender-matching-ssc", "ver": 2, "prf": "sha-256"}),
    ] {
        assert!(ok(json!([{"fn_id": "pseudonym", "return": "c", "params": params}])).is_empty());
    }
    // a second pseudonym
    let mut second = pseudonym();
    second["return"] = json!("nym2");
    assert!(ok(json!([pseudonym(), second])).is_empty());
    // holder binding waived
    let mut query = normative(json!([age()]));
    query["require_cryptographic_holder_binding"] = json!(false);
    assert!(run(&wallet(), &envelope(query, None)).ids.is_empty());
}

/// `bbs_cd` is held: no wallet stores it yet, so a request over it is simply
/// not offered, and nothing breaks.
#[test]
fn a_bbs_cd_request_is_not_offered_while_no_bbs_cd_attestation_is_stored() {
    let query = json!({"id": "nym", "format": "zkp_req",
        "meta": {"source_format": "bbs_cd", "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1"},
        "_req": [{"fn_id": "pseudonym", "return": "nym",
            "params": {"config": "known-offender-matching-ssc", "ver": 1, "prf": "hashdh-bls12381g1"}}]});
    assert!(run(&wallet(), &envelope(query, None)).ids.is_empty());
}

/// Rulebook, "Non-disclosure of seed commitments": `ssc`, `psc`,
/// `secret_seed` and `birth_date` of a nym_auth attestation are never
/// disclosed through another format, however the request words it.
#[test]
fn a_nym_auth_attestation_does_not_disclose_its_secrets_through_other_formats() {
    let mdoc = |claims: Value| {
        let mut q = json!({"id": "nym", "format": "mso_mdoc",
            "meta": {"doctype_value": NYM_AUTH_DOCTYPE}});
        if !claims.is_null() {
            q["claims"] = claims;
        }
        run(&wallet(), &envelope(q, None)).ids
    };
    for attr in ["ssc", "psc", "secret_seed", "birth_date"] {
        assert!(
            mdoc(json!([{"path": [NYM_AUTH_DOCTYPE, attr]}])).is_empty(),
            "{attr} was offered"
        );
    }
    // A wildcard includes them; no claims at all asks for everything.
    assert!(mdoc(json!([{"path": [NYM_AUTH_DOCTYPE, null]}])).is_empty());
    assert!(mdoc(Value::Null).is_empty());
    // Another attribute the credential has is not forbidden, only absent.
    assert!(mdoc(json!([{"path": [NYM_AUTH_DOCTYPE, "family_name"]}])).is_empty());
}

/// `birth_date` is only undisclosable on nym_auth: another credential's is
/// an ordinary claim.
#[test]
fn birth_date_of_another_credential_is_an_ordinary_claim() {
    let mut db = wallet();
    let mut pid = db.credentials[0].clone();
    pid.id = "pid-1".into();
    pid.doctype = Some("eu.europa.ec.eudi.pid.1".into());
    pid.claims = vec![siros_dc_matcher_core::db::Claim {
        path: vec!["eu.europa.ec.eudi.pid.1".into(), "birth_date".into()],
        value: "1990-01-01".into(),
        display: "Birth date".into(),
        display_value: None,
    }];
    db.credentials.push(pid);
    let q = json!({"id": "nym", "format": "mso_mdoc",
        "meta": {"doctype_value": "eu.europa.ec.eudi.pid.1"},
        "claims": [{"path": ["eu.europa.ec.eudi.pid.1", "birth_date"]}]});
    assert_eq!(run(&db, &envelope(q, None)).ids, ["pid-1"]);
}

/// Without a request context there is no plan, so `zkp_req` is not
/// answered: the policy fails closed rather than matching on format alone.
#[test]
fn without_a_context_zkp_req_matches_nothing() {
    let db = wallet();
    let query = siros_dcql::DcqlQuery::from_json(
        &json!({"credentials": [{"id": "nym", "format": "zkp_req",
            "meta": {"doctype_value": NYM_AUTH_DOCTYPE}}]})
        .to_string(),
    )
    .expect("dcql");
    let held = credentials(&db);
    let policy = ProfilePolicy::new(&db.profile);
    let result = execute(&query, &held, &policy);
    assert!(!result.query("nym").expect("query").is_satisfied());
}

/// An older wallet's blob, registered before the `zkp_req` rule existed,
/// still decodes and still declines the format.
#[test]
fn a_blob_from_before_the_zkp_req_rule_declines_the_format() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/credential_database_v1_before_circuit_zk.cbor"
    ))
    .expect("old golden");
    let mut db = CredentialDatabase::from_cbor(&bytes).expect("decodes");
    assert!(db.profile.format_rule("zkp_req").is_none());
    db.credentials = wallet().credentials;
    assert!(run(&db, &envelope(normative(json!([age()])), None))
        .ids
        .is_empty());
}

/// The committed blob carries the rule and round-trips through the matcher.
#[test]
fn the_committed_blob_routes_zkp_req_to_mdoc_storage() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/credential_database_v1.cbor"
    ))
    .expect("golden");
    let db = CredentialDatabase::from_cbor(&bytes).expect("decodes");
    let rule = db.profile.format_rule("zkp_req").expect("rule");
    assert_eq!(rule.stored_formats, ["mso_mdoc"]);
    assert!(rule.requires.is_empty());
}
