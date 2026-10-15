//! Matching `circuit_zk` (nym_auth) credentials through the planner.
//!
//! The matcher decides which credentials could answer a `circuit_zk` request
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
    json!({"id": "nym", "format": "circuit_zk",
           "meta": {"doctype_value": NYM_AUTH_DOCTYPE}, "req": req})
}

fn example(req: Value) -> Value {
    json!({"id": "nym", "format": "circuit_zk",
           "meta": {"source_format": "mdoc_mso", "doctype_value": NYM_AUTH_DOCTYPE},
           "claims": {"_req": req}})
}

fn age() -> Value {
    json!({"id": "age_check", "return": "age", "params": {"ge": "2008-10-10", "le": "2013-10-09"}})
}

fn pseudonym() -> Value {
    json!({"id": "pseudonym-v1-sha256", "return": "nym",
           "params": {"config": "known-offender-matching-ssc"}})
}

fn client_metadata(systems: Option<&[&str]>, ids: Option<&[&str]>) -> Value {
    let mut entry = serde_json::Map::new();
    if let Some(systems) = systems {
        entry.insert("circuit_proof_system_values".into(), json!(systems));
    }
    if let Some(ids) = ids {
        entry.insert("circuit_id_values".into(), json!(ids));
    }
    json!({"vp_formats_supported": {"circuit_zk": entry}})
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
/// one its resolved claims and `circuit_zk` selection as JSON.
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
        selection: first.and_then(|r| r.circuit_zk.map(|z| z.to_json())),
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
    assert_eq!(selection["circuit"]["params"]["circuit_id"], CIRCUIT);
    let functions = selection["plan"]["functions"].as_array().expect("array");
    assert_eq!(functions.len(), 2);
    assert_eq!(functions[0]["function_id"], "pseudonym-v1-sha256");
    assert_eq!(functions[1]["handle"], "age");
}

#[test]
fn a_nym_auth_mdoc_matches_in_the_rulebook_example_shape() {
    let req = json!([
        {"fn_id": "age_check", "id": "age", "params": {"ge": "2008-10-10", "source": {"path": ["birth_date"]}}}
    ]);
    let out = run(&wallet(), &envelope(example(req), None));
    assert_eq!(out.ids, ["nym-1"]);
    assert_eq!(
        out.selection.expect("selection")["plan"]["functions"][0]["handle"],
        "age"
    );
}

/// The credential holds a `birth_date` claim. A `circuit_zk` match proves
/// things about it and discloses nothing.
#[test]
fn a_circuit_zk_match_carries_no_claims() {
    for query in [
        normative(json!([age()])),
        example(json!([{"fn_id": "age_check", "id": "age", "params": {"ge": "2008-10-10"}}])),
    ] {
        let out = run(&wallet(), &envelope(query, None));
        assert_eq!(out.ids, ["nym-1"]);
        assert!(out.claims.is_empty());
    }
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
fn circuit_id_values_filter_the_wallets_circuits() {
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
    assert_eq!(chosen["circuit"]["params"]["circuit_id"], CIRCUIT);
    assert!(wants(&["urn:circuits:unknown"]).ids.is_empty());
}

#[test]
fn circuit_proof_system_values_filter_the_wallets_circuits() {
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
fn the_envelope_form_of_the_lists_is_read_too() {
    use serde_json::to_string;
    let inner = to_string(&json!({"circuit_id_values": ["urn:nope"]})).unwrap();
    // Standard base64, hand-rolled to keep the test dependency-free.
    let encoded = {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in inner.as_bytes().chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..=chunk.len() {
                out.push(char::from(A[((n >> (18 - 6 * i)) & 0x3F) as usize]));
            }
        }
        while out.len() % 4 != 0 {
            out.push('=');
        }
        out
    };
    let cm = json!({"vp_formats_supported": {"circuit_zk": {"fn_id": "x", "input": encoded}}});
    let out = run(&wallet(), &envelope(normative(json!([age()])), Some(cm)));
    assert!(
        out.ids.is_empty(),
        "the enveloped id list rules the circuit out"
    );
}

#[test]
fn a_circuit_declaring_functions_is_filtered_by_them() {
    let only_age = nym_wallet(vec![circuit(LONGFELLOW, CIRCUIT, Some("age_check"))]);
    let both = nym_wallet(vec![circuit(
        LONGFELLOW,
        CIRCUIT,
        Some("age_check, pseudonym-v1-sha256"),
    )]);
    let wants_both = envelope(normative(json!([pseudonym(), age()])), None);
    let wants_age = envelope(normative(json!([age()])), None);

    assert!(run(&only_age, &wants_both).ids.is_empty());
    assert_eq!(run(&only_age, &wants_age).ids, ["nym-1"]);
    assert_eq!(run(&both, &wants_both).ids, ["nym-1"]);
}

#[test]
fn a_circuit_declaring_no_functions_is_not_filtered() {
    // Not even for a function this matcher has never heard of.
    let req = json!([age(), {"id": "future_fn", "return": "f"}]);
    let out = run(&wallet(), &envelope(normative(req), None));
    assert_eq!(out.ids, ["nym-1"]);
}

/// A `claims` array is ordinary DCQL, which `circuit_zk` does not use. The
/// wallet holds the claim it names, so a fallback to claim matching would
/// offer the credential; it must not.
#[test]
fn a_request_with_claims_as_an_array_has_no_match() {
    let mut query = normative(json!([age()]));
    query["claims"] = json!([{"path": [NYM_AUTH_DOCTYPE, "birth_date"]}]);
    assert!(run(&wallet(), &envelope(query, None)).ids.is_empty());

    let mut only_claims = json!({"id": "nym", "format": "circuit_zk",
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
        {"id": "age_check", "return": "h", "params": {"ge": "2008-10-10"}},
        {"id": "age_check", "return": "h", "params": {"le": "2013-10-09"}}
    ]);
    let bad_date = json!([{"id": "age_check", "return": "h", "params": {"ge": "2026-02-30"}}]);
    let empty = json!([]);
    for req in [dup, bad_date, empty] {
        assert!(run(&wallet(), &envelope(normative(req), None))
            .ids
            .is_empty());
    }
    // Bad client_metadata is a structural defect too.
    let cm = json!({"vp_formats_supported": {"circuit_zk": ["x"]}});
    assert!(
        run(&wallet(), &envelope(normative(json!([age()])), Some(cm)))
            .ids
            .is_empty()
    );
}

/// The matcher has no opinion on satisfiability: these are all unsatisfiable
/// by the rulebook and all offered, for the wallet to refuse.
#[test]
fn satisfiability_is_left_to_the_wallet() {
    let req = json!([
        {"id": "age_check", "return": "a", "params": {"ge": "2013-10-09", "le": "2008-10-10"}},
        {"id": "age_check", "return": "b", "params": {}},
        {"id": "pseudonym-v1-sha256", "return": "c", "params": {"config": "no-such-config"}},
        {"id": "pseudonym-v1-sha256", "return": "d"}
    ]);
    let mut query = normative(req);
    query["require_cryptographic_holder_binding"] = json!(false);
    assert_eq!(run(&wallet(), &envelope(query, None)).ids, ["nym-1"]);
}

/// Without a request context there is no plan, so `circuit_zk` is not
/// answered: the policy fails closed rather than matching on format alone.
#[test]
fn without_a_context_circuit_zk_matches_nothing() {
    let db = wallet();
    let query = siros_dcql::DcqlQuery::from_json(
        &json!({"credentials": [{"id": "nym", "format": "circuit_zk",
            "meta": {"doctype_value": NYM_AUTH_DOCTYPE}}]})
        .to_string(),
    )
    .expect("dcql");
    let held = credentials(&db);
    let policy = ProfilePolicy::new(&db.profile);
    let result = execute(&query, &held, &policy);
    assert!(!result.query("nym").expect("query").is_satisfied());
}

/// An older wallet's blob, registered before the `circuit_zk` rule existed,
/// still decodes and still declines the format.
#[test]
fn a_blob_from_before_the_circuit_zk_rule_declines_the_format() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/credential_database_v1_before_circuit_zk.cbor"
    ))
    .expect("old golden");
    let mut db = CredentialDatabase::from_cbor(&bytes).expect("decodes");
    assert!(db.profile.format_rule("circuit_zk").is_none());
    db.credentials = wallet().credentials;
    assert!(run(&db, &envelope(normative(json!([age()])), None))
        .ids
        .is_empty());
}

/// The committed blob carries the rule and round-trips through the matcher.
#[test]
fn the_committed_blob_routes_circuit_zk_to_mdoc_storage() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/credential_database_v1.cbor"
    ))
    .expect("golden");
    let db = CredentialDatabase::from_cbor(&bytes).expect("decodes");
    let rule = db.profile.format_rule("circuit_zk").expect("rule");
    assert_eq!(rule.stored_formats, ["mso_mdoc"]);
    assert!(rule.requires.is_empty());
}
