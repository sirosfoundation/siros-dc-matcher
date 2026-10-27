//! Structured circuit capabilities: the shared match vectors, and the same
//! rule through the evaluator.
//!
//! `vectors/circuit_capabilities/match.json` is the corpus for the capability
//! rule; this repository owns it (see the README beside it). Each case is run
//! through `Capabilities::serves`; the proof-system, circuit-id and status
//! filters and the ranking are not the matcher's and are applied here the way
//! a wallet does before it registers circuits.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde_json::{json, Map, Value};
use siros_dc_matcher_core::circuit_capabilities::{Capabilities, RequestedItem};
use siros_dc_matcher_core::db::CredentialDatabase;
use siros_dc_matcher_core::evaluator::{credentials, ProfilePolicy};
use siros_dc_matcher_core::fixtures::{circuit, nym_wallet, NYM_AUTH_DOCTYPE};
use siros_dc_matcher_core::profile::{CAPABILITIES_PARAM, CREDENTIAL_TYPE_PARAM, SYSTEM_ID_PARAM};
use siros_dcql::execute;
use siros_oid4vp::UnverifiedRequest;

// --- the shared vectors ----------------------------------------------------

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Which circuits of a vector case the matcher's rule serves.
///
/// `Err` is the vector's `expectError`: a request without a presentation,
/// credential format or credential type. The matcher has no such request (its
/// presentation is `zkp_req` and its format and type come from the profile
/// and `meta`), so for it an error case is the case where `serves` has nothing
/// to compare against and must serve nothing.
fn served(case: &Value) -> Result<BTreeSet<String>, ()> {
    let request = &case["request"];
    let presentation = request["presentation"].as_str().unwrap_or("");
    let format = request["credential"]["format"].as_str().unwrap_or("");
    let ty = request["credential"]["type"].as_str().unwrap_or("");
    let malformed = presentation.is_empty() || format.is_empty() || ty.is_empty();

    let systems = strings(request.get("proofSystems"));
    let ids = strings(request.get("circuitIds"));
    let empty = Map::new();
    let items: Vec<(String, Map<String, Value>)> = request["req"]
        .as_array()
        .expect("req")
        .iter()
        .map(|item| {
            (
                item["id"].as_str().expect("item id").to_owned(),
                item.get("params")
                    .and_then(Value::as_object)
                    .unwrap_or(&empty)
                    .clone(),
            )
        })
        .collect();
    let items: Vec<RequestedItem<'_>> = items
        .iter()
        .map(|(function_id, params)| RequestedItem {
            function_id,
            params,
        })
        .collect();

    let mut out = BTreeSet::new();
    for c in case["circuits"].as_array().expect("circuits") {
        let id = c["id"].as_str().expect("id");
        // Steps 1 and 2: the wallet's side of the line.
        if !systems.is_empty()
            && !systems
                .iter()
                .any(|s| Some(s.as_str()) == c["system"].as_str())
        {
            continue;
        }
        let named = std::iter::once(id).chain(
            c.get("aliases")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str),
        );
        if !ids.is_empty() && !named.clone().any(|n| ids.iter().any(|i| i == n)) {
            continue;
        }
        if !matches!(c["status"].as_str(), Some("active" | "deprecated")) {
            continue;
        }
        // Step 3 starts with having capabilities at all.
        let Some(capabilities) = c.get("capabilities") else {
            continue;
        };
        let parsed = match Capabilities::parse(&capabilities.to_string()) {
            Ok(parsed) => parsed,
            // Fail closed: capabilities that do not parse are never offered.
            // Only a case that says so (`expectRejected`) may rely on it;
            // for every other case a rejection is a broken vector.
            Err(_) if case["expectRejected"].as_bool() == Some(true) => continue,
            Err(e) => panic!("{id}: the vector's own capabilities are rejected: {e}"),
        };
        if !malformed && parsed.serves(presentation, &[format], &[ty], &items) {
            out.insert(id.to_owned());
        }
    }
    if malformed {
        Ok(BTreeSet::new())
    } else {
        Ok(out)
    }
}

/// The catalog renamed `credential.profile` to `credential.issuance_profile`
/// (a non-empty string). The old key is an unknown member, like any other.
#[test]
fn issuance_profile_is_a_non_empty_string_and_the_old_profile_key_is_unknown() {
    let with = |credential: &str| {
        Capabilities::parse(&format!(
            r#"{{"schema":1,"presentation":"p","credential":{credential},
                "functions":[{{"id":"f","max":1}}]}}"#
        ))
    };
    assert!(with(r#"{"format":"f","type":"t"}"#).is_ok());
    assert!(with(r#"{"format":"f","type":"t","issuance_profile":"x"}"#).is_ok());
    for bad in [
        r#""profile":"x""#,
        r#""issuance_profile":"""#,
        r#""issuance_profile":null"#,
        r#""issuance_profile":1"#,
    ] {
        let e = with(&format!(r#"{{"format":"f","type":"t",{bad}}}"#));
        assert!(e.is_err(), "{bad} must be rejected");
    }
}

#[test]
fn the_catalogs_match_vectors() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/circuit_capabilities/match.json");
    let file: Value = serde_json::from_slice(&fs::read(path).expect("vectors")).expect("JSON");
    assert_eq!(file["version"], 1);
    let cases = file["cases"].as_array().expect("cases");
    assert!(cases.len() >= 40, "vectors went missing: {}", cases.len());

    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap_or("?");
        let want: BTreeSet<String> = if case["expectError"].as_bool() == Some(true) {
            BTreeSet::new()
        } else {
            strings(case.get("expect")).into_iter().collect()
        };
        match served(case) {
            Ok(got) if got == want => {}
            Ok(got) => failures.push(format!("{name}: want {want:?}, got {got:?}")),
            Err(()) => failures.push(format!("{name}: unexpected error")),
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

// --- parsing fails closed --------------------------------------------------

fn caps(functions: Value) -> String {
    json!({"schema": 1, "presentation": "zkp_req",
           "credential": {"format": "mso_mdoc", "type": NYM_AUTH_DOCTYPE},
           "functions": functions})
    .to_string()
}

#[test]
fn a_valid_object_parses_and_every_defect_is_refused() {
    let ok = caps(json!([{"id": "f", "params": {"p": {"enum": ["a"]}}}]));
    assert!(Capabilities::parse(&ok).is_ok());

    let bad: Vec<(&str, String)> = vec![
        ("not JSON", "{".into()),
        ("schema 2", ok.replace("\"schema\":1", "\"schema\":2")),
        ("no schema", json!({"presentation": "p"}).to_string()),
        (
            "unknown top key",
            ok.replace("\"schema\":1", "\"schema\":1,\"x\":1"),
        ),
        ("no functions", caps(json!([]))),
        ("empty id", caps(json!([{"id": ""}]))),
        ("duplicate id", caps(json!([{"id": "f"}, {"id": "f"}]))),
        ("max 0", caps(json!([{"id": "f", "max": 0}]))),
        (
            "unknown function key",
            caps(json!([{"id": "f", "pattern": "x"}])),
        ),
        (
            "unknown constraint kind",
            caps(json!([{"id": "f", "params": {"p": {"pattern": "x"}}}])),
        ),
        (
            "empty constraint",
            caps(json!([{"id": "f", "params": {"p": {}}}])),
        ),
        (
            "both enum and type",
            caps(json!([{"id": "f", "params": {"p": {"enum": ["a"], "type": "string"}}}])),
        ),
        (
            "empty enum",
            caps(json!([{"id": "f", "params": {"p": {"enum": []}}}])),
        ),
        (
            "duplicate enum value",
            caps(json!([{"id": "f", "params": {"p": {"enum": ["a", "a"]}}}])),
        ),
        (
            "unknown type",
            caps(json!([{"id": "f", "params": {"p": {"type": "uuid"}}}])),
        ),
        (
            "non-string enum value",
            caps(json!([{"id": "f", "params": {"p": {"enum": [1]}}}])),
        ),
    ];
    for (what, text) in bad {
        assert!(Capabilities::parse(&text).is_err(), "{what} was accepted");
    }
}

// --- through the evaluator ---------------------------------------------------

const LONGFELLOW: &str = "longfellow-libzk-v1";
const CIRCUIT: &str = "urn:circuits:longfellow:nym_auth:v1";

fn pseudonym(config: &str) -> Value {
    json!({"fn_id": "pseudonym", "return": "nym",
           "params": {"config": config, "ver": 1, "prf": "sha-256"}})
}

fn age() -> Value {
    json!({"fn_id": "age_check", "return": "age", "params": {"range": "18+"}})
}

/// The Verifier's lists: `zkp_req`, Section 1.2 requires both.
fn client_metadata(ids: &[&str]) -> Value {
    json!({"vp_formats_supported": {"zkp_req": {
        "proof_backend_values": [LONGFELLOW], "system_id_values": ids}}})
}

fn query(meta: Value, req: Value) -> Value {
    let mut meta = meta;
    if let Some(object) = meta.as_object_mut() {
        object.entry("source_format").or_insert(json!("mso_mdoc"));
    }
    json!({"id": "nym", "format": "zkp_req", "meta": meta, "_req": req})
}

fn nym_query(req: Value) -> Value {
    query(json!({"doctype_value": NYM_AUTH_DOCTYPE}), req)
}

/// Candidate credential ids for a request.
fn offered(db: &CredentialDatabase, query: Value) -> Vec<String> {
    let request = json!({"requests": [{"protocol": "openid4vp-v1-unsigned",
        "data": {"dcql_query": {"credentials": [query]},
                 "client_metadata": client_metadata(&[CIRCUIT])}}]})
    .to_string();
    let registered = |label: &str| db.profile.parser_for(label).is_some();
    let Some(context) = UnverifiedRequest::first_registered(request.as_bytes(), &registered) else {
        return vec![];
    };
    let typed = context.query().matching_query();
    let policy =
        ProfilePolicy::new(&db.profile).with_context(context.query(), context.client_metadata());
    execute(typed, &credentials(db), &policy)
        .query("nym")
        .map(|m| {
            m.candidates()
                .iter()
                .map(|c| c.credential_id().as_str().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn with_param(key: &str, value: &str) -> CredentialDatabase {
    let mut c = circuit(LONGFELLOW, CIRCUIT, None);
    c.params.insert(key.into(), value.into());
    nym_wallet(vec![c])
}

fn nym_auth_capabilities() -> String {
    caps(json!([
        {"id": "pseudonym", "always": true, "params": {
            "config": {"enum": ["known-offender-matching-ssc"]},
            "ver": {"type": "integer"},
            "prf": {"enum": ["sha-256"]}}},
        {"id": "age_check", "max": 1, "params": {"range": {"type": "string"}}}
    ]))
}

// credential_type

/// The wallet holds a nym_auth mdoc and a driving licence, and one circuit
/// registered with the given `credential_type`.
fn two_credential_wallet(credential_type: &str) -> CredentialDatabase {
    let mut db = with_param(CREDENTIAL_TYPE_PARAM, credential_type);
    let mut mdl = db.credentials[0].clone();
    mdl.id = "mdl-1".into();
    mdl.doctype = Some(MDL.into());
    db.credentials.push(mdl);
    db
}

const MDL: &str = "org.iso.18013.5.1.mDL";

/// Both credentials are held, so the circuit's restriction is the only thing
/// that can rule the licence out.
#[test]
fn a_circuit_restricted_to_doctype_a_is_not_offered_for_a_request_naming_b() {
    let db = two_credential_wallet(NYM_AUTH_DOCTYPE);
    let for_nym = nym_query(json!([age()]));
    let for_mdl = query(json!({"doctype_value": MDL}), json!([age()]));
    assert_eq!(offered(&db, for_nym), ["nym-1"]);
    assert!(offered(&db, for_mdl).is_empty());

    // The same wallet with an unrestricted circuit does offer the licence,
    // which is what makes the line above a statement about the restriction.
    let mut unrestricted = two_credential_wallet(NYM_AUTH_DOCTYPE);
    unrestricted
        .profile
        .capabilities
        .get_mut("zkp_req")
        .unwrap()[0]
        .params
        .remove(CREDENTIAL_TYPE_PARAM);
    let for_mdl = query(json!({"doctype_value": MDL}), json!([age()]));
    assert_eq!(offered(&unrestricted, for_mdl), ["mdl-1"]);
}

#[test]
fn a_restricted_circuit_for_another_type_is_not_offered_for_the_held_one() {
    let db = with_param(CREDENTIAL_TYPE_PARAM, "eu.example.other.1");
    assert!(offered(&db, nym_query(json!([age()]))).is_empty());
}

/// A `dc+sd-jwt` query asks for a proof over an SD-JWT VC; the profile maps
/// `zkp_req` onto stored `mso_mdoc` credentials only, so nothing is offered,
/// whatever the circuit says.
#[test]
fn a_vct_values_request_is_not_offered() {
    let mut db = with_param(CREDENTIAL_TYPE_PARAM, "urn:vct:a");
    db.credentials[0].vct = Some("urn:vct:a".into());
    let asks = query(
        json!({"source_format": "dc+sd-jwt", "vct_values": ["urn:vct:a"]}),
        json!([age()]),
    );
    assert!(offered(&db, asks).is_empty());
}

#[test]
fn a_restricted_circuit_needs_the_request_to_name_a_type() {
    let db = with_param(CREDENTIAL_TYPE_PARAM, NYM_AUTH_DOCTYPE);
    assert!(offered(&db, query(json!({}), json!([age()]))).is_empty());
}

#[test]
fn without_credential_type_a_circuit_is_unrestricted_as_before() {
    let db = nym_wallet(vec![circuit(LONGFELLOW, CIRCUIT, None)]);
    let meta = json!({"doctype_value": NYM_AUTH_DOCTYPE});
    assert_eq!(offered(&db, query(meta, json!([age()]))), ["nym-1"]);
}

// capabilities

#[test]
fn capabilities_serve_a_request_they_declare() {
    let db = with_param(CAPABILITIES_PARAM, &nym_auth_capabilities());
    let req = json!([pseudonym("known-offender-matching-ssc"), age()]);
    assert_eq!(offered(&db, nym_query(req)), ["nym-1"]);
}

#[test]
fn an_enum_miss_is_refused() {
    let db = with_param(CAPABILITIES_PARAM, &nym_auth_capabilities());
    let mut item = pseudonym("account-recovery-ssc");
    item["params"]["verifier_context"] = json!("account 7");
    assert!(offered(&db, nym_query(json!([item]))).is_empty());
}

#[test]
fn an_unlisted_param_is_refused() {
    let caps = Capabilities::parse(&nym_auth_capabilities()).unwrap();
    let mut params = Map::new();
    params.insert("range".into(), json!("18+"));
    params.insert("unlisted".into(), json!("x"));
    let items = [RequestedItem {
        function_id: "age_check",
        params: &params,
    }];
    assert!(!caps.supports(&items));
}

/// A request that still carries the retired `verifier_id_type` breaks the
/// nym_auth catalogue (a parameter the function does not define), so nothing
/// is offered before any circuit is consulted.
#[test]
fn a_legacy_verifier_id_type_param_is_not_served() {
    let db = with_param(CAPABILITIES_PARAM, &nym_auth_capabilities());
    let mut item = pseudonym("known-offender-matching-ssc");
    assert_eq!(offered(&db, nym_query(json!([item.clone()]))), ["nym-1"]);
    item["params"]["verifier_id_type"] = json!("x509_san_dns");
    assert!(offered(&db, nym_query(json!([item]))).is_empty());
}

#[test]
fn an_undeclared_function_is_refused() {
    let db = with_param(CAPABILITIES_PARAM, &nym_auth_capabilities());
    let req = json!([pseudonym("known-offender-matching-ssc"),
                     {"fn_id": "future_fn", "return": "f"}]);
    assert!(offered(&db, nym_query(req)).is_empty());
}

/// `max` bounds the items of a function in the option. For nym_auth the
/// catalogue already refuses a second `age_check` in one option, so the rule is
/// checked on the capabilities themselves.
#[test]
fn max_instances_is_enforced() {
    let caps = Capabilities::parse(&nym_auth_capabilities()).unwrap();
    let pseudonym_params = pseudonym("known-offender-matching-ssc")["params"]
        .as_object()
        .unwrap()
        .clone();
    let age_params = age()["params"].as_object().unwrap().clone();
    let item = |function_id, params| RequestedItem {
        function_id,
        params,
    };
    let one = [
        item("pseudonym", &pseudonym_params),
        item("age_check", &age_params),
    ];
    let two = [
        item("pseudonym", &pseudonym_params),
        item("age_check", &age_params),
        item("age_check", &age_params),
    ];
    assert!(caps.supports(&one));
    assert!(!caps.supports(&two));
}

#[test]
fn an_always_function_must_be_requested() {
    let db = with_param(CAPABILITIES_PARAM, &nym_auth_capabilities());
    assert!(offered(&db, nym_query(json!([age()]))).is_empty());
}

#[test]
fn the_credential_type_must_match_the_requests() {
    let db = with_param(CAPABILITIES_PARAM, &nym_auth_capabilities());
    let req = json!([pseudonym("known-offender-matching-ssc")]);
    let other = query(json!({"doctype_value": "eu.example.other.1"}), req.clone());
    assert!(offered(&db, other).is_empty());
    assert!(offered(&db, query(json!({}), req)).is_empty());
}

#[test]
fn the_presentation_must_be_zkp_req() {
    let text = nym_auth_capabilities().replace("\"zkp_req\"", "\"other_presentation\"");
    let db = with_param(CAPABILITIES_PARAM, &text);
    let req = json!([pseudonym("known-offender-matching-ssc")]);
    assert!(offered(&db, nym_query(req)).is_empty());
}

#[test]
fn the_circuit_format_must_be_one_the_profile_maps_zkp_req_onto() {
    // zkp_req answers stored mso_mdoc credentials; a circuit that proves
    // over an SD-JWT VC is not one the picker can use for them.
    let text = nym_auth_capabilities().replace("mso_mdoc", "dc+sd-jwt");
    let db = with_param(CAPABILITIES_PARAM, &text);
    let req = json!([pseudonym("known-offender-matching-ssc")]);
    assert!(offered(&db, nym_query(req)).is_empty());
}

#[test]
fn capabilities_replace_functions_and_credential_type() {
    // Each of the two would refuse this request on its own.
    let mut c = circuit(LONGFELLOW, CIRCUIT, Some("something_else"));
    c.params
        .insert(CREDENTIAL_TYPE_PARAM.into(), "eu.example.other.1".into());
    c.params
        .insert(CAPABILITIES_PARAM.into(), nym_auth_capabilities());
    let db = nym_wallet(vec![c]);
    let req = json!([pseudonym("known-offender-matching-ssc"), age()]);
    assert_eq!(offered(&db, nym_query(req)), ["nym-1"]);
    assert!(!db.profile.capabilities.is_empty());
}

#[test]
fn unreadable_capabilities_mean_the_circuit_is_not_offered() {
    let req = json!([pseudonym("known-offender-matching-ssc"), age()]);
    for text in [
        "".to_string(),
        "{not json".into(),
        "null".into(),
        "{}".into(),
        // Valid, except for a constraint kind this build does not know.
        nym_auth_capabilities().replace("\"enum\"", "\"pattern\""),
        nym_auth_capabilities().replace("\"schema\":1", "\"schema\":2"),
    ] {
        let db = with_param(CAPABILITIES_PARAM, &text);
        assert!(offered(&db, nym_query(req.clone())).is_empty(), "{text}");
    }
}

#[test]
fn the_verifiers_circuit_lists_still_apply_with_capabilities() {
    let db = with_param(CAPABILITIES_PARAM, &nym_auth_capabilities());
    let req = json!([pseudonym("known-offender-matching-ssc")]);
    let request = |ids: &[&str]| {
        json!({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": {
            "dcql_query": {"credentials": [nym_query(req.clone())]},
            "client_metadata": client_metadata(ids)}}]})
        .to_string()
    };
    let registered = |label: &str| db.profile.parser_for(label).is_some();
    let run = |ids: &[&str]| {
        let bytes = request(ids);
        let context = UnverifiedRequest::first_registered(bytes.as_bytes(), &registered).unwrap();
        let typed = context.query().matching_query();
        let policy = ProfilePolicy::new(&db.profile)
            .with_context(context.query(), context.client_metadata());
        execute(typed, &credentials(&db), &policy)
            .query("nym")
            .map_or(0, |m| m.candidates().len())
    };
    assert_eq!(run(&[CIRCUIT]), 1);
    assert_eq!(run(&["urn:other"]), 0);
}

// the 0.8.0 pin

/// A registration with none of the new params is exactly what 0.8.0 made:
/// the same selection, whatever the request names.
#[test]
fn a_registration_without_the_new_params_behaves_as_in_0_8_0() {
    let db = nym_wallet(vec![circuit(LONGFELLOW, CIRCUIT, None)]);
    let caps = &db.profile.capabilities["zkp_req"];
    assert_eq!(caps.len(), 1);
    assert_eq!(
        caps[0]
            .params
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [SYSTEM_ID_PARAM],
        "the fixture grew a param"
    );

    // Unrestricted by type. (A request with no type value, or a function the
    // catalogue does not define, is invalid before any circuit is consulted.)
    for q in [
        nym_query(json!([age()])),
        query(json!({"doctype_value": "anything"}), json!([age()])),
    ] {
        let found = offered(&db, q.clone());
        // `anything` is ruled out by the held credential's doctype, as ever;
        // the circuit never was the reason.
        let expect: &[&str] = if q["meta"]["doctype_value"] == "anything" {
            &[]
        } else {
            &["nym-1"]
        };
        assert_eq!(found, expect, "{q}");
    }

    // And `functions` alone still filters exactly as before.
    let only_age = nym_wallet(vec![circuit(LONGFELLOW, CIRCUIT, Some("age_check"))]);
    assert_eq!(offered(&only_age, nym_query(json!([age()]))), ["nym-1"]);
    assert!(offered(&only_age, nym_query(json!([pseudonym("c")]))).is_empty());
}
