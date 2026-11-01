//! Runs the shared conformance vectors in `tests/vectors/zkp_req_response/`.
//! The vector format is described in that directory's README.

use std::fs;
use std::path::PathBuf;

use serde_json::{json, Value};
use siros_dc_matcher_core::zkp_req::plan;
use siros_dc_matcher_core::zkp_req_response::validate_response;

fn text(vector: &Value, value_key: &str, text_key: &str) -> Option<String> {
    match (vector.get(value_key), vector.get(text_key)) {
        (Some(v), _) => Some(v.to_string()),
        (None, Some(t)) => t.as_str().map(str::to_owned),
        (None, None) => None,
    }
}

#[test]
fn response_conformance_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/zkp_req_response");
    let mut names: Vec<_> = fs::read_dir(&dir)
        .expect("vector directory")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    names.sort();
    assert!(names.len() >= 120, "vectors went missing: {}", names.len());

    let mut failures = Vec::new();
    let (mut oks, mut errs) = (0, 0);
    for path in &names {
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let vector: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let query = text(&vector, "query", "query_text").expect("vector has a query");
        let cm = text(&vector, "client_metadata", "client_metadata_text");
        let token = text(&vector, "vp_token", "vp_token_text").expect("vector has a vp_token");
        let request = plan(&query, cm.as_deref()).expect("vector request must plan");
        let result = validate_response(&request, &token);
        let expect = vector.get("expect").expect("vector has expect");

        if name.starts_with("ok_") != expect.get("valid").is_some() {
            failures.push(format!("{name}: file name and expect disagree"));
        }
        match (expect.get("error"), expect.get("valid"), result) {
            (Some(code), None, Err(e)) => {
                errs += 1;
                if Some(e.code()) != code.as_str() {
                    failures.push(format!("{name}: expected {code}, got {}", e.code()));
                }
            }
            (Some(code), None, Ok(())) => failures.push(format!("{name}: expected {code}, got ok")),
            (None, Some(_), Ok(())) => oks += 1,
            (None, Some(_), Err(e)) => failures.push(format!("{name}: expected ok, got {e}")),
            _ => failures.push(format!("{name}: malformed vector")),
        }
    }
    assert!(oks >= 15 && errs >= 100, "ok {oks}, err {errs}");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// Every refusal code the validator can produce has a vector that reaches it,
/// so a code cannot be added, or a rule dropped, without the vectors noticing.
#[test]
fn every_required_refusal_code_has_a_vector() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/zkp_req_response");
    let mut codes = std::collections::BTreeSet::new();
    for e in fs::read_dir(&dir).unwrap() {
        let path = e.unwrap().path();
        if path.extension().is_none_or(|x| x != "json") {
            continue;
        }
        let v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        if let Some(c) = v["expect"]["error"].as_str() {
            codes.insert(c.to_owned());
        }
    }
    for want in [
        "response_not_parseable",
        "duplicate_member",
        "query_id_missing",
        "presentations_not_array",
        "presentations_empty",
        "presentations_multiple_not_allowed",
        "presentation_not_string",
        "presentation_not_base64url",
        "cbor_malformed",
        "cbor_indefinite_length",
        "cbor_trailing_bytes",
        "cbor_duplicate_key",
        "presentation_not_map",
        "presentation_key_not_text",
        "presentation_unknown_member",
        "presentation_member_missing",
        "presentation_member_wrong_type",
        "system_id_not_offered",
        "proof_empty",
        "issuer_key_set_empty",
        "issuer_key_set_too_many",
        "issuer_key_not_bytes",
        "issuer_key_empty",
        "issuer_key_too_large",
        "proof_time_missing",
        "proof_time_not_tdate",
        "proof_time_form",
        "result_key_not_text",
        "result_handle_unexpected",
        "result_handle_missing",
        "result_function_unknown",
        "result_wrong_type",
        "result_not_satisfied",
        "pseudonym_prf_unknown",
        "pseudonym_wrong_length",
    ] {
        assert!(codes.contains(want), "no vector for {want}");
    }
}

fn encode_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(a >> 2) as usize] as char);
        out.push(ALPHABET[((a & 3) << 4 | b >> 4) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((b & 15) << 2 | c >> 6) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(c & 63) as usize] as char);
        }
    }
    out
}

fn genuine_sized_response(proof_bytes: usize) -> (String, String) {
    use ciborium::value::Value as Cbor;
    const CIRCUIT: &str = "urn:circuits:longfellow:nym_auth:v1";
    let presentation = Cbor::Map(vec![
        (Cbor::Text("system_id".into()), Cbor::Text(CIRCUIT.into())),
        (
            Cbor::Text("proof".into()),
            Cbor::Bytes(vec![7; proof_bytes]),
        ),
        (
            Cbor::Text("issuer_key_set".into()),
            Cbor::Array(vec![Cbor::Bytes(vec![1, 2, 3])]),
        ),
        (
            Cbor::Text("proof_time".into()),
            Cbor::Tag(0, Box::new(Cbor::Text("2026-10-07T12:00:00Z".into()))),
        ),
        (
            Cbor::Text("results".into()),
            Cbor::Map(vec![(Cbor::Text("nym".into()), Cbor::Bytes(vec![5; 32]))]),
        ),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&presentation, &mut encoded).unwrap();
    let query = json!({"id": "nym", "format": "zkp_req",
        "meta": {"source_format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.nym_auth.1"},
        "_req": [{"fn_id": "pseudonym", "return": "nym",
                  "params": {"config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256"}}]});
    let metadata = json!({"vp_formats_supported": {"zkp_req": {"system_id_values": [CIRCUIT]}}});
    let vp_token = json!({"nym": [encode_base64url(&encoded)]}).to_string();
    (query.to_string() + "\n" + &metadata.to_string(), vp_token)
}

#[test]
fn genuine_longfellow_sizes_use_the_response_budget() {
    let (request, token) = genuine_sized_response(900_000);
    let (query, metadata) = request.split_once('\n').unwrap();
    let plan = siros_dc_matcher_core::zkp_req::plan(query, Some(metadata)).unwrap();
    validate_response(&plan, &token).unwrap();

    let (request, token) = genuine_sized_response(2 * 1024 * 1024);
    let (query, metadata) = request.split_once('\n').unwrap();
    let plan = siros_dc_matcher_core::zkp_req::plan(query, Some(metadata)).unwrap();
    let error = validate_response(&plan, &token).unwrap_err();
    assert_eq!(error.code(), "presentation_not_base64url");
}
