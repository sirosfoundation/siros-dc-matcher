//! Runs the shared conformance vectors in `tests/vectors/circuit_zk_response/`.
//! The vector format is described in that directory's README.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use siros_dc_matcher_core::circuit_zk::plan;
use siros_dc_matcher_core::circuit_zk_response::validate_response;

fn text(vector: &Value, value_key: &str, text_key: &str) -> Option<String> {
    match (vector.get(value_key), vector.get(text_key)) {
        (Some(v), _) => Some(v.to_string()),
        (None, Some(t)) => t.as_str().map(str::to_owned),
        (None, None) => None,
    }
}

#[test]
fn response_conformance_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/circuit_zk_response");
    let mut names: Vec<_> = fs::read_dir(&dir)
        .expect("vector directory")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    names.sort();
    assert!(names.len() >= 40, "vectors went missing: {}", names.len());

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
    assert!(oks >= 5 && errs >= 25, "ok {oks}, err {errs}");
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// Every refusal code the validator can produce has a vector that reaches it,
/// so a code cannot be added, or a rule dropped, without the vectors noticing.
#[test]
fn every_required_refusal_code_has_a_vector() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/circuit_zk_response");
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
        "duplicate_handle",
        "result_handle_missing",
        "result_handle_unexpected",
        "result_not_satisfied",
        "circuit_id_not_offered",
        "proof_system_not_offered",
        "proof_not_base64url",
        "proof_empty",
        "pseudonym_wrong_length",
        "pseudonym_not_base64url",
        "result_function_unknown",
        "result_unknown_member",
        "result_member_missing",
        "result_member_wrong_type",
        "presentation_error_member",
        "result_not_object",
        "x5chain_not_array",
        "x5chain_empty",
        "x5chain_too_many",
        "x5chain_element_not_string",
        "x5chain_element_not_base64",
        "x5chain_element_empty",
        "x5chain_element_too_large",
        "presentations_multiple_not_allowed",
        "presentations_not_array",
        "presentations_empty",
        "query_id_missing",
        "presentation_unknown_member",
        "presentation_member_missing",
    ] {
        assert!(codes.contains(want), "no vector for {want}");
    }
}
