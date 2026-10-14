//! Runs the shared conformance vectors in `tests/vectors/circuit_zk/`.
//! The vector format is described in that directory's README.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use siros_dc_matcher_core::circuit_zk::plan;

fn text(vector: &Value, value_key: &str, text_key: &str) -> Option<String> {
    match (vector.get(value_key), vector.get(text_key)) {
        (Some(v), _) => Some(v.to_string()),
        (None, Some(t)) => t.as_str().map(str::to_owned),
        (None, None) => None,
    }
}

#[test]
fn conformance_vectors() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/circuit_zk");
    let mut names: Vec<_> = fs::read_dir(&dir)
        .expect("vector directory")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    names.sort();
    assert!(names.len() >= 40, "vectors went missing: {}", names.len());

    let mut failures = Vec::new();
    for path in &names {
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let vector: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let query = text(&vector, "query", "query_text").expect("vector has a query");
        let cm = text(&vector, "client_metadata", "client_metadata_text");
        let result = plan(&query, cm.as_deref());
        let expect = vector.get("expect").expect("vector has expect");

        match (expect.get("error"), expect.get("plan"), result) {
            (Some(code), None, Err(e)) => {
                if Some(e.code()) != code.as_str() {
                    failures.push(format!("{name}: expected error {code}, got {}", e.code()));
                }
            }
            (Some(code), None, Ok(_)) => {
                failures.push(format!("{name}: expected error {code}, got a plan"));
            }
            (None, Some(want), Ok(got)) => {
                let mut got_json = serde_json::to_value(&got).unwrap();
                let raw = got_json.as_object_mut().unwrap().remove("raw").unwrap();
                let query_value: Value = serde_json::from_str(&query).unwrap();
                if raw != query_value {
                    failures.push(format!("{name}: raw is not the parsed query"));
                }
                if &got_json != want {
                    failures.push(format!(
                        "{name}: plan mismatch\n  want {want}\n  got  {got_json}"
                    ));
                }
            }
            (None, Some(_), Err(e)) => failures.push(format!("{name}: expected a plan, got {e}")),
            _ => failures.push(format!("{name}: malformed vector")),
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
