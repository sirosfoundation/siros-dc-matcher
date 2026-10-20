//! Runs the shared conformance vectors in `tests/vectors/zkp_req_unsat/`.
//!
//! Each vector is a Credential Query that plans; `expect` is
//! `{"satisfiable": true}` or `{"error": "<code>"}` from `zkp_req::unsatisfiable`.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use siros_dc_matcher_core::zkp_req::{plan, unsatisfiable};

fn vectors() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/zkp_req_unsat");
    let mut out: Vec<_> = fs::read_dir(&dir)
        .expect("vector directory")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().into_owned();
            (
                name,
                serde_json::from_slice(&fs::read(&p).unwrap()).unwrap(),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn unsatisfiable_vectors() {
    let all = vectors();
    assert!(all.len() >= 35, "vectors went missing: {}", all.len());
    let mut failures = Vec::new();
    for (name, v) in &all {
        let planned = match plan(&v["query"].to_string(), None) {
            Ok(p) => p,
            Err(e) => {
                failures.push(format!("{name}: must plan, got {e}"));
                continue;
            }
        };
        let got = unsatisfiable(&planned);
        let expect = &v["expect"];
        match (expect.get("satisfiable"), expect.get("error"), got) {
            (Some(_), None, Ok(())) => {}
            (None, Some(code), Err(e)) if Some(e.code()) == code.as_str() => {}
            (_, _, got) => failures.push(format!("{name}: expected {expect}, got {got:?}")),
        }
        if name.starts_with("ok_") != expect.get("satisfiable").is_some() {
            failures.push(format!("{name}: file name and expect disagree"));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// Every code `unsatisfiable` can produce has a vector.
#[test]
fn every_unsatisfiable_code_has_a_vector() {
    let codes: BTreeSet<String> = vectors()
        .iter()
        .filter_map(|(_, v)| v["expect"]["error"].as_str().map(str::to_owned))
        .collect();
    for want in [
        "source_format_unsupported",
        "meta_type_value_invalid",
        "holder_binding_waived",
        "function_unknown",
        "pseudonym_repeated",
        "age_check_repeated",
        "pseudonym_config_missing",
        "pseudonym_config_unknown",
        "pseudonym_ver_missing",
        "pseudonym_ver_unsupported",
        "pseudonym_prf_missing",
        "pseudonym_prf_unsupported",
        "verifier_context_invalid",
        "age_check_no_bound",
        "age_check_inverted",
        "age_check_span_too_short",
    ] {
        assert!(codes.contains(want), "no vector for {want}");
    }
}
