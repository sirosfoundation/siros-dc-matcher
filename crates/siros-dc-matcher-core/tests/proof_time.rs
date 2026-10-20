//! Runs the shared vectors in `tests/vectors/proof_time/proof_time.json`.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use siros_dc_matcher_core::proof_time::{
    check_tolerance, parse, render, MAX_SECS, RECOMMENDED_MAX_AGE_SECS, RECOMMENDED_SKEW_SECS,
};

fn doc() -> Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/proof_time/proof_time.json");
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn render_and_parse_agree_with_the_vectors() {
    let doc = doc();
    let rendered = doc["render"].as_array().unwrap();
    assert!(rendered.len() >= 25);
    for case in rendered {
        let (secs, text) = (
            case["secs"].as_i64().unwrap(),
            case["text"].as_str().unwrap(),
        );
        assert_eq!(render(secs).as_deref(), Ok(text), "render {secs}");
        assert_eq!(text.len(), 20);
        assert_eq!(parse(text), Ok(secs), "parse {text}");
    }
    for case in doc["render_errors"].as_array().unwrap() {
        let err = render(case["secs"].as_i64().unwrap()).unwrap_err();
        assert_eq!(Some(err.code()), case["error"].as_str());
    }
    for case in doc["parse_ok"].as_array().unwrap() {
        assert_eq!(
            parse(case["text"].as_str().unwrap()),
            Ok(case["secs"].as_i64().unwrap())
        );
    }
    for case in doc["parse_errors"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        let err = parse(text).unwrap_err();
        assert_eq!(Some(err.code()), case["error"].as_str(), "{text:?}");
    }
}

#[test]
fn tolerance_agrees_with_the_vectors() {
    let doc = doc();
    for case in doc["tolerance"].as_array().unwrap() {
        let got = check_tolerance(
            case["proof_time"].as_str().unwrap(),
            case["now_secs"].as_i64().unwrap(),
            case["skew_secs"].as_i64().unwrap(),
            case["max_age_secs"].as_i64().unwrap(),
        );
        match (case["expect"].as_str().unwrap(), got) {
            ("ok", Ok(())) => {}
            (code, Err(e)) if e.code() == code => {}
            (want, got) => panic!("{}: expected {want}, got {got:?}", case["name"]),
        }
    }
}

#[test]
fn every_day_of_four_centuries_round_trips() {
    // Every midnight from 1970 to 2400, and the last second of each day: the
    // rendering is the inverse of the parser across every leap rule.
    let mut secs = 0;
    while secs <= 86_400 * 365 * 430 {
        for s in [secs, secs + 86_399] {
            let text = render(s).unwrap();
            assert_eq!(parse(&text), Ok(s), "{text}");
        }
        secs += 86_400;
    }
    assert!(render(MAX_SECS).is_ok());
}

#[test]
fn recommended_defaults_are_what_the_docs_say() {
    assert_eq!(RECOMMENDED_SKEW_SECS, 60);
    assert_eq!(RECOMMENDED_MAX_AGE_SECS, 600);
}
