//! The refusals of S1: one fixture per rule and per place the rule is checked.

use serde_json::json;
use siros_sdjwt::SdJwt;

use crate::common::{compact, decoy, disclosure};

#[test]
fn s1_refusals() {
    let (property, property_digest) = disclosure(&json!(["2GLC42sKQveCfGfryNRN9w", "a", 1]));
    let (element, element_digest) = disclosure(&json!(["eluV5Og3gSNII8EYnsxA_A", 1]));
    let (reserved, reserved_digest) = disclosure(&json!(["6Ij7tM-a5iVPGboS5tmvVA", "_sd", 1]));
    let (taken, taken_digest) = disclosure(&json!(["eI8ZWm9QnKPpNPeNenHdhQ", "given_name", "b"]));
    let (four, _) = disclosure(&json!(["Qg_O64zqAxe412a108iroA", "a", 1, 2]));
    let x = decoy("x");
    let deep = format!(r#"{{"a":{}{}}}"#, "[".repeat(40), "]".repeat(40));

    let rows: Vec<(&str, &str, String)> = vec![
        (
            "a repeated payload member",
            "issuer_jwt_malformed",
            compact(r#"{"a":1,"a":2}"#, &[]),
        ),
        (
            "an issuer JWT without a signature",
            "issuer_jwt_malformed",
            "eyJhbGciOiJFUzI1NiJ9.e30~".to_owned(),
        ),
        (
            "a disclosure of four elements",
            "disclosure_malformed",
            compact("{}", &[&four]),
        ),
        (
            "an empty disclosure",
            "disclosure_malformed",
            compact("{}", &[""]),
        ),
        (
            "a truncated digest",
            "sd_alg_unsupported",
            compact(r#"{"_sd_alg":"sha-256-32"}"#, &[]),
        ),
        (
            "a disclosure named _sd",
            "reserved_claim_name",
            compact(&json!({"_sd": [reserved_digest]}).to_string(), &[&reserved]),
        ),
        (
            "an object member named ...",
            "reserved_claim_name",
            compact(&json!({"a": {"...": x}}).to_string(), &[]),
        ),
        (
            "a nested _sd_alg",
            "reserved_claim_name",
            compact(r#"{"a":{"_sd_alg":"sha-256"}}"#, &[]),
        ),
        (
            "an _sd holding a number",
            "reserved_claim_name",
            compact(r#"{"_sd":[1]}"#, &[]),
        ),
        (
            "an array digest beside another member",
            "reserved_claim_name",
            compact(&json!({"a": [{"...": x, "b": 1}]}).to_string(), &[]),
        ),
        (
            "a decoy twice",
            "digest_repeated",
            compact(&json!({"_sd": [x, x]}).to_string(), &[]),
        ),
        (
            "a disclosure twice",
            "digest_repeated",
            compact(
                &json!({"_sd": [property_digest]}).to_string(),
                &[&property, &property],
            ),
        ),
        (
            "an element disclosure in _sd",
            "disclosure_misplaced",
            compact(&json!({"_sd": [element_digest]}).to_string(), &[&element]),
        ),
        (
            "a property disclosure in an array",
            "disclosure_misplaced",
            compact(
                &json!({"a": [{"...": property_digest}]}).to_string(),
                &[&property],
            ),
        ),
        (
            "a disclosure of a permanent claim's name",
            "claim_name_exists",
            compact(
                &json!({"given_name": "a", "_sd": [taken_digest]}).to_string(),
                &[&taken],
            ),
        ),
        (
            "a disclosure no digest names",
            "disclosure_unreferenced",
            compact("{}", &[&property]),
        ),
        (
            "41 levels of arrays",
            "claims_too_deep",
            compact(&deep, &[]),
        ),
    ];
    for (case, code, sd_jwt) in rows {
        match SdJwt::parse(&sd_jwt) {
            Ok(_) => panic!("{case}: accepted"),
            Err(e) => assert_eq!(e.code(), code, "{case}"),
        }
    }
}
