//! The three shapes a DC API request arrives in, and what happens to the ones
//! that arrive broken.
//!
//! The envelope is identical in all three cases (OpenID4VP 1.0 Appendix A);
//! only `data` differs. Until this suite existed the matcher read `dcql_query`
//! and nothing else, so both signed forms were declined and a verifier that
//! offered only those got no picker entry at all.
//!
//! The payloads here are constructed from the specification rather than
//! captured from a verifier. They are the shapes, not evidence that any
//! particular verifier sends them: a capture from a real one belongs in the
//! device pass.

use siros_dc_matcher_core::profile::{MatchProfile, Parser};
use siros_dc_matcher_core::request::{diagnose, extract_query, first_supported_request, NoQuery};

/// Unpadded base64url, so a test does not have to hand-encode its own payload.
fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let take = chunk.len() + 1;
        for i in 0..take {
            let idx = ((n >> (18 - 6 * i)) & 0x3F) as usize;
            out.push(char::from(A[idx]));
        }
    }
    out
}

/// The authorization request object all three protocols ultimately carry.
fn request_object() -> String {
    serde_json::json!({
        "client_id": "x509_san_dns:verifier.example",
        "response_mode": "dc_api.jwt",
        "nonce": "n-0S6_WzA2Mj",
        "expected_origins": ["https://verifier.example"],
        "dcql_query": {
            "credentials": [{
                "id": "pid",
                "format": "mso_mdoc",
                "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                "claims": [{"path": ["org.iso.18013.5.1", "age_over_18"]}]
            }]
        },
        "client_metadata": {"jwks": {"keys": []}}
    })
    .to_string()
}

fn envelope(protocol: &str, data: serde_json::Value) -> Vec<u8> {
    serde_json::json!({"requests": [{"protocol": protocol, "data": data}]})
        .to_string()
        .into_bytes()
}

fn compact_jws(payload: &str) -> String {
    format!(
        "{}.{}.{}",
        b64(br#"{"alg":"ES256"}"#),
        b64(payload.as_bytes()),
        b64(b"sig")
    )
}

// --- the three shapes ------------------------------------------------------

/// `openid4vp-v1-unsigned`: the request object is `data` itself.
#[test]
fn an_unsigned_request_still_works() {
    let data: serde_json::Value = serde_json::from_str(&request_object()).expect("json");
    let found = first_supported_request(
        &envelope("openid4vp-v1-unsigned", data),
        &MatchProfile::siros_default(),
    );
    let (protocol, query) = found.expect("unsigned request should be answered");
    assert_eq!(protocol, "openid4vp-v1-unsigned");
    assert_eq!(query.credentials.len(), 1);
}

/// `openid4vp-v1-signed`: `data.request` is a compact JWS whose middle segment
/// is the request object.
#[test]
fn a_signed_request_is_read_from_the_jws_payload() {
    let data = serde_json::json!({"request": compact_jws(&request_object())});
    let found = first_supported_request(
        &envelope("openid4vp-v1-signed", data),
        &MatchProfile::siros_default(),
    );
    let (protocol, query) = found.expect("signed request should be answered");
    assert_eq!(protocol, "openid4vp-v1-signed");
    assert_eq!(query.credentials.len(), 1);
    assert_eq!(query.credentials[0].id, "pid");
}

/// `openid4vp-v1-multisigned`: `data.request` is a JWS JSON Serialization
/// object, and the payload is one of its members.
#[test]
fn a_multisigned_request_is_read_from_the_payload_member() {
    let data = serde_json::json!({
        "request": {
            "payload": b64(request_object().as_bytes()),
            "signatures": [{"protected": b64(br#"{"alg":"ES256"}"#), "signature": b64(b"sig")}]
        }
    });
    let found = first_supported_request(
        &envelope("openid4vp-v1-multisigned", data),
        &MatchProfile::siros_default(),
    );
    let (_, query) = found.expect("multisigned request should be answered");
    assert_eq!(query.credentials[0].id, "pid");
}

/// The reference matcher also accepts the serialization at the top level of
/// `data`, with no `request` wrapper. A verifier that sends it that way is not
/// wrong enough to refuse.
#[test]
fn a_multisigned_payload_at_the_top_level_of_data_is_accepted_too() {
    let data = serde_json::json!({
        "payload": b64(request_object().as_bytes()),
        "signatures": [{"signature": b64(b"sig")}]
    });
    let found = first_supported_request(
        &envelope("openid4vp-v1-multisigned", data),
        &MatchProfile::siros_default(),
    );
    assert!(found.is_some(), "top-level payload should be read");
}

// --- what the matcher is not -----------------------------------------------

/// The signature is not checked here, and a test says so rather than leaving it
/// to be inferred from the absence of one.
///
/// The matcher has no crypto and is not the trust boundary: the wallet verifies
/// the JWS at selection time, before anything is disclosed. What this decides
/// is only which entries to draw.
#[test]
fn a_bogus_signature_does_not_stop_the_query_being_read() {
    let payload = b64(request_object().as_bytes());
    let data = serde_json::json!({
        "request": format!("{}.{}.{}", b64(br#"{"alg":"ES256"}"#), payload, b64(b"not-a-signature")),
    });
    assert!(first_supported_request(
        &envelope("openid4vp-v1-signed", data),
        &MatchProfile::siros_default()
    )
    .is_some());
}

// --- declining, rather than trapping ---------------------------------------

/// A trap shows the user nothing and is indistinguishable from "no matching
/// credential", so every malformed shape must decline instead.
#[test]
fn malformed_signed_requests_decline_without_panicking() {
    let profile = MatchProfile::siros_default();
    for data in [
        serde_json::json!({"request": ""}),
        serde_json::json!({"request": "not-a-jws"}),
        serde_json::json!({"request": "onlyheader."}),
        serde_json::json!({"request": ".."}),
        serde_json::json!({"request": "aGVhZGVy.!!!not-base64url!!!.c2ln"}),
        serde_json::json!({"request": format!("aGVhZGVy.{}.c2ln", b64(b"not json at all"))}),
        serde_json::json!({"request": format!("aGVhZGVy.{}.c2ln", b64(br#"{"nonce":"x"}"#))}),
        serde_json::json!({"request": {"payload": "!!!"}}),
        serde_json::json!({"request": {"signatures": []}}),
        serde_json::json!({"request": 42}),
        serde_json::json!({}),
    ] {
        assert!(
            first_supported_request(&envelope("openid4vp-v1-signed", data.clone()), &profile)
                .is_none(),
            "should have declined: {data}"
        );
    }
}

/// Each failure is named, because "data has no `dcql_query`" is true of every
/// signed request and tells whoever is reading the picker nothing.
#[test]
fn each_failure_is_named_separately() {
    let cases = [
        (
            serde_json::json!({"request": "no-dots"}),
            NoQuery::NotACompactJws,
        ),
        (
            serde_json::json!({"request": "aGVhZGVy."}),
            NoQuery::NotACompactJws,
        ),
        (
            serde_json::json!({"request": "aGVhZGVy.@@@@.c2ln"}),
            NoQuery::PayloadNotBase64url,
        ),
        (
            serde_json::json!({"request": format!("aGVhZGVy.{}.c2ln", b64(b"plain text"))}),
            NoQuery::PayloadNotJson,
        ),
        (
            serde_json::json!({"request": format!("aGVhZGVy.{}.c2ln", b64(br#"{"nonce":"x"}"#))}),
            NoQuery::PayloadHasNoDcqlQuery,
        ),
        (
            serde_json::json!({"unrelated": true}),
            NoQuery::NoQueryAndNoRequest,
        ),
    ];
    for (data, expected) in cases {
        assert_eq!(
            extract_query(Parser::Openid4vpV1, &data),
            Err(expected.clone()),
            "for {data}"
        );
        assert!(!expected.reason().is_empty());
    }
}

/// A `dcql_query` that is present but not DCQL is its own failure, not a
/// missing one.
#[test]
fn a_malformed_dcql_query_reports_the_parse_error() {
    let data = serde_json::json!({"dcql_query": {"credentials": "not an array"}});
    match extract_query(Parser::Openid4vpV1, &data) {
        Err(NoQuery::Malformed(e)) => assert!(!e.is_empty()),
        other => panic!("expected a parse error, got {other:?}"),
    }
}

/// ISO 18013-7 carries a CBOR DeviceRequest, not DCQL. Declining is what lets
/// the caller try another protocol rather than failing the whole request.
#[test]
fn the_iso_mdoc_protocol_declines_rather_than_failing() {
    assert_eq!(
        extract_query(Parser::IsoMdocApi, &serde_json::json!({})),
        Err(NoQuery::NoParser)
    );
}

// --- negotiation -----------------------------------------------------------

/// The behaviour the request list exists for, and which nothing exercised
/// before: a verifier offers the same request under several protocols, and the
/// first one this build can actually *read* wins - not merely the first one the
/// profile lists.
#[test]
fn an_unreadable_protocol_falls_through_to_a_readable_one() {
    let request = serde_json::json!({"requests": [
        {"protocol": "openid4vp-v1-signed", "data": {"request": "truncated"}},
        {"protocol": "openid4vp-v1-unsigned",
         "data": serde_json::from_str::<serde_json::Value>(&request_object()).expect("json")}
    ]})
    .to_string()
    .into_bytes();

    let (protocol, _) = first_supported_request(&request, &MatchProfile::siros_default())
        .expect("should fall through to the unsigned entry");
    assert_eq!(protocol, "openid4vp-v1-unsigned");
}

/// A protocol the wallet did not register is skipped even when it is readable,
/// because which protocols are supported is a registration decision.
#[test]
fn a_protocol_outside_the_profile_is_skipped() {
    let data: serde_json::Value = serde_json::from_str(&request_object()).expect("json");
    assert!(first_supported_request(
        &envelope("org.iso.mdoc", data),
        &MatchProfile::siros_default()
    )
    .is_none());
}

// --- diagnostics -----------------------------------------------------------

#[test]
fn the_diagnostic_names_the_signed_failure_rather_than_the_missing_key() {
    let profile = MatchProfile::siros_default();
    let data = serde_json::json!({"request": "aGVhZGVy.@@@@.c2ln"});
    let text = diagnose(&envelope("openid4vp-v1-signed", data), &profile);
    assert!(text.contains("base64url"), "got: {text}");
    assert!(!text.contains("has no `dcql_query`"), "got: {text}");
}

#[test]
fn the_diagnostic_survives_every_malformed_envelope() {
    let profile = MatchProfile::siros_default();
    for raw in [
        &b"not json"[..],
        b"{}",
        br#"{"requests": []}"#,
        br#"{"requests": [{}]}"#,
        br#"{"requests": [{"protocol": "openid4vp-v1-signed"}]}"#,
        br#"{"requests": [{"protocol": "nope", "data": {}}]}"#,
    ] {
        assert!(!diagnose(raw, &profile).is_empty(), "empty for {raw:?}");
    }
}
