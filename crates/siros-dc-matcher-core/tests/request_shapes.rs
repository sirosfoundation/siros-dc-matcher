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
use siros_dc_matcher_core::request::{
    diagnose, extract_query, first_supported_context, first_supported_request, NoQuery,
};

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
///
/// Keyed by protocol as well as by data, because the reason depends on both:
/// the same `{"request": 42}` is "not a compact JWS" under `-signed` and
/// "neither a JWS string nor a JWS JSON object" under `-multisigned`.
#[test]
fn each_failure_is_named_separately() {
    let cases = [
        (
            "openid4vp-v1-unsigned",
            serde_json::json!({"unrelated": true}),
            NoQuery::NoQueryAndNoRequest,
        ),
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": "no-dots"}),
            NoQuery::NotACompactJws,
        ),
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": "aGVhZGVy."}),
            NoQuery::NotACompactJws,
        ),
        // An empty header segment is malformed; offering an entry for it means
        // the user consents to something the wallet rejects afterwards.
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": ".aGk.c2ln"}),
            NoQuery::NotACompactJws,
        ),
        // Two segments is not the compact serialization, which is always three
        // (RFC 7515 §7.1). The unsecured form is `header.payload.` - see
        // `an_unsecured_token_has_an_empty_signature_not_a_missing_one`.
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": format!("aGVhZGVy.{}", b64(request_object().as_bytes()))}),
            NoQuery::NotACompactJws,
        ),
        // The mirror of the compact-JWS branch: an inline query under the
        // multisigned label is a mismatch, not an absence.
        (
            "openid4vp-v1-multisigned",
            serde_json::json!({"dcql_query": {"credentials": []}}),
            NoQuery::ShapeDoesNotMatchProtocol,
        ),
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": "aGVhZGVy.@@@@.c2ln"}),
            NoQuery::PayloadNotBase64url,
        ),
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": format!("aGVhZGVy.{}.c2ln", b64(b"plain text"))}),
            NoQuery::PayloadNotJson,
        ),
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": format!("aGVhZGVy.{}.c2ln", b64(br#"{"nonce":"x"}"#))}),
            NoQuery::PayloadHasNoDcqlQuery,
        ),
        // A signed request whose `request` is not even a string.
        (
            "openid4vp-v1-signed",
            serde_json::json!({"request": {"payload": "aGk"}}),
            NoQuery::NotACompactJws,
        ),
        (
            "openid4vp-v1-multisigned",
            serde_json::json!({"request": {"payload": "!!!"}}),
            NoQuery::PayloadNotBase64url,
        ),
        // Present but not decodable is not the same as absent.
        (
            "openid4vp-v1-multisigned",
            serde_json::json!({"request": 42}),
            NoQuery::RequestNotAJwsOrObject,
        ),
        // A string is the `-signed` shape, so under `-multisigned` it is a
        // mismatch rather than a value of the wrong type.
        (
            "openid4vp-v1-multisigned",
            serde_json::json!({"request": "aGVhZGVy.aGk.c2ln"}),
            NoQuery::ShapeDoesNotMatchProtocol,
        ),
        (
            "openid4vp-v1-multisigned",
            serde_json::json!({"request": null}),
            NoQuery::RequestNotAJwsOrObject,
        ),
        // A JWS JSON object with no payload is a malformed signed request, not
        // an absent one.
        (
            "openid4vp-v1-multisigned",
            serde_json::json!({"request": {"signatures": []}}),
            NoQuery::JwsObjectHasNoPayload,
        ),
    ];
    for (protocol, data, expected) in cases {
        assert_eq!(
            extract_query(Parser::Openid4vpV1, protocol, &data),
            Err(expected.clone()),
            "for {protocol} {data}"
        );
        assert!(!expected.to_string().is_empty());
    }
}

/// A JWE has five segments and its second is an encrypted key, not a payload.
///
/// Accepting it would decode that key as though it were the request object:
/// either a misleading failure, or — if it happened to decode — an answer built
/// from something that is not the request at all.
#[test]
fn a_jwe_is_not_mistaken_for_a_jws() {
    let jwe = format!(
        "{}.{}.{}.{}.{}",
        b64(br#"{"alg":"ECDH-ES","enc":"A256GCM"}"#),
        b64(b"encrypted-key"),
        b64(b"iv"),
        b64(b"ciphertext"),
        b64(b"tag")
    );
    assert_eq!(
        extract_query(
            Parser::Openid4vpV1,
            "openid4vp-v1-signed",
            &serde_json::json!({"request": jwe})
        ),
        Err(NoQuery::NotACompactJws)
    );
}

/// An unsecured token has an *empty* signature, not a missing one.
///
/// RFC 7519 §6: `alg: none` with the signature as the empty string, so the
/// serialization is `header.payload.` — three segments, the third empty. Its
/// payload is read, because whether an unsecured request is acceptable is the
/// wallet's decision and not the matcher's.
#[test]
fn an_unsecured_token_has_an_empty_signature_not_a_missing_one() {
    let token = format!(
        "{}.{}.",
        b64(br#"{"alg":"none"}"#),
        b64(request_object().as_bytes())
    );
    assert!(extract_query(
        Parser::Openid4vpV1,
        "openid4vp-v1-signed",
        &serde_json::json!({"request": token})
    )
    .is_ok());
}

/// A `dcql_query` that is present but not DCQL is its own failure, not a
/// missing one.
#[test]
fn a_malformed_dcql_query_reports_the_parse_error() {
    let data = serde_json::json!({"dcql_query": {"credentials": "not an array"}});
    match extract_query(Parser::Openid4vpV1, "openid4vp-v1-unsigned", &data) {
        Err(NoQuery::Malformed(e)) => assert!(!e.is_empty()),
        other => panic!("expected a parse error, got {other:?}"),
    }
}

/// ISO 18013-7 carries a CBOR DeviceRequest, not DCQL. Declining is what lets
/// the caller try another protocol rather than failing the whole request.
#[test]
fn the_iso_mdoc_protocol_declines_rather_than_failing() {
    assert_eq!(
        extract_query(Parser::IsoMdocApi, "org.iso.mdoc", &serde_json::json!({})),
        Err(NoQuery::NoParser)
    );
}

// --- the shape must match the label ----------------------------------------

/// A request labelled `-unsigned` that carries a JWS is not answered.
///
/// All three OpenID4VP protocols share a parser, so accepting any shape for any
/// of them let a verifier label a request unsigned and still send a signed one.
/// The matcher would read the query out of the signed payload, offer a
/// credential for it, and report the protocol as unsigned — and the protocol id
/// is what a wallet uses to decide whether to verify a signature. The gap
/// between what the user consented to and what gets checked is the whole
/// problem.
#[test]
fn an_unsigned_label_does_not_accept_a_signed_payload() {
    let data = serde_json::json!({"request": compact_jws(&request_object())});
    assert_eq!(
        extract_query(Parser::Openid4vpV1, "openid4vp-v1-unsigned", &data),
        Err(NoQuery::ShapeDoesNotMatchProtocol),
        "the reason should name the mismatch, not a missing key"
    );
    assert!(first_supported_request(
        &envelope("openid4vp-v1-unsigned", data),
        &MatchProfile::siros_default()
    )
    .is_none());
}

/// And the converse: a `-signed` label does not accept an inline query.
///
/// A verifier that sends an unsigned request under a signed label is either
/// confused or trying something; either way the matcher should not quietly
/// paper over it, because the wallet will look for a signature that is not
/// there.
#[test]
fn a_signed_label_does_not_accept_an_inline_query() {
    let data: serde_json::Value = serde_json::from_str(&request_object()).expect("json");
    assert_eq!(
        extract_query(Parser::Openid4vpV1, "openid4vp-v1-signed", &data),
        Err(NoQuery::ShapeDoesNotMatchProtocol)
    );
}

/// Each signed protocol takes its own serialization, not the other's.
#[test]
fn the_two_signed_protocols_do_not_accept_each_other_s_shape() {
    let compact = serde_json::json!({"request": compact_jws(&request_object())});
    let json = serde_json::json!({
        "request": {"payload": b64(request_object().as_bytes()), "signatures": []}
    });

    assert!(extract_query(Parser::Openid4vpV1, "openid4vp-v1-signed", &compact).is_ok());
    assert!(extract_query(Parser::Openid4vpV1, "openid4vp-v1-multisigned", &json).is_ok());

    assert_eq!(
        extract_query(Parser::Openid4vpV1, "openid4vp-v1-multisigned", &compact),
        Err(NoQuery::ShapeDoesNotMatchProtocol),
        "a compact JWS is the -signed shape, not a wrong-typed value"
    );
    assert_eq!(
        extract_query(Parser::Openid4vpV1, "openid4vp-v1-signed", &json),
        Err(NoQuery::NotACompactJws)
    );
}

/// A profile naming its own OpenID4VP protocol gets the inline shape, not the
/// signed ones: declaring a protocol is not opting into decoding unverified
/// payloads under it.
#[test]
fn an_unknown_openid4vp_protocol_id_gets_the_inline_shape() {
    let inline: serde_json::Value = serde_json::from_str(&request_object()).expect("json");
    assert!(extract_query(Parser::Openid4vpV1, "org.example.vp-v1", &inline).is_ok());
    assert_eq!(
        extract_query(
            Parser::Openid4vpV1,
            "org.example.vp-v1",
            &serde_json::json!({"request": compact_jws(&request_object())})
        ),
        Err(NoQuery::ShapeDoesNotMatchProtocol)
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

// --- the full request context ----------------------------------------------

fn two_entry_envelope(
    first: (&str, serde_json::Value),
    second: (&str, serde_json::Value),
) -> Vec<u8> {
    serde_json::json!({"requests": [
        {"protocol": first.0, "data": first.1},
        {"protocol": second.0, "data": second.1},
    ]})
    .to_string()
    .into_bytes()
}

fn unsigned_data() -> serde_json::Value {
    serde_json::from_str(&request_object()).expect("json")
}

fn signed_data() -> serde_json::Value {
    serde_json::json!({"request": compact_jws(&request_object())})
}

#[test]
fn an_unsigned_request_yields_its_full_context() {
    let ctx = first_supported_context(
        &envelope("openid4vp-v1-unsigned", unsigned_data()),
        &MatchProfile::siros_default(),
        None,
    )
    .expect("context");
    assert_eq!(ctx.protocol, "openid4vp-v1-unsigned");
    assert!(!ctx.signed);
    assert_eq!(
        ctx.client_id.as_deref(),
        Some("x509_san_dns:verifier.example")
    );
    assert_eq!(
        ctx.expected_origins,
        Some(vec!["https://verifier.example".to_string()])
    );
    assert_eq!(
        ctx.client_metadata,
        Some(serde_json::json!({"jwks": {"keys": []}}))
    );
    assert_eq!(ctx.dcql_query_raw["credentials"][0]["id"], "pid");
    assert_eq!(ctx.dcql_query.expect("typed").credentials[0].id, "pid");
}

#[test]
fn a_signed_request_yields_its_full_context() {
    let ctx = first_supported_context(
        &envelope("openid4vp-v1-signed", signed_data()),
        &MatchProfile::siros_default(),
        None,
    )
    .expect("context");
    assert_eq!(ctx.protocol, "openid4vp-v1-signed");
    assert!(ctx.signed);
    assert_eq!(
        ctx.client_id.as_deref(),
        Some("x509_san_dns:verifier.example")
    );
    assert_eq!(
        ctx.expected_origins,
        Some(vec!["https://verifier.example".to_string()])
    );
    assert!(ctx.client_metadata.is_some());
    assert!(ctx.dcql_query.is_some());
}

#[test]
fn origins_client_id_and_metadata_are_none_when_absent() {
    let data = serde_json::json!({"dcql_query": {"credentials": [{
        "id": "pid", "format": "mso_mdoc",
        "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
        "claims": [{"path": ["org.iso.18013.5.1", "age_over_18"]}]
    }]}});
    let ctx = first_supported_context(
        &envelope("openid4vp-v1-unsigned", data),
        &MatchProfile::siros_default(),
        None,
    )
    .expect("context");
    assert_eq!(ctx.client_id, None);
    assert_eq!(ctx.expected_origins, None);
    assert_eq!(ctx.client_metadata, None);
}

/// The rulebook example puts an object under `claims`, which the typed DCQL
/// parser rejects. It must still reach the planner.
fn zkp_req_object_claims_data() -> serde_json::Value {
    serde_json::json!({
        "client_id": "x509_san_dns:rp.example.com",
        "dcql_query": {"credentials": [{
            "id": "nym", "format": "zkp_req",
            "meta": {"doctype_value": "eu.europa.ec.eudi.nym_auth.1"},
            "claims": {"_req": [{"fn_id": "age_check", "id": "a", "params": {"ge": "2008-10-10"}}]}
        }]}
    })
}

#[test]
fn a_zkp_req_request_with_object_claims_yields_a_context() {
    let ctx = first_supported_context(
        &envelope("openid4vp-v1-unsigned", zkp_req_object_claims_data()),
        &MatchProfile::siros_default(),
        None,
    )
    .expect("a context, not Malformed");
    assert!(ctx.dcql_query.is_none());
    assert!(ctx.dcql_query_raw["credentials"][0]["claims"]["_req"].is_array());
}

/// ... but only for zkp_req. Other formats keep failing as before, and so
/// does a malformed credential sitting next to a zkp_req one.
#[test]
fn object_claims_on_any_other_format_is_still_malformed() {
    let data = serde_json::json!({"dcql_query": {"credentials": [{
        "id": "pid", "format": "mso_mdoc",
        "meta": {"doctype_value": "d"}, "claims": {"_req": []}
    }]}});
    let profile = MatchProfile::siros_default();
    assert!(first_supported_context(
        &envelope("openid4vp-v1-unsigned", data.clone()),
        &profile,
        None
    )
    .is_none());
    let parser = profile.parser_for("openid4vp-v1-unsigned").expect("parser");
    assert!(matches!(
        extract_query(parser, "openid4vp-v1-unsigned", &data),
        Err(NoQuery::Malformed(_))
    ));

    let mut mixed = zkp_req_object_claims_data();
    mixed["dcql_query"]["credentials"]
        .as_array_mut()
        .expect("array")
        .push(data["dcql_query"]["credentials"][0].clone());
    assert!(
        first_supported_context(&envelope("openid4vp-v1-unsigned", mixed), &profile, None)
            .is_none()
    );
}

/// The thin wrapper cannot return a query that does not exist, so it moves on
/// to the next entry, as it did when this was a parse failure.
#[test]
fn the_wrapper_skips_a_zkp_req_entry_that_has_no_typed_query() {
    let found = first_supported_request(
        &two_entry_envelope(
            ("openid4vp-v1-unsigned", zkp_req_object_claims_data()),
            ("openid4vp-v1-signed", signed_data()),
        ),
        &MatchProfile::siros_default(),
    );
    assert_eq!(found.expect("second entry").0, "openid4vp-v1-signed");
}

#[test]
fn a_predicate_can_skip_an_unsigned_first_entry_for_a_signed_second() {
    let bytes = two_entry_envelope(
        ("openid4vp-v1-unsigned", unsigned_data()),
        ("openid4vp-v1-signed", signed_data()),
    );
    let profile = MatchProfile::siros_default();
    let no_unsigned = |_: &str, signed: bool, _: &_| signed;
    let ctx = first_supported_context(&bytes, &profile, Some(&no_unsigned)).expect("context");
    assert_eq!(ctx.protocol, "openid4vp-v1-signed");
    assert!(ctx.signed);

    // No predicate: today's behaviour, first supported entry wins.
    let first = first_supported_context(&bytes, &profile, None).expect("context");
    assert_eq!(first.protocol, "openid4vp-v1-unsigned");
}

#[test]
fn the_predicate_sees_the_protocol_label_and_the_context() {
    let bytes = two_entry_envelope(
        ("openid4vp-v1-unsigned", unsigned_data()),
        ("openid4vp-v1-signed", signed_data()),
    );
    let wants = |protocol: &str, _: bool, ctx: &siros_dc_matcher_core::request::RequestContext| {
        protocol == "openid4vp-v1-signed" && ctx.client_id.is_some()
    };
    let ctx = first_supported_context(&bytes, &MatchProfile::siros_default(), Some(&wants))
        .expect("context");
    assert_eq!(ctx.protocol, "openid4vp-v1-signed");
}

#[test]
fn a_predicate_that_rejects_everything_yields_no_context() {
    let bytes = two_entry_envelope(
        ("openid4vp-v1-unsigned", unsigned_data()),
        ("openid4vp-v1-signed", signed_data()),
    );
    let reject_all = |_: &str, _: bool, _: &_| false;
    assert!(
        first_supported_context(&bytes, &MatchProfile::siros_default(), Some(&reject_all))
            .is_none()
    );
}

#[test]
fn an_unknown_protocol_still_yields_no_context() {
    assert!(first_supported_context(
        &envelope("some-other-protocol", unsigned_data()),
        &MatchProfile::siros_default(),
        None,
    )
    .is_none());
}
