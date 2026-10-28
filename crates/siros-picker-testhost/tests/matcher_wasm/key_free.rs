//! The rules of the request parameters and of the Client Identifier that need no key: one
//! request breaks each, and the wallet's intake and the picker refuse it alike. Over the DC API
//! the Wallet ignores `state` and, in unsigned `data`, a `request_uri` (A.2): both accept those.

use serde_json::{json, Value};
use siros_codec::cbor::Value as Cbor;
use siros_oid4vp::{UnverifiedRequest, Verdict};
use siros_presentation::testing::verifier::{
    b64, dc_api_intake, dc_api_request, encryption_jwk, intake_with, NONCE, ORIGIN, SIGNER,
};
use siros_presentation::testing::wallet::Wallet;

use crate::differential::Case;
use crate::families::{ask, case, mdl};

/// A DC API request entry that breaks one rule, or keeps every rule.
struct Row {
    name: &'static str,
    protocol: &'static str,
    data: Value,
    /// The code of the rule intake and the picker's reader refuse the entry under; `None` for
    /// an entry both accept.
    refusal: Option<&'static str>,
}

/// The parameters every row starts from.
fn params() -> Value {
    json!({"response_type": "vp_token", "response_mode": "dc_api", "nonce": NONCE,
        "dcql_query": {"credentials": [ask("q1", "age_over_18")]}})
}

/// Unsigned `data`, edited.
fn unsigned(edit: impl Fn(&mut Value)) -> (&'static str, Value) {
    let mut data = params();
    edit(&mut data);
    ("openid4vp-v1-unsigned", data)
}

/// The Request Object every signed row starts from: `dc_api.jwt`, its encryption key and
/// `expected_origins`.
fn object() -> Value {
    let mut object = params();
    object["response_mode"] = json!("dc_api.jwt");
    object["client_metadata"] = json!({"jwks": {"keys": [encryption_jwk()]}});
    object["expected_origins"] = json!([ORIGIN]);
    object
}

/// A compact JWS Request Object of [`SIGNER`] with its `client_id`, edited.
fn signed(edit: impl Fn(&mut Value)) -> (&'static str, Value) {
    let mut object = object();
    object["client_id"] = json!(SIGNER.client_id());
    edit(&mut object);
    (
        "openid4vp-v1-signed",
        json!({"request": SIGNER.compact(&object)}),
    )
}

/// A multisigned payload, edited, whose one signature's protected header names [`SIGNER`].
fn multisigned(edit: impl Fn(&mut Value)) -> (&'static str, Value) {
    let mut object = object();
    edit(&mut object);
    let mut header = SIGNER.header();
    header["client_id"] = json!(SIGNER.client_id());
    let protected = b64(header.to_string().as_bytes());
    let payload = b64(object.to_string().as_bytes());
    let signature = SIGNER.sign(&format!("{protected}.{payload}"));
    let signatures = json!([{"protected": protected, "signature": signature}]);
    (
        "openid4vp-v1-multisigned",
        json!({"payload": payload, "signatures": signatures}),
    )
}

fn without(member: &'static str) -> impl Fn(&mut Value) {
    move |data| drop(data.as_object_mut().unwrap().remove(member).unwrap())
}

fn set(member: &'static str, value: Value) -> impl Fn(&mut Value) {
    move |data| data[member] = value.clone()
}

fn verifier_info(attestations: Value) -> impl Fn(&mut Value) {
    set("verifier_info", attestations)
}

fn rows() -> Vec<Row> {
    let attestation = |extra: Value| {
        let mut attestation = json!({"format": "jwt", "data": "x"});
        attestation
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        json!([attestation])
    };
    let table: Vec<(&str, (&str, Value), Option<&str>)> = vec![
        ("unsigned, every rule kept", unsigned(|_| {}), None),
        ("signed, every rule kept", signed(|_| {}), None),
        ("multisigned, every rule kept", multisigned(|_| {}), None),
        (
            "no nonce",
            unsigned(without("nonce")),
            Some("nonce_invalid"),
        ),
        (
            "a nonce with a space",
            unsigned(set("nonce", json!("a b"))),
            Some("nonce_invalid"),
        ),
        (
            "no response_type",
            unsigned(without("response_type")),
            Some("response_type_unsupported"),
        ),
        (
            "response_type id_token",
            unsigned(set("response_type", json!("id_token"))),
            Some("response_type_unsupported"),
        ),
        (
            "no response_mode",
            unsigned(without("response_mode")),
            Some("response_mode_unsupported"),
        ),
        (
            "direct_post over the DC API",
            unsigned(set("response_mode", json!("direct_post"))),
            Some("response_mode_unsupported"),
        ),
        (
            "a signed Request Object with a request_uri",
            signed(set(
                "request_uri",
                json!("https://verifier.example/request"),
            )),
            Some("nested_request"),
        ),
        (
            "unsigned client_metadata a string",
            unsigned(set("client_metadata", json!("x"))),
            Some("client_metadata_invalid"),
        ),
        (
            "signed client_metadata a string",
            signed(set("client_metadata", json!("x"))),
            Some("client_metadata_invalid"),
        ),
        (
            "multisigned client_metadata a string",
            multisigned(set("client_metadata", json!("x"))),
            Some("client_metadata_invalid"),
        ),
        (
            "signed without expected_origins",
            signed(without("expected_origins")),
            Some("expected_origins_missing"),
        ),
        (
            "multisigned without expected_origins",
            multisigned(without("expected_origins")),
            Some("expected_origins_missing"),
        ),
        (
            "verifier_info naming its query",
            unsigned(verifier_info(attestation(
                json!({"credential_ids": ["q1"]}),
            ))),
            None,
        ),
        (
            "verifier_info no array",
            unsigned(verifier_info(json!({"format": "jwt", "data": "x"}))),
            Some("verifier_info_not_array"),
        ),
        (
            "verifier_info empty",
            unsigned(verifier_info(json!([]))),
            Some("verifier_info_empty"),
        ),
        (
            "a verifier_info attestation no object",
            unsigned(verifier_info(json!(["x"]))),
            Some("verifier_info_not_object"),
        ),
        (
            "a verifier_info attestation without format",
            unsigned(verifier_info(json!([{"data": "x"}]))),
            Some("verifier_info_format"),
        ),
        (
            "a verifier_info attestation with data a number",
            unsigned(verifier_info(json!([{"format": "jwt", "data": 7}]))),
            Some("verifier_info_data"),
        ),
        (
            "a verifier_info attestation with empty credential_ids",
            unsigned(verifier_info(attestation(json!({"credential_ids": []})))),
            Some("verifier_info_credential_ids"),
        ),
        (
            "a verifier_info attestation naming an unknown query",
            unsigned(verifier_info(attestation(
                json!({"credential_ids": ["q9"]}),
            ))),
            Some("verifier_info_credential_id_unknown"),
        ),
        (
            "signed without client_id",
            signed(without("client_id")),
            Some("client_id_missing"),
        ),
        (
            "a pre-registered client",
            signed(set("client_id", json!("verifier.example"))),
            Some("client_id_unprefixed"),
        ),
        (
            "an unsupported Client Identifier Prefix",
            signed(set("client_id", json!("https://verifier.example"))),
            Some("client_id_prefix_unsupported"),
        ),
        (
            "an empty Client Identifier",
            signed(set("client_id", json!("x509_san_dns:"))),
            Some("client_id_value_empty"),
        ),
        (
            "a decentralized_identifier client without a DID",
            signed(set(
                "client_id",
                json!("decentralized_identifier:verifier.example"),
            )),
            Some("client_id_not_a_did"),
        ),
        (
            "an x509_san_dns client not ASCII",
            signed(set("client_id", json!("x509_san_dns:vérifier.example"))),
            Some("client_id_dns_name"),
        ),
        (
            "a signed redirect_uri client",
            signed(set(
                "client_id",
                json!("redirect_uri:https://verifier.example/cb"),
            )),
            Some("signed_redirect_uri"),
        ),
        (
            "a multisigned payload with client_id",
            multisigned(set("client_id", json!(SIGNER.client_id()))),
            Some("client_id_in_payload"),
        ),
        (
            "a multisigned payload with verifier_info",
            multisigned(verifier_info(attestation(json!({})))),
            Some("verifier_info_in_payload"),
        ),
        (
            "state with a space over the DC API",
            unsigned(set("state", json!("a b"))),
            None,
        ),
        (
            "state a number over the DC API",
            unsigned(set("state", json!(7))),
            None,
        ),
        (
            "a request_uri in unsigned data",
            unsigned(set(
                "request_uri",
                json!("https://verifier.example/request"),
            )),
            None,
        ),
    ];
    table
        .into_iter()
        .map(|(name, (protocol, data), refusal)| Row {
            name,
            protocol,
            data,
            refusal,
        })
        .collect()
}

/// The rows as differential cases, over an adult's mDL.
pub fn cases() -> Vec<Case> {
    rows()
        .into_iter()
        .map(|row| {
            let wallet = Wallet::new(vec![mdl(1, &[("age_over_18", Cbor::Bool(true))])]);
            case(row.name, dc_api_request(row.protocol, row.data), wallet)
        })
        .collect()
}

/// Each row breaks the rule it names for the wallet's intake and for the picker's reader, so
/// the differential's empty offers on both sides refuse under that rule.
#[test]
fn each_row_breaks_the_rule_it_names() {
    let misread: Vec<String> = rows()
        .into_iter()
        .filter_map(|row| {
            let request = dc_api_request(row.protocol, row.data.clone());
            let intake = intake_with(dc_api_intake(&request), Verdict::Trusted);
            let wallet = intake.err().map(|error| error.code());
            let read = UnverifiedRequest::read(row.protocol, &row.data);
            let picker = read.err().map(|refusal| refusal.code());
            (wallet != row.refusal || picker != row.refusal).then(|| {
                format!(
                    "{}: wallet {wallet:?}, picker {picker:?}, named {:?}",
                    row.name, row.refusal
                )
            })
        })
        .collect();
    assert!(misread.is_empty(), "{}", misread.join("\n"));
}
