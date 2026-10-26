//! The request, credentials and type metadata the tests share.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;
use siros_credential::Credential;
use siros_dcql::DcqlQuery;
use siros_oid4vp::FetchResponse;
use siros_wallet_state::WalletState;

pub const PAYMENT: &str = "urn:eudi:sca:payment:1";
pub const LOGIN: &str = "urn:eudi:sca:login_risk_transaction:1";
pub const ACCESS: &str = "urn:eudi:sca:account_access:1";
pub const MANDATE: &str = "urn:eudi:sca:emandate:1";

/// The `vct` of the SCA Attestation of the tests.
pub const VCT: &str = "https://pay.example/card";

/// The DCQL query: `pay` and `card` ask for SD-JWT VCs with holder binding, `unbound` for one
/// without, `mdl` for an mdoc.
pub fn query() -> DcqlQuery {
    DcqlQuery::from_json(
        &json!({"credentials": [
            {"id": "pay", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]}},
            {"id": "card", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]}},
            {"id": "unbound", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]},
             "require_cryptographic_holder_binding": false},
            {"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}
        ]})
        .to_string(),
    )
    .unwrap()
}

/// base64url of the JSON text of `entry`, as a verifier sends it.
pub fn encode(entry: &Value) -> String {
    base64url::encode(entry.to_string().as_bytes())
}

/// An entry of `transaction_type` with `payload`, naming `pay` and accepting SHA-256.
pub fn entry(transaction_type: &str, payload: Value) -> Value {
    json!({
        "type": transaction_type,
        "credential_ids": ["pay"],
        "transaction_data_hashes_alg": ["sha-256"],
        "payload": payload
    })
}

/// `value` with the members of `changes`; a `null` change removes the member.
pub fn with(mut value: Value, changes: Value) -> Value {
    let object = value.as_object_mut().unwrap();
    for (name, change) in changes.as_object().unwrap() {
        if change.is_null() {
            assert!(object.remove(name).is_some(), "{name}");
        } else {
            object.insert(name.clone(), change.clone());
        }
    }
    value
}

/// A payment payload of Section 4.3.1.
pub fn payment() -> Value {
    json!({
        "transaction_id": "tx-0001",
        "payee": {"name": "Shop AB", "id": "SE1234567890"},
        "currency": "EUR",
        "amount": 49.99
    })
}

/// The SD-JWT VC payload of the SCA Attestation, with the claims of `extra`.
pub fn card(extra: Value) -> Value {
    let card = json!({
        "iss": "https://bank.example",
        "vct": VCT,
        "cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": "AQ", "y": "Ag"}}
    });
    with(card, extra)
}

/// The credentials of the entries `entries`, numbered from 1, each `(format, data)`.
pub fn credentials(entries: &[(&str, String)]) -> Vec<Credential> {
    let entries: Vec<Value> = entries
        .iter()
        .zip(1..)
        .map(|((format, data), id)| {
            json!({
                "credentialId": id,
                "format": format,
                "data": data,
                "kid": "key-1",
                "instanceId": 0,
                "batchId": id,
                "credentialIssuerIdentifier": "https://bank.example",
                "credentialConfigurationId": "card"
            })
        })
        .collect();
    let state = json!({
        "schemaVersion": 4,
        "credentials": entries,
        "keypairs": [],
        "presentations": [],
        "settings": {},
        "credentialIssuanceSessions": []
    });
    let state = WalletState::parse(&state.to_string()).unwrap();
    state
        .credentials()
        .iter()
        .map(|entry| Credential::parse(entry).unwrap())
        .collect()
}

/// The compact SD-JWT of the issuer payload `payload`, without disclosures.
pub fn sd_jwt(payload: &Value) -> String {
    format!(
        "{}.{}.{}~",
        base64url::encode(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#),
        base64url::encode(payload.to_string().as_bytes()),
        base64url::encode(&[7; 64]),
    )
}

/// The SD-JWT VC of `payload`.
pub fn sd_jwt_vc(payload: &Value) -> Credential {
    credentials(&[("dc+sd-jwt", sd_jwt(payload))]).remove(0)
}

/// An mdoc of one element.
pub fn mdoc() -> Credential {
    let text = |s: &str| Cbor::Text(s.to_owned());
    let map = |entries: Vec<(&str, Cbor)>| {
        Cbor::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
    };
    let tagged = |item: &Cbor| Cbor::Tag(24, Box::new(Cbor::Bytes(item.encode())));
    let tdate = |t: &str| Cbor::Tag(0, Box::new(text(t)));
    let item = tagged(&map(vec![
        ("digestID", Cbor::Unsigned(0)),
        ("random", Cbor::Bytes(vec![0x11; 16])),
        ("elementIdentifier", text("family_name")),
        ("elementValue", text("Doe")),
    ]));
    let digest = Cbor::Bytes(Sha256::digest(item.encode()).to_vec());
    let mso = map(vec![
        ("version", text("1.0")),
        ("digestAlgorithm", text("SHA-256")),
        (
            "valueDigests",
            Cbor::Map(vec![(
                text("org.iso.18013.5.1"),
                Cbor::Map(vec![(Cbor::Unsigned(0), digest)]),
            )]),
        ),
        (
            "deviceKeyInfo",
            map(vec![(
                "deviceKey",
                Cbor::Map(vec![
                    (Cbor::Unsigned(1), Cbor::Unsigned(2)),
                    (Cbor::Negative(0), Cbor::Unsigned(1)),
                    (Cbor::Negative(1), Cbor::Bytes(vec![0x01; 32])),
                    (Cbor::Negative(2), Cbor::Bytes(vec![0x02; 32])),
                ]),
            )]),
        ),
        ("docType", text("org.iso.18013.5.1.mDL")),
        (
            "validityInfo",
            map(vec![
                ("signed", tdate("2026-01-01T00:00:00Z")),
                ("validFrom", tdate("2026-01-01T00:00:00Z")),
                ("validUntil", tdate("2027-01-01T00:00:00Z")),
            ]),
        ),
    ]);
    let issuer_signed = map(vec![
        (
            "nameSpaces",
            Cbor::Map(vec![(text("org.iso.18013.5.1"), Cbor::Array(vec![item]))]),
        ),
        (
            "issuerAuth",
            Cbor::Array(vec![
                Cbor::Bytes(vec![0xa1, 0x01, 0x26]),
                Cbor::Map(vec![(Cbor::Unsigned(33), Cbor::Bytes(vec![0x30, 0x00]))]),
                Cbor::Bytes(tagged(&mso).encode()),
                Cbor::Bytes(vec![0; 64]),
            ]),
        ),
    ]);
    credentials(&[("mso_mdoc", base64url::encode(&issuer_signed.encode()))]).remove(0)
}

/// Claim metadata of `path` below `payload`, labelled in English, at `visualisation` when
/// given.
pub fn claim(path: &[&str], label: &str, visualisation: Option<u64>) -> Value {
    let mut full = vec!["payload"];
    full.extend_from_slice(path);
    let mut claim = json!({"path": full, "display": [{"lang": "en", "label": label}]});
    if let Some(level) = visualisation {
        claim = with(claim, json!({"visualisation": level}));
    }
    claim
}

/// Claim metadata for every leaf of [`payment`].
pub fn payment_claims() -> Value {
    json!([
        claim(&["transaction_id"], "Transaction ID", Some(4)),
        claim(&["payee", "name"], "Payee", Some(1)),
        claim(&["payee", "id"], "Payee ID", None),
        claim(&["currency"], "Currency", Some(2)),
        claim(&["amount"], "Amount", Some(1))
    ])
}

/// A UI elements catalogue with all four elements.
pub fn ui_labels() -> Value {
    json!({
        "affirmative_action_label": [{"lang": "en", "value": "Confirm Payment"}],
        "denial_action_label": [{"lang": "en", "value": "Cancel Payment"}],
        "transaction_title": [{"lang": "en", "value": "Confirm your payment"}],
        "security_hint": [{"lang": "en", "value": "Check the amount"}]
    })
}

/// The type metadata of the SCA Attestation, listing the payment type with `entry`.
pub fn type_metadata(entry: Value) -> Value {
    json!({
        "vct": VCT,
        "name": "Pay Card",
        "category": "urn:eu:europa:ec:eudi:sua:sca",
        "transaction_data_types": {PAYMENT: entry}
    })
}

/// The payment entry of `transaction_data_types` with inline claims and labels.
pub fn inline_payment_type() -> Value {
    json!({"schema": PAYMENT, "claims": payment_claims(), "ui_labels": ui_labels()})
}

/// A `200` response holding the JSON text of `document`.
pub fn response(document: &Value) -> FetchResponse {
    FetchResponse::new(
        200,
        Some("application/json".to_owned()),
        document.to_string().into_bytes(),
    )
}

/// SRI integrity metadata of `bytes`: `sha256-` and the base64 of their SHA-256.
pub fn sri(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::from("sha256-");
    for chunk in Sha256::digest(bytes).chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}
