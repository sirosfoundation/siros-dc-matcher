//! One fixture per condition of OpenID4VP 1.0, Section 8.5, and per construction rule of the
//! entry (T1), the TS12 types (T6) and the type metadata (T7). The honest inputs each row
//! edits are accepted, so each row breaks only its rule.

use serde_json::{json, Value};
use siros_codec::base64url;
use siros_credential::Credential;
use siros_display::Locale;
use siros_oid4vp::FetchResponse;
use siros_transaction_data::{
    bind, Amr, Entry, Factor, Fetched, Inherence, Knowledge, Possession, Presented, Step,
    TypeMetadata, MAX_DEPTH,
};

use crate::common::{
    card, claim, encode, entry, inline_payment_type, mdoc, payment, payment_claims, query,
    response, sd_jwt_vc, sri, type_metadata, ui_labels, with, LOGIN, PAYMENT,
};
use crate::fixtures::payloads;

enum Input {
    /// A `transaction_data` string, against the query of the tests.
    Entry(String),
    /// The type metadata fetch of a credential.
    Fetch(Credential),
    /// A response to the type metadata fetch of the SD-JWT VC with this payload.
    Metadata(Value, FetchResponse),
    /// Entries bound to the SD-JWT VC with this payload, presented for `pay`, with the type
    /// metadata document in `metadata`.
    Bind {
        entries: Vec<Value>,
        card: Value,
        metadata: Value,
    },
    /// The views of the payment `entry` bound as in `Bind`, with the referenced documents.
    View {
        entry: Value,
        card: Value,
        metadata: Value,
        documents: Vec<(&'static str, FetchResponse)>,
    },
    /// The authentication factors of a signing key.
    Amr(Vec<Factor>),
}

fn outcome(input: Input) -> Result<(), &'static str> {
    match input {
        Input::Entry(raw) => Entry::parse(&raw, &query()).map(drop).map_err(|e| e.code()),
        Input::Fetch(credential) => TypeMetadata::fetch(&credential)
            .map(drop)
            .map_err(|e| e.code()),
        Input::Metadata(card, response) => {
            let credential = sd_jwt_vc(&card);
            TypeMetadata::parse(&credential, &response)
                .map(drop)
                .map_err(|e| e.code())
        }
        Input::Bind {
            entries,
            card,
            metadata,
        } => views(&entries, &card, &metadata, None),
        Input::View {
            entry,
            card,
            metadata,
            documents,
        } => views(&[entry], &card, &metadata, Some(&documents)),
        Input::Amr(factors) => Amr::new(factors).map(drop).map_err(|e| e.code()),
    }
}

/// Binds `entries` to the SD-JWT VC of `card` presented for `pay`, then, with `documents`,
/// takes the views, answering each fetch from `documents`.
fn views(
    entries: &[Value],
    card: &Value,
    metadata: &Value,
    documents: Option<&[(&str, FetchResponse)]>,
) -> Result<(), &'static str> {
    let entries: Vec<Entry> = entries
        .iter()
        .map(|e| Entry::parse(&encode(e), &query()).unwrap())
        .collect();
    let credential = sd_jwt_vc(card);
    let metadata = TypeMetadata::parse(&credential, &response(metadata)).map_err(|e| e.code())?;
    let offer = [Presented::new("pay", &metadata)];
    let bound = bind(&entries, &offer).map_err(|e| e.code())?;
    let Some(documents) = documents else {
        return Ok(());
    };
    let preferences = [Locale::parse("en-GB").unwrap()];
    let mut fetched = Fetched::new();
    for member in &bound {
        loop {
            match member.views(&fetched, &preferences).map_err(|e| e.code())? {
                Step::Done(_) => break,
                Step::Fetch(fetch) => {
                    let (_, document) = documents
                        .iter()
                        .find(|(url, _)| *url == fetch.url().as_str())
                        .unwrap_or_else(|| panic!("no document at {}", fetch.url().as_str()));
                    assert!(fetched.insert(&fetch, document.clone()).is_none());
                }
            }
        }
    }
    Ok(())
}

/// The display of the honest payment with `metadata` as its type metadata.
fn display(metadata: Value) -> Input {
    display_of(entry(PAYMENT, payment()), metadata)
}

fn display_of(entry: Value, metadata: Value) -> Input {
    Input::View {
        entry,
        card: card(json!({})),
        metadata,
        documents: Vec::new(),
    }
}

/// The type metadata with the payment entry `payment_type`.
fn listing(payment_type: Value) -> Value {
    type_metadata(payment_type)
}

/// The honest payment type with its claims replaced by `claims`.
fn claims(claims: Value) -> Value {
    listing(with(inline_payment_type(), json!({"claims": claims})))
}

/// The base64url of the text `text`.
fn text(text: &str) -> Input {
    Input::Entry(base64url::encode(text.as_bytes()))
}

/// An honest payment entry with `changes`.
fn changed(changes: Value) -> Input {
    Input::Entry(encode(&with(entry(PAYMENT, payment()), changes)))
}

/// The response to the type metadata fetch of the honest card with the document `document`.
fn metadata(document: Value) -> Input {
    Input::Metadata(card(json!({})), response(&document))
}

#[test]
fn each_rule_is_refused_alone() {
    let honest = entry(PAYMENT, payment());
    let honest_metadata = listing(inline_payment_type());
    let honest_text = honest.to_string();
    let deep = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
    let referenced = listing(json!({
        "claims_uri": "https://bank.example/claims.json",
        "ui_labels_uri": "https://bank.example/labels.json"
    }));
    let claims_document = response(&payment_claims());
    let labels_document = response(&ui_labels());
    let mut pins = serde_json::Map::new();
    for (member, document) in [
        ("claims_uri", &claims_document),
        ("ui_labels_uri", &labels_document),
    ] {
        let name = format!("transaction_data_types['{PAYMENT}'].{member}#integrity");
        pins.insert(name, sri(document.body()).into());
    }
    let pinned = card(Value::Object(pins));
    let documents = vec![
        ("https://bank.example/claims.json", claims_document.clone()),
        ("https://bank.example/labels.json", labels_document.clone()),
    ];
    let two_factors = vec![
        Factor::Knowledge(Knowledge::Pin6OrMoreDigits),
        Factor::Inherence(Inherence::FingerprintDevice),
    ];

    let mut table: Vec<(&str, Input, Result<(), &str>)> = vec![
        // T1 (OpenID4VP 1.0, Section 5.1).
        ("an honest payment", Input::Entry(encode(&honest)), Ok(())),
        (
            "base64url with padding (Section 1.2)",
            Input::Entry(format!("{}=", encode(&honest))),
            Err("transaction_data_not_base64url"),
        ),
        (
            "a character outside base64url",
            Input::Entry(format!("{}+", encode(&honest))),
            Err("transaction_data_not_base64url"),
        ),
        (
            "bytes that are not UTF-8",
            Input::Entry(base64url::encode(&[0x7b, 0xff, 0x7d])),
            Err("transaction_data_not_json_object"),
        ),
        (
            "text that is not JSON",
            text("{type}"),
            Err("transaction_data_not_json_object"),
        ),
        (
            "a JSON array",
            text("[1]"),
            Err("transaction_data_not_json_object"),
        ),
        (
            "an object followed by more text",
            text(&format!("{honest_text} {{}}")),
            Err("transaction_data_not_json_object"),
        ),
        (
            "a repeated member name",
            text(&honest_text.replacen('{', r#"{"type":"x","#, 1)),
            Err("transaction_data_duplicate_key"),
        ),
        (
            "a repeated member name in the payload",
            text(&honest_text.replace(r#""amount":49.99"#, r#""amount":49.99,"amount":4999"#)),
            Err("transaction_data_duplicate_key"),
        ),
        (
            "nesting deeper than MAX_DEPTH",
            text(&honest_text.replacen('{', &format!(r#"{{"deep":{deep},"#), 1)),
            Err("transaction_data_too_deep"),
        ),
        (
            "no type",
            changed(json!({"type": null})),
            Err("transaction_data_member_missing"),
        ),
        (
            "a type that is not a string",
            changed(json!({"type": 1})),
            Err("transaction_data_member_wrong_type"),
        ),
        (
            "an unsupported type (Section 8.5)",
            changed(json!({"type": "urn:eudi:sca:payment:2"})),
            Err("transaction_data_type_unsupported"),
        ),
        (
            "no credential_ids",
            changed(json!({"credential_ids": null})),
            Err("transaction_data_member_missing"),
        ),
        (
            "credential_ids that is not an array",
            changed(json!({"credential_ids": "pay"})),
            Err("transaction_data_member_wrong_type"),
        ),
        (
            "an empty credential_ids",
            changed(json!({"credential_ids": []})),
            Err("transaction_data_member_invalid"),
        ),
        (
            "a credential_ids element that is not a string",
            changed(json!({"credential_ids": ["pay", 1]})),
            Err("transaction_data_member_wrong_type"),
        ),
        (
            "credential_ids naming no Credential Query (Section 8.5)",
            changed(json!({"credential_ids": ["pay", "nope"]})),
            Err("transaction_data_credential_id_unknown"),
        ),
        (
            "an entry member the type does not define (Section 8.5)",
            changed(json!({"note": "x"})),
            Err("transaction_data_member_unknown"),
        ),
        // T6 (EC TS12 v1.0.1) and T5 (B.3.3).
        (
            "a Credential Query for an mdoc (TS12 Section 1.2)",
            changed(json!({"credential_ids": ["pay", "mdl"]})),
            Err("transaction_data_query_format"),
        ),
        (
            "a Credential Query without holder binding (B.3.3)",
            changed(json!({"credential_ids": ["unbound"]})),
            Err("transaction_data_holder_binding_not_required"),
        ),
        (
            "no transaction_data_hashes_alg (TS12 Section 4.2)",
            changed(json!({"transaction_data_hashes_alg": null})),
            Err("transaction_data_member_missing"),
        ),
        (
            "transaction_data_hashes_alg as a string (B.3.3.1)",
            changed(json!({"transaction_data_hashes_alg": "sha-256"})),
            Err("transaction_data_member_wrong_type"),
        ),
        (
            "an empty transaction_data_hashes_alg",
            changed(json!({"transaction_data_hashes_alg": []})),
            Err("transaction_data_member_invalid"),
        ),
        (
            "a transaction_data_hashes_alg element that is not a string",
            changed(json!({"transaction_data_hashes_alg": ["sha-256", 256]})),
            Err("transaction_data_member_wrong_type"),
        ),
        (
            "no algorithm the wallet computes",
            changed(json!({"transaction_data_hashes_alg": ["md5", "sha3-256"]})),
            Err("transaction_data_hash_alg_unsupported"),
        ),
        (
            "an unknown algorithm before a supported one",
            changed(json!({"transaction_data_hashes_alg": ["md5", "sha-512"]})),
            Ok(()),
        ),
        (
            "no payload (TS12 Section 4.2)",
            changed(json!({"payload": null})),
            Err("transaction_data_member_missing"),
        ),
        (
            "a payload that is not an object",
            changed(json!({"payload": "x"})),
            Err("transaction_data_member_wrong_type"),
        ),
        // T3 and T4.
        (
            "an honest binding",
            Input::Bind {
                entries: vec![honest.clone()],
                card: card(json!({})),
                metadata: honest_metadata.clone(),
            },
            Ok(()),
        ),
        (
            "entries of one credential with a common algorithm (B.3.3.1)",
            Input::Bind {
                entries: vec![
                    with(
                        honest.clone(),
                        json!({"transaction_data_hashes_alg": ["sha-512", "sha-256"]}),
                    ),
                    honest.clone(),
                ],
                card: card(json!({})),
                metadata: honest_metadata.clone(),
            },
            Ok(()),
        ),
        (
            "entries of one credential without a common algorithm (B.3.3.1)",
            Input::Bind {
                entries: vec![
                    with(
                        honest.clone(),
                        json!({"transaction_data_hashes_alg": ["sha-512"]}),
                    ),
                    honest.clone(),
                ],
                card: card(json!({})),
                metadata: honest_metadata.clone(),
            },
            Err("transaction_data_hash_alg_conflict"),
        ),
        (
            "an entry naming a query the offer does not answer (Section 8.5)",
            Input::Bind {
                entries: vec![with(honest.clone(), json!({"credential_ids": ["card"]}))],
                card: card(json!({})),
                metadata: honest_metadata.clone(),
            },
            Err("transaction_data_credential_unavailable"),
        ),
        (
            "a credential that is no SCA Attestation (TS12 Section 3)",
            Input::Bind {
                entries: vec![honest.clone()],
                card: card(json!({})),
                metadata: with(honest_metadata.clone(), json!({"category": null})),
            },
            Err("transaction_data_credential_unavailable"),
        ),
        (
            "type metadata that does not list the type (TS12 Section 3.2)",
            Input::Bind {
                entries: vec![honest.clone()],
                card: card(json!({})),
                metadata: with(
                    honest_metadata.clone(),
                    json!({"transaction_data_types": {LOGIN: inline_payment_type()}}),
                ),
            },
            Err("transaction_data_credential_unavailable"),
        ),
        // The `amr` of TS12 Section 3.6.
        ("two categories of factor", Input::Amr(two_factors), Ok(())),
        (
            "two factors of one category",
            Input::Amr(vec![
                Factor::Possession(Possession::KeyInLocalNativeWscd),
                Factor::Possession(Possession::KeyInRemoteWscd),
            ]),
            Err("transaction_data_amr_categories"),
        ),
        (
            "no factor",
            Input::Amr(vec![]),
            Err("transaction_data_amr_categories"),
        ),
        // The display of TS12 Section 3.3.
        (
            "an honest display",
            display(honest_metadata.clone()),
            Ok(()),
        ),
        (
            "referenced claims and labels, pinned (TS12 Section 4.1.2)",
            Input::View {
                entry: honest.clone(),
                card: pinned.clone(),
                metadata: referenced.clone(),
                documents: documents.clone(),
            },
            Ok(()),
        ),
        (
            "a referenced document that does not match its pin (TS12 Section 4.1.2)",
            Input::View {
                entry: honest.clone(),
                card: pinned,
                metadata: referenced.clone(),
                documents: vec![
                    ("https://bank.example/claims.json", response(&json!([]))),
                    ("https://bank.example/labels.json", labels_document),
                ],
            },
            Err("metadata_integrity_mismatch"),
        ),
        (
            "a leaf without a localised name (TS12 Section 3.3.1)",
            display(claims(json!([
                claim(&["transaction_id"], "Transaction ID", None),
                claim(&["payee", "name"], "Payee", None),
                claim(&["payee", "id"], "Payee ID", None),
                claim(&["amount"], "Amount", None)
            ]))),
            Err("transaction_display_label_missing"),
        ),
        (
            "a leaf of level 4 without a label, left out",
            display_of(
                entry(
                    PAYMENT,
                    with(payment(), json!({"date_time": "2026-10-26T10:00:00Z"})),
                ),
                claims(json!([
                    claim(&["transaction_id"], "Transaction ID", None),
                    {"path": ["payload", "date_time"], "visualisation": 4},
                    claim(&["payee", "name"], "Payee", None),
                    claim(&["payee", "id"], "Payee ID", None),
                    claim(&["currency"], "Currency", None),
                    claim(&["amount"], "Amount", None)
                ])),
            ),
            Ok(()),
        ),
        (
            "a transaction_id of level 4 without a label: every TS12 type shows it",
            display(claims(json!([
                {"path": ["payload", "transaction_id"], "visualisation": 4},
                claim(&["payee", "name"], "Payee", None),
                claim(&["payee", "id"], "Payee ID", None),
                claim(&["currency"], "Currency", None),
                claim(&["amount"], "Amount", None)
            ]))),
            Err("transaction_display_label_missing"),
        ),
        (
            "no affirmative_action_label (TS12 Section 3.3.3)",
            display(listing(with(
                inline_payment_type(),
                json!({"ui_labels": with(ui_labels(), json!({"affirmative_action_label": null}))}),
            ))),
            Err("transaction_display_affirmative_label_missing"),
        ),
        (
            "an affirmative_action_label over 30 characters (TS12 Section 3.3.3)",
            display(listing(with(
                inline_payment_type(),
                json!({"ui_labels": {"affirmative_action_label":
                    [{"lang": "en", "value": "Confirm this payment to Shop AB now"}]}}),
            ))),
            Err("metadata_malformed"),
        ),
        (
            "a payload value with a line feed",
            display_of(
                entry(
                    PAYMENT,
                    with(
                        payment(),
                        json!({"payee": {"name": "Shop\nPay", "id": "1"}}),
                    ),
                ),
                honest_metadata.clone(),
            ),
            Err("transaction_display_value_refused"),
        ),
        (
            "a label with a right-to-left override",
            display(claims(json!([
                claim(&["transaction_id"], "Transaction ID", None),
                claim(&["payee", "name"], "Payee", None),
                claim(&["payee", "id"], "Payee ID", None),
                claim(&["currency"], "Currency", None),
                claim(&["amount"], "Am\u{202e}ount", None)
            ]))),
            Err("transaction_display_label_refused"),
        ),
        // T7: the type metadata (SD-JWT VC, Sections 6 and 7; TS12 Section 4.1).
        (
            "the fetch of an SD-JWT VC's type metadata",
            Input::Fetch(sd_jwt_vc(&card(json!({})))),
            Ok(()),
        ),
        (
            "a vct that is no https URL (SD-JWT VC Section 6.3.1)",
            Input::Fetch(sd_jwt_vc(&card(json!({"vct": "urn:example:card"})))),
            Err("type_metadata_vct_not_https"),
        ),
        (
            "an mdoc",
            Input::Fetch(mdoc()),
            Err("type_metadata_not_sd_jwt_vc"),
        ),
        (
            "honest type metadata",
            metadata(honest_metadata.clone()),
            Ok(()),
        ),
        (
            "a status other than 200",
            Input::Metadata(
                card(json!({})),
                FetchResponse::new(404, None, honest_metadata.to_string().into_bytes()),
            ),
            Err("metadata_fetch_status"),
        ),
        (
            "a body over the cap",
            Input::Metadata(
                card(json!({})),
                response(&with(
                    honest_metadata.clone(),
                    json!({"pad": "x".repeat(256 * 1024)}),
                )),
            ),
            Err("metadata_fetch_too_large"),
        ),
        (
            "a body that is not JSON",
            Input::Metadata(
                card(json!({})),
                FetchResponse::new(200, None, b"<html>".to_vec()),
            ),
            Err("metadata_malformed"),
        ),
        (
            "another vct (SD-JWT VC Section 6.3)",
            metadata(with(
                honest_metadata.clone(),
                json!({"vct": "https://pay.example/other"}),
            )),
            Err("type_metadata_vct_mismatch"),
        ),
        (
            "a document vct#integrity pins (SD-JWT VC Section 7)",
            Input::Metadata(
                card(json!({"vct#integrity": sri(honest_metadata.to_string().as_bytes())})),
                response(&honest_metadata),
            ),
            Ok(()),
        ),
        (
            "a document that does not match vct#integrity",
            Input::Metadata(
                card(json!({"vct#integrity": sri(b"{}")})),
                response(&honest_metadata),
            ),
            Err("metadata_integrity_mismatch"),
        ),
        (
            "a vct#integrity without a supported algorithm (SRI Section 3)",
            Input::Metadata(
                card(json!({"vct#integrity": "md5-1B2M2Y8AsgTpgAmY7PhCfg=="})),
                response(&honest_metadata),
            ),
            Err("metadata_integrity_malformed"),
        ),
        (
            "a category that is not a string",
            metadata(with(honest_metadata.clone(), json!({"category": 1}))),
            Err("metadata_malformed"),
        ),
        (
            "claims and claims_uri both (TS12 Section 4.1)",
            metadata(listing(with(
                inline_payment_type(),
                json!({"claims_uri": "https://bank.example/claims.json"}),
            ))),
            Err("metadata_malformed"),
        ),
        (
            "neither ui_labels nor ui_labels_uri",
            metadata(listing(with(
                inline_payment_type(),
                json!({"ui_labels": null}),
            ))),
            Err("metadata_malformed"),
        ),
        (
            "a claims_uri that is no https URL",
            metadata(listing(with(
                inline_payment_type(),
                json!({"claims": null, "claims_uri": "http://bank.example/claims.json"}),
            ))),
            Err("metadata_document_not_https"),
        ),
        (
            "a visualisation outside 1 to 4 (TS12 Section 3.3.2)",
            metadata(claims(json!([claim(&["amount"], "Amount", Some(5))]))),
            Err("metadata_malformed"),
        ),
        (
            "a claim label without a language tag (SD-JWT VC Section 9.2)",
            metadata(claims(
                json!([{"path": ["payload", "amount"], "display": [{"label": "Amount"}]}]),
            )),
            Err("metadata_malformed"),
        ),
        (
            "two claims of one path",
            metadata(claims(json!([
                claim(&["amount"], "Amount", None),
                claim(&["amount"], "Sum", None)
            ]))),
            Err("metadata_malformed"),
        ),
    ];
    // The payload rules of the four TS12 schemas.
    for fixture in payloads() {
        table.push((
            fixture.case,
            Input::Entry(encode(&entry(fixture.transaction_type, fixture.payload))),
            fixture.expected,
        ));
    }

    for (case, input, expected) in table {
        assert_eq!(outcome(input), expected, "{case}");
    }
}
