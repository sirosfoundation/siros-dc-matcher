//! The rows of a presentation: binding (T3, T4), `amr` and display (T6), and the type metadata
//! (T7).

use serde_json::{json, Value};
use siros_oid4vp::{FetchResponse, HttpStatus};
use siros_transaction_data::{Factor, Inherence, Knowledge, Possession};

use super::{claims, display, display_of, listing, metadata, Input, Row};
use crate::common::{
    card, claim, entry, inline_payment_type, mdoc, payment, payment_claims, response, sd_jwt_vc,
    sri, ui_labels, with, LOGIN, PAYMENT,
};

pub(super) fn rows() -> Vec<Row> {
    let honest = entry(PAYMENT, payment());
    let honest_metadata = listing(inline_payment_type());
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
    vec![
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
            "an honest display, its labels in the user's primary language",
            display(honest_metadata.clone()),
            Ok(()),
        ),
        (
            "a parameter name in another language only (TS12 Section 3.3.1)",
            display(claims(json!([
                claim(&["transaction_id"], "Transaction ID", None),
                claim(&["payee", "name"], "Payee", None),
                claim(&["payee", "id"], "Payee ID", None),
                claim(&["currency"], "Currency", None),
                {"path": ["payload", "amount"], "display": [{"lang": "fr", "label": "Montant"}]}
            ]))),
            Err("transaction_display_label_missing"),
        ),
        (
            "an affirmative_action_label in another language only (TS12 Section 3.3.1)",
            display(listing(with(
                inline_payment_type(),
                json!({"ui_labels": {"affirmative_action_label":
                    [{"lang": "fr", "value": "Confirmer le paiement"}]}}),
            ))),
            Err("transaction_display_affirmative_label_missing"),
        ),
        (
            "a denial_action_label in another language only: the wallet labels the control",
            display(listing(with(
                inline_payment_type(),
                json!({"ui_labels": with(ui_labels(), json!({"denial_action_label":
                    [{"lang": "fr", "value": "Annuler"}]}))}),
            ))),
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
            Input::Fetch(Box::new(sd_jwt_vc(&card(json!({}))))),
            Ok(()),
        ),
        (
            "a vct that is no https URL (SD-JWT VC Section 6.3.1)",
            Input::Fetch(Box::new(sd_jwt_vc(&card(
                json!({"vct": "urn:example:card"}),
            )))),
            Err("type_metadata_vct_not_https"),
        ),
        (
            "an mdoc",
            Input::Fetch(Box::new(mdoc())),
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
                FetchResponse::new(
                    HttpStatus::new(404),
                    None,
                    honest_metadata.to_string().into_bytes(),
                ),
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
                FetchResponse::new(HttpStatus::OK, None, b"<html>".to_vec()),
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
            "type metadata without vct",
            metadata(with(honest_metadata.clone(), json!({"vct": null}))),
            Err("metadata_malformed"),
        ),
        (
            "transaction_data_types that is not an object (TS12 Section 4.1)",
            metadata(with(
                honest_metadata.clone(),
                json!({"transaction_data_types": [PAYMENT]}),
            )),
            Err("metadata_malformed"),
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
    ]
}
