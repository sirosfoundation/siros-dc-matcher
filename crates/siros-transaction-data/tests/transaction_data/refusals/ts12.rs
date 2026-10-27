//! TS12 v1.0.1 type metadata as a source (Sections 3, 3.3 and 4.1; SD-JWT VC, Sections 6 and
//! 7), and the TS12 rendering rules of Section 3.3.1: a row per rule.

use serde_json::{json, Value};
use siros_oid4vp::HttpStatus;
use siros_transaction_data::{
    FetchFault, Incompatibility, IntegrityFault, Location, LocationStep, Prominence, RenderFault,
    Selection, Ts12Fault, Ts12Member, Ts12Type,
};

use crate::common::{credential_with, entries, ok, query, sri, Documents, Host, PAYMENT};

const VCT: &str = "https://pay.example/card";
const CLAIMS_URI: &str = "https://pay.example/claims.json";

fn claim(path: &[&str], label: &str) -> Value {
    let mut full = vec!["payload"];
    full.extend_from_slice(path);
    json!({"path": full, "display": [{"lang": "en", "label": label}]})
}

fn claims() -> Value {
    json!([
        claim(&["transaction_id"], "Transaction ID"),
        claim(&["payee", "name"], "Payee"),
        claim(&["payee", "id"], "Payee ID"),
        claim(&["currency"], "Currency"),
        claim(&["amount"], "Amount")
    ])
}

/// The payment entry of the type metadata, with `changes`; a `null` change removes a member.
fn payment_type(changes: Value) -> Value {
    let mut entry = json!({
        "schema_uri": PAYMENT,
        "claims": claims(),
        "ui_labels": {"affirmative_action_label": [{"lang": "en", "value": "Confirm"}]}
    });
    for (name, change) in changes.as_object().unwrap() {
        if change.is_null() {
            entry.as_object_mut().unwrap().remove(name);
        } else {
            entry[name] = change.clone();
        }
    }
    entry
}

fn document(payment: Value) -> Value {
    json!({"vct": VCT, "category": "urn:eu:europa:ec:eudi:sua:sca",
           "transaction_data_types": {PAYMENT: payment}})
}

/// What the card of the claims `extra` takes of a payment of `payload`, the host serving
/// `documents`.
fn outcome(payload: &Value, extra: &Value, documents: Documents) -> Selection {
    let mut host = Host::new(json!([]));
    host.documents = documents;
    let entry = json!({"type": PAYMENT, "credential_ids": ["pay"],
                       "transaction_data_hashes_alg": ["sha-256"], "payload": payload});
    let entries = entries(&[entry.to_string()], &query(&["pay"], VCT));
    host.select(&[&entries[0]], &credential_with(VCT, &[], extra))
        .unwrap()
}

fn payment() -> Value {
    json!({"transaction_id": "tx-1", "payee": {"name": "Shop", "id": "SE1"}, "currency": "EUR",
           "amount": 9.25})
}

fn served(document: &Value) -> Documents {
    vec![(VCT.to_owned(), ok(document.to_string().as_bytes()))]
}

fn fault(fault: Ts12Fault) -> Option<Incompatibility> {
    Some(Incompatibility::TypeMetadata(fault))
}

fn cause(selection: Selection) -> Option<Incompatibility> {
    match selection {
        Selection::Takes(_) => None,
        Selection::Excluded(mut causes) => Some(causes.remove(0).1),
    }
}

#[test]
fn each_type_metadata_rule_is_refused_alone() {
    let honest = document(payment_type(json!({})));
    let claims_document = claims().to_string();
    let pin = format!("transaction_data_types['{PAYMENT}'].claims_uri#integrity");
    let referenced = document(payment_type(
        json!({"claims": null, "claims_uri": CLAIMS_URI}),
    ));
    let with_claims = |text: &str| {
        let mut documents = served(&referenced);
        documents.push((CLAIMS_URI.to_owned(), ok(text.as_bytes())));
        documents
    };
    let none = json!({});
    let rows: Vec<(&str, Value, Documents, Option<Incompatibility>)> = vec![
        ("honest type metadata", none.clone(), served(&honest), None),
        (
            "no schema",
            none.clone(),
            served(&document(payment_type(json!({"schema_uri": null})))),
            fault(Ts12Fault::OneOf(Ts12Member::Schema)),
        ),
        (
            "an embedded JSON Schema",
            none.clone(),
            served(&document(payment_type(
                json!({"schema_uri": null, "schema": {"type": "object"}}),
            ))),
            fault(Ts12Fault::SchemaEmbedded),
        ),
        (
            "a schema of no built-in type",
            none.clone(),
            served(&document(payment_type(
                json!({"schema_uri": "urn:example:schema"}),
            ))),
            fault(Ts12Fault::SchemaUnknown("urn:example:schema".to_owned())),
        ),
        (
            "the schema of another type",
            none.clone(),
            served(&document(payment_type(
                json!({"schema_uri": "urn:eudi:sca:login_risk_transaction:1"}),
            ))),
            fault(Ts12Fault::SchemaMismatch(Ts12Type::Payment)),
        ),
        (
            "claims and claims_uri both",
            none.clone(),
            served(&document(payment_type(json!({"claims_uri": CLAIMS_URI})))),
            fault(Ts12Fault::OneOf(Ts12Member::Claims)),
        ),
        (
            "a claims_uri that is no https URL",
            none.clone(),
            served(&document(payment_type(
                json!({"claims": null, "claims_uri": "http://pay.example/c"}),
            ))),
            fault(Ts12Fault::DocumentNotHttps(
                "http://pay.example/c".to_owned(),
            )),
        ),
        (
            "claims referenced and pinned",
            json!({pin.clone(): sri(claims_document.as_bytes())}),
            with_claims(&claims_document),
            None,
        ),
        (
            "claims that do not match their pin (Section 4.1.2)",
            json!({pin.clone(): sri(b"[]")}),
            with_claims(&claims_document),
            fault(Ts12Fault::Integrity(IntegrityFault::Mismatch)),
        ),
        (
            "a document of another vct (SD-JWT VC, Section 6.3)",
            none.clone(),
            served(
                &json!({"vct": "https://pay.example/other", "category": "urn:eu:europa:ec:eudi:sua:sca",
                           "transaction_data_types": {PAYMENT: payment_type(json!({}))}}),
            ),
            fault(Ts12Fault::VctMismatch),
        ),
        (
            "a document that does not match vct#integrity (SD-JWT VC, Section 7)",
            json!({"vct#integrity": sri(b"{}")}),
            served(&honest),
            fault(Ts12Fault::Integrity(IntegrityFault::Mismatch)),
        ),
        (
            "a document vct#integrity pins, absent",
            json!({"vct#integrity": sri(b"{}")}),
            vec![],
            fault(Ts12Fault::Fetch(FetchFault::Status(HttpStatus::new(404)))),
        ),
        (
            "no document: no source",
            none.clone(),
            vec![],
            Some(Incompatibility::TypeUnsupported),
        ),
        (
            "no SCA category (Section 3.2): no source",
            none.clone(),
            served(
                &json!({"vct": VCT, "transaction_data_types": {PAYMENT: payment_type(json!({}))}}),
            ),
            Some(Incompatibility::TypeUnsupported),
        ),
        (
            "a path outside payload (Section 2.3)",
            none.clone(),
            served(&document(payment_type(
                json!({"claims": [{"path": ["amount"]}]}),
            ))),
            fault(Ts12Fault::PathOutsidePayload),
        ),
        (
            "a visualisation of 5 (Section 3.3.2)",
            none.clone(),
            served(&document(payment_type(
                json!({"claims": [{"path": ["payload", "amount"], "visualisation": 5}]}),
            ))),
            fault(Ts12Fault::Visualisation),
        ),
        (
            "both lang and locale",
            none.clone(),
            served(&document(payment_type(
                json!({"claims": [{"path": ["payload", "amount"],
                "display": [{"lang": "en", "locale": "en", "label": "Amount"}]}]}),
            ))),
            fault(Ts12Fault::OneOf(Ts12Member::Lang)),
        ),
        (
            "an affirmative_action_label over 30 characters (Section 3.3.3)",
            none.clone(),
            served(&document(payment_type(
                json!({"ui_labels": {"affirmative_action_label":
                [{"lang": "en", "value": "Confirm this payment to the shop"}]}}),
            ))),
            fault(Ts12Fault::LabelLength("affirmative_action_label", 32)),
        ),
        (
            "no affirmative_action_label (Section 3.3.3)",
            none.clone(),
            served(&document(payment_type(json!({"ui_labels": {}})))),
            fault(Ts12Fault::AffirmativeAbsent),
        ),
    ];
    for (case, extra, documents, expected) in rows {
        assert_eq!(
            cause(outcome(&payment(), &extra, documents)),
            expected,
            "{case}"
        );
    }
}

/// Section 3.3.1: each leaf takes its level, 3 when unset, raised to the floor of its type; a
/// leaf of level 4 without a name is left out, any other needs one.
#[test]
fn every_leaf_shows_unless_level_4() {
    let at = |key: &str| Location::new(vec![LocationStep::Key(key.to_owned())]);
    let with_claims = |claims: Value| served(&document(payment_type(json!({"claims": claims}))));
    let mut payload = payment();
    payload["date_time"] = json!("2026-10-26T10:00:00Z");
    let mut leveled = claims();
    leveled
        .as_array_mut()
        .unwrap()
        .push(json!({"path": ["payload", "date_time"], "visualisation": 4}));
    leveled[0]["visualisation"] = json!(4);
    let selection = outcome(&payload, &json!({}), with_claims(leveled));
    let Selection::Takes(taken) = selection else {
        panic!("a level-4 leaf without a name is left out")
    };
    let prominence: Vec<(String, Option<Prominence>)> = taken
        .view()
        .rows()
        .iter()
        .map(|row| (row.label().text().to_owned(), row.prominence()))
        .collect();
    assert_eq!(
        prominence,
        [
            // Level 4 set, raised to the transaction_id's floor.
            ("Transaction ID".to_owned(), Some(Prominence::Main)),
            ("Payee".to_owned(), Some(Prominence::Prominent)),
            ("Payee ID".to_owned(), Some(Prominence::Main)),
            ("Currency".to_owned(), Some(Prominence::Prominent)),
            ("Amount".to_owned(), Some(Prominence::Prominent)),
        ]
    );
    let mut unnamed = claims();
    unnamed[0] = json!({"path": ["payload", "transaction_id"], "visualisation": 4});
    assert_eq!(
        cause(outcome(&payment(), &json!({}), with_claims(unnamed))),
        Some(Incompatibility::Render(RenderFault::LabelMissing(at(
            "transaction_id"
        ))))
    );
}
