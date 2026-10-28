//! SD-JWT VC fixtures: a TS12 payment entry of `transaction_data`, and the Type Metadata that
//! lists its type.

use serde_json::json;

use crate::verifier::b64;
use crate::wallet::VCT;

const PAYMENT: &str = "urn:eudi:sca:payment:1";

/// The payment entry of `transaction_data` naming the query `pid`, as the verifier sends it.
pub fn payment() -> String {
    payment_for("pid")
}

/// The payment entry of `transaction_data` naming the query `query`.
pub fn payment_for(query: &str) -> String {
    payment_naming(&[query])
}

/// The payment entry of `transaction_data` naming the queries `queries`.
pub fn payment_naming(queries: &[&str]) -> String {
    let entry = json!({
        "type": PAYMENT,
        "credential_ids": queries,
        "transaction_data_hashes_alg": ["sha-256"],
        "payload": {
            "transaction_id": "tx-0001",
            "payee": {"name": "Shop AB", "id": "SE1234567890"},
            "currency": "EUR",
            "amount": 49.99
        }
    });
    b64(entry.to_string().as_bytes())
}

/// The SCA Attestation type metadata of [`VCT`], listing the payment type with its labels.
pub fn type_metadata() -> Vec<u8> {
    type_metadata_of(VCT)
}

/// The SCA Attestation type metadata of `vct`, listing the payment type with its labels.
pub fn type_metadata_of(vct: &str) -> Vec<u8> {
    let claim = |path: &[&str], label: &str| {
        let mut full = vec!["payload"];
        full.extend_from_slice(path);
        json!({"path": full, "display": [{"lang": "en", "label": label}]})
    };
    let document = json!({
        "vct": vct,
        "name": "Pay Card",
        "category": "urn:eu:europa:ec:eudi:sua:sca",
        "transaction_data_types": {PAYMENT: {
            "schema_uri": PAYMENT,
            "claims": [
                claim(&["transaction_id"], "Transaction ID"),
                claim(&["payee", "name"], "Payee"),
                claim(&["payee", "id"], "Payee ID"),
                claim(&["currency"], "Currency"),
                claim(&["amount"], "Amount")
            ],
            "ui_labels": {
                "affirmative_action_label": [{"lang": "en", "value": "Confirm Payment"}]
            }
        }}
    });
    document.to_string().into_bytes()
}
