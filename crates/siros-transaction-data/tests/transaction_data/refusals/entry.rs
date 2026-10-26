//! The rows of the entry: T1, and the entry members of the TS12 types (T6, B.3.3).

use serde_json::json;
use siros_codec::base64url;
use siros_transaction_data::MAX_DEPTH;

use super::{changed, text, Input, Row};
use crate::common::{encode, entry, payment, PAYMENT};

pub(super) fn rows() -> Vec<Row> {
    let honest = entry(PAYMENT, payment());
    let honest_text = honest.to_string();
    let deep = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
    let unpadded = encode(&honest);
    let padded = format!("{unpadded}{}", "=".repeat((4 - unpadded.len() % 4) % 4));
    assert_ne!(padded, unpadded);
    vec![
        // T1 (OpenID4VP 1.0, Section 5.1).
        ("an honest payment", Input::Entry(unpadded.clone()), Ok(())),
        (
            "base64url with padding (Section 1.2)",
            Input::Entry(padded),
            Err("transaction_data_not_base64url"),
        ),
        (
            "a character outside base64url",
            Input::Entry(format!("{unpadded}+")),
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
    ]
}
