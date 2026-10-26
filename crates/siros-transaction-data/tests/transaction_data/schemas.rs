//! The payload parsers against the TS12 schemas of `tests/ts12-schemas` (see
//! `tests/ts12-schemas/SOURCE`): on every payload fixture, an entry of the payload parses
//! exactly when the schema of its type accepts the payload.

use jsonschema::{Resource, Validator};
use serde_json::Value;
use siros_transaction_data::Entry;

use crate::common::{encode, entry, query, ACCESS, LOGIN, MANDATE, PAYMENT};
use crate::fixtures::payloads;

const PAYMENT_SCHEMA: &str =
    include_str!("../ts12-schemas/ts12-urn-eudi-sca-payment-1-data-model.json");

/// The validator of the schema `text`. The e-mandate schema's `$ref` names the payment schema
/// by its file name, relative to the default base URI.
fn validator(text: &str) -> Validator {
    let schema: Value = serde_json::from_str(text).unwrap();
    let payment: Value = serde_json::from_str(PAYMENT_SCHEMA).unwrap();
    jsonschema::options()
        .should_validate_formats(false)
        .with_resource(
            "json-schema:///ts12-urn-eudi-sca-payment-1-data-model.json",
            Resource::from_contents(payment),
        )
        .build(&schema)
        .unwrap()
}

#[test]
fn the_parsers_accept_what_the_schemas_accept() {
    let schemas = [
        (PAYMENT, validator(PAYMENT_SCHEMA)),
        (
            LOGIN,
            validator(include_str!(
                "../ts12-schemas/ts12-urn-eudi-sca-login_risk_transaction-1-data-model.json"
            )),
        ),
        (
            ACCESS,
            validator(include_str!(
                "../ts12-schemas/ts12-urn-eudi-sca-account_access-1-data-model.json"
            )),
        ),
        (
            MANDATE,
            validator(include_str!(
                "../ts12-schemas/ts12-urn-eudi-sca-emandate-1-data-model.json"
            )),
        ),
    ];
    for fixture in payloads() {
        let (_, schema) = schemas
            .iter()
            .find(|(t, _)| *t == fixture.transaction_type)
            .unwrap();
        let schema_accepts = schema.is_valid(&fixture.payload);
        let raw = encode(&entry(fixture.transaction_type, fixture.payload));
        let parser_accepts = Entry::parse(&raw, &query()).is_ok();
        assert_eq!(parser_accepts, schema_accepts, "{}", fixture.case);
    }
}
