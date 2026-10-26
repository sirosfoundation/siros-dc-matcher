//! One table: a fixture per condition of OpenID4VP 1.0, Section 8.5, and per construction rule
//! of the entry (T1), the TS12 types (T6) and the type metadata (T7). The honest inputs each
//! row edits are accepted, so each row breaks only its rule.

mod entry;
mod presentation;

use serde_json::{json, Value};
use siros_codec::base64url;
use siros_credential::Credential;
use siros_display::Locale;
use siros_oid4vp::FetchResponse;
use siros_transaction_data::{bind, Amr, Entry, Factor, Fetched, Presented, ScaMetadata, Step};

use crate::common::{
    card, encode, encode_payload, entry, inline_payment_type, now, payment, query, response,
    sd_jwt_vc, type_metadata, with, PAYMENT,
};
use crate::fixtures::payloads;

/// A row: its case, its input, and `Ok` or the code of the refusal.
type Row = (&'static str, Input, Result<(), &'static str>);

enum Input {
    /// A `transaction_data` string, against the query of the tests.
    Entry(String),
    /// The type metadata fetch of a credential.
    Fetch(Box<Credential>),
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
        Input::Entry(raw) => Entry::parse(&raw, &query(), now())
            .map(drop)
            .map_err(|e| e.code()),
        Input::Fetch(credential) => ScaMetadata::fetch(&credential)
            .map(drop)
            .map_err(|e| e.code()),
        Input::Metadata(card, response) => {
            let credential = sd_jwt_vc(&card);
            ScaMetadata::parse(&credential, &response)
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
        .map(|e| Entry::parse(&encode(e), &query(), now()).unwrap())
        .collect();
    let credential = sd_jwt_vc(card);
    let metadata = ScaMetadata::parse(&credential, &response(metadata)).map_err(|e| e.code())?;
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
    let mut table = entry::rows();
    table.extend(presentation::rows());
    // The payload rules of the four TS12 schemas.
    for fixture in payloads() {
        table.push((
            fixture.case,
            Input::Entry(encode_payload(fixture.transaction_type, &fixture.payload)),
            fixture.expected,
        ));
    }
    for (case, input, expected) in table {
        assert_eq!(outcome(input), expected, "{case}");
    }
}
