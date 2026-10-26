//! T4: an entry naming two Credential Queries binds to exactly one presented credential, the
//! first of its `credential_ids` whose credential its type authorizes (OpenID4VP 1.0, Section
//! 5.1), and adds its claims to that credential's KB-JWT alone (B.3.3.1; EC TS12 v1.0.1,
//! Section 3.6).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_dcql::QueryId;
use siros_oid4vp::ResponseMode;
use siros_transaction_data::{
    bind, Amr, Entry, Factor, Inherence, Jti, KbJwtInputs, Knowledge, Presented, ScaMetadata,
};

use crate::common::{
    card, credentials, encode, entry, inline_payment_type, now, payment, query, response, sd_jwt,
    type_metadata, with, PAYMENT,
};

#[test]
fn an_entry_binds_to_one_credential() {
    let raw = encode(&with(
        entry(PAYMENT, payment()),
        json!({"credential_ids": ["pay", "card"]}),
    ));
    let entries = [Entry::parse(&raw, &query(), now()).unwrap()];
    let cards = credentials(&[
        ("dc+sd-jwt", sd_jwt(&card(json!({})))),
        ("dc+sd-jwt", sd_jwt(&card(json!({})))),
    ]);
    let sca = response(&type_metadata(inline_payment_type()));
    let not_sca = response(&with(
        type_metadata(inline_payment_type()),
        json!({"category": null}),
    ));
    let first = ScaMetadata::parse(&cards[0], &sca).unwrap();
    let second = ScaMetadata::parse(&cards[1], &sca).unwrap();
    let first_not_sca = ScaMetadata::parse(&cards[0], &not_sca).unwrap();

    let card_id = QueryId::parse("card").unwrap();
    let pay_id = QueryId::parse("pay").unwrap();
    // (offer, the query of the one credential bound)
    let cases = [
        (
            [
                Presented::new(&card_id, &second),
                Presented::new(&pay_id, &first),
            ],
            "pay",
        ),
        (
            [
                Presented::new(&card_id, &second),
                Presented::new(&pay_id, &first_not_sca),
            ],
            "card",
        ),
    ];
    let hash = base64url::encode(&Sha256::digest(raw.as_bytes()));
    let amr = Amr::new(vec![
        Factor::Knowledge(Knowledge::Pin6OrMoreDigits),
        Factor::Inherence(Inherence::FingerprintDevice),
    ])
    .unwrap();
    let inputs = KbJwtInputs::new(Jti::new([9; 16]), ResponseMode::DirectPost, amr);
    for (offer, query_id) in cases {
        let bound = bind(&entries, &offer).unwrap();
        assert_eq!(bound.len(), 1, "{query_id}");
        assert_eq!(bound[0].presented().query_id().as_str(), query_id);
        assert_eq!(bound[0].entries().len(), 1);
        let expected: Vec<(String, Value)> = [
            ("transaction_data_hashes", json!([hash])),
            ("transaction_data_hashes_alg", json!("sha-256")),
            ("jti", json!(base64url::encode(&[9; 16]))),
            ("response_mode", json!("direct_post")),
            (
                "amr",
                json!([{"knowledge": "pin_6_or_more_digits"}, {"inherence": "fingerprint_device"}]),
            ),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        assert_eq!(bound[0].kb_jwt_claims(&inputs), expected, "{query_id}");
    }
}
