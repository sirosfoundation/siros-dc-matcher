//! A3 and A1: the offers of credential sets, and no query other than `zkp_req` reaches a
//! nym_auth attestation's undisclosable attributes.

use serde_json::{json, Value};
use siros_codec::cbor::Value as Cbor;
use siros_dcql::Dropped;
use siros_dcql::QueryId;
use siros_oid4vp::{ErrorCode, Submission};
use siros_presentation::{
    Failure, Position, PresentationError, SubsetError, WalletDisplay, MAX_ADDITIONS, MAX_EXAMINED,
    MAX_OFFERS,
};
use siros_zkp_req_nym_auth::testing::Spec;

use crate::sd_jwt::{payment_naming, type_metadata_of};
use crate::verifier::{dc_api_unsigned, redirect_unsigned, NONCE, STATE};
use crate::wallet::{mdoc, nym_auth, ready, respond_to, sd_jwt, Held, Wallet, MDL, MDL_NS, VCT};

fn request(dcql: Value) -> siros_oid4vp::VerifiedRequest {
    redirect_unsigned(&json!({
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "nonce": NONCE,
        "state": STATE,
        "dcql_query": dcql
    }))
}

#[test]
fn all_optional_sets_offer_each_option() {
    let wallet = Wallet::new(vec![
        Held::new(
            1,
            "dc+sd-jwt",
            sd_jwt(VCT, &[("given_name", json!("Erika"))]),
        ),
        Held::new(
            2,
            "mso_mdoc",
            mdoc(MDL, MDL_NS, &[("family_name", Cbor::text("Doe"))]),
        ),
    ]);
    let request = request(json!({
        "credentials": [
            {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]}},
            {"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": MDL}}
        ],
        "credential_sets": [
            {"options": [["pid"]], "required": false, "purpose": "Identify"},
            {"options": [["mdl"]], "required": false, "purpose": "Drive"}
        ]
    }));
    let fetches = wallet.fetches(&request);
    let planned = ready(&wallet.input(&request, &fetches)).unwrap();
    // (purpose, the queries of the members, the queries of each addition)
    type Shape<'v> = (Option<&'v str>, Vec<&'v str>, Vec<Vec<&'v str>>);
    let offers: Vec<Shape<'_>> = planned
        .view()
        .offers()
        .iter()
        .map(|offer| {
            let queries = offer
                .members()
                .iter()
                .map(|m| m.query_id().as_str())
                .collect();
            let additions = offer
                .additions()
                .iter()
                .map(|a| a.members().iter().map(|m| m.query_id().as_str()).collect())
                .collect();
            (offer.purpose(), queries, additions)
        })
        .collect();
    assert_eq!(
        offers,
        [
            (Some("Identify"), vec!["pid"], vec![vec!["mdl"]]),
            (Some("Drive"), vec!["mdl"], vec![vec!["pid"]]),
        ]
    );
}

#[test]
fn no_query_but_zkp_req_reaches_a_nym_auth_attestation() {
    let (data, auxiliary) = nym_auth(&Spec::default());
    let mut nym = Held::new(1, "mso_mdoc", data);
    nym.metadata = Some(auxiliary);
    let wallet = Wallet::new(vec![nym]);
    let ns = "eu.europa.ec.eudi.nym_auth.1";
    let queries = [
        json!({"id": "q", "format": "mso_mdoc", "meta": {"doctype_value": ns},
            "claims": [{"path": [ns, "birth_date"]}]}),
        json!({"id": "q", "format": "mso_mdoc", "meta": {"doctype_value": ns},
            "claims": [{"path": [ns, "ssc"]}]}),
        json!({"id": "q", "format": "mso_mdoc", "meta": {"doctype_value": ns}}),
        json!({"id": "q", "format": "mso_mdoc_zk", "meta": {"doctype_value": ns},
            "claims": [{"path": [ns, "birth_date"]}]}),
    ];
    for query in queries {
        let request = request(json!({"credentials": [query.clone()]}));
        let fetches = wallet.fetches(&request);
        let refused = ready(&wallet.input(&request, &fetches)).err().unwrap();
        assert_eq!(
            refused,
            PresentationError::NoOffer(Failure::Unsatisfied),
            "{query}"
        );
        assert_eq!(refused.error_code(), ErrorCode::AccessDenied, "{query}");
    }
}

/// What the view shows of an offer: the queries of its members with their number of
/// credentials, and the queries of each addition.
type Shape = (Vec<(String, usize)>, Vec<Vec<String>>);

fn shape(offer: &siros_presentation::OfferView) -> Shape {
    let members = offer
        .members()
        .iter()
        .map(|m| (m.query_id().as_str().to_owned(), m.credentials().len()))
        .collect();
    let additions = offer
        .additions()
        .iter()
        .map(|a| {
            a.members()
                .iter()
                .map(|m| m.query_id().as_str().to_owned())
                .collect()
        })
        .collect();
    (members, additions)
}

/// The request of `dcql` in `direct_post`.
fn asked(dcql: Value) -> siros_oid4vp::VerifiedRequest {
    request(dcql)
}

fn mdl(id: u64) -> Held {
    Held::new(
        id,
        "mso_mdoc",
        mdoc(MDL, MDL_NS, &[("family_name", Cbor::text("Doe"))]),
    )
}

fn mdl_query(multiple: bool) -> Value {
    json!({"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": MDL}, "multiple": multiple,
        "claims": [{"path": [MDL_NS, "family_name"]}]})
}

fn pid_query() -> Value {
    json!({"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]}})
}

/// A3: required and optional sets, additions, `multiple` members, an optional set joined for a
/// transaction entry, and the limits.
#[test]
fn offers_of_credential_sets() {
    let pid = |id| {
        Held::new(
            id,
            "dc+sd-jwt",
            sd_jwt(VCT, &[("given_name", json!("Erika"))]),
        )
    };

    // An optional option that shares a query with the offer is no addition.
    let wallet = Wallet::new(vec![pid(1), mdl(2)]);
    let request = asked(json!({
        "credentials": [pid_query(), mdl_query(false)],
        "credential_sets": [
            {"options": [["pid"]]},
            {"options": [["pid", "mdl"]], "required": false},
            {"options": [["mdl"]], "required": false}
        ]
    }));
    let fetches = wallet.fetches(&request);
    let planned = ready(&wallet.input(&request, &fetches)).unwrap();
    let offers: Vec<Shape> = planned.view().offers().iter().map(shape).collect();
    let addition = vec![vec!["mdl".to_owned()]];
    assert_eq!(offers, [(vec![("pid".to_owned(), 1)], addition)]);

    // A `multiple` member holds every candidate; the selection chooses a non-empty subset.
    let wallet = Wallet::new(vec![mdl(1), mdl(2), mdl(3)]);
    let request = dc_api_unsigned(&json!({
        "response_type": "vp_token", "response_mode": "dc_api", "nonce": NONCE,
        "dcql_query": {"credentials": [mdl_query(true)]}
    }));
    let fetches = wallet.fetches(&request);
    let input = wallet.input(&request, &fetches);
    let planned = ready(&input).unwrap();
    let [offer] = planned.view().offers() else {
        panic!("one offer")
    };
    assert_eq!(shape(offer), (vec![("mdl".to_owned(), 3)], Vec::new()));
    assert_eq!(offer.wallet_display(), WalletDisplay::Needed);
    let response = respond_to(&input, 0, Vec::new(), vec![("mdl".into(), vec![0, 2])]).unwrap();
    let Submission::DcApi(data) = response.submission() else {
        panic!("a DC API response")
    };
    assert_eq!(data["vp_token"]["mdl"].as_array().unwrap().len(), 2);
    let record = serde_json::to_value(response.record()).unwrap();
    assert_eq!(record["usedCredentialIds"], json!([1, 3]));
    let subset = |query: &str, positions: Vec<usize>| (query.to_owned(), positions);
    let id = |query: &str| QueryId::parse(query).unwrap();
    let refusals = [
        (
            vec![subset("mdl", vec![])],
            PresentationError::Subset(SubsetError::Empty),
        ),
        (
            vec![subset("mdl", vec![3])],
            PresentationError::Subset(SubsetError::OutOfRange(Position::new(3))),
        ),
        (
            vec![subset("mdl", vec![1, 1])],
            PresentationError::Subset(SubsetError::Repeated(Position::new(1))),
        ),
        (
            vec![subset("pid", vec![0])],
            PresentationError::SubsetQuery(id("pid")),
        ),
        (
            vec![subset("mdl", vec![0]), subset("mdl", vec![1])],
            PresentationError::SubsetRepeated(id("mdl")),
        ),
    ];
    for (subsets, refusal) in refusals {
        let response = respond_to(&input, 0, Vec::new(), subsets.clone());
        assert_eq!(response.err(), Some(refusal), "{subsets:?}");
    }

    // At most one option per optional set.
    let photo = Held::new(
        3,
        "mso_mdoc",
        mdoc(
            "org.example.photo.1",
            "org.example.photo",
            &[("photo", Cbor::Bytes(vec![1]))],
        ),
    );
    let wallet = Wallet::new(vec![pid(1), mdl(2), photo]);
    let photo_query = json!({"id": "photo", "format": "mso_mdoc",
        "meta": {"doctype_value": "org.example.photo.1"}});
    let request = asked(json!({
        "credentials": [pid_query(), mdl_query(false), photo_query],
        "credential_sets": [
            {"options": [["pid"]]},
            {"options": [["mdl"], ["photo"]], "required": false}
        ]
    }));
    let fetches = wallet.fetches(&request);
    let input = wallet.input(&request, &fetches);
    let planned = ready(&input).unwrap();
    let additions = planned.view().offers()[0].additions();
    assert_eq!(additions.len(), 2);
    let both = respond_to(&input, 0, vec![0, 1], Vec::new());
    let set = additions[0].set();
    assert_eq!(
        both.err(),
        Some(PresentationError::AdditionSetRepeated(set))
    );

    // The limits: 40 candidates give MAX_OFFERS offers and MAX_ADDITIONS additions, and two
    // required sets of one query examine MAX_EXAMINED of the 1600 combinations, 25 of them one.
    let mut held: Vec<Held> = (1..=40).map(mdl).collect();
    held.push(Held::new(
        41,
        "dc+sd-jwt",
        sd_jwt(VCT, &[("given_name", json!("Erika"))]),
    ));
    let wallet = Wallet::new(held);
    let limits = [
        (json!({"credentials": [mdl_query(false)]}), MAX_OFFERS, 0),
        (
            json!({"credentials": [pid_query(), mdl_query(false)], "credential_sets": [
                {"options": [["pid"]]}, {"options": [["mdl"]], "required": false}]}),
            1,
            MAX_ADDITIONS,
        ),
        (
            json!({"credentials": [mdl_query(false)], "credential_sets": [
                {"options": [["mdl"]]}, {"options": [["mdl"]]}]}),
            25,
            0,
        ),
    ];
    let unexamined = [
        (Dropped::Exact(8), Dropped::Exact(0)),
        (Dropped::Exact(0), Dropped::Exact(8)),
        (Dropped::Exact(1600 - MAX_EXAMINED), Dropped::Exact(0)),
    ];
    for ((dcql, offers, additions), (unexamined, additions_unexamined)) in
        limits.into_iter().zip(unexamined)
    {
        let request = asked(dcql.clone());
        let fetches = wallet.fetches(&request);
        let planned = ready(&wallet.input(&request, &fetches)).unwrap();
        let view = planned.view();
        assert_eq!(view.offers().len(), offers, "{dcql}");
        assert_eq!(view.unexamined(), unexamined, "{dcql}");
        assert_eq!(view.offers()[0].additions().len(), additions, "{dcql}");
        assert_eq!(
            view.offers()[0].unexamined(),
            additions_unexamined,
            "{dcql}"
        );
    }
}

/// A3: when no member of an offer can carry a transaction entry, each optional set whose
/// credentials can carry it joins the offer, in an offer of its own; a credential without type
/// metadata carries nothing.
#[test]
fn optional_sets_join_an_offer_that_carries_no_entry() {
    const VCT2: &str = "https://issuer.example/pay2";
    const UNLOCATED: &str = "urn:example:pay";
    let card = |id, vct: &str| {
        Held::new(
            id,
            "dc+sd-jwt",
            sd_jwt(vct, &[("given_name", json!("Erika"))]),
        )
    };
    let mut wallet = Wallet::new(vec![
        mdl(1),
        card(2, VCT),
        card(3, VCT2),
        card(4, UNLOCATED),
    ]);
    wallet
        .documents
        .push((VCT.to_owned(), type_metadata_of(VCT)));
    wallet
        .documents
        .push((VCT2.to_owned(), type_metadata_of(VCT2)));
    let query = |id: &str, vct: &str| json!({"id": id, "format": "dc+sd-jwt", "meta": {"vct_values": [vct]}});
    let optional = |options: Value| json!({"options": options, "required": false});
    // (case, queries, credential sets, the members of each offer with the entries each binds)
    type Members = Vec<(&'static str, Vec<usize>)>;
    let cases: [(&str, Vec<Value>, Value, Vec<Members>); 3] = [
        (
            "each optional set that carries the entry gives an offer",
            vec![mdl_query(false), query("pay", VCT), query("pay2", VCT2)],
            json!([{"options": [["mdl"]]}, optional(json!([["pay"]])), optional(json!([["pay2"]]))]),
            vec![
                vec![("mdl", vec![]), ("pay", vec![0])],
                vec![("mdl", vec![]), ("pay2", vec![0])],
            ],
        ),
        (
            "an offer that carries the entry joins nothing",
            vec![mdl_query(false), query("pay", VCT), query("pay2", VCT2)],
            json!([{"options": [["mdl"], ["pay"]]}, optional(json!([["pay2"]]))]),
            vec![
                vec![("mdl", vec![]), ("pay2", vec![0])],
                vec![("pay", vec![0])],
            ],
        ),
        (
            "a required credential without type metadata carries nothing",
            vec![query("pay", UNLOCATED), query("pay2", VCT2)],
            json!([{"options": [["pay"]]}, optional(json!([["pay2"]]))]),
            vec![vec![("pay", vec![]), ("pay2", vec![0])]],
        ),
    ];
    for (case, queries, sets, expected) in cases {
        let request = redirect_unsigned(&json!({
            "response_type": "vp_token", "response_mode": "direct_post", "nonce": NONCE,
            "state": STATE, "transaction_data": [payment_naming(&["pay", "pay2"])],
            "dcql_query": {"credentials": queries, "credential_sets": sets}
        }));
        let fetches = wallet.fetches(&request);
        let input = wallet.input(&request, &fetches);
        let planned = ready(&input).unwrap();
        let offers: Vec<Vec<(String, Vec<usize>)>> = planned
            .view()
            .offers()
            .iter()
            .map(|offer| {
                offer
                    .members()
                    .iter()
                    .map(|member| {
                        let entries = member.credentials()[0].entries();
                        let entries = entries.iter().map(|e| e.value()).collect();
                        (member.query_id().as_str().to_owned(), entries)
                    })
                    .collect()
            })
            .collect();
        let expected: Vec<Vec<(String, Vec<usize>)>> = expected
            .into_iter()
            .map(|offer| offer.into_iter().map(|(q, e)| (q.to_owned(), e)).collect())
            .collect();
        assert_eq!(offers, expected, "{case}");
        for offer in 0..offers.len() {
            respond_to(&input, offer, Vec::new(), Vec::new()).unwrap();
        }
    }
}
