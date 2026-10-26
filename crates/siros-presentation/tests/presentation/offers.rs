//! A3 and A1: every option of a request whose credential sets are all optional is an offer, and
//! no query other than `zkp_req` reaches a nym_auth attestation's undisclosable attributes.

use serde_json::{json, Value};
use siros_codec::cbor::Value as Cbor;
use siros_oid4vp::ErrorCode;
use siros_presentation::PresentationError;
use siros_zkp_req_nym_auth::testing::Spec;

use crate::verifier::{redirect_unsigned, NONCE, STATE};
use crate::wallet::{mdoc, nym_auth, ready, sd_jwt, Held, Wallet, MDL, MDL_NS, VCT};

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
    let usable = wallet.usable();
    let fetches = wallet.fetches(&request, &usable);
    let planned = ready(&wallet.input(&request, &usable, &fetches)).unwrap();
    // (purpose, the queries of the members, the queries of each addition)
    type Shape<'v> = (Option<&'v str>, Vec<&'v str>, Vec<Vec<&'v str>>);
    let offers: Vec<Shape<'_>> = planned
        .view()
        .offers()
        .iter()
        .map(|offer| {
            let queries = offer.members().iter().map(|m| m.query_id()).collect();
            let additions = offer
                .additions()
                .iter()
                .map(|a| a.members().iter().map(|m| m.query_id()).collect())
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
        let usable = wallet.usable();
        let fetches = wallet.fetches(&request, &usable);
        let planned = ready(&wallet.input(&request, &usable, &fetches));
        assert_eq!(
            planned.err(),
            Some(PresentationError::NoOffer(ErrorCode::AccessDenied)),
            "{query}"
        );
    }
}
