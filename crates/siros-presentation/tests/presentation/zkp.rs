//! The honest paths of `zkp_req`: over redirects with `direct_post.cwt`, and over the DC API with
//! `dc_api.jwt` beside an mdoc, in one consent and one `vp_token`. nym_auth's verifier accepts
//! each proof against the session the verifier computes from its own values.

use ciborium::Value as Ciborium;
use serde_json::{json, Value};
use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;
use siros_oid4vp::Handover;
use siros_presentation::{Shown, WalletDisplay};
use siros_zkp_req_nym_auth::presenter::Session;
use siros_zkp_req_nym_auth::testing::{query, Spec, TestVerifier};
use siros_zkp_req_nym_auth::verifier_id::VerifierId;
use siros_zkp_req_nym_auth::verify::{verify, Tolerance, VerifyInput};

use crate::verifier::{
    client_metadata, dc_api_handover, dc_api_signed, decrypt_cwt, decrypt_jwe, get,
    redirect_handover, redirect_signed, signed_client_id, transcript, NONCE, NOW, STATE,
};
use crate::wallet::{
    ciborium, holder_signed, mdoc, nym_auth, nym_auth_issuer, ready, respond, Held, Wallet, MDL,
    MDL_NS,
};

/// A wallet holding the nym_auth attestation as credential 1 and an mDL as credential 2.
fn wallet() -> Wallet {
    let (data, auxiliary) = nym_auth(&Spec::default());
    let mut nym = Held::new(1, "mso_mdoc", data);
    nym.metadata = Some(auxiliary);
    let mdl = Held::new(
        2,
        "mso_mdoc",
        mdoc(MDL, MDL_NS, &[("family_name", Cbor::text("Doe"))]),
    );
    Wallet::new(vec![nym, mdl])
}

/// The nym_auth query: a pseudonym and an adult's age check.
fn nym_query() -> Value {
    query(Some("18+"), true)
}

/// nym_auth's verifier accepts `presentation`, the CBOR `ZkpPresentation`, in the session of
/// `handover`.
fn accepted(presentation: &[u8], handover: &[u8]) {
    let session = Session {
        handover: Handover::from_cbor(handover).unwrap(),
        verifier_id: VerifierId::x509_san_dns(&signed_client_id(), false).unwrap(),
    };
    let verified = verify(
        &VerifyInput {
            query: &nym_query(),
            client_metadata: &client_metadata(),
            session: &session,
            presentation,
            now: NOW + 5,
            tolerance: Tolerance {
                future: 60,
                past: 600,
            },
            trust_anchors: &[nym_auth_issuer()],
        },
        &TestVerifier,
    )
    .unwrap();
    assert_eq!(verified.issuer_certificate, nym_auth_issuer());
}

#[test]
fn zkp_req_over_redirect_direct_post_cwt() {
    let wallet = wallet();
    let request = redirect_signed(&json!({
        "response_type": "vp_token",
        "response_mode": "direct_post.cwt",
        "nonce": NONCE,
        "state": STATE,
        "client_metadata": client_metadata(),
        "dcql_query": {"credentials": [nym_query()]}
    }));
    let usable = wallet.usable();
    let fetches = wallet.fetches(&request, &usable);
    let input = wallet.input(&request, &usable, &fetches);
    let planned = ready(&input).unwrap();
    let Shown::Proof(rows) = planned.view().offers()[0].members()[0].shown() else {
        panic!("proof statement rows")
    };
    let rows: Vec<(&str, Option<&str>)> = rows
        .iter()
        .map(|r| (r.label().as_str(), r.value().map(|v| v.as_str())))
        .collect();
    assert_eq!(
        rows,
        [
            ("Pseudonym", Some("config known-offender-matching-ssc")),
            ("Age check", Some("age 18+"))
        ]
    );

    let (_, response) = respond(&input);
    let authorization = decrypt_cwt(response.submission());
    assert_eq!(
        get(&authorization, &Ciborium::Text("state".into())),
        &Ciborium::Text(STATE.into())
    );
    let token = get(&authorization, &Ciborium::Text("vp_token".into()));
    let [presentation] = &get(token, &Ciborium::Text("nym".into()))
        .as_array()
        .unwrap()[..]
    else {
        panic!("one presentation")
    };
    let mut encoded = Vec::new();
    ciborium::into_writer(presentation, &mut encoded).unwrap();
    accepted(&encoded, &redirect_handover());
    let record = serde_json::to_value(response.record()).unwrap();
    assert_eq!(record["usedCredentialIds"], json!([1]));
    assert_eq!(record["audience"], signed_client_id());
}

#[test]
fn zkp_req_and_mdoc_over_dc_api_jwt() {
    let wallet = wallet();
    let mdl = json!({"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": MDL},
        "claims": [{"path": [MDL_NS, "family_name"]}]});
    let request = dc_api_signed(&json!({
        "response_type": "vp_token",
        "response_mode": "dc_api.jwt",
        "nonce": NONCE,
        "client_metadata": client_metadata(),
        "dcql_query": {"credentials": [mdl, nym_query()]}
    }));
    let usable = wallet.usable();
    let fetches = wallet.fetches(&request, &usable);
    let input = wallet.input(&request, &usable, &fetches);
    let planned = ready(&input).unwrap();
    let view = planned.view();
    let [offer] = view.offers() else {
        panic!("one consent: {}", view.offers().len())
    };
    let queries: Vec<&str> = offer.members().iter().map(|m| m.query_id()).collect();
    assert_eq!(queries, ["mdl", "nym"]);
    assert_eq!(offer.wallet_display(), WalletDisplay::Needed);

    let (_, response) = respond(&input);
    let payload = decrypt_jwe(response.submission());
    let token = payload["vp_token"].as_object().unwrap();
    let mut keys: Vec<&String> = token.keys().collect();
    keys.sort();
    assert_eq!(keys, ["mdl", "nym"]);

    let zkp = base64url::decode(token["nym"][0].as_str().unwrap()).unwrap();
    accepted(&zkp, &dc_api_handover());

    let device_response = ciborium(&base64url::decode(token["mdl"][0].as_str().unwrap()).unwrap());
    let text = |s: &str| Ciborium::Text(s.into());
    let document = &get(&device_response, &text("documents"))
        .as_array()
        .unwrap()[0];
    let device_signed = get(document, &text("deviceSigned"));
    let signature = get(
        get(device_signed, &text("deviceAuth")),
        &text("deviceSignature"),
    );
    let [Ciborium::Bytes(protected), _, Ciborium::Null, Ciborium::Bytes(signature)] =
        &signature.as_array().unwrap()[..]
    else {
        panic!("a COSE_Sign1 with a detached payload")
    };
    let encode = |value: &Ciborium| {
        let mut out = Vec::new();
        ciborium::into_writer(value, &mut out).unwrap();
        out
    };
    let authentication = Ciborium::Array(vec![
        text("DeviceAuthentication"),
        ciborium(&transcript(&dc_api_handover())),
        text(MDL),
        get(device_signed, &text("nameSpaces")).clone(),
    ]);
    let sig_structure = Ciborium::Array(vec![
        text("Signature1"),
        Ciborium::Bytes(protected.clone()),
        Ciborium::Bytes(Vec::new()),
        Ciborium::Bytes(encode(&Ciborium::Tag(
            24,
            Box::new(Ciborium::Bytes(encode(&authentication))),
        ))),
    ]);
    assert!(holder_signed(&encode(&sig_structure), signature));

    let record = serde_json::to_value(response.record()).unwrap();
    assert_eq!(record["usedCredentialIds"], json!([2, 1]));
}
