//! The honest path of an SD-JWT VC over redirects with `direct_post.jwt`, authorizing a TS12
//! payment: the KB-JWT verifies under the holder's key, binds the presentation as sent and the
//! payment, and names the verifier (A6).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_oid4vp::FetchResponse;
use siros_presentation::{plan, PlanStep, WalletDisplay};

use crate::verifier::{
    b64, client_metadata, decrypt_jwe, redirect_unsigned, NONCE, NOW, RESPONSE_URI, STATE,
};
use crate::wallet::{disclosed, holder_signed, ready, respond, sd_jwt, Held, Wallet, VCT};

const PAYMENT: &str = "urn:eudi:sca:payment:1";

/// The payment entry of `transaction_data`, as the verifier sends it.
pub fn payment() -> String {
    let entry = json!({
        "type": PAYMENT,
        "credential_ids": ["pid"],
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
pub fn type_metadata() -> FetchResponse {
    let claim = |path: &[&str], label: &str| {
        let mut full = vec!["payload"];
        full.extend_from_slice(path);
        json!({"path": full, "display": [{"lang": "en", "label": label}]})
    };
    let document = json!({
        "vct": VCT,
        "name": "Pay Card",
        "category": "urn:eu:europa:ec:eudi:sua:sca",
        "transaction_data_types": {PAYMENT: {
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
    FetchResponse::new(
        200,
        Some("application/json".into()),
        document.to_string().into_bytes(),
    )
}

#[test]
fn sd_jwt_over_redirect_direct_post_jwt() {
    let given = json!("Erika");
    let family = json!("Mustermann");
    let mut wallet = Wallet::new(vec![Held::new(
        1,
        "dc+sd-jwt",
        sd_jwt(
            VCT,
            &[("given_name", given.clone()), ("family_name", family)],
        ),
    )]);
    wallet.documents.push((VCT.to_owned(), type_metadata()));
    let request = redirect_unsigned(&json!({
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "nonce": NONCE,
        "state": STATE,
        "client_metadata": client_metadata(),
        "transaction_data": [payment()],
        "dcql_query": {"credentials": [{"id": "pid", "format": "dc+sd-jwt",
            "meta": {"vct_values": [VCT]}, "claims": [{"path": ["given_name"]}]}]}
    }));
    let empty = siros_presentation::Fetches::new();
    let first = plan(&wallet.input(&request, &empty)).unwrap();
    let PlanStep::Fetch(fetch) = first else {
        panic!("the plan fetches the type metadata first")
    };
    assert_eq!(fetch.url().as_str(), VCT);
    let fetches = wallet.fetches(&request);
    let input = wallet.input(&request, &fetches);

    let planned = ready(&input).unwrap();
    let offer = &planned.view().offers()[0];
    assert_eq!(offer.members()[0].entries(), [0]);
    assert_eq!(offer.members()[0].transactions().len(), 1);
    assert_eq!(offer.wallet_display(), WalletDisplay::Needed);

    let (_, response) = respond(&input);
    let payload = decrypt_jwe(response.submission());
    assert_eq!(payload["state"], STATE);
    let sent = payload["vp_token"]["pid"][0].as_str().unwrap();
    let (presentation, kb_jwt) = sent.rsplit_once('~').unwrap();
    let presentation = format!("{presentation}~");
    let (issuer_jwt, rest) = presentation.split_once('~').unwrap();
    assert!(issuer_jwt.starts_with("eyJ"));
    assert_eq!(rest, format!("{}~", disclosed("given_name", &given)));

    let [header, body, signature] = kb_jwt.split('.').collect::<Vec<_>>()[..] else {
        panic!("a compact KB-JWT")
    };
    let header: Value = serde_json::from_slice(&base64url::decode(header).unwrap()).unwrap();
    assert_eq!(header, json!({"typ": "kb+jwt", "alg": "ES256"}));
    let signing_input = kb_jwt.rsplit_once('.').unwrap().0;
    assert!(holder_signed(
        signing_input.as_bytes(),
        &base64url::decode(signature).unwrap()
    ));
    let claims: Value = serde_json::from_slice(&base64url::decode(body).unwrap()).unwrap();
    assert_eq!(claims["aud"], format!("redirect_uri:{RESPONSE_URI}"));
    assert_eq!(claims["nonce"], NONCE);
    assert_eq!(claims["iat"], NOW);
    assert_eq!(
        claims["sd_hash"],
        b64(&Sha256::digest(presentation.as_bytes()))
    );
    assert_eq!(
        claims["transaction_data_hashes"],
        json!([b64(&Sha256::digest(payment().as_bytes()))])
    );
    assert_eq!(claims["transaction_data_hashes_alg"], "sha-256");
    assert_eq!(claims["response_mode"], "direct_post.jwt");
    assert_eq!(
        claims["amr"],
        json!([{"possession": "key_in_local_native_wscd"}, {"inherence": "fingerprint_device"}])
    );
    assert_eq!(
        base64url::decode(claims["jti"].as_str().unwrap())
            .unwrap()
            .len(),
        16
    );

    let record = serde_json::to_value(response.record()).unwrap();
    assert_eq!(record["usedCredentialIds"], json!([1]));
    assert_eq!(record["audience"], format!("redirect_uri:{RESPONSE_URI}"));
    assert_eq!(record["presentationTimestampSeconds"], NOW);
    let data: Value = serde_json::from_str(record["data"].as_str().unwrap()).unwrap();
    assert_eq!(data, payload["vp_token"]);
}
