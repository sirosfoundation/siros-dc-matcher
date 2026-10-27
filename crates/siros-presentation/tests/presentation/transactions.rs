//! Transaction data in the plan (PaSO Core, Section 7.4; OpenID4VP 1.0, Sections 5.1 and 8.5):
//! the honest path from signed credential metadata to the KB-JWT, the next entry for a credential
//! that supports no type of the first, and a refusal per plan rule with the error the verifier
//! receives.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::Signature;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_display::{DisplayCache, IssuerMetadata};
use siros_oid4vp::{ErrorCode, FetchResponse, HttpStatus};
use siros_presentation::PresentationError;
use siros_transaction_data::{
    EntryPosition, Exclusion, Incompatibility, Location, LocationStep, PayloadFault, RowValue,
    SourceKind, TransactionDataError, UnsignedWarning,
};
use siros_trust::TrustStore;
use siros_zkp_req_nym_auth::testing::Issuer;

use crate::verifier::{
    b64, client_metadata, dc_api_signed, dc_api_unsigned, decrypt_jwe, NONCE, NOW,
};
use crate::wallet::{base64, ready, respond, sd_jwt_x5c, Held, Wallet, VCT};

const APPROVAL: &str = "urn:paso:sca:com.example:approval:1";
const METADATA_URI: &str = "https://issuer.example/metadata/pid";

/// The definition of [`APPROVAL`]: one mandatory claim and the affirmative action label.
fn approval() -> Value {
    json!({
        "claims": [{"path": ["what"], "mandatory": true,
                    "display": [{"locale": "en", "name": "What"}]}],
        "ui_labels": {"affirmative_action_label": [{"locale": "en", "value": "Approve"}]}
    })
}

/// A `transaction_data` entry of `type_id` naming the query `query`, with `payload`, as the
/// verifier sends it.
fn entry(type_id: &str, query: &str, payload: Value) -> String {
    let entry = json!({"type": type_id, "credential_ids": [query], "payload": payload});
    b64(entry.to_string().as_bytes())
}

/// The signed credential metadata JWT of [`VCT`] (PaSO Proof Metadata, Section 4) defining
/// [`APPROVAL`], which `signer` signs.
fn credential_metadata(signer: &Issuer) -> FetchResponse {
    let header =
        json!({"alg": "ES256", "typ": "credential-metadata+jwt", "x5c": [base64(&signer.der)]});
    let claims = json!({
        "iss": "https://issuer.example", "sub": VCT, "format": "dc+sd-jwt",
        "iat": NOW - 86_400, "exp": NOW + 86_400, "credential_metadata_uri": METADATA_URI,
        "credential_metadata": {"transaction_data_types": {APPROVAL: approval()}}
    });
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let signature: Signature = signer.key.sign(input.as_bytes());
    let jwt = format!("{input}.{}", b64(&signature.to_bytes()));
    FetchResponse::new(
        HttpStatus::OK,
        Some("application/jwt".into()),
        jwt.into_bytes(),
    )
}

/// A wallet holding one PID of a Document Signer under a trusted root, whose issuer metadata
/// names [`METADATA_URI`], and whose host serves there the credential metadata the Document
/// Signer signs.
fn paso_wallet() -> Wallet {
    let root = Issuer::root(0x71, "Bank root");
    let signer = root.sign_child(0x72, "Bank Document Signer");
    let claims = [("given_name", json!("Erika"))];
    let mut wallet = Wallet::new(vec![Held::new(
        1,
        "dc+sd-jwt",
        sd_jwt_x5c(VCT, &claims, &[&signer.der]),
    )]);
    let anchors = json!([{"type": "etsi_tl", "value": "https://tl.example/eu",
                          "certificates": [base64(&root.der)]}]);
    wallet.trust = TrustStore::parse(&anchors.to_string()).unwrap();
    let issuer = json!({
        "credential_issuer": "https://issuer.example",
        "credential_configurations_supported": {"example": {
            "format": "dc+sd-jwt", "vct": VCT, "credential_metadata_uri": METADATA_URI
        }}
    });
    let metadata = IssuerMetadata::merge(&issuer, "example", None).unwrap();
    wallet.display = DisplayCache::new(vec![metadata], Vec::new()).unwrap();
    wallet
        .documents
        .push((METADATA_URI.to_owned(), credential_metadata(&signer)));
    wallet
}

/// The parameters of a DC API request for the `given_name` of each query of `queries`, all
/// required, carrying `transaction_data`.
fn params(queries: &[(&str, &str)], transaction_data: &[String]) -> Value {
    let credentials: Vec<Value> = queries
        .iter()
        .map(|(id, vct)| {
            json!({"id": id, "format": "dc+sd-jwt", "meta": {"vct_values": [vct]},
                   "claims": [{"path": ["given_name"]}]})
        })
        .collect();
    json!({
        "response_type": "vp_token", "response_mode": "dc_api.jwt", "nonce": NONCE,
        "client_metadata": client_metadata(), "transaction_data": transaction_data,
        "dcql_query": {"credentials": credentials}
    })
}

/// The claims of the KB-JWT the response of `input` sends for `pid`.
fn kb_jwt_claims(input: &siros_presentation::PlanInput<'_>) -> Value {
    let payload = decrypt_jwe(respond(input).submission());
    let sent = payload["vp_token"]["pid"][0].as_str().unwrap();
    let body = sent.rsplit('~').next().unwrap().split('.').nth(1).unwrap();
    serde_json::from_slice(&base64url::decode(body).unwrap()).unwrap()
}

#[test]
fn signed_credential_metadata_binds_the_entry_into_the_kb_jwt() {
    let wallet = paso_wallet();
    let approval = entry(APPROVAL, "pid", json!({"what": "Pay 10.00 EUR"}));
    let request = dc_api_signed(&params(&[("pid", VCT)], std::slice::from_ref(&approval)));
    let fetches = wallet.fetches(&request);
    let input = wallet.input(&request, &fetches);
    let planned = ready(&input).unwrap();
    let card = &planned.view().offers()[0].members()[0].credentials()[0];
    let view = card.transaction().unwrap().view();
    assert_eq!(view.source(), SourceKind::CredentialMetadata);
    assert_eq!(view.unsigned_warning(), UnsignedWarning::NotNeeded);
    let rows: Vec<(&str, String)> = view
        .rows()
        .iter()
        .map(|row| match row.value() {
            RowValue::Value(value) => (row.label().text(), value.text()),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(rows, [("What", "Pay 10.00 EUR".to_owned())]);
    assert_eq!(
        view.affirmative_action_label().map(|label| label.text()),
        Some("Approve")
    );

    let claims = kb_jwt_claims(&input);
    assert_eq!(
        claims["transaction_data_hashes"],
        json!([b64(&Sha256::digest(approval.as_bytes()))])
    );
    // B.3.3.1: `_alg` only when the entry carries one; the TS12 claims only under a TS12
    // rulebook.
    for absent in ["transaction_data_hashes_alg", "jti", "response_mode", "amr"] {
        assert!(claims.get(absent).is_none(), "{absent}");
    }
}

/// OpenID4VP 1.0, Section 5.1, under PaSO's first match: an entry of a type no source defines
/// for the credential refuses nothing while the credential takes a later entry.
#[test]
fn a_credential_takes_the_next_entry_of_a_type_it_supports() {
    let wallet = paso_wallet();
    let entries = [
        entry(
            "urn:paso:sca:com.example:approval:2",
            "pid",
            json!({"what": "Pay", "points": 3}),
        ),
        entry(APPROVAL, "pid", json!({"what": "Pay"})),
    ];
    let request = dc_api_signed(&params(&[("pid", VCT)], &entries));
    let fetches = wallet.fetches(&request);
    let planned = ready(&wallet.input(&request, &fetches)).unwrap();
    let card = &planned.view().offers()[0].members()[0].credentials()[0];
    assert_eq!(card.transaction().unwrap().entry(), EntryPosition::new(1));
}

#[test]
fn each_plan_rule_refuses_the_request() {
    let wallet = paso_wallet();
    let credential = wallet.credentials[0].entry();
    let excluded = |cause| {
        vec![Exclusion {
            credential,
            causes: vec![(EntryPosition::new(0), cause)],
        }]
    };
    let pid = [("pid", VCT)];
    let rows = [
        (
            "a type no source defines for the credential",
            dc_api_signed(&params(
                &pid,
                &[entry("urn:example:unknown", "pid", json!({}))],
            )),
            TransactionDataError::TypeUnknown(
                EntryPosition::new(0),
                excluded(Incompatibility::TypeUnsupported),
            ),
            ErrorCode::InvalidTransactionData,
        ),
        (
            "a payload the only candidate does not conform to",
            dc_api_signed(&params(
                &pid,
                &[entry(APPROVAL, "pid", json!({"what": "Pay", "extra": 1}))],
            )),
            TransactionDataError::NoCompatibleCredential(excluded(Incompatibility::Payload(
                PayloadFault::Uncovered(Location::new(vec![LocationStep::Key("extra".to_owned())])),
            ))),
            ErrorCode::InvalidTransactionData,
        ),
        (
            "an entry for a query no credential answers",
            dc_api_signed(&params(
                &[("pid", VCT), ("card", "https://bank.example/card")],
                &[entry(APPROVAL, "card", json!({"what": "Pay"}))],
            )),
            TransactionDataError::CredentialUnavailable,
            ErrorCode::InvalidTransactionData,
        ),
        (
            "a PaSO type in an unsigned request",
            dc_api_unsigned(&params(
                &pid,
                &[entry(APPROVAL, "pid", json!({"what": "Pay"}))],
            )),
            TransactionDataError::Unsigned(EntryPosition::new(0)),
            ErrorCode::InvalidRequest,
        ),
    ];
    for (case, request, expected, code) in rows {
        let fetches = wallet.fetches(&request);
        let error = ready(&wallet.input(&request, &fetches))
            .map(drop)
            .unwrap_err();
        assert_eq!(error.error_code(), code, "{case}");
        assert_eq!(
            error,
            PresentationError::TransactionData(expected),
            "{case}"
        );
    }
}
