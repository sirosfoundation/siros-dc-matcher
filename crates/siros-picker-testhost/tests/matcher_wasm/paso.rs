//! Transaction data cases: the requests of PaSO Core, Annex A (A.1, A.5, A.6, A.7), the Payment
//! rulebook's example, signed credential metadata, ad-hoc metadata, and the CS-12 example, each
//! over credentials whose metadata defines the types they target.

use serde_json::{json, Value};
use siros_display::Locale;
use siros_oid4vp::HttpsUrl;
use siros_presentation::testing::host::holding_absent;
use siros_presentation::testing::paso::{approval, paso_wallet, APPROVAL};
use siros_presentation::testing::verifier::{
    b64, client_metadata, dc_api_signed_request, SignedForm, NONCE, SIGNER,
};
use siros_presentation::testing::wallet::{sd_jwt, Held, Wallet, VCT};
use siros_transaction_data::{Configuration, HeldDocument, HeldMetadata};

use crate::differential::{Case, Exception};

macro_rules! vector {
    ($name:literal) => {
        serde_json::from_str::<Value>(include_str!(concat!(
            "../../../siros-transaction-data/tests/vectors/",
            $name
        )))
        .unwrap()
    };
}

pub const CARD: &str = "https://bank.example/sca/card";
pub const ACCOUNT: &str = "https://bank.example/sca/account";
pub const PID: &str = "https://credentials.example/pid";
pub const PID_2: &str = "https://credentials.example/pid-2";
pub const LOYALTY: &str = "https://shop.example/loyalty";
pub const PAYMENT: &str = "urn:paso:sca:global:payment:1";
/// A transaction data type a configuration defines, of the generic rulebook.
pub const POINTS: &str = "urn:example:loyalty-points:1";
const VERSIONED: &str = "https://bank.example/sca/versioned";
const LEGACY: &str = "https://bank.example/sca/legacy";
const IBAN: &str = "https://issuer.bank.example/credentials/sca/iban/1.0";

/// The signed DC API request of `dcql_query` carrying `entries`.
pub fn request(dcql_query: Value, entries: &[Value]) -> Vec<u8> {
    let transaction_data: Vec<String> = entries
        .iter()
        .map(|entry| b64(entry.to_string().as_bytes()))
        .collect();
    let params = json!({
        "response_type": "vp_token", "response_mode": "dc_api.jwt", "nonce": NONCE,
        "client_metadata": client_metadata(), "transaction_data": transaction_data,
        "dcql_query": dcql_query
    });
    dc_api_signed_request(&params, SIGNER, SignedForm::Compact)
}

/// A query of `id` for an SD-JWT VC of `vct`, asking for `claims`.
fn query(id: &str, vct: &str, claims: &[&str]) -> Value {
    let claims: Vec<Value> = claims
        .iter()
        .map(|claim| json!({"path": [claim]}))
        .collect();
    let mut query = json!({"id": id, "format": "dc+sd-jwt", "meta": {"vct_values": [vct]}});
    if !claims.is_empty() {
        query["claims"] = json!(claims);
    }
    query
}

/// The PaSO payment definition of Proof Metadata, Annex A.2.
pub fn payment_definition() -> Value {
    vector!("paso/metadata-a2-payload.json")["credential_metadata"]["transaction_data_types"]
        [PAYMENT]
        .clone()
}

/// A wallet holding `held`, the host configuring `configured` and holding no type metadata of
/// the credentials' types.
pub fn configured_wallet(held: Vec<Held>, configured: &Value, absent: &[&str]) -> Wallet {
    let mut wallet = Wallet::new(held);
    wallet.configuration = Configuration::parse(&configured.to_string()).unwrap();
    wallet.metadata = holding_absent(absent);
    wallet
}

fn case(name: &str, dcql_query: Value, entries: Vec<Value>, wallet: Wallet) -> Case {
    Case {
        name: name.to_owned(),
        request: request(dcql_query, &entries),
        entries,
        wallet,
        icons: Vec::new(),
        exception: None,
    }
}

/// The transaction data cases.
pub fn cases() -> Vec<Case> {
    let mut cases = core_annex();
    cases.extend(sources());
    cases.extend(cs12());
    cases.push(two_definitions());
    cases
}

/// The definition of [`POINTS`]: one claim, `points`.
pub fn points_definition() -> Value {
    json!({"claims": [{"path": ["points"], "display": [{"locale": "en", "name": "Points"}]}]})
}

/// A card and a loyalty card in one offer, each taking an entry of a type the configuration
/// defines for it alone: the picker reads two definitions in one run and shows each on its
/// credential.
fn two_definitions() -> Case {
    let configured = json!([
        {"type": PAYMENT, "vct_values": [CARD], "definition": payment_definition()},
        {"type": POINTS, "vct_values": [LOYALTY], "definition": points_definition()}
    ]);
    let card = [("pan_last_four", json!("4242")), ("scheme", json!("visa"))];
    let wallet = configured_wallet(
        vec![
            Held::new(1, "dc+sd-jwt", sd_jwt(CARD, &card)),
            Held::new(2, "dc+sd-jwt", sd_jwt(LOYALTY, &[])),
        ],
        &configured,
        &[CARD, LOYALTY],
    );
    let points = json!({"type": POINTS, "credential_ids": ["loyalty"],
                        "payload": {"points": "120"}});
    let dcql_query = json!({
        "credentials": [query("sca_card", CARD, &[]), query("loyalty", LOYALTY, &[])],
        "credential_sets": [{"options": [["sca_card", "loyalty"]]}]
    });
    case(
        "two definitions in one run",
        dcql_query,
        vec![vector!("paso/core-a1-entry.json"), points],
        wallet,
    )
}

/// PaSO Core, Annex A.1, A.5, A.6 and A.7.
fn core_annex() -> Vec<Case> {
    let names = [
        ("given_name", json!("Erika")),
        ("family_name", json!("Mustermann")),
    ];
    let card = |id| {
        let claims = [("pan_last_four", json!("4242")), ("scheme", json!("visa"))];
        Held::new(id, "dc+sd-jwt", sd_jwt(CARD, &claims))
    };
    let payment = json!([{"type": PAYMENT, "vct_values": [CARD, ACCOUNT], "definition": payment_definition()}]);
    let a1 = case(
        "PaSO A.1",
        vector!("paso/core-a1-request.json")["dcql_query"].clone(),
        vec![vector!("paso/core-a1-entry.json")],
        configured_wallet(vec![card(1)], &payment, &[CARD]),
    );
    let a5_wallet = configured_wallet(
        vec![
            card(1),
            Held::new(2, "dc+sd-jwt", sd_jwt(ACCOUNT, &[])),
            Held::new(3, "dc+sd-jwt", sd_jwt(PID, &names)),
        ],
        &payment,
        &[CARD, ACCOUNT, PID],
    );
    let entries: Vec<Value> = vector!("paso/core-a5-entries.json")
        .as_array()
        .unwrap()
        .clone();
    let a5 = case(
        "PaSO A.5",
        vector!("paso/core-a5-request.json")["dcql_query"].clone(),
        entries,
        a5_wallet,
    );
    let mut a1_entry = vector!("paso/core-a1-entry.json");
    a1_entry["credential_ids"] = json!(["sca_card"]);
    let a6 = |name: &str, options: Value| {
        let wallet = configured_wallet(
            vec![
                card(1),
                Held::new(2, "dc+sd-jwt", sd_jwt(PID, &names)),
                Held::new(3, "dc+sd-jwt", sd_jwt(PID_2, &names)),
                Held::new(4, "dc+sd-jwt", sd_jwt(LOYALTY, &[])),
            ],
            &payment,
            &[CARD, PID, PID_2, LOYALTY],
        );
        let dcql_query = json!({
            "credentials": [
                query("sca_card", CARD, &[]), query("pid_1", PID, &["given_name"]),
                query("pid_2", PID_2, &["given_name"]), query("loyalty", LOYALTY, &[])],
            "credential_sets": [{"options": options}]
        });
        case(name, dcql_query, vec![a1_entry.clone()], wallet)
    };
    vec![
        a1,
        a5,
        a6(
            "PaSO A.6, transposable",
            json!([["sca_card", "pid_1"], ["sca_card", "pid_2"], ["sca_card"]]),
        ),
        a6(
            "PaSO A.6, not transposable",
            json!([
                ["sca_card", "pid_1"],
                ["sca_card", "pid_2", "loyalty"],
                ["sca_card"]
            ]),
        ),
        a6(
            "PaSO A.6, made transposable",
            json!([
                ["sca_card", "pid_1", "loyalty"],
                ["sca_card", "pid_1"],
                ["sca_card", "pid_2", "loyalty"],
                ["sca_card", "pid_2"],
                ["sca_card", "loyalty"],
                ["sca_card"]
            ]),
        ),
        a7(),
    ]
}

/// PaSO Core, Annex A.7: a credential that supports version 2 takes the first entry, one that
/// supports version 1 alone the second.
fn a7() -> Case {
    let display = |name: &str| json!([{"locale": "en", "name": name}]);
    let mut claims = vec![
        json!({"path": ["transaction_id"], "mandatory": true}),
        json!({"path": ["amount"], "mandatory": true, "value_type": "iso_currency_amount", "display": display("Amount")}),
        json!({"path": ["payee", "name"], "mandatory": true, "display": display("Payee")}),
        json!({"path": ["payee", "id"], "mandatory": true}),
    ];
    let first = json!({"claims": claims.clone()});
    claims.push(json!({"path": ["reward_points"], "display": display("Reward points")}));
    let second = json!({"claims": claims});
    let configured = json!([
        {"type": "urn:paso:sca:com.example.pay:transaction:2", "vct_values": [VERSIONED], "definition": second},
        {"type": "urn:paso:sca:com.example.pay:transaction:1", "vct_values": [VERSIONED, LEGACY], "definition": first}
    ]);
    let wallet = configured_wallet(
        vec![
            Held::new(1, "dc+sd-jwt", sd_jwt(VERSIONED, &[])),
            Held::new(2, "dc+sd-jwt", sd_jwt(LEGACY, &[])),
        ],
        &configured,
        &[VERSIONED, LEGACY],
    );
    let dcql_query = json!({"credentials": [{"id": "sca", "format": "dc+sd-jwt",
        "meta": {"vct_values": [VERSIONED, LEGACY]}}]});
    let entries = vector!("paso/core-a7-entries.json")
        .as_array()
        .unwrap()
        .clone();
    case("PaSO A.7", dcql_query, entries, wallet)
}

/// The sources of a definition: signed credential metadata, the Payment rulebook's example with
/// its logo at an `https` URL, and an entry's ad-hoc metadata.
fn sources() -> Vec<Case> {
    let approval_entry = json!({"type": APPROVAL, "credential_ids": ["pid"],
                                "payload": {"what": "Pay 10.00 EUR"}});
    let pid_query = json!({"credentials": [query("pid", VCT, &["given_name"])]});
    let signed_metadata = case(
        "signed credential metadata",
        pid_query.clone(),
        vec![approval_entry.clone()],
        paso_wallet(json!({APPROVAL: approval()})),
    );
    let mut ad_hoc_entry = approval_entry;
    ad_hoc_entry["metadata"] = json!("eyJhbGciOiJFUzI1NiJ9.e30.c2lnbmF0dXJl");
    let mut ad_hoc = case(
        "ad-hoc metadata",
        pid_query,
        vec![ad_hoc_entry],
        paso_wallet(json!({APPROVAL: approval()})),
    );
    // The wallet verifies the ad-hoc metadata JWT against the trust store; the picker cannot.
    ad_hoc.exception = Some(Exception::AdHocMetadata);
    let types = vector!("paso/payment-a1-types.json");
    let mut payment_entry = vector!("paso/payment-a1-entry.json");
    // A digest of the integrity form; the example's own is no SHA-256 digest.
    payment_entry["payload"]["payee"]["logo#integrity"] =
        json!("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    let configured = json!([{"type": PAYMENT, "vct_values": [CARD], "definition": types[PAYMENT]}]);
    // Over the DC API, both sides refuse the logo at an https URL.
    let logo = case(
        "PaSO Payment A.1, a logo at an https URL",
        json!({"credentials": [query("bank_payment_card", CARD, &[])]}),
        vec![payment_entry],
        configured_wallet(
            vec![Held::new(1, "dc+sd-jwt", sd_jwt(CARD, &[]))],
            &configured,
            &[CARD],
        ),
    );
    vec![signed_metadata, ad_hoc, logo]
}

/// CS-12, Section 8.1: the payment and the login of an SCA-IBAN attestation whose type metadata
/// (Section 7.2) the host holds, in the wallet's language `en-GB`, as given and with a label for
/// each payload member TS12 shows. The query names the attestation's own `vct`.
fn cs12() -> Vec<Case> {
    let metadata = vector!("cs12/sca-iban-type-metadata.json");
    let mut labelled = metadata.clone();
    let label = |path: &[&str], text: &str| json!({"path": path, "display": [{"lang": "en-GB", "label": text}]});
    let types = &mut labelled["transaction_data_types"];
    for (type_id, paths) in [
        (
            "urn:eudi:sca:payment:1",
            &[
                (&["payload", "transaction_id"][..], "Transaction"),
                (&["payload", "payee", "id"][..], "Payee ID"),
                (&["payload", "currency"][..], "Currency"),
            ][..],
        ),
        (
            "urn:eudi:sca:login_risk_transaction:1",
            &[(&["payload", "transaction_id"][..], "Transaction")][..],
        ),
    ] {
        let claims = types[type_id]["claims"].as_array_mut().unwrap();
        claims.extend(paths.iter().map(|(path, text)| label(path, text)));
    }
    [
        ("CS-12", metadata),
        ("CS-12, every member labelled", labelled),
    ]
    .into_iter()
    .map(|(name, metadata)| {
        let mut wallet = Wallet::new(vec![Held::new(1, "dc+sd-jwt", sd_jwt(IBAN, &[]))]);
        // The type metadata labels its claims in `en-GB` alone.
        wallet.language = Locale::parse("en-GB").unwrap();
        let document = HeldDocument::new(
            HttpsUrl::parse(IBAN).unwrap(),
            metadata.to_string().into_bytes(),
        );
        wallet.metadata = HeldMetadata::new(Vec::new(), vec![document]).unwrap();
        let dcql_query = json!({"credentials": [query("sca_iban", IBAN, &[])]});
        let entries = vec![
            vector!("cs12/payment-entry.json"),
            vector!("cs12/login-entry-iban.json"),
        ];
        case(name, dcql_query, entries, wallet)
    })
    .collect()
}
