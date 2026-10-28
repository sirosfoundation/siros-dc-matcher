//! The case families the K2 differential needs beyond the G2 corpus: `values` filters,
//! SD-JWT objects and arrays, `multiple`, `claim_sets` and additions, credentials presented in
//! the background with clipped rows or with transaction data, the `verifier_id` forms, a
//! multisigned request of mixed signers, offers whose rows do not show, a payment with a purpose,
//! and one entry two queries share.

use serde_json::{json, Value};
use siros_codec::cbor::Value as Cbor;
use siros_presentation::testing::host::holding_absent;
use siros_presentation::testing::verifier::{
    b64, client_metadata, dc_api_request, dc_api_signed_request, encryption_jwk, SignedForm,
    SignedPrefix, Signer, NONCE, ORIGIN, SIGNER,
};
use siros_presentation::testing::wallet::{
    mdoc, nym_auth, sd_jwt, sd_jwt_with, Held, Wallet, MDL, MDL_NS, VCT,
};
use siros_transaction_data::Configuration;
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::testing::{query as nym_query, Spec};
use siros_zkp_req_nym_auth::verifier_id::VerifierIdForm;

use crate::differential::{Case, Exception};

const CARD: &str = "https://bank.example/sca/card";
const ACCOUNT: &str = "https://bank.example/sca/account";
const PAYMENT: &str = "urn:paso:sca:global:payment:1";

macro_rules! vector {
    ($name:literal) => {
        serde_json::from_str::<Value>(include_str!(concat!(
            "../../../siros-transaction-data/tests/vectors/",
            $name
        )))
        .unwrap()
    };
}

/// The cases.
pub fn cases() -> Vec<Case> {
    let mut cases = values();
    cases.extend(sd_jwt_claims());
    cases.extend(choices());
    cases.extend(background());
    cases.extend(verifier_ids());
    cases.extend(mixed_signers());
    cases.extend(unshown());
    cases.extend(payments());
    cases
}

fn unsigned(params: Value) -> Vec<u8> {
    let mut data = params;
    data["response_type"] = json!("vp_token");
    data["response_mode"] = json!("dc_api");
    data["nonce"] = json!(NONCE);
    dc_api_request("openid4vp-v1-unsigned", data)
}

fn signed_by(params: Value, signer: Signer) -> Vec<u8> {
    let mut object = params;
    object["response_type"] = json!("vp_token");
    object["response_mode"] = json!("dc_api.jwt");
    object["nonce"] = json!(NONCE);
    if object.get("client_metadata").is_none() {
        object["client_metadata"] = client_metadata();
    }
    object["client_metadata"]["jwks"] = json!({"keys": [encryption_jwk()]});
    dc_api_signed_request(&object, signer, SignedForm::Compact)
}

pub(crate) fn case(name: &str, request: Vec<u8>, wallet: Wallet) -> Case {
    Case {
        name: name.to_owned(),
        request,
        entries: Vec::new(),
        wallet,
        icons: Vec::new(),
        exception: None,
    }
}

pub(crate) fn mdl(id: u64, items: &[(&str, Cbor)]) -> Held {
    Held::new(id, "mso_mdoc", mdoc(MDL, MDL_NS, items))
}

pub(crate) fn ask(id: &str, element: &str) -> Value {
    json!({"id": id, "format": "mso_mdoc", "meta": {"doctype_value": MDL},
        "claims": [{"path": [MDL_NS, element]}]})
}

fn queries(credentials: Value) -> Vec<u8> {
    unsigned(json!({"dcql_query": {"credentials": credentials}}))
}

/// `values` filters on a boolean, a full-date and an SD-JWT object member.
fn values() -> Vec<Case> {
    let valued = |element: &str, values: Value| {
        queries(
            json!([{"id": "q1", "format": "mso_mdoc", "meta": {"doctype_value": MDL},
            "claims": [{"path": [MDL_NS, element], "values": values}]}]),
        )
    };
    let adult = || Wallet::new(vec![mdl(1, &[("age_over_18", Cbor::Bool(true))])]);
    let born = || {
        let date = Cbor::Tag(1004, Box::new(Cbor::text("2000-01-31")));
        Wallet::new(vec![mdl(1, &[("birth_date", date)])])
    };
    let address = [
        ("address", json!({"street": "Main 1", "locality": "Town"})),
        ("given_name", json!("Erika")),
    ];
    let member = |values: Value| {
        queries(
            json!([{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]},
            "claims": [{"path": ["address", "locality"], "values": values}]}]),
        )
    };
    let pid = || Wallet::new(vec![Held::new(1, "dc+sd-jwt", sd_jwt(VCT, &address))]);
    vec![
        case(
            "values [true] on true",
            valued("age_over_18", json!([true])),
            adult(),
        ),
        case(
            "values [false] on true",
            valued("age_over_18", json!([false])),
            adult(),
        ),
        case(
            "full-date values match",
            valued("birth_date", json!(["2000-01-31"])),
            born(),
        ),
        case(
            "full-date values miss",
            valued("birth_date", json!(["2000-02-01"])),
            born(),
        ),
        case("SD-JWT member values match", member(json!(["Town"])), pid()),
        case("SD-JWT member values miss", member(json!(["City"])), pid()),
    ]
}

/// SD-JWT objects and arrays: an object claim, an array with a withheld element before the
/// indexed one, and an array selected whole by `null`.
fn sd_jwt_claims() -> Vec<Case> {
    // The digest of a disclosure the holder does not hold: a withheld element.
    let withheld = b64(&[7; 32]);
    let nationalities = json!({"nationalities": ["DE", {"...": withheld}, "FR"]});
    let pid = || {
        Wallet::new(vec![Held::new(
            1,
            "dc+sd-jwt",
            sd_jwt_with(
                VCT,
                &[("given_name", json!("Erika"))],
                nationalities.clone(),
            ),
        )])
    };
    let path = |path: Value| {
        queries(
            json!([{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]},
            "claims": [{"path": path}]}]),
        )
    };
    let address = [("address", json!({"street": "Main 1", "locality": "Town"}))];
    vec![
        case(
            "SD-JWT object claim",
            path(json!(["address"])),
            Wallet::new(vec![Held::new(1, "dc+sd-jwt", sd_jwt(VCT, &address))]),
        ),
        case(
            "SD-JWT array element after a withheld one",
            path(json!(["nationalities", 2])),
            pid(),
        ),
        case(
            "SD-JWT array element at a withheld position",
            path(json!(["nationalities", 1])),
            pid(),
        ),
        case(
            "SD-JWT array whole",
            path(json!(["nationalities", null])),
            pid(),
        ),
    ]
}

/// `multiple`, `claim_sets`, and an optional set whose option has candidates.
fn choices() -> Vec<Case> {
    let mut multiple = ask("q1", "age_over_18");
    multiple["multiple"] = json!(true);
    let two = || {
        Wallet::new(vec![
            mdl(1, &[("age_over_18", Cbor::Bool(true))]),
            mdl(2, &[("age_over_18", Cbor::Bool(true))]),
        ])
    };
    let claim_sets = json!([{"id": "q1", "format": "mso_mdoc", "meta": {"doctype_value": MDL},
        "claims": [{"id": "a", "path": [MDL_NS, "age_over_21"]},
                   {"id": "b", "path": [MDL_NS, "age_over_18"]}],
        "claim_sets": [["a"], ["b"]]}]);
    let sets = |credential_sets: Value| {
        unsigned(json!({"dcql_query": {
            "credentials": [ask("q1", "age_over_18"), ask("q2", "family_name")],
            "credential_sets": credential_sets}}))
    };
    let additions = sets(json!([{"options": [["q1"]]}, {"options": [["q2"]], "required": false}]));
    let one_each = || {
        Wallet::new(vec![
            mdl(1, &[("age_over_18", Cbor::Bool(true))]),
            mdl(2, &[("family_name", Cbor::text("Andersson"))]),
        ])
    };
    vec![
        case(
            "multiple, two candidates",
            queries(json!([multiple])),
            two(),
        ),
        case("claim_sets, the second", queries(claim_sets), two()),
        case(
            "an addition with candidates",
            additions,
            Wallet::new(vec![
                mdl(1, &[("age_over_18", Cbor::Bool(true))]),
                mdl(2, &[("family_name", Cbor::text("Johansson"))]),
                mdl(3, &[("family_name", Cbor::text("Andersson"))]),
            ]),
        ),
        // K3: the picks of the offer {q1, q2} are held by its members alone, and by {q1} with
        // its addition {q2}.
        case(
            "an offer another holds with an addition",
            sets(json!([{"options": [["q1"], ["q1", "q2"]]},
                {"options": [["q2"]], "required": false}])),
            one_each(),
        ),
        case(
            "optional sets, an offer two others hold with additions",
            sets(json!([{"options": [["q1"]], "required": false},
                {"options": [["q2"]], "required": false},
                {"options": [["q1", "q2"]], "required": false}])),
            one_each(),
        ),
    ]
}

/// Credentials presented in the background: rows whole, a value longer than a field, a byte
/// string, an SD-JWT object, and a transaction.
fn background() -> Vec<Case> {
    let one = |element: &str, value: Cbor| {
        case(
            &format!("background, {element}"),
            queries(json!([ask("q1", element)])),
            Wallet::new(vec![mdl(1, &[(element, value)])]).all_in_background(),
        )
    };
    let address = [("address", json!({"street": "Main 1", "locality": "Town"}))];
    let mut transaction = payment_case(
        "background, a PaSO payment",
        None,
        card_wallet().all_in_background(),
    );
    transaction.name = "background, a PaSO payment".to_owned();
    vec![
        one("age_over_18", Cbor::Bool(true)),
        one("family_name", Cbor::text(&"A".repeat(100))),
        one("portrait", Cbor::Bytes(vec![1, 2, 3])),
        case(
            "background, SD-JWT object",
            queries(json!([{"id": "pid", "format": "dc+sd-jwt",
                "meta": {"vct_values": [VCT]}, "claims": [{"path": ["address"]}]}])),
            Wallet::new(vec![Held::new(1, "dc+sd-jwt", sd_jwt(VCT, &address))]).all_in_background(),
        ),
        transaction,
    ]
}

/// The `verifier_id` forms: `x509_san_dns` with a client of that prefix and of another, and the
/// `semantic` form, the owner's K2 exception, which the wallet decides after the pick.
fn verifier_ids() -> Vec<Case> {
    let nym_wallet = |form: VerifierIdForm, others: Vec<Held>| {
        let (data, auxiliary) = nym_auth(&Spec::default());
        let mut held = Held::new(1, "mso_mdoc", data);
        held.metadata = Some(auxiliary);
        let mut wallet = Wallet::new(std::iter::once(held).chain(others).collect());
        wallet.systems = NymAuthSystem::ALL.to_vec();
        wallet.verifier_id = form;
        wallet
    };
    let request = || json!({"dcql_query": {"credentials": [nym_query(Some("18+"), true)]}});
    let hashed = Signer {
        prefix: SignedPrefix::X509Hash,
        ..SIGNER
    };
    let anonymous = Signer {
        subject: "CN=Test verifier,O=Test only",
        ..SIGNER
    };
    // The adult's attestation fails "18-" in the wallet (N3), which the picker cannot test: the
    // picker numbers the nym offer the wallet leaves out, and the mDL's picks still select the
    // wallet's offer (K3).
    let numbering = nym_wallet(
        VerifierIdForm::X509SanDns,
        vec![mdl(2, &[("age_over_18", Cbor::Bool(true))])],
    );
    let mut renumbered = case(
        "nym 18- of an adult, or an mDL",
        signed_by(
            json!({"dcql_query": {
                "credentials": [nym_query(Some("18-"), true), ask("q1", "age_over_18")],
                "credential_sets": [{"options": [["nym"], ["q1"]]}]}}),
            SIGNER,
        ),
        numbering,
    );
    renumbered.exception = Some(Exception::CredentialTests);
    let mut semantic = case(
        "nym, semantic form, no semantics identifier",
        signed_by(request(), anonymous),
        nym_wallet(VerifierIdForm::Semantic, Vec::new()),
    );
    // The owner's K2 exception: the semantic identifier comes from the access certificate's DER,
    // which the projection leaves out.
    semantic.exception = Some(Exception::SemanticVerifierId);
    vec![
        case(
            "nym, x509_san_dns form, x509_san_dns client",
            signed_by(request(), SIGNER),
            nym_wallet(VerifierIdForm::X509SanDns, Vec::new()),
        ),
        case(
            "nym, x509_san_dns form, x509_hash client",
            signed_by(request(), hashed),
            nym_wallet(VerifierIdForm::X509SanDns, Vec::new()),
        ),
        semantic,
        renumbered,
    ]
}

/// A multisigned request whose first signature is [`SIGNER`]'s and whose second names an
/// `openid_federation` client, with a `client_metadata` that is no object: the wallet verifies
/// the first, takes the metadata from the request and refuses it; the picker cannot tell which
/// signature qualifies, and shows the entry. The owner's K2 exception.
fn mixed_signers() -> Vec<Case> {
    let object = json!({"response_type": "vp_token", "response_mode": "dc_api.jwt",
        "nonce": NONCE, "client_metadata": "x", "expected_origins": [ORIGIN],
        "dcql_query": {"credentials": [ask("q1", "age_over_18")]}});
    let payload = b64(object.to_string().as_bytes());
    let mut header = SIGNER.header();
    header["client_id"] = json!(SIGNER.client_id());
    let protected = b64(header.to_string().as_bytes());
    let signature = SIGNER.sign(&format!("{protected}.{payload}"));
    let federation =
        json!({"alg": "ES256", "client_id": "openid_federation:https://verifier.example"});
    let signatures = json!([
        {"protected": protected, "signature": signature},
        {"protected": b64(federation.to_string().as_bytes()), "signature": b64(b"sig")}
    ]);
    let mut mixed = case(
        "multisigned, an x509_san_dns signer and an openid_federation one",
        dc_api_request(
            "openid4vp-v1-multisigned",
            json!({"payload": payload, "signatures": signatures}),
        ),
        Wallet::new(vec![mdl(1, &[("age_over_18", Cbor::Bool(true))])]),
    );
    mixed.exception = Some(Exception::MixedSigners);
    vec![mixed]
}

/// Two offers whose second shows a claim key that is no safe label, or longer than a label: the
/// wallet and the picker leave that offer out, and keep the first.
fn unshown() -> Vec<Case> {
    let two_offers = |second: &str| {
        unsigned(json!({"dcql_query": {
            "credentials": [ask("q1", "age_over_18"), ask("q2", second)],
            "credential_sets": [{"options": [["q2"], ["q1"]]}]}}))
    };
    let wallet = |key: &str| {
        Wallet::new(vec![mdl(
            1,
            &[("age_over_18", Cbor::Bool(true)), (key, Cbor::Bool(true))],
        )])
    };
    let long = "k".repeat(501);
    vec![
        case(
            "an offer with an unsafe key",
            two_offers("x\u{200B}y"),
            wallet("x\u{200B}y"),
        ),
        case(
            "an offer with a 501-character key",
            two_offers(&long),
            wallet(&long),
        ),
        case("an offer with a blank key", two_offers(" "), wallet(" ")),
    ]
}

fn card_wallet() -> Wallet {
    let claims = [("pan_last_four", json!("4242")), ("scheme", json!("visa"))];
    let mut wallet = Wallet::new(vec![Held::new(1, "dc+sd-jwt", sd_jwt(CARD, &claims))]);
    wallet.configuration = Configuration::parse(&configured(&[CARD]).to_string()).unwrap();
    wallet.metadata = holding_absent(&[CARD]);
    wallet
}

fn configured(vcts: &[&str]) -> Value {
    let a2 = vector!("paso/metadata-a2-payload.json");
    let definition = a2["credential_metadata"]["transaction_data_types"][PAYMENT].clone();
    json!([{"type": PAYMENT, "vct_values": vcts, "definition": definition}])
}

fn paso_request(dcql_query: Value, entry: &Value) -> Vec<u8> {
    let params = json!({
        "response_type": "vp_token", "response_mode": "dc_api.jwt", "nonce": NONCE,
        "client_metadata": client_metadata(),
        "transaction_data": [b64(entry.to_string().as_bytes())],
        "dcql_query": dcql_query
    });
    dc_api_signed_request(&params, SIGNER, SignedForm::Compact)
}

/// The PaSO Core A.1 payment over `wallet`, its credential set stating `purpose`.
fn payment_case(name: &str, purpose: Option<&str>, wallet: Wallet) -> Case {
    let mut query = vector!("paso/core-a1-request.json")["dcql_query"].clone();
    if let Some(purpose) = purpose {
        query["credential_sets"] = json!([{"options": [["sca_card"]], "purpose": purpose}]);
    }
    let entry = vector!("paso/core-a1-entry.json");
    let mut case = case(name, paso_request(query, &entry), wallet);
    case.entries = vec![entry];
    case
}

/// A payment with a purpose, and one entry two queries of an offer share.
fn payments() -> Vec<Case> {
    let mut wallet = Wallet::new(vec![
        Held::new(1, "dc+sd-jwt", sd_jwt(CARD, &[("scheme", json!("visa"))])),
        Held::new(2, "dc+sd-jwt", sd_jwt(ACCOUNT, &[])),
    ]);
    wallet.configuration = Configuration::parse(&configured(&[CARD, ACCOUNT]).to_string()).unwrap();
    wallet.metadata = holding_absent(&[CARD, ACCOUNT]);
    let mut shared = vector!("paso/core-a1-entry.json");
    shared["credential_ids"] = json!(["sca_card", "sca_account"]);
    let query = json!({"credentials": [
        {"id": "sca_card", "format": "dc+sd-jwt", "meta": {"vct_values": [CARD]}},
        {"id": "sca_account", "format": "dc+sd-jwt", "meta": {"vct_values": [ACCOUNT]}}],
        "credential_sets": [{"options": [["sca_card", "sca_account"]]}]});
    let mut one_entry = case(
        "one entry, two queries of an offer",
        paso_request(query, &shared),
        wallet,
    );
    one_entry.entries = vec![shared];
    let mut purpose = payment_case(
        "a payment with a purpose",
        Some("Pay the shop"),
        card_wallet(),
    );
    purpose.exception = Some(Exception::PaymentPurpose);
    vec![purpose, one_entry]
}
