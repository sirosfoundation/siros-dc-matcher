//! The G2 corpus as wallet states and DC API requests: the requests the matcher's transcript
//! test sends, each made a request intake verifies, over wallets that hold what its fixtures
//! described, and the `zkp_req` request vectors of this repository, signed.

use std::path::Path;

use serde_json::{json, Map, Value};
use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;
use siros_presentation::testing::verifier::{
    client_metadata, dc_api_request, dc_api_signed_request, encryption_jwk, SignedForm, NONCE,
    SIGNER,
};
use siros_presentation::testing::wallet::{
    base64, mdoc, mdoc_by, nym_auth, sd_jwt, sd_jwt_x5c, Held, Wallet, MDL, MDL_NS, VCT,
};
use siros_registration::CredentialIcon;
use siros_trust::{Certificate, TrustStore};
use siros_wallet_state::CredentialId;
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::testing::{query as nym_query, Issuer, Spec};

use crate::differential::{Case, Exception};
use crate::paso::{PID, PID_2};

/// The wallet of the corpus: one mDL, as `credentialId` `id`, holding `age_over_18` and
/// `family_name`.
fn mdl(id: u64) -> Held {
    let items = [
        ("age_over_18", Cbor::Bool(true)),
        ("family_name", Cbor::text("Johansson")),
    ];
    Held::new(id, "mso_mdoc", mdoc(MDL, MDL_NS, &items))
}

/// The nym_auth attestation of `spec`, its seed delivered, as `credentialId` `id`.
fn nym(id: u64, spec: &Spec) -> Held {
    let (data, auxiliary) = nym_auth(spec);
    let mut held = Held::new(id, "mso_mdoc", data);
    held.metadata = Some(auxiliary);
    held
}

/// The parameters an unsigned DC API request needs beside `params`: `vp_token`, `dc_api`, a
/// nonce.
fn unsigned(params: Value) -> Vec<u8> {
    let mut data = params;
    data["response_type"] = json!("vp_token");
    data["response_mode"] = json!("dc_api");
    data["nonce"] = json!(NONCE);
    dc_api_request("openid4vp-v1-unsigned", data)
}

/// A request for `age_over_18` of query `q1`, of `format` and `meta`.
fn age(format: &str, meta: Value) -> Value {
    json!({"dcql_query": {"credentials": [{
        "id": "q1", "format": format, "meta": meta,
        "claims": [{"path": [MDL_NS, "age_over_18"]}]}]}})
}

fn mdl_meta() -> Value {
    json!({"doctype_value": MDL})
}

/// A request for `age_over_18` whose one credential set states `purpose`.
fn with_purpose(purpose: Value) -> Value {
    let mut params = age("mso_mdoc", mdl_meta());
    params["dcql_query"]["credential_sets"] = json!([{"options": [["q1"]], "purpose": purpose}]);
    params
}

/// The signed form of `params`: `dc_api.jwt` with the verifier's encryption key, signed by the
/// test verifier, in `form`.
fn signed(params: Value, form: SignedForm) -> Vec<u8> {
    let mut object = params;
    object["response_type"] = json!("vp_token");
    object["response_mode"] = json!("dc_api.jwt");
    object["nonce"] = json!(NONCE);
    if object.get("client_metadata").is_none() {
        object["client_metadata"] = client_metadata();
    }
    object["client_metadata"]["jwks"] = json!({"keys": [encryption_jwk()]});
    dc_api_signed_request(&object, SIGNER, form)
}

fn case(name: &str, request: Vec<u8>, wallet: Wallet) -> Case {
    Case {
        name: name.to_owned(),
        request,
        entries: Vec::new(),
        wallet,
        icons: Vec::new(),
        exception: None,
    }
}

/// The G2 corpus.
pub fn cases() -> Vec<Case> {
    let mut cases = mdl_cases();
    cases.push(interleaved());
    cases.extend(request_cases());
    cases.extend(nym_cases());
    cases.extend(trust_cases());
    cases.extend(vector_cases());
    cases
}

fn mdl_cases() -> Vec<Case> {
    let plain = || Wallet::new(vec![mdl(1)]);
    let two = || Wallet::new(vec![mdl(1), mdl(2)]);
    let mut icon = case("raw icon", unsigned(age("mso_mdoc", mdl_meta())), plain());
    icon.icons = vec![CredentialIcon {
        credential: CredentialId::new(1),
        icon: crate::sides::icon(120, 80),
    }];
    let two_member = json!({"dcql_query": {
        "credentials": [
            {"id": "q1", "format": "mso_mdoc", "meta": mdl_meta(), "claims": [{"path": [MDL_NS, "age_over_18"]}]},
            {"id": "q2", "format": "mso_mdoc", "meta": mdl_meta(), "claims": [{"path": [MDL_NS, "age_over_18"]}]}],
        "credential_sets": [{"options": [["q1", "q2"]]}]}});
    let optional = json!({"dcql_query": {
        "credentials": [
            {"id": "q1", "format": "mso_mdoc", "meta": {"doctype_value": "org.example.none"}, "claims": [{"path": ["a", "b"]}]}],
        "credential_sets": [{"options": [["q1"]], "required": false}]}});
    vec![
        case("mdoc", unsigned(age("mso_mdoc", mdl_meta())), plain()),
        case(
            "two candidates",
            unsigned(age("mso_mdoc", mdl_meta())),
            two(),
        ),
        case(
            "missing claim",
            unsigned(age("mso_mdoc", mdl_meta())),
            Wallet::new(vec![Held::new(
                1,
                "mso_mdoc",
                mdoc(MDL, MDL_NS, &[("family_name", Cbor::text("Johansson"))]),
            )]),
        ),
        case(
            "empty wallet",
            unsigned(age("mso_mdoc", json!({}))),
            Wallet::new(Vec::new()),
        ),
        case("two-member option", unsigned(two_member), two()),
        case("optional set unmatched", unsigned(optional), plain()),
        icon,
        case(
            "40 candidates",
            unsigned(age("mso_mdoc", mdl_meta())),
            Wallet::new((1..=40).map(mdl).collect()),
        ),
        case(
            "purpose text",
            unsigned(with_purpose(json!("Confirming you are over 18"))),
            plain(),
        ),
        case(
            "purpose blank",
            unsigned(with_purpose(json!("   "))),
            plain(),
        ),
        case(
            "purpose object",
            unsigned(with_purpose(json!({"id": 7}))),
            plain(),
        ),
        case(
            "purpose with NUL",
            unsigned(with_purpose(json!("Before\u{0}after"))),
            plain(),
        ),
        case(
            "all in background",
            unsigned(age("mso_mdoc", mdl_meta())),
            plain().all_in_background(),
        ),
    ]
}

/// A query of two SD-JWT VC types whose credentials alternate in the wallet's order: the picker
/// reads the records of each type and merges them by position, as the wallet's plan lists its
/// candidates.
fn interleaved() -> Case {
    let name = [("given_name", json!("Erika"))];
    let wallet = Wallet::new(vec![
        Held::new(1, "dc+sd-jwt", sd_jwt(PID, &name)),
        Held::new(2, "dc+sd-jwt", sd_jwt(PID_2, &name)),
        Held::new(3, "dc+sd-jwt", sd_jwt(PID, &name)),
        Held::new(4, "dc+sd-jwt", sd_jwt(PID_2, &name)),
    ]);
    let query = json!({"dcql_query": {"credentials": [{"id": "pid", "format": "dc+sd-jwt",
        "meta": {"vct_values": [PID_2, PID]}, "claims": [{"path": ["given_name"]}]}]}});
    case("two types interleaved", unsigned(query), wallet)
}

/// The requests the transcript test sends that no wallet state changes: unknown protocols,
/// malformed requests, and the signed shapes, signed.
fn request_cases() -> Vec<Case> {
    let plain = || Wallet::new(vec![mdl(1)]);
    let malformed: [&[u8]; 7] = [
        b"",
        b"not json",
        br#"{"requests":[]}"#,
        br#"{"requests":"not an array"}"#,
        br#"{"unexpected":"shape"}"#,
        br#"{"requests":[{"protocol":"openid4vp-v1-signed","data":{}}]}"#,
        br#"{"requests":[{"protocol":"openid4vp-v1-signed","data":{"dcql_query":42}}]}"#,
    ];
    let mut cases: Vec<Case> = malformed
        .iter()
        .enumerate()
        .map(|(at, request)| {
            case(
                &format!("malformed request {at}"),
                request.to_vec(),
                plain(),
            )
        })
        .collect();
    let fallthrough = {
        let signed: Value =
            serde_json::from_slice(&signed(age("mso_mdoc", mdl_meta()), SignedForm::Compact))
                .unwrap();
        let entry = signed["requests"][0].clone();
        json!({"requests": [
            {"protocol": "openid4vp-v1-signed", "data": {"request": "@@@not-a-jws@@@"}},
            entry]})
        .to_string()
        .into_bytes()
    };
    cases.extend([
        case(
            "unknown protocol",
            dc_api_request("some-future-thing", json!({})),
            plain(),
        ),
        case(
            "signed",
            signed(age("mso_mdoc", mdl_meta()), SignedForm::Compact),
            plain(),
        ),
        case(
            "multisigned",
            signed(age("mso_mdoc", mdl_meta()), SignedForm::Multisigned),
            plain(),
        ),
        case(
            "truncated signed",
            dc_api_request(
                "openid4vp-v1-signed",
                json!({"request": "aGVhZGVy.dHJ1bmM"}),
            ),
            plain(),
        ),
        case("fallthrough", fallthrough, plain()),
    ]);
    cases
}

/// TR3 through the TR5 facts: an `aki` and an `etsi_tl` authority that admit one Document
/// Signer of two, and a malformed `aki` value.
fn trust_cases() -> Vec<Case> {
    const LIST: &str = "https://tl.example/eu";
    let root = Issuer::root(0x61, "Admitted root");
    let admitted = root.sign_child(0x62, "Admitted Document Signer");
    let other = Issuer::root(0x63, "Other root").sign_child(0x64, "Other Document Signer");
    let claims = [("given_name", json!("Erika"))];
    let items = [("family_name", Cbor::text("Mustermann"))];
    let wallet = || {
        let mut wallet = Wallet::new(vec![
            Held::new(1, "dc+sd-jwt", sd_jwt_x5c(VCT, &claims, &[&admitted.der])),
            Held::new(2, "dc+sd-jwt", sd_jwt_x5c(VCT, &claims, &[&other.der])),
            Held::new(3, "mso_mdoc", mdoc_by(&admitted, MDL, MDL_NS, &items)),
            Held::new(4, "mso_mdoc", mdoc_by(&other, MDL, MDL_NS, &items)),
        ]);
        let store =
            json!([{"type": "etsi_tl", "value": LIST, "certificates": [base64(&root.der)]}]);
        wallet.trust = TrustStore::parse(&store.to_string()).unwrap();
        wallet
    };
    let aki = Certificate::parse(&admitted.der)
        .unwrap()
        .authority_key_identifier()
        .map(|key| base64url::encode(key.as_bytes()).into_string())
        .unwrap();
    let request = |aki: &str| {
        unsigned(json!({"dcql_query": {"credentials": [
            {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]},
                "trusted_authorities": [{"type": "aki", "values": [aki]}],
                "claims": [{"path": ["given_name"]}]},
            {"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": MDL},
                "trusted_authorities": [{"type": "etsi_tl", "values": [LIST]}],
                "claims": [{"path": [MDL_NS, "family_name"]}]}
        ]}}))
    };
    vec![
        case("trusted authorities", request(&aki), wallet()),
        case("a malformed aki value", request("!"), wallet()),
    ]
}

/// nym_auth: the corpus's unsigned requests, and the nym_auth query signed, over the
/// attestation of an adult and of a minor.
fn nym_cases() -> Vec<Case> {
    let nym_wallet = |systems: Vec<NymAuthSystem>| {
        let mut wallet = Wallet::new(vec![nym(1, &Spec::default())]);
        wallet.systems = systems;
        wallet
    };
    let query = || nym_query(Some("18+"), true);
    let request = |query: Value, client_metadata: Option<Value>| {
        let mut params = json!({"dcql_query": {"credentials": [query]}});
        if let Some(client_metadata) = client_metadata {
            params["client_metadata"] = client_metadata;
        }
        params
    };
    let mut minor = case(
        "nym signed, minor",
        signed(
            request(nym_query(Some("18-"), true), None),
            SignedForm::Compact,
        ),
        nym_wallet(NymAuthSystem::ALL.to_vec()),
    );
    // The age check reads `birth_date`, which the registration leaves out (N3, K2).
    minor.exception = Some(Exception::CredentialTests);
    vec![
        case(
            "nym",
            unsigned(request(query(), None)),
            nym_wallet(Vec::new()),
        ),
        case(
            "nym no circuit",
            unsigned(request(query(), None)),
            nym_wallet(Vec::new()),
        ),
        case(
            "nym unsigned with lists",
            unsigned(request(query(), Some(client_metadata()))),
            nym_wallet(NymAuthSystem::ALL.to_vec()),
        ),
        case(
            "nym signed",
            signed(request(query(), None), SignedForm::Compact),
            nym_wallet(NymAuthSystem::ALL.to_vec()),
        ),
        case(
            "nym signed, no system",
            signed(request(query(), None), SignedForm::Compact),
            nym_wallet(Vec::new()),
        ),
        case(
            "nym signed, multisigned",
            signed(request(query(), None), SignedForm::Multisigned),
            nym_wallet(NymAuthSystem::ALL.to_vec()),
        ),
        case(
            "nym signed beside an mDL",
            signed(request(query(), None), SignedForm::Compact),
            {
                let mut wallet = Wallet::new(vec![nym(1, &Spec::default()), mdl(2)]);
                wallet.systems = NymAuthSystem::ALL.to_vec();
                wallet
            },
        ),
        minor,
    ]
}

/// The `zkp_req` request vectors of this repository's `zkp_req` and nym_auth crates, each a
/// signed request over the adult's attestation.
fn vector_cases() -> Vec<Case> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let directories = [
        crates.join("siros-zkp-req/tests/vectors/request"),
        crates.join("siros-zkp-req-nym-auth/tests/vectors/request"),
    ];
    let mut files: Vec<_> = directories
        .iter()
        .flat_map(|directory| std::fs::read_dir(directory).unwrap())
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    files.sort();
    files
        .into_iter()
        .filter_map(|path| {
            let vector: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).ok()?;
            let query = vector.get("query")?.clone();
            let mut params = json!({"dcql_query": {"credentials": [query]}});
            if let Some(Value::Object(lists)) = vector.get("client_metadata") {
                let mut client_metadata: Map<String, Value> = lists.clone();
                client_metadata.remove("jwks");
                params["client_metadata"] = Value::Object(client_metadata);
            }
            let name = path.file_stem()?.to_string_lossy().into_owned();
            let mut wallet = Wallet::new(vec![nym(1, &Spec::default())]);
            wallet.systems = NymAuthSystem::ALL.to_vec();
            Some(case(
                &format!("vector {name}"),
                signed(params, SignedForm::Compact),
                wallet,
            ))
        })
        .collect()
}
