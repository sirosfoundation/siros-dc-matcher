//! One refusal per construction rule of siros-wallet-state and siros-credential. The honest
//! inputs each row edits are accepted, so each row breaks only its rule.

use serde_json::{json, Value};
use siros_codec::cbor::Value as Cbor;
use siros_credential::{ClaimPointer, Credential};
use siros_dcql::PathComponent;
use siros_wallet_state::WalletState;

use crate::common::{disclosure, entry, mdoc, sd_jwt, state, tdate, NAME_SPACE};

enum Input {
    /// An `S`, parsed, and each of its credentials read.
    State(String),
    /// Pointer components.
    Pointer(Vec<PathComponent>),
    /// An `S` of one credential, and a pointer whose claims are read.
    Claim(String, Vec<PathComponent>),
}

fn outcome(input: &Input) -> Result<(), &'static str> {
    match input {
        Input::State(text) => {
            let state = WalletState::parse(text).map_err(|e| e.code())?;
            for entry in state.credentials() {
                Credential::parse(entry).map_err(|e| e.code())?;
            }
            Ok(())
        }
        Input::Pointer(components) => ClaimPointer::parse(components.clone())
            .map(|_| ())
            .map_err(|e| e.code()),
        Input::Claim(text, components) => {
            let state = WalletState::parse(text).unwrap();
            let credential = Credential::parse(&state.credentials()[0]).unwrap();
            let pointer = ClaimPointer::parse(components.clone()).unwrap();
            credential
                .claims(&pointer)
                .map(|_| ())
                .map_err(|e| e.code())
        }
    }
}

fn key(k: &str) -> PathComponent {
    PathComponent::Key(k.to_owned())
}

/// The payload of an honest SD-JWT VC, with `given_name` selectively disclosed.
fn honest_payload(given_name_digest: &str) -> Value {
    json!({
        "iss": "https://issuer.example",
        "vct": "https://credentials.example/identity",
        "cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": "AQ", "y": "Ag"}},
        "nbf": 1_700_000_000,
        "exp": 1_900_000_000,
        "_sd": [given_name_digest]
    })
}

/// An `S` holding one SD-JWT VC entry with `payload` and `disclosures`.
fn vc_state(payload: &Value, disclosures: &[&str]) -> String {
    let data = sd_jwt(payload, disclosures);
    state(vec![entry(1, 1, 0, "dc+sd-jwt", &data)], vec![])
}

/// An `S` holding one SD-JWT VC entry of `data`, edited by `edit`.
fn entry_state(data: &str, edit: impl FnOnce(&mut Value)) -> String {
    let mut credential = entry(1, 1, 0, "dc+sd-jwt", data);
    edit(&mut credential);
    state(vec![credential], vec![])
}

/// An `S` edited by `edit`.
fn edited_state(edit: impl FnOnce(&mut Value)) -> String {
    let mut s: Value = serde_json::from_str(&state(vec![], vec![])).unwrap();
    edit(&mut s);
    s.to_string()
}

fn presentation() -> Value {
    json!({
        "presentationId": 1,
        "transactionId": 1,
        "data": "",
        "usedCredentialIds": [1],
        "presentationTimestampSeconds": 1_750_000_000,
        "audience": "https://verifier.example"
    })
}

#[test]
fn each_rule_refuses_its_input() {
    let (given_name, given_name_digest) = disclosure(&json!(["s0", "given_name", "Ada"]));
    let honest = honest_payload(&given_name_digest);
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut payload = honest.clone();
        edit(&mut payload);
        payload
    };
    let (vct, vct_digest) = disclosure(&json!([
        "s1",
        "vct",
        "https://credentials.example/identity"
    ]));
    let (jwk, jwk_digest) = disclosure(&json!(["s2", "jwk", {"kty": "EC"}]));
    let valid = ("2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z");
    let mdoc_state = |elements| {
        let data = mdoc(elements, valid.0, valid.1);
        state(vec![entry(1, 1, 0, "mso_mdoc", &data)], vec![])
    };
    let element = vec![key(NAME_SPACE), key("issue_date")];
    let data = sd_jwt(&honest, &[&given_name]);

    let accepted = [
        Input::State(edited_state(|_| {})),
        Input::State(entry_state(&data, |_| {})),
        Input::State(mdoc_state(vec![("given_name", Cbor::text("Ada"))])),
        Input::Claim(
            mdoc_state(vec![(
                "issue_date",
                Cbor::Tag(1004, Box::new(Cbor::text("2024-02-29"))),
            )]),
            element.clone(),
        ),
    ];
    for input in &accepted {
        assert_eq!(outcome(input), Ok(()));
    }

    let rows: Vec<(&str, &str, Input)> = vec![
        // W1
        (
            "S is an array",
            "state_malformed",
            Input::State("[]".into()),
        ),
        (
            "no schemaVersion: version 1",
            "schema_version_unsupported",
            Input::State(edited_state(|s| {
                drop(s.as_object_mut().unwrap().remove("schemaVersion"))
            })),
        ),
        (
            "schemaVersion 2",
            "schema_version_unsupported",
            Input::State(edited_state(|s| s["schemaVersion"] = json!(2))),
        ),
        // W2
        (
            "no credentials",
            "credentials_malformed",
            Input::State(edited_state(|s| {
                drop(s.as_object_mut().unwrap().remove("credentials"))
            })),
        ),
        (
            "a credential entry is a string",
            "credential_entry_malformed",
            Input::State(edited_state(|s| s["credentials"] = json!(["entry"]))),
        ),
        (
            "no kid",
            "credential_member_malformed",
            Input::State(entry_state(&data, |e| {
                drop(e.as_object_mut().unwrap().remove("kid"))
            })),
        ),
        (
            "a negative credentialId",
            "credential_member_malformed",
            Input::State(entry_state(&data, |e| e["credentialId"] = json!(-1))),
        ),
        (
            "a credentialId of 2^64",
            "credential_member_malformed",
            Input::State(entry_state(&data, |e| {
                e["credentialId"] = serde_json::from_str("18446744073709551616").unwrap()
            })),
        ),
        (
            "a batchId as a string",
            "credential_member_malformed",
            Input::State(entry_state(&data, |e| e["batchId"] = json!("1"))),
        ),
        (
            "a repeated credentialId",
            "credential_id_repeated",
            Input::State(state(
                vec![
                    entry(1, 1, 0, "dc+sd-jwt", &data),
                    entry(1, 1, 1, "dc+sd-jwt", &data),
                ],
                vec![],
            )),
        ),
        (
            "metadata as an object",
            "metadata_malformed",
            Input::State(entry_state(&data, |e| {
                e["metadata"] = json!({"type": "a", "value": 1})
            })),
        ),
        (
            "metadata of an empty type",
            "metadata_malformed",
            Input::State(entry_state(&data, |e| {
                e["metadata"] = json!([{"type": "", "value": 1}])
            })),
        ),
        (
            "metadata without a value",
            "metadata_malformed",
            Input::State(entry_state(&data, |e| {
                e["metadata"] = json!([{"type": "a"}])
            })),
        ),
        // W3
        (
            "no keypairs",
            "keypairs_malformed",
            Input::State(edited_state(|s| {
                drop(s.as_object_mut().unwrap().remove("keypairs"))
            })),
        ),
        (
            "a presentation without audience",
            "presentations_malformed",
            Input::State(edited_state(|s| {
                let mut p = presentation();
                drop(p.as_object_mut().unwrap().remove("audience"));
                s["presentations"] = json!([p]);
            })),
        ),
        (
            "a presentation after 9999",
            "presentations_malformed",
            Input::State(edited_state(|s| {
                let mut p = presentation();
                p["presentationTimestampSeconds"] = json!(253_402_300_800_i64);
                s["presentations"] = json!([p]);
            })),
        ),
        // C1
        (
            "format jwt_vc_json",
            "format_unsupported",
            Input::State(state(vec![entry(1, 1, 0, "jwt_vc_json", &data)], vec![])),
        ),
        (
            "an SD-JWT without a signature",
            "issuer_jwt_malformed",
            Input::State(state(
                vec![entry(1, 1, 0, "vc+sd-jwt", "eyJhbGciOiJFUzI1NiJ9.e30~")],
                vec![],
            )),
        ),
        (
            "an mdoc that is not base64url",
            "encoding",
            Input::State(state(vec![entry(1, 1, 0, "mso_mdoc", "a+b")], vec![])),
        ),
        // SD-JWT VC
        (
            "no vct",
            "vct_malformed",
            Input::State(vc_state(
                &with(&|p| drop(p.as_object_mut().unwrap().remove("vct"))),
                &[&given_name],
            )),
        ),
        (
            "vct a number",
            "vct_malformed",
            Input::State(vc_state(&with(&|p| p["vct"] = json!(1)), &[&given_name])),
        ),
        (
            "vct selectively disclosed",
            "claim_selectively_disclosed",
            Input::State(vc_state(
                &with(&|p| {
                    drop(p.as_object_mut().unwrap().remove("vct"));
                    p["_sd"] = json!([given_name_digest, vct_digest]);
                }),
                &[&given_name, &vct],
            )),
        ),
        (
            "a sub-claim of cnf selectively disclosed",
            "claim_selectively_disclosed",
            Input::State(vc_state(
                &with(&|p| p["cnf"] = json!({"_sd": [jwk_digest]})),
                &[&given_name, &jwk],
            )),
        ),
        (
            "cnf a string",
            "cnf_malformed",
            Input::State(vc_state(
                &with(&|p| p["cnf"] = json!("key-1")),
                &[&given_name],
            )),
        ),
        (
            "nbf a string",
            "numeric_date_malformed",
            Input::State(vc_state(
                &with(&|p| p["nbf"] = json!("1700000000")),
                &[&given_name],
            )),
        ),
        (
            "exp after 9999",
            "numeric_date_malformed",
            Input::State(vc_state(
                &with(&|p| p["exp"] = json!(253_402_300_800.5)),
                &[&given_name],
            )),
        ),
        // C2
        (
            "a full-date of 2023-02-29",
            "claim_value_untyped",
            Input::Claim(
                mdoc_state(vec![(
                    "issue_date",
                    Cbor::Tag(1004, Box::new(Cbor::text("2023-02-29"))),
                )]),
                element.clone(),
            ),
        ),
        (
            "a tdate with a fraction of a second",
            "claim_value_untyped",
            Input::Claim(
                mdoc_state(vec![("issue_date", tdate("2024-02-29T00:00:00.5Z"))]),
                element,
            ),
        ),
        // C3
        ("an empty pointer", "pointer_empty", Input::Pointer(vec![])),
    ];
    for (case, code, input) in rows {
        assert_eq!(outcome(&input), Err(code), "{case}");
    }
}
