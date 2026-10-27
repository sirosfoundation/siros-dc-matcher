//! The signed request shapes and the verifier's purpose, through the shipping binary.

use crate::*;

/// Unpadded base64url, so a test does not hand-encode its own payload.
fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..chunk.len() + 1 {
            let idx = ((n >> (18 - 6 * i)) & 0x3F) as usize;
            out.push(char::from(A[idx]));
        }
    }
    out
}

/// The authorization request object the signed protocols carry as a payload.
fn signed_request_object() -> String {
    json!({
        "client_id": "x509_san_dns:verifier.example",
        "response_mode": "dc_api.jwt",
        "nonce": "n-0S6_WzA2Mj",
        "expected_origins": ["https://verifier.example.org"],
        "dcql_query": {"credentials": [{
            "id": "q1",
            "format": "mso_mdoc",
            "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
            "claims": [{"path": ["org.iso.18013.5.1", "age_over_18"]}]
        }]},
        "client_metadata": {"jwks": {"keys": []}}
    })
    .to_string()
}

fn envelope(protocol: &str, data: Value) -> Vec<u8> {
    json!({"requests": [{"protocol": protocol, "data": data}]})
        .to_string()
        .into_bytes()
}

/// A signed request produces a picker entry, which it never did before: the
/// binary read only `data.dcql_query`, so a verifier offering just this
/// protocol got nothing and no way to find out why.
#[test]
fn a_signed_request_produces_an_entry() {
    let jws = format!(
        "{}.{}.{}",
        b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#),
        b64(signed_request_object().as_bytes()),
        b64(b"signature")
    );

    let captured = invoke(
        &wallet(None),
        envelope("openid4vp-v1-signed", json!({"request": jws})),
    );

    assert_eq!(captured.sets, vec![("siros-0".to_string(), 1)]);
    let entry = captured.entry("siros-0", 0).expect("one entry");
    assert_eq!(entry.credential_id, "mdl-1");
    assert!(
        !entry.icon.is_empty(),
        "the host silently drops an entry whose icon is null"
    );
}

/// The multisigned shape reaches the same place by a different member.
#[test]
fn a_multisigned_request_produces_an_entry() {
    let data = json!({"request": {
        "payload": b64(signed_request_object().as_bytes()),
        "signatures": [{
            "protected": b64(br#"{"alg":"ES256"}"#),
            "signature": b64(b"signature")
        }]
    }});

    let captured = invoke(&wallet(None), envelope("openid4vp-v1-multisigned", data));
    assert_eq!(captured.sets, vec![("siros-0".to_string(), 1)]);
    assert_eq!(
        captured
            .entry("siros-0", 0)
            .expect("one entry")
            .credential_id,
        "mdl-1"
    );
}

/// A truncated JWS emits nothing and, more importantly, does not trap: a
/// trapped matcher shows the user exactly what "no matching credential" shows.
#[test]
fn a_truncated_signed_request_emits_nothing_without_trapping() {
    let captured = invoke(
        &wallet(None),
        envelope(
            "openid4vp-v1-signed",
            json!({"request": "aGVhZGVy.dHJ1bmM"}),
        ),
    );
    assert!(captured.sets.is_empty());
}

/// Protocol negotiation, end to end through the binary: the verifier offers a
/// signed request this build cannot read and an unsigned one it can, and the
/// second is answered.
#[test]
fn the_binary_falls_through_to_a_protocol_it_can_read() {
    let unsigned: Value = serde_json::from_str(&signed_request_object()).expect("json");
    let request = json!({"requests": [
        {"protocol": "openid4vp-v1-signed", "data": {"request": "@@@not-a-jws@@@"}},
        {"protocol": "openid4vp-v1-unsigned", "data": unsigned}
    ]})
    .to_string()
    .into_bytes();

    let captured = invoke(&wallet(None), request);
    assert_eq!(
        captured.sets,
        vec![("siros-0".to_string(), 1)],
        "the unsigned entry should have been answered"
    );
}

/// A request carrying `purpose`, so the reason reaches the picker.
fn request_with_purpose(purpose: Value) -> Vec<u8> {
    json!({"requests": [{
        "protocol": "openid4vp-v1-unsigned",
        "data": {"dcql_query": {
            "credentials": [{
                "id": "q1",
                "format": "mso_mdoc",
                "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                "claims": [{"path": ["org.iso.18013.5.1", "age_over_18"]}]
            }],
            "credential_sets": [{"options": [["q1"]], "purpose": purpose}]
        }}
    }]})
    .to_string()
    .into_bytes()
}

/// §6.2 `purpose` reaches the host as the entry's disclaimer, so the picker
/// can tell the user what they are consenting to and not merely that they are.
#[test]
fn a_verifier_purpose_is_shown_on_the_entry() {
    let db = wallet(None);
    let captured = invoke(
        &db,
        request_with_purpose(json!("Confirming you are over 18")),
    );

    let entry = captured.entry("siros-0", 0).expect("an entry");
    assert_eq!(
        entry.disclaimer.as_deref(),
        Some("Confirming you are over 18")
    );
    assert_eq!(entry.warning, None, "a reason to ask is not a warning");
}

/// A verifier that gives no reason produces a null pointer, not a pointer to
/// an empty string.
///
/// The distinction is the v0.6.1 bug exactly: the host renders the *presence*
/// of this field, so an empty string draws a label with nothing in it. Every
/// entry carried a warning triangle that way, on a real Pixel, for two
/// releases.
#[test]
fn no_purpose_means_a_null_disclaimer_not_an_empty_one() {
    let db = wallet(None);
    let captured = invoke(
        &db,
        request(
            "mso_mdoc",
            json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
        ),
    );

    let entry = captured.entry("siros-0", 0).expect("an entry");
    assert_eq!(
        entry.disclaimer, None,
        "absent must be a null pointer; Some(\"\") is what put a badge on \
         every entry before v0.6.2"
    );
    assert_eq!(entry.warning, None);
}

/// A verifier that sends `purpose: ""` is saying nothing, and must be treated
/// as such rather than passed through into a blank label — the same bug,
/// arriving from the other side.
#[test]
fn an_empty_purpose_is_treated_as_no_purpose() {
    let db = wallet(None);
    let captured = invoke(&db, request_with_purpose(json!("   ")));

    let entry = captured.entry("siros-0", 0).expect("an entry");
    assert_eq!(entry.disclaimer, None);
}

/// §6.2's object and integer forms are machine-readable identifiers, and they
/// do not go on the consent screen.
///
/// Established by looking: before this rule, an object purpose put
/// `{"id":7,"name":"Age verification"}` on a real Pixel's share sheet, under
/// the list of attributes about to be disclosed. The application still gets it
/// over the FFI, where a lookup is possible; the picker shows nothing rather
/// than showing that.
#[test]
fn a_machine_readable_purpose_is_not_put_on_the_consent_screen() {
    let db = wallet(None);
    let captured = invoke(&db, request_with_purpose(json!({"id": 7})));

    let entry = captured.entry("siros-0", 0).expect("an entry");
    assert_eq!(entry.disclaimer, None);
    assert_eq!(entry.warning, None);
}
