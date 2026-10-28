//! Signed and multisigned requests, through the real binary.

use super::*;

// `request()` in main.rs sends the unsigned shape under the unsigned label. These
// send what a verifier actually sends for the two signed protocols: a JWS the
// matcher has to decode before it can see a query at all. Which shape is
// accepted follows the protocol id, so these cannot be reached by relabelling
// an inline request.

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
