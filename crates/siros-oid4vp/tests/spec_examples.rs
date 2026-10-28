//! The request examples of OpenID4VP 1.0 reach the results the specification states.
//!
//! The examples elide parts (`{...}`) and carry illustrative signatures. Each test names its
//! source, what it fills in, and what it changes; a signature is made with a test key under a
//! certificate or DID key the host vouches for.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use serde_json::{json, Value};
use siros_oid4vp::{
    ClientIdPrefix, Effect, EffectResult, IntakeState, KeyMaterial, Kid, Origin, RequestUriMethod,
};
use support::*;

/// SOURCE: OpenID4VP 1.0, Section 5.4, the DCQL query of the Request Object by value.
fn identity_query() -> Value {
    json!({"credentials": [{
        "id": "some_identity_credential",
        "format": "dc+sd-jwt",
        "meta": {"vct_values": ["https://credentials.example.com/identity_credential"]},
        "claims": [{"path": ["last_name"]}, {"path": ["first_name"]}]
    }]})
}

/// SOURCE: Section 5.4, the request by reference with `request_uri_method=post`, and Section
/// 5.10.1, the payload of its Request Object, signed with ES256 under a certificate for
/// `client.example.org`. `dcql_query` is that of Section 5.4.
///
/// Stated: the wallet sends `wallet_metadata` and `wallet_nonce` as form parameters (Section
/// 5.10), and the Request Object holding the `wallet_nonce` sent verifies (Section 5.10.1).
#[test]
fn request_uri_post() {
    let key = key(7);
    let certificate = certificate(&key, &["client.example.org"]);
    let uri = authorization_uri(&[
        ("client_id", "x509_san_dns:client.example.org"),
        (
            "request_uri",
            "https://client.example.org/request/vapof4ql2i7m41m68uep",
        ),
        ("request_uri_method", "post"),
    ]);
    let document = |wallet_nonce: &str| {
        // SOURCE: Section 5.10.1, the payload of the Request Object.
        let payload = json!({
            "client_id": "x509_san_dns:client.example.org",
            "response_uri": "https://client.example.org/post",
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "dcql_query": identity_query(),
            "nonce": "n-0S6_WzA2Mj",
            "wallet_nonce": wallet_nonce,
            "state": "eyJhb...6-sVA"
        });
        request_object(&sign(&x5c_header(&certificate), &payload, &key))
    };
    let host = Host::trusting();
    let answer = |effect: &Effect| match effect {
        Effect::RequestObject(request) => {
            assert_eq!(
                request.uri().as_str(),
                "https://client.example.org/request/vapof4ql2i7m41m68uep"
            );
            let RequestUriMethod::Post(parameters) = request.method() else {
                panic!("post, got {request:?}")
            };
            let fields = form(parameters.form().as_str());
            let field = |name: &str| fields.iter().find(|(n, _)| n == name).unwrap().1.clone();
            assert_eq!(fields.len(), 2);
            let metadata: Value = serde_json::from_str(&field("wallet_metadata")).unwrap();
            assert_eq!(metadata["vp_formats_supported"], Value::Object(formats()));
            assert_eq!(
                &metadata,
                &Value::Object(parameters.wallet_metadata().as_map().clone())
            );
            assert_eq!(field("wallet_nonce"), parameters.wallet_nonce().as_str());
            EffectResult::RequestObject(document(parameters.wallet_nonce().as_str()))
        }
        Effect::Trust(_) => host.answer(effect),
    };

    let state = IntakeState::redirect(&uri, formats(), now(), &mut Rng(3));
    let (request, effects) = run(state, answer).unwrap();
    assert_eq!(
        request.verifier().client_id().unwrap().as_str(),
        "x509_san_dns:client.example.org"
    );
    assert_eq!(
        request.response_uri().unwrap().as_str(),
        "https://client.example.org/post"
    );
    assert!(matches!(
        effects.as_slice(),
        [Effect::RequestObject(_), Effect::Trust(_)]
    ));
}

/// SOURCE: Appendix A.3.2.2, the payload and a protected header of a request in the JWS JSON
/// Serialization; the header gains `typ` (Section 5), its `x5c` is a certificate for
/// `rp.example.com`, and `dcql_query` is that of Section 5.4.
///
/// Stated: `client_id` travels in the protected header, and the request is that client's.
#[test]
fn multisigned_dc_api() {
    let key = key(11);
    let certificate = certificate(&key, &["rp.example.com"]);
    let payload = json!({
        "expected_origins": ["https://origin1.example.com", "https://origin2.example.com"],
        "response_type": "vp_token",
        "response_mode": "dc_api",
        "nonce": "n-0S6_WzA2Mj",
        "dcql_query": identity_query(),
        "client_metadata": {"jwks": {"keys": [{
            "kty": "EC", "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "use": "enc", "kid": "1"
        }]}}
    });
    let payload_b64 = b64(payload.to_string().as_bytes());
    let protected = json!({
        "alg": "ES256",
        "typ": "oauth-authz-req+jwt",
        "x5c": [b64_padded(&certificate)],
        "client_id": "x509_san_dns:rp.example.com"
    });
    let data = json!({"request": {
        "payload": payload_b64,
        "signatures": [signature_object(&protected, &payload_b64, &key)]
    }});
    let state = IntakeState::dc_api(
        &dc_api("openid4vp-v1-multisigned", data),
        Origin::new("https://origin2.example.com"),
        now(),
    );
    let host = Host::trusting();
    let (request, _) = run(state, |e| host.answer(e)).unwrap();
    assert_eq!(
        request.verifier().client_id().unwrap().as_str(),
        "x509_san_dns:rp.example.com"
    );
}

/// SOURCE: Section 5.9.3, the Request Object of a `decentralized_identifier` client, passed by
/// value. `alg` is ES256 for RS256 (this core verifies ES256 only); `response_mode`
/// `direct_post` and `response_uri` stand for its `redirect_uri` (redirects use
/// `direct_post`); `dcql_query` is that of Section 5.4.
///
/// Stated: the key is the one `kid` names in the DID Document, which the host resolves.
#[test]
fn decentralized_identifier_by_value() {
    let key = key(13);
    let header = json!({"typ": "oauth-authz-req+jwt", "alg": "ES256", "kid": "did:example:123#1"});
    let payload = json!({
        "client_id": "decentralized_identifier:did:example:123",
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "response_uri": "https://client.example.org/callback",
        "nonce": "n-0S6_WzA2Mj",
        "dcql_query": identity_query(),
        "client_metadata": {"vp_formats_supported": {
            "dc+sd-jwt": {"sd-jwt_alg_values": ["ES256", "ES384"], "kb-jwt_alg_values": ["ES256", "ES384"]}
        }}
    });
    let uri = authorization_uri(&[
        ("client_id", "decentralized_identifier:did:example:123"),
        ("request", &sign(&header, &payload, &key)),
    ]);
    let host = Host {
        keys: vec![("did:example:123#1".into(), jwk(key.verifying_key()))],
        ..Host::trusting()
    };
    let state = IntakeState::redirect(&uri, formats(), now(), &mut Rng(6));
    let (request, effects) = run(state, |e| host.answer(e)).unwrap();
    assert_eq!(
        request.verifier().client_id().unwrap().prefix(),
        ClientIdPrefix::DecentralizedIdentifier
    );
    let [Effect::Trust(trust)] = effects.as_slice() else {
        panic!("one trust effect, got {effects:?}")
    };
    assert_eq!(
        trust.key(),
        &KeyMaterial::Resolve {
            kid: Some(Kid::new("did:example:123#1")),
            trust_chain: None
        }
    );
}
