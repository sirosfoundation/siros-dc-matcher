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
    read_reply, ClientIdPrefix, ContentEncryption, Effect, ErrorCode, FetchResponse, IntakeError,
    IntakeState, KeyMaterial, Method, Presentation, ResponseMode, Submission, TrustSubject,
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

/// SOURCE: Section 8.2, the Request Object with Response Mode `direct_post`, sent as parameters
/// by value: a `redirect_uri` client's request is unsigned (Section 5.9.3). `dcql_query` is
/// that of Section 5.4; the presentation is that of Section 8.1.1.
///
/// Stated: the response is a POST of `vp_token` and `state` to the Response URI, and the
/// Response URI's reply sends the user agent to its `redirect_uri`.
#[test]
fn direct_post_by_value() {
    let query = identity_query().to_string();
    let uri = authorization_uri(&[
        ("client_id", "redirect_uri:https://client.example.org/post"),
        ("response_uri", "https://client.example.org/post"),
        ("response_type", "vp_token"),
        ("response_mode", "direct_post"),
        ("dcql_query", &query),
        ("nonce", "n-0S6_WzA2Mj"),
        ("state", "eyJhb...6-sVA"),
    ]);
    let state = IntakeState::redirect(&uri, formats(), NOW, &mut Rng(1));
    let host = Host::trusting();
    let (request, effects) = run(state, |e| host.answer(e)).unwrap();

    let client_id = request.verifier().client_id().unwrap();
    assert_eq!(client_id.prefix(), ClientIdPrefix::RedirectUri);
    assert_eq!(client_id.value(), "https://client.example.org/post");
    assert_eq!(request.response_mode(), ResponseMode::DirectPost);
    assert_eq!(request.state(), Some("eyJhb...6-sVA"));
    let [Effect::Trust(trust)] = effects.as_slice() else {
        panic!("one trust effect, got {effects:?}")
    };
    assert_eq!(trust.subject(), &TrustSubject::Client(client_id.clone()));
    assert_eq!(trust.key(), &KeyMaterial::None);

    let presentation = Presentation::text("eyJhbGci...QMA".into());
    let token = request
        .vp_token(vec![(
            "some_identity_credential".into(),
            vec![presentation],
        )])
        .unwrap();
    let Submission::Post(post) = token.submission(&mut Rng(2)).unwrap() else {
        panic!("a POST")
    };
    assert_eq!(post.url().as_str(), "https://client.example.org/post");
    let Method::Post { content_type, body } = post.method() else {
        panic!("a POST")
    };
    assert_eq!(*content_type, "application/x-www-form-urlencoded");
    let fields = form(std::str::from_utf8(body).unwrap());
    let field = |name: &str| fields.iter().find(|(n, _)| n == name).unwrap().1.clone();
    assert_eq!(field("state"), "eyJhb...6-sVA");
    assert_eq!(
        serde_json::from_str::<Value>(&field("vp_token")).unwrap(),
        json!({"some_identity_credential": ["eyJhbGci...QMA"]})
    );
    assert_eq!(fields.len(), 2);

    // SOURCE: Section 8.2, the response of the Response URI to the wallet.
    let reply = FetchResponse::new(
        200,
        Some("application/json".into()),
        br#"{"redirect_uri": "https://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee"}"#
            .to_vec(),
    );
    assert_eq!(
        read_reply(&reply).unwrap().as_deref(),
        Some("https://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee")
    );
}

/// SOURCE: Section 5.4, the request by reference with `request_uri_method=post`, and Section
/// 5.10.1, the payload of its Request Object, signed with ES256 under a certificate for
/// `client.example.org`. `dcql_query` is that of Section 5.4.
///
/// Stated: the wallet POSTs `wallet_metadata` and `wallet_nonce` (Section 5.10); the Request
/// Object must hold the `wallet_nonce` sent, or processing terminates (Section 5.10.1).
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
    let host = &Host::trusting();
    let document = &document;
    let answer = |echo: bool| {
        move |effect: &Effect| match effect {
            Effect::Fetch(fetch) => {
                let Method::Post { body, .. } = fetch.method() else {
                    panic!("a POST")
                };
                let body = std::str::from_utf8(body).unwrap();
                assert_eq!(fetch.accept(), "application/oauth-authz-req+jwt");
                let fields = form(body);
                let field = |name: &str| fields.iter().find(|(n, _)| n == name).unwrap().1.clone();
                let metadata: Value = serde_json::from_str(&field("wallet_metadata")).unwrap();
                assert_eq!(metadata["vp_formats_supported"], Value::Object(formats()));
                let nonce = if echo {
                    field("wallet_nonce")
                } else {
                    "qPmxiNFCR3QTm19POc8u".into()
                };
                siros_oid4vp::EffectResult::Fetched(document(&nonce))
            }
            Effect::Trust(_) => host.answer(effect),
        }
    };

    let state = IntakeState::redirect(&uri, formats(), NOW, &mut Rng(3));
    let (request, _) = run(state.clone(), answer(true)).unwrap();
    assert_eq!(
        request.verifier().client_id().unwrap().as_str(),
        "x509_san_dns:client.example.org"
    );
    assert_eq!(
        request.response_uri().unwrap().as_str(),
        "https://client.example.org/post"
    );
    assert_eq!(
        run(state, answer(false)).unwrap_err(),
        IntakeError::WalletNonceMismatch
    );
}

/// SOURCE: Section 8.3, the request asking for an encrypted response with four keys in
/// `client_metadata.jwks`, sent over the DC API unsigned.
///
/// Stated: the response is encrypted to the first key, `kid` `ac`, with `ECDH-ES` and
/// `A128GCM`, and the JWE header names both and the key.
#[test]
fn encrypted_response_key_choice() {
    let data = json!({
        "response_type": "vp_token",
        "response_mode": "dc_api.jwt",
        "nonce": "xyz123ltcaccescbwc777",
        "dcql_query": {"credentials": [{
            "id": "my_credential",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["https://credentials.example.com/identity_credential"]},
            "claims": [
                {"path": ["last_name"]},
                {"path": ["first_name"]},
                {"path": ["address", "postal_code"]}
            ]
        }]},
        "client_metadata": {
            "jwks": {"keys": [
                {"kty": "EC", "kid": "ac", "use": "enc", "crv": "P-256", "alg": "ECDH-ES",
                 "x": "YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
                 "y": "Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk"},
                {"kty": "OKP", "kid": "jc", "use": "enc", "crv": "X25519", "alg": "ECDH-ES",
                 "x": "WPX7wnwq10hFNK9aDSyG1QlLswE_CJY14LdhcFUIVVc"},
                {"kty": "EC", "kid": "lc", "use": "enc", "crv": "P-384", "alg": "ECDH-ES",
                 "x": "iHytgLNtXjEyYMAIGwfgjINZRmLfObYbmjPhkaPD8OiTkJtRHjegTNdH31Mxg4nV",
                 "y": "MizXWSqNB7sSt_SNjg3spvaJnmjB-LpxsPpLUaea33rvINL3Mq-gEaANErRQpbLx"},
                {"kty": "OKP", "kid": "bc", "use": "enc", "crv": "X448", "alg": "ECDH-ES",
                 "x": "pK5IRpLlX-8XcsRYWHejpzkfsHoDOmAYuBzAC7aTpewWOw_QFHSa64t9p2kuommI8JQQLohS2AIA"}
            ]},
            "encrypted_response_enc_values_supported": ["A128GCM", "A128CBC-HS256"]
        }
    });
    let state = IntakeState::dc_api(
        &dc_api("openid4vp-v1-unsigned", data),
        "https://verifier.example.com",
        NOW,
    );
    let host = Host::trusting();
    let (request, _) = run(state, |e| host.answer(e)).unwrap();
    let encryption = request.encryption().unwrap();
    assert_eq!(encryption.kid(), Some("ac"));
    assert_eq!(encryption.enc(), ContentEncryption::A128Gcm);
    assert_eq!(request.response_mode(), ResponseMode::DcApiJwt);

    let token = request
        .vp_token(vec![(
            "my_credential".into(),
            vec![Presentation::text("eyJhb...YMetA".into())],
        )])
        .unwrap();
    let Submission::DcApi(data) = token.submission(&mut Rng(4)).unwrap() else {
        panic!("a DC API response")
    };
    let jwe = data["response"].as_str().unwrap();
    let header: Value = serde_json::from_slice(
        &siros_codec::base64url::decode(jwe.split('.').next().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(header["alg"], "ECDH-ES");
    assert_eq!(header["enc"], "A128GCM");
    assert_eq!(header["kid"], "ac");
    assert_eq!(header["epk"]["kty"], "EC");
    assert_eq!(header["epk"]["crv"], "P-256");
}

/// SOURCE: Appendix A.2, the unsigned request over the DC API; `client_metadata` holds
/// `vp_formats_supported` and `dcql_query` the query of Section 5.4.
///
/// Stated: the request carries no `client_id`, the verifier is the origin, and the response
/// is the object `{vp_token}` within `data` (A.4).
#[test]
fn unsigned_dc_api() {
    let data = json!({
        "response_type": "vp_token",
        "response_mode": "dc_api",
        "nonce": "n-0S6_WzA2Mj",
        "client_metadata": {"vp_formats_supported": {"dc+sd-jwt": {}}},
        "dcql_query": identity_query()
    });
    let origin = "https://verifier.example.com";
    let state = IntakeState::dc_api(&dc_api("openid4vp-v1-unsigned", data), origin, NOW);
    let host = Host::trusting();
    let (request, effects) = run(state, |e| host.answer(e)).unwrap();
    assert_eq!(request.verifier().client_id(), None);
    assert_eq!(request.verifier().display(), origin);
    assert_eq!(request.origin(), Some(origin));
    let [Effect::Trust(trust)] = effects.as_slice() else {
        panic!("one trust effect, got {effects:?}")
    };
    assert_eq!(trust.subject(), &TrustSubject::Origin(origin.into()));

    let token = request
        .vp_token(vec![(
            "some_identity_credential".into(),
            vec![Presentation::text("a~b~".into())],
        )])
        .unwrap();
    assert_eq!(
        token.submission(&mut Rng(5)).unwrap(),
        Submission::DcApi(json!({"vp_token": {"some_identity_credential": ["a~b~"]}}))
    );
}

/// SOURCE: Appendix A.3.2.1, the payload of a signed request in the JWS Compact Serialization,
/// signed with ES256 under a certificate for `rp.example.com`; `dcql_query` is that of
/// Section 5.4.
///
/// Stated: the request verifies from an origin in `expected_origins`; from any other the
/// wallet returns an error, `invalid_request` (A.2), as `{"error": …}` (A.4).
#[test]
fn signed_dc_api() {
    let key = key(9);
    let certificate = certificate(&key, &["rp.example.com"]);
    let payload = json!({
        "expected_origins": ["https://origin1.example.com", "https://origin2.example.com"],
        "client_id": "x509_san_dns:rp.example.com",
        "client_metadata": {"jwks": {"keys": [{
            "kty": "EC", "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "use": "enc", "kid": "1"
        }]}},
        "response_type": "vp_token",
        "response_mode": "dc_api",
        "nonce": "n-0S6_WzA2Mj",
        "dcql_query": identity_query()
    });
    let request = dc_api(
        "openid4vp-v1-signed",
        json!({"request": sign(&x5c_header(&certificate), &payload, &key)}),
    );
    let host = Host::trusting();

    let state = IntakeState::dc_api(&request, "https://origin1.example.com", NOW);
    let (verified, _) = run(state, |e| host.answer(e)).unwrap();
    assert_eq!(
        verified.verifier().client_id().unwrap().as_str(),
        "x509_san_dns:rp.example.com"
    );
    assert_eq!(verified.response_mode(), ResponseMode::DcApi);

    let state = IntakeState::dc_api(&request, "https://attacker.example", NOW);
    let error = run(state.clone(), |e| host.answer(e)).unwrap_err();
    assert_eq!(error, IntakeError::OriginNotExpected);
    assert_eq!(error.error_code(), ErrorCode::InvalidRequest);
    assert_eq!(
        state.error_submission(error),
        Some(Submission::DcApi(json!({"error": "invalid_request"})))
    );
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
        "https://origin2.example.com",
        NOW,
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
    let state = IntakeState::redirect(&uri, formats(), NOW, &mut Rng(6));
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
            kid: Some("did:example:123#1".into()),
            trust_chain: None
        }
    );
}
