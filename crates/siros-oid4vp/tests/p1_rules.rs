//! P1: one fixture per construction rule of `VerifiedRequest`. Each refusal names the exact
//! rule it breaks; each fixture starts from a request that verifies and changes one thing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_oid4vp::{
    Effect, EffectResult, FetchResponse, IntakeError, IntakeState, Origin, TrustSubject,
};
use support::*;

const ORIGIN: &str = "https://verifier.example";
const DNS: &str = "verifier.example";
const ATTESTATION_ISSUER: &str = "https://attestation-issuer.example";
const FEDERATION: &str = "openid_federation:https://federation-verifier.example";

/// What a fixture must give: a refusal, a request of this client and trust verdict, or the
/// panic of a host that breaks the effect protocol.
enum Expect {
    Refused(IntakeError),
    Verified {
        client_id: &'static str,
        trusted: bool,
    },
    Panics(&'static str),
}

type Answer = Box<dyn Fn(&Effect) -> EffectResult>;

struct Fixture {
    rule: &'static str,
    state: IntakeState,
    answer: Answer,
    expect: Expect,
}

fn honest(host: Host) -> Answer {
    Box::new(move |e| host.answer(e))
}

/// The parameters of a redirect request of `client_id`.
fn redirect_payload(client_id: &str) -> Value {
    json!({
        "client_id": client_id,
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "response_uri": "https://verifier.example/post",
        "nonce": "n-0S6_WzA2Mj",
        "dcql_query": query(),
    })
}

/// The parameters of a signed DC API request of `client_id`.
fn dc_api_payload(client_id: &str) -> Value {
    json!({
        "client_id": client_id,
        "expected_origins": [ORIGIN],
        "response_type": "vp_token",
        "response_mode": "dc_api",
        "nonce": "n-0S6_WzA2Mj",
        "dcql_query": query(),
    })
}

/// A Request Object by value under the `client_id` parameter `outer`.
fn by_value(outer: &str, jws: &str) -> IntakeState {
    let uri = authorization_uri(&[("client_id", outer), ("request", jws)]);
    IntakeState::redirect(&uri, formats(), now(), &mut Rng(1))
}

/// An `x509_san_dns` request by value: `x5c` holds a certificate of `certified` naming
/// `san`, and `signer` signs.
fn x509_san_dns(
    san: &str,
    certified: &SigningKey,
    signer: &SigningKey,
    payload: Value,
) -> IntakeState {
    let jws = sign(
        &x5c_header(&certificate(certified, &[san])),
        &payload,
        signer,
    );
    by_value(payload["client_id"].as_str().unwrap(), &jws)
}

fn x509_client() -> String {
    format!("x509_san_dns:{DNS}")
}

fn signed_dc_api(payload: Value, origin: &str) -> IntakeState {
    let key = key(1);
    let jws = sign(&x5c_header(&certificate(&key, &[DNS])), &payload, &key);
    IntakeState::dc_api(
        &dc_api("openid4vp-v1-signed", json!({"request": jws})),
        Origin::new(origin),
        now(),
    )
}

fn unsigned_dc_api(change: impl Fn(&mut Value)) -> IntakeState {
    let mut data = json!({
        "response_type": "vp_token",
        "response_mode": "dc_api",
        "nonce": "n-0S6_WzA2Mj",
        "dcql_query": query(),
    });
    change(&mut data);
    IntakeState::dc_api(
        &dc_api("openid4vp-v1-unsigned", data),
        Origin::new(ORIGIN),
        now(),
    )
}

/// A `decentralized_identifier` request by value whose `kid` is `kid`, signed by `signer`;
/// the host resolves `did:example:123#key-1` to `key(3)`.
fn did(kid: &str, signer: &SigningKey) -> (IntakeState, Answer) {
    let client_id = "decentralized_identifier:did:example:123";
    let header = json!({"alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": kid});
    let jws = sign(&header, &redirect_payload(client_id), signer);
    let host = Host {
        keys: vec![("did:example:123#key-1".into(), jwk(key(3).verifying_key()))],
        ..Host::trusting()
    };
    (by_value(client_id, &jws), honest(host))
}

/// A `verifier_attestation` request by value. `issuer` signs the attestation under its `x5c`;
/// `cnf` is the attested key; `signer` signs the request.
fn attestation(
    sub: &str,
    exp: u64,
    issuer: &SigningKey,
    cnf: &SigningKey,
    signer: &SigningKey,
) -> IntakeState {
    let issuer_certificate = certificate(&key(4), &["attestation-issuer.example"]);
    let attestation = sign(
        &json!({"alg": "ES256", "typ": "verifier-attestation+jwt", "x5c": [b64_padded(&issuer_certificate)]}),
        &json!({"iss": ATTESTATION_ISSUER, "sub": sub, "exp": exp, "cnf": {"jwk": jwk(cnf.verifying_key())}}),
        issuer,
    );
    let client_id = format!("verifier_attestation:{DNS}");
    let header = json!({"alg": "ES256", "typ": "oauth-authz-req+jwt", "jwt": attestation});
    let jws = sign(&header, &redirect_payload(&client_id), signer);
    by_value(&client_id, &jws)
}

/// An `openid_federation` request by value signed by `signer`; the host resolves `fed-1` to
/// `key(6)`, with the Trust Chain's metadata.
fn federation(signer: &SigningKey) -> (IntakeState, Answer) {
    let header = json!({"alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": "fed-1", "trust_chain": ["eyJ.e.s"]});
    let jws = sign(&header, &redirect_payload(FEDERATION), signer);
    let host = Host {
        keys: vec![("fed-1".into(), jwk(key(6).verifying_key()))],
        metadata: Some(json!({"vp_formats_supported": {"dc+sd-jwt": {}}})),
        ..Host::trusting()
    };
    (by_value(FEDERATION, &jws), honest(host))
}

/// An `openid4vp-v1-multisigned` request with one signature per `(dns, certified, signer)`.
fn multisigned(signers: &[(&str, &SigningKey, &SigningKey)], payload: Value) -> IntakeState {
    let payload_b64 = b64(payload.to_string().as_bytes());
    let signatures: Vec<Value> = signers
        .iter()
        .map(|(dns, certified, signer)| {
            let mut protected = x5c_header(&certificate(certified, &[dns]));
            protected["client_id"] = format!("x509_san_dns:{dns}").into();
            signature_object(&protected, &payload_b64, signer)
        })
        .collect();
    let data = json!({"request": {"payload": payload_b64, "signatures": signatures}});
    IntakeState::dc_api(
        &dc_api("openid4vp-v1-multisigned", data),
        Origin::new(ORIGIN),
        now(),
    )
}

fn multisigned_payload() -> Value {
    let mut payload = dc_api_payload("");
    payload.as_object_mut().unwrap().remove("client_id");
    payload
}

/// A host that trusts only the Client Identifier `trusted`.
fn trusting_only(trusted: &'static str) -> Answer {
    Box::new(move |effect| match effect {
        Effect::Trust(trust) => {
            let yes = matches!(trust.subject(), TrustSubject::Client(c) if c.as_str() == trusted);
            EffectResult::Trusted(siros_oid4vp::TrustAnswer::new(yes.into(), None, None))
        }
        Effect::Fetch(_) => panic!("no fetch"),
    })
}

fn fixtures() -> Vec<Fixture> {
    let (a, b) = (key(1), key(2));
    let x509 = x509_client();
    let mut fixtures = vec![
        // The signature verifies under the rule of the Client Identifier Prefix.
        Fixture {
            rule: "x509_san_dns: the leaf certificate names the DNS name",
            state: x509_san_dns("other.example", &a, &a, redirect_payload(&x509)),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::SanMismatch),
        },
        Fixture {
            rule: "x509_san_dns: the leaf certificate's key signs",
            state: x509_san_dns(DNS, &a, &b, redirect_payload(&x509)),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::SignatureInvalid),
        },
        Fixture {
            rule: "x509_hash: the value is the SHA-256 of the leaf certificate",
            state: {
                let other = certificate(&b, &[DNS]);
                let client_id = format!("x509_hash:{}", b64(&Sha256::digest(&other)));
                let jws = sign(
                    &x5c_header(&certificate(&a, &[DNS])),
                    &redirect_payload(&client_id),
                    &a,
                );
                by_value(&client_id, &jws)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::CertificateHashMismatch),
        },
        Fixture {
            rule: "decentralized_identifier: kid is a key of the DID",
            state: did("did:example:456#key-1", &key(3)).0,
            answer: did("did:example:456#key-1", &key(3)).1,
            expect: Expect::Refused(IntakeError::KidNotOfClient),
        },
        Fixture {
            rule: "decentralized_identifier: the resolved key signs",
            state: did("did:example:123#key-1", &a).0,
            answer: did("did:example:123#key-1", &a).1,
            expect: Expect::Refused(IntakeError::SignatureInvalid),
        },
        Fixture {
            rule: "verifier_attestation: the attestation's sub is the client",
            state: attestation("other.example", NOW + 3600, &key(4), &key(5), &key(5)),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::AttestationSubjectMismatch),
        },
        Fixture {
            rule: "verifier_attestation: the attestation has not expired",
            state: attestation(DNS, NOW, &key(4), &key(5), &key(5)),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::AttestationExpired),
        },
        Fixture {
            rule: "verifier_attestation: the cnf key signs the request",
            state: attestation(DNS, NOW + 3600, &key(4), &key(5), &a),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::SignatureInvalid),
        },
        Fixture {
            rule: "verifier_attestation: the issuer's key signs the attestation",
            state: attestation(DNS, NOW + 3600, &a, &key(5), &key(5)),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::AttestationSignatureInvalid),
        },
        Fixture {
            rule: "openid_federation: the Trust Chain's key signs",
            state: federation(&a).0,
            answer: federation(&a).1,
            expect: Expect::Refused(IntakeError::SignatureInvalid),
        },
        Fixture {
            rule: "redirect_uri: a signed request does not use it",
            state: {
                let client_id = "redirect_uri:https://verifier.example/post";
                let jws = sign(
                    &x5c_header(&certificate(&a, &[DNS])),
                    &redirect_payload(client_id),
                    &a,
                );
                by_value(client_id, &jws)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::SignedRedirectUri),
        },
        Fixture {
            rule: "redirect_uri: an unsigned request uses no other prefix",
            state: {
                let query = query().to_string();
                let uri = authorization_uri(&[
                    ("client_id", &x509),
                    ("response_type", "vp_token"),
                    ("response_mode", "direct_post"),
                    ("response_uri", "https://verifier.example/post"),
                    ("nonce", "n-0S6_WzA2Mj"),
                    ("dcql_query", &query),
                ]);
                IntakeState::redirect(&uri, formats(), now(), &mut Rng(1))
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::UnsignedNeedsRedirectUri),
        },
        Fixture {
            rule: "a Request Object has typ oauth-authz-req+jwt",
            state: {
                let mut header = x5c_header(&certificate(&a, &[DNS]));
                header.as_object_mut().unwrap().remove("typ");
                by_value(&x509, &sign(&header, &redirect_payload(&x509), &a))
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::TypMismatch),
        },
        Fixture {
            rule: "a Request Object is signed with ES256",
            state: {
                let mut header = x5c_header(&certificate(&a, &[DNS]));
                header["alg"] = "ES384".into();
                by_value(&x509, &sign(&header, &redirect_payload(&x509), &a))
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::AlgorithmUnsupported),
        },
        // The outer and inner client_id are equal.
        Fixture {
            rule: "the client_id parameter is the Request Object's client_id",
            state: {
                let jws = sign(
                    &x5c_header(&certificate(&a, &[DNS])),
                    &redirect_payload(&x509),
                    &a,
                );
                by_value("x509_san_dns:other.example", &jws)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::ClientIdMismatch),
        },
        // A trust verdict was obtained.
        Fixture {
            rule: "the trust effect is answered by a trust verdict",
            state: x509_san_dns(DNS, &a, &a, redirect_payload(&x509)),
            answer: Box::new(|_| {
                EffectResult::Fetched(FetchResponse::new(HttpStatus::OK, None, Vec::new()))
            }),
            expect: Expect::Panics("the host answered a trust lookup with a fetch response"),
        },
        Fixture {
            rule: "the trust verdict is carried, untrusted included",
            state: x509_san_dns(DNS, &a, &a, redirect_payload(&x509)),
            answer: honest(Host {
                trusted: false,
                ..Host::trusting()
            }),
            expect: Expect::Verified {
                client_id: "x509_san_dns:verifier.example",
                trusted: false,
            },
        },
        // nonce is present.
        Fixture {
            rule: "nonce is present",
            state: {
                let mut payload = redirect_payload(&x509);
                payload.as_object_mut().unwrap().remove("nonce");
                x509_san_dns(DNS, &a, &a, payload)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::NonceInvalid),
        },
        // The response mode belongs to the channel.
        Fixture {
            rule: "redirects use direct_post or direct_post.jwt",
            state: {
                let mut payload = redirect_payload(&x509);
                payload["response_mode"] = "dc_api".into();
                x509_san_dns(DNS, &a, &a, payload)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::ResponseModeUnsupported),
        },
        Fixture {
            rule: "the DC API uses dc_api or dc_api.jwt",
            state: unsigned_dc_api(|data| data["response_mode"] = "direct_post".into()),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::ResponseModeUnsupported),
        },
        // A redirect response has a response_uri.
        Fixture {
            rule: "a redirect request has a response_uri",
            state: {
                let mut payload = redirect_payload(&x509);
                payload.as_object_mut().unwrap().remove("response_uri");
                x509_san_dns(DNS, &a, &a, payload)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::ResponseUriMissing),
        },
        // A signed DC API request lists the calling origin in expected_origins.
        Fixture {
            rule: "a signed DC API request lists the calling origin",
            state: signed_dc_api(dc_api_payload(&x509), "https://attacker.example"),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::OriginNotExpected),
        },
        Fixture {
            rule: "a signed DC API request has expected_origins",
            state: {
                let mut payload = dc_api_payload(&x509);
                payload.as_object_mut().unwrap().remove("expected_origins");
                signed_dc_api(payload, ORIGIN)
            },
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::ExpectedOriginsMissing),
        },
        // An encrypted mode has a chosen key and enc.
        Fixture {
            rule: "an encrypted mode has a P-256 ECDH-ES key",
            state: unsigned_dc_api(|data| {
                data["response_mode"] = "dc_api.jwt".into();
                data["client_metadata"] = json!({"jwks": {"keys": [{
                    "kty": "EC", "crv": "P-384", "alg": "ECDH-ES", "kid": "lc",
                    "x": "iHytgLNtXjEyYMAIGwfgjINZRmLfObYbmjPhkaPD8OiTkJtRHjegTNdH31Mxg4nV",
                    "y": "MizXWSqNB7sSt_SNjg3spvaJnmjB-LpxsPpLUaea33rvINL3Mq-gEaANErRQpbLx"
                }]}});
            }),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::EncryptionKeyMissing),
        },
        Fixture {
            rule: "an encrypted mode has an enc this wallet supports",
            state: unsigned_dc_api(|data| {
                data["response_mode"] = "dc_api.jwt".into();
                let mut key = jwk(key(8).verifying_key());
                key["alg"] = "ECDH-ES".into();
                data["client_metadata"] = json!({
                    "jwks": {"keys": [key]},
                    "encrypted_response_enc_values_supported": ["A128CBC-HS256"]
                });
            }),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::EncryptionUnsupported),
        },
        // Multisigned: the Client Identifier of the first signature that qualifies.
        Fixture {
            rule: "multisigned: a signature that does not verify is passed over",
            state: multisigned(
                &[("a.example", &a, &b), ("b.example", &b, &b)],
                multisigned_payload(),
            ),
            answer: honest(Host::trusting()),
            expect: Expect::Verified {
                client_id: "x509_san_dns:b.example",
                trusted: true,
            },
        },
        Fixture {
            rule: "multisigned: an untrusted signature is passed over for a trusted one",
            state: multisigned(
                &[("a.example", &a, &a), ("b.example", &b, &b)],
                multisigned_payload(),
            ),
            answer: trusting_only("x509_san_dns:b.example"),
            expect: Expect::Verified {
                client_id: "x509_san_dns:b.example",
                trusted: true,
            },
        },
        Fixture {
            rule: "multisigned: with none trusted, the first that verifies",
            state: multisigned(
                &[("a.example", &a, &a), ("b.example", &b, &b)],
                multisigned_payload(),
            ),
            answer: trusting_only("x509_san_dns:c.example"),
            expect: Expect::Verified {
                client_id: "x509_san_dns:a.example",
                trusted: false,
            },
        },
        Fixture {
            rule: "multisigned: some signature verifies",
            state: multisigned(
                &[("a.example", &a, &b), ("b.example", &b, &a)],
                multisigned_payload(),
            ),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::NoVerifiableSignature),
        },
        Fixture {
            rule: "multisigned: client_id is in the protected headers only",
            state: multisigned(
                &[("a.example", &a, &a)],
                dc_api_payload("x509_san_dns:a.example"),
            ),
            answer: honest(Host::trusting()),
            expect: Expect::Refused(IntakeError::ClientIdInPayload),
        },
    ];
    // Each prefix's request verifies before it is broken.
    fixtures.extend([
        Fixture {
            rule: "honest: x509_hash",
            state: {
                let leaf = certificate(&a, &[DNS]);
                let client_id = format!("x509_hash:{}", b64(&Sha256::digest(&leaf)));
                by_value(
                    &client_id,
                    &sign(&x5c_header(&leaf), &redirect_payload(&client_id), &a),
                )
            },
            answer: honest(Host::trusting()),
            expect: Expect::Verified {
                client_id: "x509_hash:",
                trusted: true,
            },
        },
        Fixture {
            rule: "honest: decentralized_identifier",
            state: did("did:example:123#key-1", &key(3)).0,
            answer: did("did:example:123#key-1", &key(3)).1,
            expect: Expect::Verified {
                client_id: "decentralized_identifier:did:example:123",
                trusted: true,
            },
        },
        Fixture {
            rule: "honest: verifier_attestation",
            state: attestation(DNS, NOW + 3600, &key(4), &key(5), &key(5)),
            answer: honest(Host::trusting()),
            expect: Expect::Verified {
                client_id: "verifier_attestation:verifier.example",
                trusted: true,
            },
        },
        Fixture {
            rule: "honest: openid_federation",
            state: federation(&key(6)).0,
            answer: federation(&key(6)).1,
            expect: Expect::Verified {
                client_id: FEDERATION,
                trusted: true,
            },
        },
        Fixture {
            rule: "honest: signed DC API",
            state: signed_dc_api(dc_api_payload(&x509), ORIGIN),
            answer: honest(Host::trusting()),
            expect: Expect::Verified {
                client_id: "x509_san_dns:verifier.example",
                trusted: true,
            },
        },
    ]);
    fixtures
}

#[test]
fn each_construction_rule_of_verified_request() {
    for fixture in fixtures() {
        if let Expect::Panics(message) = fixture.expect {
            let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(fixture.state, &fixture.answer)
            }))
            .err()
            .unwrap_or_else(|| panic!("{}: no panic, expected {message:?}", fixture.rule));
            let text = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
            assert_eq!(text, Some(message), "{}", fixture.rule);
            continue;
        }
        let outcome = run(fixture.state, &fixture.answer);
        match (fixture.expect, outcome) {
            (Expect::Refused(expected), Err(error)) => {
                assert_eq!(error, expected, "{}", fixture.rule);
            }
            (Expect::Verified { client_id, trusted }, Ok((request, _))) => {
                let verifier = request.verifier();
                assert!(
                    verifier
                        .client_id()
                        .unwrap()
                        .as_str()
                        .starts_with(client_id),
                    "{}: {:?}",
                    fixture.rule,
                    verifier.client_id()
                );
                assert_eq!(verifier.verdict(), trusted.into(), "{}", fixture.rule);
            }
            (Expect::Refused(expected), Ok(_)) => {
                panic!("{}: verified, expected {expected:?}", fixture.rule)
            }
            (Expect::Verified { .. }, Err(error)) => {
                panic!("{}: refused with {error:?}", fixture.rule)
            }
            (Expect::Panics(_), _) => unreachable!("a panic fixture runs above"),
        }
    }
}
