//! The semantics identifier of an access certificate (ETSI TS 119 475, Clauses 5.1.3 and
//! 5.1.5): one row per refusal, and one accepting row per person.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod support;

use serde_json::json;
use siros_oid4vp::{IntakeState, SemanticIdError};
use support::*;

const DNS: &str = "verifier.example";
const NATURAL: &str = "0.4.0.194118.1.1";
const LEGAL: &str = "0.4.0.194118.1.4";

/// The semantics identifier intake reads from a request signed under a certificate of
/// `subject` with `policies`.
fn semantic_id(subject: &str, policies: Policies) -> Result<String, SemanticIdError> {
    let key = key(1);
    let certificate = subject_certificate(&key, &[DNS], subject, policies);
    let client_id = format!("x509_san_dns:{DNS}");
    let payload = json!({
        "client_id": client_id,
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "response_uri": "https://verifier.example/post",
        "nonce": "n-0S6_WzA2Mj",
        "dcql_query": query(),
    });
    let jws = sign(&x5c_header(&certificate), &payload, &key);
    let uri = authorization_uri(&[("client_id", &client_id), ("request", &jws)]);
    let state = IntakeState::redirect(&uri, formats(), NOW, &mut Rng(1));
    let host = Host::trusting();
    let (request, _) = run(state, |effect| host.answer(effect)).unwrap();
    let certificate = request.access_certificate().unwrap();
    certificate
        .semantic_identifier()
        .map(|identifier| identifier.as_str().to_owned())
}

#[test]
fn the_access_certificate_names_its_wallet_relying_party() {
    let legal = Policies::Listed(&[LEGAL]);
    let natural = Policies::Listed(&[NATURAL]);
    let org = |value: &str| format!("CN=Verifier,2.5.4.97={value}");
    // (case, subject, policies, outcome)
    let cases: [(&str, String, Policies, Result<&str, SemanticIdError>); 13] = [
        (
            "a legal person's organizationIdentifier",
            org("VATBE-0876866142"),
            legal,
            Ok("VATBE-0876866142"),
        ),
        (
            "a natural person's serialNumber, an employer's organizationIdentifier beside it",
            "CN=Jane Doe,O=Employer AB,2.5.4.97=VATSE-556000000101,2.5.4.5=PNOSE-200007292386"
                .to_owned(),
            natural,
            Ok("PNOSE-200007292386"),
        ),
        (
            "a policies extension that does not decode",
            org("VATBE-0876866142"),
            Policies::Malformed,
            Err(SemanticIdError::Policies),
        ),
        (
            "no access certificate policy",
            org("VATBE-0876866142"),
            Policies::Listed(&[]),
            Err(SemanticIdError::Unclassified),
        ),
        (
            "both a natural and a legal person policy",
            org("VATBE-0876866142"),
            Policies::Listed(&[NATURAL, LEGAL]),
            Err(SemanticIdError::Contradictory),
        ),
        (
            "a natural person without serialNumber",
            org("VATBE-0876866142"),
            natural,
            Err(SemanticIdError::Absent),
        ),
        (
            "two organizationIdentifiers",
            "CN=Verifier,2.5.4.97=VATBE-0876866142,2.5.4.97=NTRBE-0876866142".to_owned(),
            legal,
            Err(SemanticIdError::Repeated),
        ),
        (
            "a serialNumber in a UTF8String",
            // UTF8String "PNOSE-1".
            "CN=Jane Doe,2.5.4.5=#0c07504e4f53452d31".to_owned(),
            natural,
            Err(SemanticIdError::Encoding),
        ),
        (
            "a natural person's type reference for a legal person",
            org("PNOSE-200007292386"),
            legal,
            Err(SemanticIdError::TypeReference),
        ),
        (
            "a lowercase country code",
            org("VATbe-0876866142"),
            legal,
            Err(SemanticIdError::Country),
        ),
        (
            "no hyphen-minus",
            org("VATBE0876866142"),
            legal,
            Err(SemanticIdError::Separator),
        ),
        (
            "an empty identifier",
            org("VATBE-"),
            legal,
            Err(SemanticIdError::Identifier),
        ),
        (
            "a control character",
            // UTF8String "VATBE-08\u{1}".
            "CN=Verifier,2.5.4.97=#0c0956415442452d303801".to_owned(),
            legal,
            Err(SemanticIdError::Character),
        ),
    ];
    for (case, subject, policies, outcome) in cases {
        let read = semantic_id(&subject, policies);
        assert_eq!(read.as_deref().map_err(|e| *e), outcome, "{case}");
    }
}
