//! The verification of an ad-hoc metadata JWT (PaSO Proof Metadata, Section 5.3) and of a
//! signed credential metadata JWT (Section 7): a row per step, the honest JWTs accepted, and no
//! other source after a failed one.

use serde_json::{json, Value};
use siros_oid4vp::RequestSignature;
use siros_transaction_data::{
    CredentialMetadataFault, FetchFault, Incompatibility, KeySetFault, Selection, SignedFault,
    SourceKind, TransactionDataError,
};

use crate::common::{
    configured, credential, display, entries, jwt, ok, query, store, Cert, Documents, Host, CARD,
    ISSUER, METADATA_URI,
};

const TYPE: &str = "urn:paso:sca:com.example:approval:1";

/// The definition the JWTs carry.
fn definition() -> Value {
    json!({"claims": [{"path": ["what"], "mandatory": true,
                       "display": [{"locale": "en", "name": "What"}]}]})
}

/// The claims of an honest ad-hoc metadata JWT for the card (Section 5.2), valid until 2027.
fn adhoc_claims() -> Value {
    json!({
        "iss": ISSUER, "sub": CARD, "format": "dc+sd-jwt", "iat": 1_790_000_000,
        "exp": 1_820_000_000, "transaction_data_type": TYPE, "metadata": definition()
    })
}

/// The certificates: the trusted root, the credential's issuer leaf, a metadata-signing leaf
/// of the issuer's Subject with a key of its own, and a second trusted root.
struct Pki {
    root: Cert,
    issuer: Cert,
    signer: Cert,
    other_root: Cert,
}

fn pki() -> Pki {
    let root = Cert::root("Bank Root", 1);
    let issuer = Cert::leaf("Bank Issuer", 2, &root);
    let signer = Cert::leaf("Bank Issuer", 3, &root);
    let other_root = Cert::root("Other Root", 4);
    Pki {
        root,
        issuer,
        signer,
        other_root,
    }
}

fn header(typ: &str, chain: &[&Cert]) -> Value {
    json!({"alg": "ES256", "typ": typ, "x5c": chain.iter().map(|c| c.x5c()).collect::<Vec<_>>()})
}

/// What the card of `chain`, under a trust store of both roots, takes of an entry of `TYPE`
/// carrying the ad-hoc JWT `metadata`; the configuration defines the type too.
fn adhoc(
    pki: &Pki,
    metadata: &str,
    chain: &[&Cert],
    signature: RequestSignature,
) -> Result<Selection, TransactionDataError> {
    adhoc_typed(pki, metadata, chain, signature, TYPE)
}

fn adhoc_typed(
    pki: &Pki,
    metadata: &str,
    chain: &[&Cert],
    signature: RequestSignature,
    type_id: &str,
) -> Result<Selection, TransactionDataError> {
    let mut host = Host::new(json!([configured(type_id, CARD, &definition())]));
    host.trust = store(&[&pki.root, &pki.other_root]);
    host.signature = signature;
    let entry = json!({"type": type_id, "credential_ids": ["card"], "payload": {"what": "Pay"},
                       "metadata": metadata});
    let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
    host.select(&[&entries[0]], &credential(CARD, chain))
}

/// The cause of the one entry `selection` excludes.
fn cause(selection: Selection) -> Incompatibility {
    match selection {
        Selection::Excluded(mut causes) => causes.remove(0).1,
        Selection::Takes(taken) => panic!("takes {:?}", taken.entry()),
    }
}

#[test]
fn each_adhoc_verification_step_refuses() {
    let pki = pki();
    let signed = |header: &Value, claims: &Value| jwt(header, claims, &pki.signer.key);
    let honest_header = header("adhoc-transaction-metadata+jwt", &[&pki.signer]);
    let claims_with = |name: &str, value: Value| {
        let mut claims = adhoc_claims();
        claims[name] = value;
        claims
    };
    let honest = signed(&honest_header, &adhoc_claims());
    let selection = adhoc(&pki, &honest, &[&pki.issuer], RequestSignature::Signed).unwrap();
    let Selection::Takes(taken) = selection else {
        panic!("the honest JWT")
    };
    assert_eq!(taken.view().source(), SourceKind::AdHoc);

    let stranger = Cert::leaf("Bank Issuer", 5, &pki.other_root);
    let other_subject = Cert::leaf("Someone Else", 6, &pki.root);
    let untrusted_root = Cert::root("Bank Root", 7);
    let untrusted = Cert::leaf("Bank Issuer", 8, &untrusted_root);
    let rows: Vec<(&str, String, SignedFault)> = vec![
        (
            "step 1: another typ",
            signed(
                &header("credential-metadata+jwt", &[&pki.signer]),
                &adhoc_claims(),
            ),
            SignedFault::Typ,
        ),
        (
            "step 2: a signature of another key",
            jwt(&honest_header, &adhoc_claims(), &pki.issuer.key),
            SignedFault::Signature,
        ),
        (
            "step 3: a kid where the issuer's keys are an x5c chain",
            signed(
                &json!({"alg": "ES256", "typ": "adhoc-transaction-metadata+jwt", "kid": "k1"}),
                &adhoc_claims(),
            ),
            SignedFault::KeyKind,
        ),
        (
            "step 3: both x5c and kid",
            signed(
                &{
                    let mut h = honest_header.clone();
                    h["kid"] = json!("k1");
                    h
                },
                &adhoc_claims(),
            ),
            SignedFault::KeyChoice,
        ),
        (
            "step 4: another iss",
            signed(
                &honest_header,
                &claims_with("iss", json!("https://other.example")),
            ),
            SignedFault::Issuer,
        ),
        (
            "step 5: an exp that has passed",
            signed(&honest_header, &claims_with("exp", json!(1_700_000_000))),
            SignedFault::Expired,
        ),
        (
            "step 6: a sub of another type",
            signed(
                &honest_header,
                &claims_with("sub", json!("https://bank.example/sca/account")),
            ),
            SignedFault::Subject,
        ),
        (
            "step 6: the device-signed namespace as sub",
            signed(&honest_header, &claims_with("sub", json!("urn:paso:sca:1"))),
            SignedFault::Subject,
        ),
        (
            "another format",
            signed(&honest_header, &claims_with("format", json!("mso_mdoc"))),
            SignedFault::Format,
        ),
        (
            "step 6: a chain to another trusted root",
            jwt(
                &header("adhoc-transaction-metadata+jwt", &[&stranger]),
                &adhoc_claims(),
                &stranger.key,
            ),
            SignedFault::Root,
        ),
        (
            "step 6: a leaf of another Subject",
            jwt(
                &header("adhoc-transaction-metadata+jwt", &[&other_subject]),
                &adhoc_claims(),
                &other_subject.key,
            ),
            SignedFault::LeafSubject,
        ),
        (
            "step 7: another transaction_data_type",
            signed(
                &honest_header,
                &claims_with(
                    "transaction_data_type",
                    json!("urn:paso:sca:global:payment:1"),
                ),
            ),
            SignedFault::TransactionDataType,
        ),
    ];
    for (case, metadata, fault) in rows {
        let selection = adhoc(&pki, &metadata, &[&pki.issuer], RequestSignature::Signed).unwrap();
        assert_eq!(cause(selection), Incompatibility::AdHoc(fault), "{case}");
    }
    // Step 3: a chain without a path to the trust store.
    let unanchored = jwt(
        &header("adhoc-transaction-metadata+jwt", &[&untrusted]),
        &adhoc_claims(),
        &untrusted.key,
    );
    let selection = adhoc(&pki, &unanchored, &[&pki.issuer], RequestSignature::Signed).unwrap();
    assert!(matches!(
        cause(selection),
        Incompatibility::AdHoc(SignedFault::Untrusted(_))
    ));

    // A request served by an ad-hoc JWT must be signed (PaSO Core, Section 3).
    let other_type = signed(
        &honest_header,
        &claims_with("transaction_data_type", json!("urn:example:approval")),
    );
    assert_eq!(
        adhoc_typed(
            &pki,
            &other_type,
            &[&pki.issuer],
            RequestSignature::Unsigned,
            "urn:example:approval"
        )
        .map(drop),
        Err(TransactionDataError::Unsigned(
            siros_transaction_data::EntryPosition::new(0)
        ))
    );
}

/// The `kid` branch: a credential without a chain, the key in its issuer's key set (Section 7,
/// step 3), each document a host fetch.
#[test]
fn a_kid_names_a_key_of_the_issuers_key_set() {
    let pki = pki();
    let key = &pki.signer.key;
    let point = key.verifying_key().to_encoded_point(false);
    let jwk = |kid: &str| {
        json!({"kty": "EC", "crv": "P-256", "kid": kid,
               "x": siros_codec::base64url::encode(point.x().unwrap()).as_str(),
               "y": siros_codec::base64url::encode(point.y().unwrap()).as_str()})
    };
    let metadata_url = "https://issuer.bank.example/.well-known/jwt-vc-issuer";
    let header = json!({"alg": "ES256", "typ": "adhoc-transaction-metadata+jwt", "kid": "k1"});
    let token = jwt(&header, &adhoc_claims(), key);
    let outcome = |keys: Value| {
        let mut host = Host::new(json!([]));
        host.documents = vec![(
            metadata_url.to_owned(),
            ok(json!({"issuer": ISSUER, "jwks": {"keys": keys}})
                .to_string()
                .as_bytes()),
        )];
        let entry = json!({"type": TYPE, "credential_ids": ["card"], "payload": {"what": "Pay"},
                           "metadata": token});
        let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
        host.select(&[&entries[0]], &credential(CARD, &[])).unwrap()
    };
    assert!(matches!(outcome(json!([jwk("k1")])), Selection::Takes(_)));
    assert_eq!(
        cause(outcome(json!([jwk("k2")]))),
        Incompatibility::AdHoc(SignedFault::KeySet(KeySetFault::KidUnknown))
    );
}

/// The signed credential metadata JWT, fetched from the configuration's
/// `credential_metadata_uri`: honest, it serves the type; invalid or absent, it excludes the
/// credential, the configuration notwithstanding (Section 7).
#[test]
fn signed_credential_metadata_serves_or_excludes() {
    let pki = pki();
    let claims = |exp: i64| {
        json!({
            "iss": ISSUER, "sub": CARD, "format": "dc+sd-jwt", "iat": 1_790_000_000, "exp": exp,
            "credential_metadata_uri": METADATA_URI,
            "credential_metadata": {"transaction_data_types": {TYPE: definition()}}
        })
    };
    let token = |exp: i64| {
        jwt(
            &header("credential-metadata+jwt", &[&pki.signer]),
            &claims(exp),
            &pki.signer.key,
        )
    };
    let outcome = |documents: Documents| {
        let mut host = Host::new(json!([configured(TYPE, CARD, &definition())]));
        host.trust = store(&[&pki.root]);
        host.display = display(Some(METADATA_URI));
        host.documents = documents;
        let entry = json!({"type": TYPE, "credential_ids": ["card"], "payload": {"what": "Pay"}});
        let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
        host.select(&[&entries[0]], &credential(CARD, &[&pki.issuer]))
            .unwrap()
    };
    let honest = outcome(vec![(
        METADATA_URI.to_owned(),
        ok(token(1_820_000_000).as_bytes()),
    )]);
    let Selection::Takes(taken) = honest else {
        panic!("the honest JWT")
    };
    assert_eq!(taken.view().source(), SourceKind::CredentialMetadata);
    assert_eq!(
        cause(outcome(vec![(
            METADATA_URI.to_owned(),
            ok(token(1_700_000_000).as_bytes())
        )])),
        Incompatibility::CredentialMetadata(CredentialMetadataFault::Invalid(SignedFault::Expired))
    );
    assert_eq!(
        cause(outcome(Vec::new())),
        Incompatibility::CredentialMetadata(CredentialMetadataFault::Fetch(FetchFault::Status(
            siros_oid4vp::HttpStatus::new(404)
        )))
    );
}
