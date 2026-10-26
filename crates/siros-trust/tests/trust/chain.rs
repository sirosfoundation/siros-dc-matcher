//! TR3's path validation, one case per rule, each refusal by its reason; and the picker's
//! admission from the TR5 facts, which must equal the wallet's in every case.

use serde_json::{json, Value};
use siros_codec::base64url;
use siros_dcql::AuthorityType;
use siros_trust::{
    Admission, AdmittedIssuer, CertificateIndex, ChainIndex, ChainRefusal, Ground, IssuerChain,
    IssuerFacts, KeyIdentifier, OnPath, PathRefusal, Refusal, StoreAuthority, StoreType,
    TrustStore,
};

use crate::support::{at, authorities, chain, store, Cert, Key, NOW};

const LIST: &str = "https://tl.example/eu";

/// One rule's case: the chain, the store, the query's `trusted_authorities`, and the outcome.
struct Case {
    name: &'static str,
    chain: IssuerChain,
    store: TrustStore,
    authorities: Value,
    expected: Result<Ground, Vec<Refusal<ChainRefusal>>>,
}

fn etsi_tl(value: &str) -> Value {
    json!([{"type": "etsi_tl", "values": [value]}])
}

fn listed() -> Ground {
    Ground::Store(StoreAuthority::new(
        StoreType::EtsiTl,
        siros_dcql::AuthorityValue::new(LIST),
    ))
}

fn path(refusal: PathRefusal) -> Result<Ground, Vec<Refusal<ChainRefusal>>> {
    Err(vec![Refusal::Issuer(ChainRefusal::Path(refusal))])
}

/// A Document Signer that `iaca` signs, and the store that lists `iaca` under [`LIST`].
fn signed_by(iaca: &Cert, edit: impl FnOnce(Cert) -> Cert) -> (IssuerChain, TrustStore) {
    let document_signer = edit(Cert::issued_by(
        "Test Document Signer",
        Key::p256(0x32),
        iaca,
    ));
    (
        chain(&[&document_signer]),
        store(&[("etsi_tl", LIST, &[iaca])]),
    )
}

fn case(
    name: &'static str,
    (chain, store): (IssuerChain, TrustStore),
    authorities: Value,
    expected: Result<Ground, Vec<Refusal<ChainRefusal>>>,
) -> Case {
    Case {
        name,
        chain,
        store,
        authorities,
        expected,
    }
}

fn cases() -> Vec<Case> {
    let iaca = Cert::root("Test IACA", Key::p256(0x31));
    let first = ChainIndex::new(0);
    let anchor = OnPath::Store(CertificateIndex::new(0));
    let p384_root = Cert::root("Test P-384 IACA", Key::p384(0x41));
    let intermediate =
        Cert::issued_by("Test intermediate", Key::p384(0x42), &p384_root).ca(Some(true));
    let leaf = Cert::issued_by("Test Document Signer", Key::p256(0x43), &intermediate);
    let named_key = [0x5a; 20];
    vec![
        case(
            "no trusted_authorities",
            signed_by(&iaca, |ds| ds),
            Value::Null,
            Ok(Ground::Unconstrained),
        ),
        case(
            "an aki value a chain certificate's AuthorityKeyIdentifier names",
            signed_by(&iaca, |ds| ds.aki(&named_key)),
            json!([{"type": "aki", "values": [base64url::encode(&named_key)]}]),
            Ok(Ground::KeyIdentifier(
                KeyIdentifier::new(&named_key).unwrap(),
            )),
        ),
        case(
            "a two-level chain admitted through a store entry",
            signed_by(&iaca, |ds| ds),
            etsi_tl(LIST),
            Ok(listed()),
        ),
        case(
            "a three-level chain, the intermediate in the chain, over P-384",
            (
                chain(&[&leaf, &intermediate]),
                store(&[("etsi_tl", LIST, &[&p384_root])]),
            ),
            etsi_tl(LIST),
            Ok(listed()),
        ),
        case(
            "an expired leaf",
            signed_by(&iaca, |ds| {
                ds.valid("2025-01-01T00:00:00Z", "2026-10-26T11:59:59Z")
            }),
            etsi_tl(LIST),
            path(PathRefusal::NotValid(OnPath::Chain(first))),
        ),
        case(
            "an expired anchor",
            signed_by(
                &iaca
                    .clone()
                    .valid("2024-01-01T00:00:00Z", "2026-10-26T11:59:59Z"),
                |ds| ds,
            ),
            etsi_tl(LIST),
            path(PathRefusal::NotValid(anchor)),
        ),
        case(
            "a signer without basicConstraints cA",
            signed_by(&iaca.clone().ca(None), |ds| ds),
            etsi_tl(LIST),
            path(PathRefusal::NotCa(anchor)),
        ),
        case(
            "a wrong signature",
            signed_by(&iaca, |ds| ds.signed_with(Key::p256(0x39))),
            etsi_tl(LIST),
            path(PathRefusal::Signature(first)),
        ),
        case(
            "an issuer-name mismatch",
            signed_by(&iaca, |ds| ds.issuer_named("Another IACA")),
            etsi_tl(LIST),
            path(PathRefusal::IssuerName(first)),
        ),
        case(
            "an unsupported signature algorithm",
            signed_by(&iaca, Cert::sha512_declared),
            etsi_tl(LIST),
            path(PathRefusal::Algorithm(first)),
        ),
        case(
            "a value without a store entry",
            signed_by(&iaca, |ds| ds),
            etsi_tl("https://tl.example/other"),
            Err(vec![Refusal::Issuer(ChainRefusal::NoStoreEntry)]),
        ),
        case(
            "an unknown type",
            signed_by(&iaca, |ds| ds),
            json!([{"type": "x_unknown", "values": [LIST]}]),
            Err(vec![Refusal::Type(AuthorityType::new("x_unknown"))]),
        ),
    ]
}

#[test]
fn each_rule_of_tr3() {
    let failures: Vec<String> = cases()
        .into_iter()
        .filter_map(|case| {
            let query = authorities(case.authorities);
            let got = AdmittedIssuer::resolve(&query, Some(&case.chain), &case.store, at(NOW))
                .map(|admitted| admitted.ground())
                .map_err(|unadmitted| unadmitted.refusals().to_vec());
            (got != case.expected)
                .then(|| format!("{}: got {got:?}, want {:?}", case.name, case.expected))
        })
        .collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// TR5: the facts the wallet records give the picker the wallet's admission, ground included,
/// for every case at the same time.
#[test]
fn the_picker_admits_from_the_facts_as_the_wallet_does() {
    let failures: Vec<String> = cases()
        .into_iter()
        .filter_map(|case| {
            let query = authorities(case.authorities);
            let wallet = AdmittedIssuer::resolve(&query, Some(&case.chain), &case.store, at(NOW))
                .map(|admitted| admitted.ground())
                .ok();
            let facts = IssuerFacts::at(Some(&case.chain), &case.store, at(NOW));
            let picker = Admission::of(&query, &facts)
                .map(|admission| admission.ground().clone())
                .ok();
            (wallet != picker)
                .then(|| format!("{}: wallet {wallet:?}, picker {picker:?}", case.name))
        })
        .collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
