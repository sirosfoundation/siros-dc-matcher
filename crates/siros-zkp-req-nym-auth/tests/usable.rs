//! N3: a usable attestation takes only the admission of its own Document Signer for its own
//! query.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use serde_json::{json, Value};
use siros_codec::date::DateTime;
use siros_dcql::DcqlQuery;
use siros_mdoc::Mdoc;
use siros_trust::{AdmittedIssuer, IssuerChain, QueryAuthorities, TrustStore};
use siros_zkp_req_nym_auth::attestation::{OtherIssuer, TestedAttestation, UsableAttestation};
use support::*;

/// The admission, for the Credential Query `query`, of the issuer whose chain is `der`.
fn admitted(query: &Value, der: &[u8], now: DateTime) -> AdmittedIssuer {
    let dcql = DcqlQuery::parse(&json!({"credentials": [query]})).unwrap();
    let authorities = QueryAuthorities::of(&dcql.credentials()[0]).unwrap();
    let chain = IssuerChain::parse([der]).unwrap();
    let store = TrustStore::parse("[]").unwrap();
    AdmittedIssuer::resolve(&authorities, Some(&chain), &store, now).unwrap()
}

#[test]
fn the_admission_of_another_certificate_or_query_is_refused() {
    let now = DateTime::from_unix(NOW).unwrap();
    let query = query(None, false);
    let nym = nym_query(&query);
    let ds = Issuer::root(0x11, "Test Document Signer");
    let other_signer = Issuer::root(0x22, "Another Document Signer");
    let mdoc = Mdoc::parse(&issue(&ds, &Spec::default())).unwrap();
    let mut other_query = query.clone();
    other_query["id"] = json!("other");
    let usable = |issuer: AdmittedIssuer| {
        let tested = TestedAttestation::of(&mdoc, now).unwrap();
        UsableAttestation::new(tested, issuer, &nym).map(drop)
    };

    assert_eq!(usable(admitted(&query, &ds.der, now)), Ok(()));
    assert_eq!(
        usable(admitted(&query, &other_signer.der, now)),
        Err(OtherIssuer::Certificate)
    );
    assert_eq!(
        usable(admitted(&other_query, &ds.der, now)),
        Err(OtherIssuer::Query)
    );
}
