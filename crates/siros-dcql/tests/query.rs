//! The query model's parse (§6.1–6.3): defaults, tolerated deviations, and the identifier rules.

// `expect` alongside `unwrap`: a test that states why it expects to succeed
// says what broke when it stops succeeding.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::{json, Value};
use siros_dcql::{
    DcqlQuery, HolderBinding, Multiplicity, QueryError, QueryId, QueryIdError, SetRequirement,
    TrustedAuthorityError,
};

/// Defaults the spec states explicitly, all of which change behaviour if
/// got wrong: a missing `required` would make a mandatory set optional,
/// and a missing `require_cryptographic_holder_binding` would silently
/// accept an unbound credential.
#[test]
fn omitted_fields_take_their_specified_defaults() {
    let q = DcqlQuery::from_json(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{}}],
            "credential_sets":[{"options":[["pid"]]}]}"#,
    )
    .unwrap();
    let c = &q.credentials()[0];
    assert_eq!(c.multiplicity(), Multiplicity::One);
    assert_eq!(c.holder_binding(), HolderBinding::Required);
    assert_eq!(
        q.credential_sets().unwrap()[0].requirement(),
        SetRequirement::Required
    );
}

/// "Implementations MUST ignore any unknown properties" (§6). A wallet
/// that rejects tomorrow's extension is worse than one that ignores it.
#[test]
fn unknown_properties_are_ignored() {
    let q = DcqlQuery::from_json(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{},
             "some_future_field":{"a":1}}],
            "another_future_field":[1,2,3]}"#,
    )
    .unwrap();
    assert_eq!(q.credentials().len(), 1);
}

/// `meta` is REQUIRED by the letter of §6.1, but an empty one means "no
/// constraints" — so a missing one asks for the same thing and is not
/// worth failing a request over.
#[test]
fn missing_meta_is_treated_as_no_constraints() {
    let q = DcqlQuery::from_json(r#"{"credentials":[{"id":"pid","format":"mso_mdoc"}]}"#).unwrap();
    assert!(q.credentials()[0].meta().is_empty());
}

/// §6.1: an `id` "MUST be unique across all Credential Query objects".
/// Without this check the duplicate changes what gets offered, because `credential_sets`
/// resolves a reference to whichever entry came first and the second is answered by nobody.
#[test]
fn duplicate_credential_ids_are_rejected() {
    let err = DcqlQuery::from_json(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc"},
                           {"id":"pid","format":"dc+sd-jwt"}]}"#,
    )
    .expect_err("a duplicated credential id is not usable");
    assert!(
        matches!(&err, QueryError::DuplicateCredentialId(id) if id == "pid"),
        "got {err:?}"
    );
}

/// §6.3: a claims `id` must be "unique within the particular claims
/// array". Same defect one level down — `claim_sets` refers to claims by
/// id, so a duplicate makes an option ambiguous.
#[test]
fn duplicate_claim_ids_are_rejected() {
    let err = DcqlQuery::from_json(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc","claims":[
             {"id":"a","path":["ns","given_name"]},
             {"id":"a","path":["ns","family_name"]}],
             "claim_sets":[["a"]]}]}"#,
    )
    .expect_err("a duplicated claim id is not usable");
    assert!(
        matches!(
            &err,
            QueryError::DuplicateClaimId { credential, claim }
                if credential == "pid" && claim == "a"
        ),
        "got {err:?}"
    );
}

/// Claims without ids are the ordinary case when there are no
/// `claim_sets`, and any number of them is fine — the uniqueness rule is
/// about ids.
#[test]
fn claims_without_ids_do_not_collide() {
    let q = DcqlQuery::from_json(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc","claims":[
             {"path":["ns","given_name"]},
             {"path":["ns","family_name"]}]}]}"#,
    )
    .expect("unidentified claims are not duplicates");
    assert_eq!(q.credentials()[0].claims().len(), 2);
}

/// §6.1: an `id` is "a non-empty string consisting of alphanumeric,
/// underscore (_), or hyphen (-) characters". One rule per row.
#[test]
fn credential_ids_follow_section_6_1() {
    let cases = [
        ("pid_1-a", Ok(())),
        ("", Err(QueryIdError::Empty)),
        ("eu.europa.ec.eudi.pid.1", Err(QueryIdError::Character('.'))),
        ("pïd", Err(QueryIdError::Character('ï'))),
    ];
    for (id, outcome) in cases {
        assert_eq!(QueryId::parse(id).map(drop), outcome, "{id:?}");
        let json = format!(r#"{{"credentials":[{{"id":"{id}","format":"mso_mdoc"}}]}}"#);
        let parsed = DcqlQuery::from_json(&json).map(drop).map_err(|e| match e {
            QueryError::Id(e) => Some(e),
            _ => None,
        });
        assert_eq!(parsed, outcome.map_err(Some), "{id:?}");
    }
}

/// A `credential_sets` option naming a query that does not exist is not
/// fatal either: an option the wallet cannot satisfy is one it does not
/// offer, which §6.4 already handles.
#[test]
fn a_dangling_credential_set_reference_is_tolerated() {
    let q = DcqlQuery::from_json(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc"}],
            "credential_sets":[{"options":[["pid"],["nonexistent"]]}]}"#,
    )
    .expect("a dangling reference is an option, not a contradiction");
    assert_eq!(q.credential_sets().map(<[_]>::len), Some(1));
}

/// `purpose` is why the verifier wants a combination, and the wallet's
/// only chance to tell the user. §6.2 allows a string, an integer or an
/// object, so all three have to survive parsing.
#[test]
fn purpose_is_kept_in_all_three_shapes() {
    let q = DcqlQuery::from_json(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc"}],
            "credential_sets":[
              {"options":[["pid"]],"purpose":"Proving your age"},
              {"options":[["pid"]],"purpose":1},
              {"options":[["pid"]],"purpose":{"id":1,"name":"Age check"}}]}"#,
    )
    .expect("valid DCQL");
    let sets = q.credential_sets().expect("sets");
    assert_eq!(
        sets[0].purpose(),
        Some(&Value::String("Proving your age".into()))
    );
    assert_eq!(sets[1].purpose(), Some(&Value::from(1)));
    assert_eq!(
        sets[2].purpose().and_then(|p| p.get("name")),
        Some(&Value::String("Age check".into()))
    );
    assert_eq!(
        serde_json::to_string(&sets[0]).expect("serialize"),
        r#"{"options":[["pid"]],"required":true,"purpose":"Proving your age"}"#,
        "purpose round-trips; a wallet passing the query on must not drop it"
    );
}

/// An absent `purpose` stays absent rather than serialising as null — a
/// verifier reading a re-encoded query should not see a field it never
/// sent.
#[test]
fn an_absent_purpose_is_not_serialised() {
    let q = DcqlQuery::from_json(
        r#"{"credentials":[{"id":"pid","format":"mso_mdoc"}],
            "credential_sets":[{"options":[["pid"]]}]}"#,
    )
    .expect("valid DCQL");
    let sets = q.credential_sets().expect("sets");
    assert!(sets[0].purpose().is_none());
    assert_eq!(
        serde_json::to_string(&sets[0]).expect("serialize"),
        r#"{"options":[["pid"]],"required":true}"#
    );
}

/// A full query round-trips, including mdoc paths and value filters.
#[test]
fn realistic_query_round_trips() {
    let json = r#"{"credentials":[{"id":"mdl","format":"mso_mdoc",
        "meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
        "claims":[{"id":"a","path":["org.iso.18013.5.1","age_over_18"],"values":[true]}],
        "claim_sets":[["a"]]}]}"#;
    let q = DcqlQuery::from_json(json).unwrap();
    let c = &q.credentials()[0];
    assert_eq!(c.claims()[0].values().unwrap()[0], Value::Bool(true));
    assert_eq!(c.claim_sets().unwrap()[0], vec!["a"]);
    assert_eq!(c.claim("a").unwrap().path().len(), 2);

    let back: DcqlQuery = serde_json::from_str(&serde_json::to_string(&q).unwrap()).unwrap();
    assert_eq!(back, q);
}

/// §6.1.1: `trusted_authorities` is a non-empty array of objects, each with a string `type` and
/// a non-empty array of string `values`. One rule per row; `null` reads as an absent member.
#[test]
fn trusted_authorities_follow_section_6_1_1() {
    let cases = [
        (
            json!([{"type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"]}]),
            None,
        ),
        (Value::Null, None),
        (
            json!({"type": "aki"}),
            Some(TrustedAuthorityError::NotArray),
        ),
        (json!([]), Some(TrustedAuthorityError::Empty)),
        (json!(["aki"]), Some(TrustedAuthorityError::EntryNotObject)),
        (
            json!([{"values": ["a"]}]),
            Some(TrustedAuthorityError::Type),
        ),
        (
            json!([{"type": "aki"}]),
            Some(TrustedAuthorityError::Values),
        ),
        (
            json!([{"type": "aki", "values": []}]),
            Some(TrustedAuthorityError::Values),
        ),
        (
            json!([{"type": "aki", "values": [1]}]),
            Some(TrustedAuthorityError::Values),
        ),
    ];
    for (authorities, expected) in cases {
        let query = json!({"credentials": [{"id": "pid", "format": "mso_mdoc",
            "trusted_authorities": authorities}]});
        let got = DcqlQuery::parse(&query).map(drop).map_err(|e| match e {
            QueryError::TrustedAuthorities { credential, error } if credential == "pid" => {
                Some(error)
            }
            _ => None,
        });
        assert_eq!(
            got,
            expected.map_or(Ok(()), |e| Err(Some(e))),
            "{authorities}"
        );
    }
}
