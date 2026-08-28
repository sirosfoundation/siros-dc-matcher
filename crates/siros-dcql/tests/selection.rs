//! Selection behaviour against the normative rules of OpenID4VP 1.0 §6.4.
//!
//! Each test names the rule it pins. The ones worth reading twice are the
//! two whose *absence* silently changes what a wallet offers: a credential
//! missing a requested claim must not be offered at all, and an absent
//! `credential_sets` means every query must be satisfied rather than none.

use serde_json::{json, Value};
use siros_dcql::{execute, DcqlQuery, ExactFormat, PathComponent, PathError};

/// A JSON credential, resolved with the §7.1 rules the crate provides.
struct JsonCredential {
    id: String,
    format: String,
    body: Value,
}

impl JsonCredential {
    fn new(id: &str, format: &str, body: Value) -> Self {
        Self {
            id: id.into(),
            format: format.into(),
            body,
        }
    }
}

impl siros_dcql::Credential for JsonCredential {
    fn id(&self) -> &str {
        &self.id
    }
    fn format(&self) -> &str {
        &self.format
    }
    fn claim(&self, path: &[PathComponent]) -> Result<Vec<Value>, PathError> {
        siros_dcql::resolve_json(&self.body, path).map(|v| v.into_iter().cloned().collect())
    }
}

fn pid(body: Value) -> JsonCredential {
    JsonCredential::new("pid-1", "dc+sd-jwt", body)
}

fn query(json: &str) -> DcqlQuery {
    DcqlQuery::from_json(json).expect("valid DCQL")
}

/// §6.4.1 — "If the Wallet cannot deliver all claims requested by the
/// Verifier according to these rules, it MUST NOT return the respective
/// Credential."
///
/// The rule this crate exists to get right: a credential lacking a requested
/// claim is not a weak match, it is not a match. Filtering on format and
/// metadata alone would offer it.
#[test]
fn credential_missing_a_requested_claim_is_not_offered() {
    let q = query(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
             "claims":[{"path":["given_name"]},{"path":["family_name"]}]}]}"#,
    );
    let creds = [pid(json!({"given_name": "Erika"}))];

    let r = execute(&q, &creds, &ExactFormat);
    assert!(r.query("c").unwrap().candidates.is_empty());
    assert!(!r.satisfiable);
}

#[test]
fn credential_with_every_requested_claim_is_offered() {
    let q = query(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
             "claims":[{"path":["given_name"]},{"path":["family_name"]}]}]}"#,
    );
    let creds = [pid(
        json!({"given_name": "Erika", "family_name": "Mustermann"}),
    )];

    let r = execute(&q, &creds, &ExactFormat);
    let c = &r.query("c").unwrap().candidates;
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].credential_id, "pid-1");
    assert_eq!(c[0].claims.len(), 2, "both claims should be disclosed");
    assert!(r.satisfiable);
}

/// §6.4.1 — "If `claims` is absent, the Verifier is requesting no claims that
/// are selectively disclosable". The credential still matches; it just
/// discloses nothing extra.
#[test]
fn absent_claims_matches_and_selects_nothing() {
    let q = query(r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{}}]}"#);
    let creds = [pid(json!({"given_name": "Erika"}))];

    let r = execute(&q, &creds, &ExactFormat);
    let c = &r.query("c").unwrap().candidates;
    assert_eq!(c.len(), 1);
    assert!(c[0].claims.is_empty());
}

/// §6.4.1 — "the Wallet SHOULD return the first option that it can satisfy",
/// the order expressing the verifier's preference. Least-disclosure ordering
/// only works if the first satisfiable option actually wins.
#[test]
fn claim_sets_take_the_first_satisfiable_option() {
    let q = query(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
             "claims":[{"id":"over18","path":["age_over_18"]},
                       {"id":"dob","path":["birth_date"]}],
             "claim_sets":[["over18"],["dob"]]}]}"#,
    );

    // Holds both: the privacy-preserving first option must win.
    let both = [pid(
        json!({"age_over_18": true, "birth_date": "1979-04-12"}),
    )];
    let r = execute(&q, &both, &ExactFormat);
    let claims = &r.query("c").unwrap().candidates[0].claims;
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].claim_id.as_deref(), Some("over18"));

    // Holds only the fallback: the second option is used.
    let dob_only = [pid(json!({"birth_date": "1979-04-12"}))];
    let r = execute(&q, &dob_only, &ExactFormat);
    let claims = &r.query("c").unwrap().candidates[0].claims;
    assert_eq!(claims[0].claim_id.as_deref(), Some("dob"));
}

/// §6.4.1 — "If the Wallet cannot satisfy any of the options, it MUST NOT
/// return any claims."
#[test]
fn no_satisfiable_claim_set_means_no_match() {
    let q = query(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
             "claims":[{"id":"over18","path":["age_over_18"]},
                       {"id":"dob","path":["birth_date"]}],
             "claim_sets":[["over18"],["dob"]]}]}"#,
    );
    let creds = [pid(json!({"given_name": "Erika"}))];

    let r = execute(&q, &creds, &ExactFormat);
    assert!(r.query("c").unwrap().candidates.is_empty());
}

/// §6.3 — value matching is exact in "type and value". A boolean `true` is
/// not the string `"true"`, and 1 is not `"1"`; a looser comparison would
/// disclose a claim the verifier did not ask for.
#[test]
fn value_matching_is_exact_in_type_and_value() {
    let q = query(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
             "claims":[{"path":["age_over_18"],"values":[true]}]}]}"#,
    );

    assert!(
        !execute(&q, &[pid(json!({"age_over_18": true}))], &ExactFormat)
            .query("c")
            .unwrap()
            .candidates
            .is_empty()
    );

    for wrong in [json!("true"), json!(1), json!(false)] {
        let creds = [pid(json!({"age_over_18": wrong}))];
        assert!(
            execute(&q, &creds, &ExactFormat)
                .query("c")
                .unwrap()
                .candidates
                .is_empty(),
            "value {wrong} should not match `true`"
        );
    }
}

/// §6.4 — "If `credential_sets` is not provided, the Verifier requests
/// presentations for all Credentials in `credentials`."
///
/// Absent is not "no constraint". Reading it that way would report a request
/// as satisfiable when half of it cannot be answered.
#[test]
fn absent_credential_sets_requires_every_query_to_be_satisfied() {
    let q = query(
        r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{}},
                           {"id":"b","format":"mso_mdoc","meta":{}}]}"#,
    );
    let only_a = [pid(json!({"given_name": "Erika"}))];

    let r = execute(&q, &only_a, &ExactFormat);
    assert!(r.query("a").unwrap().is_satisfied());
    assert!(!r.query("b").unwrap().is_satisfied());
    assert!(
        !r.satisfiable,
        "one unsatisfied query must fail the request"
    );
}

/// §6.4 — a required set needs one satisfiable option; an optional one
/// imposes nothing.
#[test]
fn credential_sets_require_one_satisfiable_option() {
    let q = query(
        r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{}},
                           {"id":"b","format":"mso_mdoc","meta":{}}],
            "credential_sets":[{"options":[["a"],["b"]]}]}"#,
    );
    let only_a = [pid(json!({"given_name": "Erika"}))];
    assert!(execute(&q, &only_a, &ExactFormat).satisfiable);

    // Both members of the single option are needed.
    let q_both = query(
        r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{}},
                           {"id":"b","format":"mso_mdoc","meta":{}}],
            "credential_sets":[{"options":[["a","b"]]}]}"#,
    );
    assert!(!execute(&q_both, &only_a, &ExactFormat).satisfiable);
}

#[test]
fn an_optional_credential_set_does_not_block_the_request() {
    let q = query(
        r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{}},
                           {"id":"b","format":"mso_mdoc","meta":{}}],
            "credential_sets":[{"options":[["a"]]},
                               {"options":[["b"]],"required":false}]}"#,
    );
    let only_a = [pid(json!({"given_name": "Erika"}))];

    let r = execute(&q, &only_a, &ExactFormat);
    assert!(
        r.satisfiable,
        "an optional set must not make the request fail"
    );
    assert!(!r.query("b").unwrap().is_satisfied());
}

/// §6.4.1 — "`claim_sets` MUST NOT be present if `claims` is absent." The
/// verifier asked for a combination of claims it never listed, so what it
/// wants cannot be determined and nothing is offered.
#[test]
fn claim_sets_without_claims_matches_nothing() {
    let q = query(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
             "claim_sets":[["nonexistent"]]}]}"#,
    );
    let creds = [pid(json!({"given_name": "Erika"}))];

    assert!(execute(&q, &creds, &ExactFormat)
        .query("c")
        .unwrap()
        .candidates
        .is_empty());
}

/// §6.1 — "Multiple Credential Queries in a request MAY request a
/// presentation of the same Credential."
#[test]
fn one_credential_can_answer_several_queries() {
    let q = query(
        r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["given_name"]}]},
                           {"id":"b","format":"dc+sd-jwt","meta":{},
                            "claims":[{"path":["family_name"]}]}]}"#,
    );
    let creds = [pid(
        json!({"given_name": "Erika", "family_name": "Mustermann"}),
    )];

    let r = execute(&q, &creds, &ExactFormat);
    assert_eq!(r.query("a").unwrap().candidates[0].credential_id, "pid-1");
    assert_eq!(r.query("b").unwrap().candidates[0].credential_id, "pid-1");
    assert!(r.satisfiable);
}

/// Every credential that qualifies is a candidate — choosing between them is
/// the wallet's and the user's business (§6.4 "User Interface
/// Considerations"), not the engine's.
#[test]
fn all_qualifying_credentials_are_returned_as_candidates() {
    let q = query(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
             "claims":[{"path":["given_name"]}]}]}"#,
    );
    let creds = [
        JsonCredential::new("pid-1", "dc+sd-jwt", json!({"given_name": "Erika"})),
        JsonCredential::new("pid-2", "dc+sd-jwt", json!({"given_name": "Max"})),
        JsonCredential::new("mdl-1", "mso_mdoc", json!({"given_name": "Erika"})),
    ];

    let ids: Vec<_> = execute(&q, &creds, &ExactFormat)
        .query("c")
        .unwrap()
        .candidates
        .iter()
        .map(|c| c.credential_id.clone())
        .collect();
    assert_eq!(ids, ["pid-1", "pid-2"], "the mdoc has the wrong format");
}

/// A path whose *type* is wrong for the credential aborts resolution (§7.1.1),
/// which must disqualify the credential rather than propagate as a panic.
#[test]
fn a_type_mismatched_path_disqualifies_without_panicking() {
    let q = query(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
             "claims":[{"path":["given_name","first"]}]}]}"#,
    );
    let creds = [pid(json!({"given_name": "Erika"}))];

    let r = execute(&q, &creds, &ExactFormat);
    assert!(r.query("c").unwrap().candidates.is_empty());
    assert!(!r.satisfiable);
}

/// An empty wallet satisfies nothing, and must not be reported otherwise.
#[test]
fn an_empty_wallet_satisfies_nothing() {
    let q = query(r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{}}]}"#);
    let creds: [JsonCredential; 0] = [];

    let r = execute(&q, &creds, &ExactFormat);
    assert!(!r.satisfiable);
    assert!(r.query("c").unwrap().candidates.is_empty());
}

/// §6 — `credentials` is REQUIRED and non-empty, but parsing does not enforce
/// it and every set check is vacuously true over an empty set. Without a
/// guard, an empty query reports as satisfiable and the picker offers an entry
/// backed by nothing.
#[test]
fn an_empty_query_is_not_satisfiable() {
    let q = query(r#"{"credentials":[]}"#);
    let creds = [pid(json!({"given_name": "Erika"}))];
    assert!(!execute(&q, &creds, &ExactFormat).satisfiable);
}

/// A request whose sets are all optional passes "all required sets satisfied"
/// vacuously. Conformant, and useless in a picker: the wallet would be offered
/// with no credential behind it.
#[test]
fn all_optional_sets_with_nothing_matching_is_not_satisfiable() {
    let q = query(
        r#"{"credentials":[{"id":"a","format":"mso_mdoc","meta":{}}],
            "credential_sets":[{"options":[["a"]],"required":false}]}"#,
    );
    let no_mdoc = [pid(json!({"given_name": "Erika"}))];

    let r = execute(&q, &no_mdoc, &ExactFormat);
    assert!(!r.query("a").unwrap().is_satisfied());
    assert!(!r.satisfiable);
}
