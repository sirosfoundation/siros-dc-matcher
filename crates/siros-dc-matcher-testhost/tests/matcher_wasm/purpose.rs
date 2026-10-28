//! The verifier's `purpose`, which reaches the picker as the disclaimer.

use super::*;

/// A request carrying `purpose`, so the reason reaches the picker.
fn request_with_purpose(purpose: Value) -> Vec<u8> {
    json!({"requests": [{
        "protocol": "openid4vp-v1-unsigned",
        "data": {"dcql_query": {
            "credentials": [{
                "id": "q1",
                "format": "mso_mdoc",
                "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
                "claims": [{"path": ["org.iso.18013.5.1", "age_over_18"]}]
            }],
            "credential_sets": [{"options": [["q1"]], "purpose": purpose}]
        }}
    }]})
    .to_string()
    .into_bytes()
}

/// §6.2 `purpose` reaches the host as the entry's disclaimer, so the picker
/// can tell the user what they are consenting to and not merely that they are.
#[test]
fn a_verifier_purpose_is_shown_on_the_entry() {
    let db = wallet(None);
    let captured = invoke(
        &db,
        request_with_purpose(json!("Confirming you are over 18")),
    );

    let entry = captured.entry("siros-0", 0).expect("an entry");
    assert_eq!(
        entry.disclaimer.as_deref(),
        Some("Confirming you are over 18")
    );
    assert_eq!(entry.warning, None, "a reason to ask is not a warning");
}

/// A verifier that gives no reason produces a null pointer, not a pointer to
/// an empty string.
///
/// The distinction is the v0.6.1 bug exactly: the host renders the *presence*
/// of this field, so an empty string draws a label with nothing in it. Every
/// entry carried a warning triangle that way, on a real Pixel, for two
/// releases.
#[test]
fn no_purpose_means_a_null_disclaimer_not_an_empty_one() {
    let db = wallet(None);
    let captured = invoke(
        &db,
        request(
            "mso_mdoc",
            json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
        ),
    );

    let entry = captured.entry("siros-0", 0).expect("an entry");
    assert_eq!(
        entry.disclaimer, None,
        "absent must be a null pointer; Some(\"\") is what put a badge on \
         every entry before v0.6.2"
    );
    assert_eq!(entry.warning, None);
}

/// A verifier that sends `purpose: ""` is saying nothing, and must be treated
/// as such rather than passed through into a blank label — the same bug,
/// arriving from the other side.
#[test]
fn an_empty_purpose_is_treated_as_no_purpose() {
    let db = wallet(None);
    let captured = invoke(&db, request_with_purpose(json!("   ")));

    let entry = captured.entry("siros-0", 0).expect("an entry");
    assert_eq!(entry.disclaimer, None);
}

/// §6.2's object and integer forms are machine-readable identifiers, and they
/// do not go on the consent screen.
///
/// Established by looking: before this rule, an object purpose put
/// `{"id":7,"name":"Age verification"}` on a real Pixel's share sheet, under
/// the list of attributes about to be disclosed. The application still gets it
/// over the FFI, where a lookup is possible; the picker shows nothing rather
/// than showing that.
#[test]
fn a_machine_readable_purpose_is_not_put_on_the_consent_screen() {
    let db = wallet(None);
    let captured = invoke(&db, request_with_purpose(json!({"id": 7})));

    let entry = captured.entry("siros-0", 0).expect("an entry");
    assert_eq!(entry.disclaimer, None);
    assert_eq!(entry.warning, None);
}
