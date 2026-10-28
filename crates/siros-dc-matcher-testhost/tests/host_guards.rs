//! Tests for the host's own guards.
//!
//! The matcher under test cannot produce these failures on purpose, so the
//! guests here are written by hand in WebAssembly text. Without them the
//! guards are unexercised code — and a test host whose guards do not fire is
//! worth less than no test host, because it reports success either way.

use siros_dc_matcher_testhost::{run, CapturedEntry, Invocation};

/// A guest that adds one entry as `cred-a`, then attaches a field claiming
/// `field_cred_id`.
///
/// Passing the id in is what makes the mismatch case expressible: the shape of
/// the real bug is that the platform keys fields by credential id as well as by
/// set position, so a field carrying the wrong id never attaches to the entry
/// in a picker — and says nothing about it.
fn guest(field_cred_id: &str, with_entry: bool) -> String {
    let entry = if with_entry {
        "(call $add_entry
           (i32.const 32) (i32.const 96) (i32.const 0)
           (i32.const 64) (i32.const 80) (i32.const 96) (i32.const 96) (i32.const 96)
           (i32.const 16) (i32.const 0))"
    } else {
        ""
    };
    format!(
        r#"
(module
  (import "credman_v2" "AddEntrySet" (func $add_set (param i32 i32)))
  (import "credman_v2" "AddEntryToSet"
    (func $add_entry (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)))
  (import "credman_v2" "AddFieldToEntrySet"
    (func $add_field (param i32 i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "set\00")
  (data (i32.const 32) "cred-a\00")
  (data (i32.const 64) "title\00")
  (data (i32.const 80) "subtitle\00")
  (data (i32.const 96) "\00")
  (data (i32.const 112) "Field\00")
  (data (i32.const 128) "Value\00")
  (data (i32.const 144) "{field_cred_id}\00")
  (func (export "_start")
    (call $add_set (i32.const 16) (i32.const 1))
    {entry}
    (call $add_field
      (i32.const 144) (i32.const 112) (i32.const 128) (i32.const 16) (i32.const 0))))
"#
    )
}

/// A field naming a different credential than its entry is rejected, and the
/// error names both ids so the mismatch is obvious.
#[test]
fn field_with_a_mismatched_credential_id_is_rejected() {
    let err = run(guest("cred-b", true).as_bytes(), Invocation::default())
        .expect_err("host should reject a field carrying the wrong credential id");
    let text = format!("{err:#}");
    assert!(
        text.contains("cred-b"),
        "error should name the wrong id: {text}"
    );
    assert!(
        text.contains("cred-a"),
        "error should name the entry's id: {text}"
    );
}

/// The guard must not fire on correct guests, or it would simply be broken in
/// the other direction.
#[test]
fn field_with_the_entrys_credential_id_is_accepted() {
    let captured = run(guest("cred-a", true).as_bytes(), Invocation::default())
        .expect("host should accept it");
    let entry = captured.entry("set", 0).expect("one entry");
    assert_eq!(entry.credential_id, "cred-a");
    assert_eq!(
        entry.fields,
        vec![("Field".to_string(), "Value".to_string())]
    );
}

/// A field for an entry that was never added is a matcher bug; dropping it
/// silently would hide exactly that.
#[test]
fn field_for_an_unknown_entry_is_rejected() {
    let err = run(guest("cred-a", false).as_bytes(), Invocation::default())
        .expect_err("host should reject a field for an entry that does not exist");
    assert!(format!("{err:#}").contains("unknown entry"));
}

/// Two alternatives at `set[0]`, `cred-a` then `cred-b`, and a field, a
/// display text, a link and a delegation for `cred-b`.
const ALTERNATIVES: &str = r#"
(module
  (import "credman_v2" "AddEntrySet" (func $add_set (param i32 i32)))
  (import "credman_v2" "AddEntryToSet"
    (func $add_entry (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)))
  (import "credman_v2" "AddFieldToEntrySet"
    (func $add_field (param i32 i32 i32 i32 i32)))
  (import "credman_v5" "AddMetadataDisplayTextToEntrySet"
    (func $add_text (param i32 i32 i32 i32)))
  (import "credman_v6" "SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet"
    (func $add_link (param i32 i32 i32 i32 i32 i32)))
  (import "credman_v7" "SetDelegationTypeForEntryInSet"
    (func $delegate (param i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "set\00")
  (data (i32.const 32) "cred-a\00")
  (data (i32.const 48) "cred-b\00")
  (data (i32.const 64) "title\00")
  (data (i32.const 80) "subtitle\00")
  (data (i32.const 96) "\00")
  (data (i32.const 112) "Field\00")
  (data (i32.const 128) "Value\00")
  (data (i32.const 144) "Shown text\00")
  (data (i32.const 160) "Disclaimer\00")
  (data (i32.const 176) "Link text\00")
  (data (i32.const 192) "https://b.example\00")
  (func (export "_start")
    (call $add_set (i32.const 16) (i32.const 1))
    (call $add_entry
      (i32.const 32) (i32.const 96) (i32.const 0)
      (i32.const 64) (i32.const 80) (i32.const 96) (i32.const 96) (i32.const 96)
      (i32.const 16) (i32.const 0))
    (call $add_entry
      (i32.const 48) (i32.const 96) (i32.const 0)
      (i32.const 64) (i32.const 80) (i32.const 96) (i32.const 96) (i32.const 96)
      (i32.const 16) (i32.const 0))
    (call $add_field
      (i32.const 48) (i32.const 112) (i32.const 128) (i32.const 16) (i32.const 0))
    (call $add_text (i32.const 48) (i32.const 144) (i32.const 16) (i32.const 0))
    (call $add_link
      (i32.const 48) (i32.const 160) (i32.const 176) (i32.const 192)
      (i32.const 16) (i32.const 0))
    (call $delegate (i32.const 48) (i32.const 1) (i32.const 16) (i32.const 0))))
"#;

/// The platform keys entries by set, position and credential id, so every
/// call for the second alternative at a position attaches to that
/// alternative alone.
#[test]
fn calls_for_the_second_alternative_at_a_position_attach_to_it() {
    let captured = run(
        ALTERNATIVES.as_bytes(),
        Invocation {
            wasm_version: 7,
            ..Invocation::default()
        },
    )
    .expect("host should accept calls for either alternative");
    let alternative = |id: &str| {
        captured
            .entries
            .iter()
            .find(|e| e.credential_id == id)
            .unwrap_or_else(|| panic!("{id} was added"))
    };
    let (first, second) = (alternative("cred-a"), alternative("cred-b"));
    let attached = |e: &CapturedEntry| {
        (
            e.fields.clone(),
            e.metadata_display_text.clone(),
            e.link.clone(),
            e.delegation,
        )
    };
    assert_eq!(attached(first), (Vec::new(), None, None, None));
    assert_eq!(
        attached(second),
        (
            vec![("Field".to_string(), "Value".to_string())],
            Some("Shown text".to_string()),
            Some((
                "Disclaimer".to_string(),
                "Link text".to_string(),
                "https://b.example".to_string()
            )),
            Some(1)
        )
    );
}
