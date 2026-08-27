//! Tests for the host's own guards.
//!
//! The matcher under test cannot produce these failures on purpose, so the
//! guests here are written by hand in WebAssembly text. Without them the
//! guards are unexercised code — and a test host whose guards do not fire is
//! worth less than no test host, because it reports success either way.

use siros_dc_matcher_testhost::{run, Invocation};

/// A guest that adds one entry as `cred-a`, then attaches a field claiming
/// `cred-b`.
///
/// This is the shape of the real bug: the platform keys fields by credential
/// id as well as by set position, so a field carrying the wrong id never
/// attaches to the entry in a picker — and says nothing about it.
const MISMATCHED_FIELD_ID: &str = r#"
(module
  (import "credman_v2" "AddEntrySet" (func $add_set (param i32 i32)))
  (import "credman_v2" "AddEntryToSet"
    (func $add_entry (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)))
  (import "credman_v2" "AddFieldToEntrySet"
    (func $add_field (param i32 i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "set\00")
  (data (i32.const 32) "cred-a\00")
  (data (i32.const 48) "cred-b\00")
  (data (i32.const 64) "title\00")
  (data (i32.const 80) "subtitle\00")
  (data (i32.const 96) "\00")
  (data (i32.const 112) "Field\00")
  (data (i32.const 128) "Value\00")
  (func (export "_start")
    (call $add_set (i32.const 16) (i32.const 1))
    (call $add_entry
      (i32.const 32) (i32.const 96) (i32.const 0)
      (i32.const 64) (i32.const 80) (i32.const 96) (i32.const 96) (i32.const 96)
      (i32.const 16) (i32.const 0))
    (call $add_field
      (i32.const 48) (i32.const 112) (i32.const 128) (i32.const 16) (i32.const 0))))
"#;

/// The same guest, but with the field carrying the entry's own id.
const MATCHING_FIELD_ID: &str = r#"
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
  (func (export "_start")
    (call $add_set (i32.const 16) (i32.const 1))
    (call $add_entry
      (i32.const 32) (i32.const 96) (i32.const 0)
      (i32.const 64) (i32.const 80) (i32.const 96) (i32.const 96) (i32.const 96)
      (i32.const 16) (i32.const 0))
    (call $add_field
      (i32.const 32) (i32.const 112) (i32.const 128) (i32.const 16) (i32.const 0))))
"#;

/// A field naming a different credential than its entry is rejected, and the
/// error names both ids so the mismatch is obvious.
#[test]
fn field_with_a_mismatched_credential_id_is_rejected() {
    let err = run(MISMATCHED_FIELD_ID.as_bytes(), Invocation::default())
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
    let captured =
        run(MATCHING_FIELD_ID.as_bytes(), Invocation::default()).expect("host should accept it");
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
    let guest = MATCHING_FIELD_ID.replace(
        "(call $add_set (i32.const 16) (i32.const 1))",
        "(call $add_set (i32.const 16) (i32.const 0))",
    );
    let guest = guest.replace(
        "(call $add_entry\n      (i32.const 32) (i32.const 96) (i32.const 0)\n      (i32.const 64) (i32.const 80) (i32.const 96) (i32.const 96) (i32.const 96)\n      (i32.const 16) (i32.const 0))",
        "",
    );
    let err = run(guest.as_bytes(), Invocation::default())
        .expect_err("host should reject a field for an entry that does not exist");
    assert!(format!("{err:#}").contains("unknown entry"));
}
