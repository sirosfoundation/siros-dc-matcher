//! Claims path pointers (§7): the §7.1.1 processing over JSON, and the §7.2 mdoc form.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use serde_json::json;
use siros_dcql::{mdoc_components, resolve_json, ComponentIndex, PathComponent, PathError};

fn key(k: &str) -> PathComponent {
    PathComponent::Key(k.to_string())
}

/// The example from §7's own text: a nested object claim.
#[test]
fn selects_a_nested_key() {
    let c = json!({"address": {"street_address": "Weidenstraße 22"}});
    let got = resolve_json(&c, &[key("address"), key("street_address")]).unwrap();
    assert_eq!(got, vec![&json!("Weidenstraße 22")]);
}

/// Null selects every element of an array (§7.1 "all elements").
#[test]
fn null_selects_all_array_elements() {
    let c = json!({"degrees": [{"type": "BA"}, {"type": "MA"}]});
    let got = resolve_json(&c, &[key("degrees"), PathComponent::Null, key("type")]).unwrap();
    assert_eq!(got, vec![&json!("BA"), &json!("MA")]);
}

#[test]
fn integer_selects_one_array_element() {
    let c = json!({"degrees": [{"type": "BA"}, {"type": "MA"}]});
    let got = resolve_json(&c, &[key("degrees"), PathComponent::Index(1), key("type")]).unwrap();
    assert_eq!(got, vec![&json!("MA")]);
}

/// §7.1.1 2.1 — a key that does not exist removes the element from the
/// selection. With nothing left, step 3 makes that an Empty error, which
/// is a different thing from the query being malformed.
#[test]
fn missing_key_is_empty_not_a_type_error() {
    let c = json!({"given_name": "Erika"});
    assert_eq!(
        resolve_json(&c, &[key("family_name")]),
        Err(PathError::Empty)
    );
}

/// A missing key removes only *that* element; siblings survive. This is
/// the case that separates "remove from selection" from "abort".
#[test]
fn missing_key_removes_only_the_element_that_lacks_it() {
    let c = json!({"degrees": [{"type": "BA"}, {"other": "x"}, {"type": "MA"}]});
    let got = resolve_json(&c, &[key("degrees"), PathComponent::Null, key("type")]).unwrap();
    assert_eq!(got, vec![&json!("BA"), &json!("MA")]);
}

/// §7.1.1 2.3 — an out-of-range index removes the array from the
/// selection rather than aborting.
#[test]
fn out_of_range_index_is_empty_not_a_type_error() {
    let c = json!({"degrees": [{"type": "BA"}]});
    assert_eq!(
        resolve_json(&c, &[key("degrees"), PathComponent::Index(7)]),
        Err(PathError::Empty)
    );
}

/// §7.1.1 2.1 — a string component applied to a non-object aborts.
#[test]
fn string_component_on_a_non_object_aborts() {
    let c = json!({"name": "Erika"});
    assert_eq!(
        resolve_json(&c, &[key("name"), key("first")]),
        Err(PathError::TypeMismatch {
            at: ComponentIndex::new(1)
        })
    );
}

/// §7.1.1 2.2 and 2.3 — null or an index on a non-array aborts.
#[test]
fn null_or_index_on_a_non_array_aborts() {
    let c = json!({"name": "Erika"});
    assert_eq!(
        resolve_json(&c, &[key("name"), PathComponent::Null]),
        Err(PathError::TypeMismatch {
            at: ComponentIndex::new(1)
        })
    );
    assert_eq!(
        resolve_json(&c, &[key("name"), PathComponent::Index(0)]),
        Err(PathError::TypeMismatch {
            at: ComponentIndex::new(1)
        })
    );
}

/// An empty array yields nothing, but that only becomes an error at step
/// 3 — it is not a type mismatch.
#[test]
fn null_over_an_empty_array_is_empty_not_a_type_error() {
    let c = json!({"degrees": []});
    assert_eq!(
        resolve_json(&c, &[key("degrees"), PathComponent::Null]),
        Err(PathError::Empty)
    );
}

/// §7 — "A claims path pointer MUST be a non-empty array". An empty one
/// would otherwise return the whole credential.
#[test]
fn an_empty_pointer_is_malformed_not_the_whole_credential() {
    let c = json!({"given_name": "Erika", "family_name": "Mustermann"});
    assert_eq!(resolve_json(&c, &[]), Err(PathError::Malformed));
}

/// §7.2.1 step 1 — mdoc pointers are exactly two strings.
#[test]
fn mdoc_path_must_be_exactly_two_strings() {
    assert_eq!(
        mdoc_components(&[key("org.iso.18013.5.1"), key("family_name")]),
        Ok(("org.iso.18013.5.1", "family_name"))
    );
    assert_eq!(
        mdoc_components(&[key("only_one")]),
        Err(PathError::Malformed)
    );
    assert_eq!(
        mdoc_components(&[key("a"), key("b"), key("c")]),
        Err(PathError::Malformed)
    );
    assert_eq!(
        mdoc_components(&[key("ns"), PathComponent::Index(0)]),
        Err(PathError::Malformed)
    );
    assert_eq!(mdoc_components(&[]), Err(PathError::Malformed));
}

/// The dotted ISO namespace stays one component. Flattening it and
/// splitting on the first dot yields namespace `org`, which matches
/// nothing while looking entirely reasonable.
#[test]
fn dotted_iso_namespace_is_one_component() {
    let path = [key("org.iso.18013.5.1"), key("age_over_18")];
    let (ns, id) = mdoc_components(&path).unwrap();
    assert_eq!(ns, "org.iso.18013.5.1");
    assert_eq!(id, "age_over_18");
}

/// Wire form: strings, integers and nulls all round-trip.
#[test]
fn components_deserialise_from_the_wire_form() {
    let p: Vec<PathComponent> = serde_json::from_str(r#"["degrees", null, 0, "type"]"#).unwrap();
    assert_eq!(
        p,
        vec![
            key("degrees"),
            PathComponent::Null,
            PathComponent::Index(0),
            key("type")
        ]
    );
    assert_eq!(
        serde_json::to_string(&p).unwrap(),
        r#"["degrees",null,0,"type"]"#
    );
}
