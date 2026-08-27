//! Claims path pointers — OpenID4VP 1.0 §7.
//!
//! A claims path pointer identifies one or more claims inside a credential.
//! It is "a non-empty array of strings, nulls and non-negative integers"
//! (§7), and what those components mean depends on the credential format:
//! §7.1 defines JSON semantics, §7.2 defines ISO mdoc semantics.
//!
//! Both are implemented here so that callers holding ordinary JSON or mdoc
//! credentials do not each reinvent the processing rules — which is where the
//! subtle mistakes live, since the spec distinguishes carefully between
//! *removing an element from the selection* and *aborting with an error*.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One component of a claims path pointer (§7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathComponent {
    /// A key to select within an object.
    Key(String),
    /// An index to select within an array.
    Index(u64),
    /// All elements of the currently selected array(s).
    ///
    /// Serialises as JSON `null`, which is how it appears on the wire.
    Null,
}

impl PathComponent {
    /// The key, if this component is one.
    pub fn as_key(&self) -> Option<&str> {
        match self {
            Self::Key(k) => Some(k),
            _ => None,
        }
    }
}

// Deserialising `null` into a unit-like variant does not fall out of
// `untagged` on its own, so the two null-ish cases are handled explicitly.
impl<'de> serde::de::Deserialize<'de> for Box<PathComponent> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        PathComponent::deserialize(d).map(Box::new)
    }
}

/// Why a claims path pointer could not be processed.
///
/// The distinction matters: §7.1.1 says a *type* mismatch aborts processing,
/// while a *missing* key or index merely removes that element from the
/// selection. Collapsing the two would turn "this credential lacks the claim"
/// into "this query is malformed", and the caller responds differently to
/// each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// A component was applied to an element of the wrong kind — a string
    /// component to a non-object, or a null/integer to a non-array (§7.1.1).
    TypeMismatch {
        /// Index of the offending component within the pointer.
        at: usize,
    },
    /// Nothing was selected once the pointer had been fully processed
    /// (§7.1.1 step 3). Ordinarily this means the credential does not carry
    /// the claim.
    Empty,
    /// The pointer is not valid for this credential format — for mdoc, "does
    /// not contain exactly two components or one of the components is not a
    /// string" (§7.2.1 step 1).
    Malformed,
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TypeMismatch { at } => write!(f, "path component {at} applied to the wrong kind of element"),
            Self::Empty => write!(f, "path selected nothing"),
            Self::Malformed => write!(f, "path is not valid for this credential format"),
        }
    }
}

/// Process a claims path pointer against a JSON credential (§7.1.1).
///
/// Returns the selected elements. Follows the specified steps exactly,
/// including the asymmetry that gives this function its shape: a component of
/// the wrong *type* aborts, whereas a key or index that simply is not there
/// drops that element from the selection and processing continues.
///
/// # Errors
///
/// [`PathError::TypeMismatch`] per steps 2.1–2.3, and [`PathError::Empty`]
/// per step 3 when the selection ends up empty.
pub fn resolve_json<'a>(root: &'a Value, path: &[PathComponent]) -> Result<Vec<&'a Value>, PathError> {
    // Step 1: select the root element.
    let mut selected: Vec<&Value> = vec![root];

    // Step 2: process components from left to right.
    for (at, component) in path.iter().enumerate() {
        let mut next: Vec<&Value> = Vec::new();
        match component {
            // 2.1 — string: select the key. Non-object aborts; a missing key
            // removes that element rather than aborting.
            PathComponent::Key(key) => {
                for element in &selected {
                    let object = element.as_object().ok_or(PathError::TypeMismatch { at })?;
                    if let Some(v) = object.get(key) {
                        next.push(v);
                    }
                }
            }
            // 2.2 — null: select all elements of the selected array(s).
            // Non-array aborts. Note there is no "missing" case here: an
            // empty array contributes nothing and that is not an error yet.
            PathComponent::Null => {
                for element in &selected {
                    let array = element.as_array().ok_or(PathError::TypeMismatch { at })?;
                    next.extend(array.iter());
                }
            }
            // 2.3 — integer: select that index. Non-array aborts; an index
            // past the end removes that array rather than aborting.
            PathComponent::Index(i) => {
                for element in &selected {
                    let array = element.as_array().ok_or(PathError::TypeMismatch { at })?;
                    if let Some(v) = usize::try_from(*i).ok().and_then(|i| array.get(i)) {
                        next.push(v);
                    }
                }
            }
        }
        selected = next;
    }

    // Step 3: an empty selection is an error, not an empty result.
    if selected.is_empty() {
        return Err(PathError::Empty);
    }
    Ok(selected)
}

/// Validate a claims path pointer for an ISO mdoc credential (§7.2.1 step 1)
/// and return its `(namespace, data_element_identifier)`.
///
/// # Errors
///
/// [`PathError::Malformed`] unless the pointer is exactly two string
/// components.
///
/// Note what this rules out: an mdoc path may not use `null` or an index, and
/// may not be flattened to a single dotted string. ISO namespaces contain dots
/// themselves (`org.iso.18013.5.1`), so a flattened path cannot be split back
/// unambiguously — a mistake that yields namespace `org` and looks plausible
/// right up until nothing matches.
pub fn mdoc_components(path: &[PathComponent]) -> Result<(&str, &str), PathError> {
    match path {
        [PathComponent::Key(ns), PathComponent::Key(id)] => Ok((ns, id)),
        _ => Err(PathError::Malformed),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

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
        assert_eq!(resolve_json(&c, &[key("family_name")]), Err(PathError::Empty));
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
            Err(PathError::TypeMismatch { at: 1 })
        );
    }

    /// §7.1.1 2.2 and 2.3 — null or an index on a non-array aborts.
    #[test]
    fn null_or_index_on_a_non_array_aborts() {
        let c = json!({"name": "Erika"});
        assert_eq!(
            resolve_json(&c, &[key("name"), PathComponent::Null]),
            Err(PathError::TypeMismatch { at: 1 })
        );
        assert_eq!(
            resolve_json(&c, &[key("name"), PathComponent::Index(0)]),
            Err(PathError::TypeMismatch { at: 1 })
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

    /// §7.2.1 step 1 — mdoc pointers are exactly two strings.
    #[test]
    fn mdoc_path_must_be_exactly_two_strings() {
        assert_eq!(
            mdoc_components(&[key("org.iso.18013.5.1"), key("family_name")]),
            Ok(("org.iso.18013.5.1", "family_name"))
        );
        assert_eq!(mdoc_components(&[key("only_one")]), Err(PathError::Malformed));
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
        let (ns, id) = mdoc_components(&[key("org.iso.18013.5.1"), key("age_over_18")]).unwrap();
        assert_eq!(ns, "org.iso.18013.5.1");
        assert_eq!(id, "age_over_18");
    }

    /// Wire form: strings, integers and nulls all round-trip.
    #[test]
    fn components_deserialise_from_the_wire_form() {
        let p: Vec<PathComponent> = serde_json::from_str(r#"["degrees", null, 0, "type"]"#).unwrap();
        assert_eq!(
            p,
            vec![key("degrees"), PathComponent::Null, PathComponent::Index(0), key("type")]
        );
        assert_eq!(serde_json::to_string(&p).unwrap(), r#"["degrees",null,0,"type"]"#);
    }
}
