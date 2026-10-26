//! A verifier's stated purpose (OpenID4VP 1.0, Section 6.2 `purpose`).

use serde_json::Value;

/// One purpose as a string.
///
/// Section 6.2 permits "a string, integer or object". A string loses its JSON quotes; any other
/// value keeps its JSON form.
pub fn display(purpose: &Value) -> String {
    match purpose {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// The purposes of one offered combination as one line of the consent screen: the string
/// purposes, trimmed and joined by `" · "`.
///
/// The integer and object forms of Section 6.2 are identifiers for a scheme the verifier and
/// the wallet share, and are left out; [`display`] gives them to the application.
///
/// `None` when no string purpose holds more than whitespace. A blank purpose is no purpose: the
/// host shows a warning triangle for any line, a blank one included (v0.6.1).
// `inline`: see `proof::rows`.
#[inline]
pub fn line(purposes: &[Value]) -> Option<String> {
    let joined = purposes
        .iter()
        .filter_map(|p| match p {
            Value::String(s) => Some(s.trim()),
            _ => None,
        })
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        // A combination that satisfies several required credential sets has the purpose of
        // each: the user consents to the combination as a unit.
        .join(" · ");
    (!joined.is_empty()).then_some(joined)
}
