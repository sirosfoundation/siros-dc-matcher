//! Rendering a verifier's stated purpose for display.
//!
//! OpenID4VP 1.0 §6.2 lets a credential set carry a `purpose`: why the
//! verifier wants this combination. It is the wallet's only chance to tell the
//! person consenting what the disclosure is *for*, so it is rendered here
//! rather than in each consumer — the picker shows it, the FFI hands it to the
//! app, and two renderings of the same field would eventually disagree about
//! what a verifier said.

use serde_json::Value;

/// One purpose as a string to show a user.
///
/// §6.2 permits "a string, integer or object". A string loses its JSON quotes;
/// anything else keeps its JSON form, because a verifier specific enough to
/// send an object is the last one whose reason should be dropped.
pub fn display(purpose: &Value) -> String {
    match purpose {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Every purpose behind one offered combination, as a single line to show on
/// the consent screen.
///
/// **Strings only.** §6.2's integer and object forms are machine-readable
/// purpose identifiers, to be looked up against whatever scheme the verifier
/// and wallet share — not sentences. Rendering one puts
/// `{"id":7,"name":"Age verification"}` in front of someone being asked to
/// hand over an identity document, which is worse than saying nothing: the
/// screen exists to be understood, and text nobody can read undermines the
/// part they *can*. Non-string reasons still reach the application through the
/// FFI, which is where a lookup can happen.
///
/// `None` when the verifier gave no usable reason, and *usable* is the
/// important word: a `purpose` of `""` is a present field with nothing in it,
/// and passing that on as a displayable string is how an entry ends up
/// carrying an empty label. The host renders the presence of such a field
/// rather than its content — that is what put a warning triangle on every
/// entry in v0.6.1 — so blank reasons are dropped here, at the point where
/// "the verifier said nothing" and "the verifier said nothing legible" become
/// the same answer.
pub fn line(purposes: &[Value]) -> Option<String> {
    let joined = purposes
        .iter()
        .filter_map(|p| match p {
            Value::String(s) => Some(s.trim()),
            _ => None,
        })
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        // A combination can satisfy several required credential sets, each
        // with its own reason. All of them apply to it, because the user
        // consents to the combination as a unit.
        .join(" · ");
    (!joined.is_empty()).then_some(joined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_string_purpose_loses_its_quotes() {
        assert_eq!(display(&json!("Proving your age")), "Proving your age");
    }

    #[test]
    fn a_non_string_purpose_keeps_its_json_form() {
        assert_eq!(display(&json!(7)), "7");
        assert_eq!(display(&json!({"id": 7})), r#"{"id":7}"#);
    }

    #[test]
    fn several_reasons_join_into_one_line() {
        let line = line(&[json!("Confirming your age"), json!("Addressing you")]);
        assert_eq!(
            line.as_deref(),
            Some("Confirming your age · Addressing you")
        );
    }

    /// The case that matters most, because getting it wrong is a bug we have
    /// already shipped once: an empty reason must be indistinguishable from no
    /// reason, or the entry carries a label with nothing in it.
    #[test]
    fn a_blank_reason_is_no_reason() {
        assert_eq!(line(&[]), None);
        assert_eq!(line(&[json!("")]), None);
        assert_eq!(line(&[json!("   ")]), None);
        assert_eq!(line(&[json!("\n\t ")]), None);
    }

    /// And a blank one among real ones does not leave a dangling separator.
    #[test]
    fn a_blank_reason_does_not_produce_a_stray_separator() {
        assert_eq!(
            line(&[json!("Age check"), json!(""), json!("Name check")]).as_deref(),
            Some("Age check · Name check")
        );
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(
            line(&[json!("  Age check  ")]).as_deref(),
            Some("Age check")
        );
    }

    /// A machine-readable reason is not consent-screen text.
    ///
    /// Verified on a Pixel before this rule existed: an object purpose put
    /// `{"id":7,"name":"Age verification"}` on the share sheet, directly under
    /// the list of attributes about to be disclosed. §6.2's integer and object
    /// forms are identifiers to look up, and the application still receives
    /// them over the FFI — the consent screen is the wrong place for them.
    #[test]
    fn a_machine_readable_reason_is_not_displayed() {
        assert_eq!(line(&[json!({"id": 7, "name": "Age verification"})]), None);
        assert_eq!(line(&[json!(7)]), None);
        assert_eq!(line(&[json!(["a", "b"])]), None);
    }

    /// And it does not suppress a legible reason sitting beside it.
    #[test]
    fn a_machine_readable_reason_does_not_hide_a_readable_one() {
        assert_eq!(
            line(&[json!({"id": 7}), json!("Confirming your age")]).as_deref(),
            Some("Confirming your age")
        );
    }

    /// `display` keeps rendering everything: it serves the FFI, where an
    /// application can interpret what a picker cannot show.
    #[test]
    fn display_still_renders_what_line_declines_to_show() {
        assert_eq!(display(&json!({"id": 7})), r#"{"id":7}"#);
        assert_eq!(line(&[json!({"id": 7})]), None);
    }
}
