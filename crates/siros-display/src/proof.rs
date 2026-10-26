//! Proof statement rows: what a `zkp_req` option asks the wallet to prove.

use serde_json::Value;
use siros_zkp_req::{QueryOption, ZkpReqQuery};

use crate::error::DisplayError;

/// The most characters of a row's label or value.
const ROW_MAX_CHARS: usize = 80;

/// The end of every row value. The rows come from a request whose signature nobody has
/// checked, so they state what is asked and nothing more.
const UNVERIFIED: &str = "(unverified request)";

/// One `(label, value)` row per `_req` item of `option`, in the Verifier's order.
///
/// `age_check` shows its `range` and `pseudonym` its `config`, as given. Any other function
/// shows its `fn_id` as the label. The detail is clipped to fit with the `(unverified request)`
/// marker in 80 characters, the label to 80, each ending in an ellipsis where clipped. The rows
/// judge nothing: whether the request is acceptable is the wallet's decision.
///
/// # Errors
///
/// [`DisplayError::OptionItemUnknown`] when `option` names an item `query` lacks.
// `inline` makes the matcher compile this function with its own copies of the std functions it
// calls. Compiled here, it brings a second copy of each into matcher.wasm.
#[inline]
pub fn rows(
    query: &ZkpReqQuery,
    option: &QueryOption,
) -> Result<Vec<(String, String)>, DisplayError> {
    let mut rows = Vec::with_capacity(option.items.len());
    for &index in &option.items {
        let item = query
            .items
            .get(index)
            .ok_or(DisplayError::OptionItemUnknown)?;
        let param = |name: &str| item.params.get(name).and_then(Value::as_str);
        let (label, detail) = match item.fn_id.as_str() {
            "age_check" => ("Age check", param("range").map(|r| format!("age {r}"))),
            "pseudonym" => ("Pseudonym", param("config").map(|c| format!("config {c}"))),
            other => (other, None),
        };
        // Clipping shortens the detail and keeps the marker.
        let value = match detail {
            None => UNVERIFIED.to_string(),
            Some(detail) => format!(
                "{} {UNVERIFIED}",
                clip(&detail, ROW_MAX_CHARS - UNVERIFIED.len() - 1)
            ),
        };
        rows.push((clip(label, ROW_MAX_CHARS), value));
    }
    Ok(rows)
}

/// At most `max` characters, ending in an ellipsis when cut.
#[inline]
fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// A proof statement row of a request intake verified: the picker's row without the
/// `(unverified request)` marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRow {
    label: String,
    value: String,
}

impl ProofRow {
    /// The label: the function's name.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The value: the parameter the function shows; empty for a function that shows none.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Whether the row shows clipped: its label fills 80 characters, or its value the width
    /// the marker leaves, and ends in an ellipsis.
    pub fn clipped(&self) -> bool {
        let full =
            |text: &str, max: usize| text.chars().count() == max && text.ends_with('\u{2026}');
        full(&self.label, ROW_MAX_CHARS) || full(&self.value, ROW_MAX_CHARS - UNVERIFIED.len() - 1)
    }
}

/// One row per `_req` item of `option`, in the Verifier's order, for a request intake verified:
/// each row [`rows`] gives, without the marker.
///
/// # Errors
///
/// [`DisplayError::OptionItemUnknown`] when `option` names an item `query` lacks.
// `inline`: see `rows`. Compiled here, it changes the code the matcher links for `rows`.
#[inline]
pub fn verified_rows(
    query: &ZkpReqQuery,
    option: &QueryOption,
) -> Result<Vec<ProofRow>, DisplayError> {
    Ok(rows(query, option)?
        .into_iter()
        .map(|(label, value)| {
            // `rows` ends each value with the marker, after a space when it shows a detail.
            let value = match value.strip_suffix(UNVERIFIED) {
                Some(rest) => rest.strip_suffix(' ').unwrap_or(rest).to_owned(),
                None => value,
            };
            ProofRow { label, value }
        })
        .collect())
}
