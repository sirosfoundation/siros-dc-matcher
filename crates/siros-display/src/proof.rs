//! Proof statement rows: what a `zkp_req` option asks the wallet to prove.

use serde_json::Value;
use siros_zkp_req::{QueryOption, ReqItem, ZkpReqQuery};

use crate::error::DisplayError;

/// The most characters of a row's label or value.
const ROW_MAX_CHARS: usize = 80;

/// The end of every row value the picker shows. The rows come from a request whose signature
/// nobody has checked, so they state what is asked and nothing more.
const UNVERIFIED: &str = "(unverified request)";

/// The most characters of a row's detail: the value with room for the [`UNVERIFIED`] marker.
const DETAIL_MAX_CHARS: usize = ROW_MAX_CHARS - UNVERIFIED.len() - 1;

/// One `(label, value)` row per `_req` item of `option`, in the Verifier's order, for the picker.
///
/// `age_check` shows its `range` and `pseudonym` its `config`, as given. Any other function
/// shows its `fn_id` as the label. The detail is clipped to fit with the [`UNVERIFIED`] marker
/// in 80 characters, the label to 80, each ending in an ellipsis where clipped. The rows judge
/// nothing: whether the request is acceptable is the wallet's decision.
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
        let (label, detail) = parts(item);
        // Clipping shortens the detail and keeps the marker.
        let value = match detail {
            None => UNVERIFIED.to_string(),
            Some(detail) => format!("{} {UNVERIFIED}", clip(&detail, DETAIL_MAX_CHARS)),
        };
        rows.push((clip(label, ROW_MAX_CHARS), value));
    }
    Ok(rows)
}

/// A proof statement row of a verified request: the picker's row without the marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRow {
    label: String,
    value: String,
    clipped: bool,
}

impl ProofRow {
    /// The label: the function's name.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The value: the parameter the function shows, empty for a function that shows none.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Whether the label or the value was clipped. The picker's row of the item is clipped
    /// exactly then.
    pub fn clipped(&self) -> bool {
        self.clipped
    }
}

/// One row per `_req` item of `option`, in the Verifier's order, for a request intake verified.
///
/// Each row is the row [`rows`] gives without the marker: the same label and detail, clipped at
/// the same lengths.
///
/// # Errors
///
/// [`DisplayError::OptionItemUnknown`] when `option` names an item `query` lacks.
pub fn verified_rows(
    query: &ZkpReqQuery,
    option: &QueryOption,
) -> Result<Vec<ProofRow>, DisplayError> {
    option
        .items
        .iter()
        .map(|&index| {
            let item = query
                .items
                .get(index)
                .ok_or(DisplayError::OptionItemUnknown)?;
            let (label, detail) = parts(item);
            let detail = detail.unwrap_or_default();
            let shown_label = clip(label, ROW_MAX_CHARS);
            let value = clip(&detail, DETAIL_MAX_CHARS);
            Ok(ProofRow {
                clipped: shown_label != label || value != detail,
                label: shown_label,
                value,
            })
        })
        .collect()
}

/// The label of `item` and the detail it shows.
#[inline]
fn parts(item: &ReqItem) -> (&str, Option<String>) {
    let param = |name: &str| item.params.get(name).and_then(Value::as_str);
    match item.fn_id.as_str() {
        "age_check" => ("Age check", param("range").map(|r| format!("age {r}"))),
        "pseudonym" => ("Pseudonym", param("config").map(|c| format!("config {c}"))),
        other => (other, None),
    }
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
