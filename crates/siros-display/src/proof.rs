//! Proof statement rows: what a `zkp_req` option asks the wallet to prove.

use serde_json::Value;
use siros_zkp_req::{QueryOption, ReqItem, ZkpReqQuery};

use crate::error::DisplayError;
use crate::field::{Field, FieldText, FIELD_MAX};
use crate::text::DisplayText;

/// The end of every row value. The rows come from a request whose signature nobody has
/// checked, so they state what is asked and nothing more.
const UNVERIFIED: &str = "(unverified request)";

/// One picker field per `_req` item of `option`, in the Verifier's order.
///
/// `age_check` shows its `range` and `pseudonym` its `config`, as given. Any other function
/// shows its `fn_id` as the label. The detail is clipped to fit with the `(unverified request)`
/// marker in [`FIELD_MAX`] characters, the label to [`FIELD_MAX`], each ending in an ellipsis
/// where clipped. The rows judge nothing: whether the request is acceptable is the wallet's
/// decision.
///
/// # Errors
///
/// [`DisplayError::OptionItemUnknown`] when `option` names an item `query` lacks.
// `inline` makes the matcher compile this function with its own copies of the std functions it
// calls. Compiled here, it brings a second copy of each into matcher.wasm.
#[inline]
pub fn rows(query: &ZkpReqQuery, option: &QueryOption) -> Result<Vec<Field>, DisplayError> {
    items(query, option)
        .map(|item| {
            let (label, detail) = parts(item?);
            // Clipping shortens the detail and keeps the marker.
            let value = match detail {
                None => FieldText::fit(UNVERIFIED),
                Some(detail) => FieldText::fit_within(&detail, FIELD_MAX - UNVERIFIED.len() - 1)
                    .marked(UNVERIFIED),
            };
            Ok(Field::new(FieldText::fit(label), Some(value)))
        })
        .collect()
}

/// The `_req` items `option` names, in the Verifier's order.
#[inline]
fn items<'q>(
    query: &'q ZkpReqQuery,
    option: &'q QueryOption,
) -> impl Iterator<Item = Result<&'q ReqItem, DisplayError>> {
    option.items().iter().map(move |&index| {
        query
            .item(index)
            .ok_or(DisplayError::OptionItemUnknown(index.value()))
    })
}

/// The label of `item` and the detail it shows.
#[inline]
fn parts(item: &ReqItem) -> (&str, Option<String>) {
    let param = |name: &str| item.params().get(name).and_then(Value::as_str);
    match item.fn_id().as_str() {
        "age_check" => ("Age check", param("range").map(|r| format!("age {r}"))),
        "pseudonym" => ("Pseudonym", param("config").map(|c| format!("config {c}"))),
        other => (other, None),
    }
}

/// A proof statement row of a request intake verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRow {
    label: DisplayText,
    value: Option<DisplayText>,
}

impl ProofRow {
    /// The label: the function's name.
    pub fn label(&self) -> &DisplayText {
        &self.label
    }

    /// The parameter the function shows; `None` for a function that shows none.
    pub fn value(&self) -> Option<&DisplayText> {
        self.value.as_ref()
    }
}

/// One row per `_req` item of `option`, in the Verifier's order, for a request intake verified.
///
/// Each row has the label and the detail of the picker's row, whole and without the marker.
///
/// # Errors
///
/// - [`DisplayError::OptionItemUnknown`] when `option` names an item `query` lacks.
/// - [`DisplayError::Text`] when a label or a detail is unsafe to show or too long.
pub fn verified_rows(
    query: &ZkpReqQuery,
    option: &QueryOption,
) -> Result<Vec<ProofRow>, DisplayError> {
    items(query, option)
        .map(|item| {
            let (label, detail) = parts(item?);
            Ok(ProofRow {
                label: DisplayText::label(label).map_err(DisplayError::Text)?,
                value: detail
                    .map(|detail| DisplayText::value(&detail))
                    .transpose()
                    .map_err(DisplayError::Text)?,
            })
        })
        .collect()
}
