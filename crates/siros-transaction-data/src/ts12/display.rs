//! The display of a TS12 entry (EC TS12 v1.0.1, Sections 3.3.1 to 3.3.3).

use serde_json::Value as JsonValue;
use siros_codec::date::Date;
use siros_display::{preferred, DisplayText, Locale};

use crate::error::TransactionDataError;
use crate::json::{Json, Number};
use crate::kind::SupportedType;
use crate::labels::{DisplayMetadata, KeyPath, Label};
use crate::ts12::rules::ImageUrl;
use crate::view::{Frequency, Labels, Level, Row, RowValue, TransactionView};

/// The leaf parameters of a payload, each with its path in the entry.
pub(crate) struct Leaves {
    path: KeyPath,
    leaves: Vec<Leaf>,
}

/// A leaf parameter.
struct Leaf {
    path: KeyPath,
    value: LeafValue,
    /// The least prominent level the type allows, whatever the metadata sets: for a member its
    /// schema requires and the user must see.
    floor: Option<Level>,
}

enum LeafValue {
    Text(String),
    Number(String),
    Boolean(bool),
    Date(Date),
    Image(ImageUrl),
    Frequency(Frequency),
}

impl Leaves {
    /// The leaves below `payload`.
    pub(crate) fn payload() -> Self {
        Self {
            path: KeyPath::root("payload"),
            leaves: Vec::new(),
        }
    }

    fn push(&mut self, name: &str, value: LeafValue, floor: Option<Level>) {
        self.leaves.push(Leaf {
            path: self.path.child(name),
            value,
            floor,
        });
    }

    /// The string member `name`.
    pub(crate) fn text(&mut self, name: &str, value: &impl AsRef<str>, floor: Option<Level>) {
        self.push(name, LeafValue::Text(value.as_ref().to_owned()), floor);
    }

    /// The string member `name`, when present.
    pub(crate) fn optional_text(&mut self, name: &str, value: Option<&impl AsRef<str>>) {
        if let Some(value) = value {
            self.text(name, value, None);
        }
    }

    /// The date member `name`, when present.
    pub(crate) fn optional_date(&mut self, name: &str, value: Option<Date>) {
        if let Some(value) = value {
            self.push(name, LeafValue::Date(value), None);
        }
    }

    /// The image URL member `name`, when present.
    pub(crate) fn optional_image(&mut self, name: &str, value: Option<&ImageUrl>) {
        if let Some(value) = value {
            self.push(name, LeafValue::Image(value.clone()), None);
        }
    }

    /// The number member `name`.
    pub(crate) fn number(&mut self, name: &str, value: &Number, floor: Option<Level>) {
        self.push(name, LeafValue::Number(value.text().to_owned()), floor);
    }

    /// The number member `name`, when present.
    pub(crate) fn optional_number(&mut self, name: &str, value: Option<&Number>) {
        if let Some(value) = value {
            self.number(name, value, None);
        }
    }

    /// The boolean member `name`, when present.
    pub(crate) fn optional_boolean(&mut self, name: &str, value: Option<bool>) {
        if let Some(value) = value {
            self.push(name, LeafValue::Boolean(value), None);
        }
    }

    /// The frequency member `name`.
    pub(crate) fn frequency(&mut self, name: &str, value: Frequency) {
        self.push(name, LeafValue::Frequency(value), None);
    }

    /// The leaves of the object member `name`, which `leaves` adds.
    pub(crate) fn object(&mut self, name: &str, leaves: impl FnOnce(&mut Self)) {
        let child = self.path.child(name);
        let parent = std::mem::replace(&mut self.path, child);
        leaves(self);
        self.path = parent;
    }

    /// The members the schema of an object leaves open: an object's leaves, or the value of any
    /// other member as one leaf.
    pub(crate) fn rest(&mut self, members: &[(String, Json)]) {
        for (name, value) in members {
            match value {
                Json::Object(object) => {
                    self.object(name, |leaves| leaves.rest(object.members()));
                }
                Json::String(text) => self.text(name, text, None),
                Json::Number(number) => self.number(name, number, None),
                Json::Bool(b) => self.push(name, LeafValue::Boolean(*b), None),
                Json::Null | Json::Array(_) => {
                    self.push(name, LeafValue::Text(compact(value)), None)
                }
            }
        }
    }
}

/// The compact JSON text of `value`.
fn compact(value: &Json) -> String {
    let quoted = |text: &str| JsonValue::from(text).to_string();
    match value {
        Json::Null => "null".to_owned(),
        Json::Bool(b) => b.to_string(),
        Json::Number(number) => number.text().to_owned(),
        Json::String(text) => quoted(text),
        Json::Array(items) => format!(
            "[{}]",
            items.iter().map(compact).collect::<Vec<_>>().join(",")
        ),
        Json::Object(object) => {
            let members = object
                .members()
                .iter()
                .map(|(name, item)| format!("{}:{}", quoted(name), compact(item)))
                .collect::<Vec<_>>();
            format!("{{{}}}", members.join(","))
        }
    }
}

/// The view of an entry of type `transaction_type` with `leaves`.
///
/// A leaf takes the `visualisation` of its claim metadata, 3 when unset, raised to its floor.
/// It needs a localised name, except one the metadata marks 4, which is left out without one
/// (Section 3.3.1). The rows go by level, in schema order within a level. The required UI
/// element, `affirmative_action_label`, needs a localised label; an optional one without a
/// localised label is absent.
pub(crate) fn view(
    transaction_type: SupportedType,
    leaves: Leaves,
    metadata: &DisplayMetadata,
    preferences: &[Locale],
) -> Result<TransactionView, TransactionDataError> {
    let mut rows = leaves
        .leaves
        .into_iter()
        .filter_map(|leaf| row(leaf, metadata, preferences).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by_key(Row::level);
    let ui = &metadata.ui_labels;
    let labels = Labels {
        affirmative: preferred(preferences, &ui.affirmative)
            .ok_or(TransactionDataError::AffirmativeLabelMissing)
            .and_then(shown)?,
        denial: optional(preferences, &ui.denial)?,
        title: optional(preferences, &ui.title)?,
        security_hint: optional(preferences, &ui.security_hint)?,
    };
    Ok(TransactionView::new(transaction_type, labels, rows))
}

/// The row of `leaf`; `None` for a leaf without a localised name that the metadata marks 4.
fn row(
    leaf: Leaf,
    metadata: &DisplayMetadata,
    preferences: &[Locale],
) -> Result<Option<Row>, TransactionDataError> {
    let claim = metadata.claims.get(&leaf.path);
    let set = claim
        .and_then(|c| c.level())
        .unwrap_or(Level::Supplementary);
    let level = leaf.floor.map_or(set, |floor| set.min(floor));
    match claim.and_then(|c| preferred(preferences, c.labels())) {
        Some(label) => Ok(Some(Row::new(shown(label)?, leaf.value.shown()?, level))),
        None if claim.is_some() && level == Level::Omittable => Ok(None),
        None => Err(TransactionDataError::LabelMissing),
    }
}

/// The label of `labels` localised for the user's `preferences`, most preferred first (Section
/// 3.3.1); `None` without one.
fn optional(
    preferences: &[Locale],
    labels: &[Label],
) -> Result<Option<DisplayText>, TransactionDataError> {
    preferred(preferences, labels).map(shown).transpose()
}

/// `label` as display text.
fn shown(label: &Label) -> Result<DisplayText, TransactionDataError> {
    DisplayText::label(label.text()).map_err(TransactionDataError::LabelNotDisplayable)
}

impl LeafValue {
    /// The value of a row.
    fn shown(self) -> Result<RowValue, TransactionDataError> {
        let text = |text: &str| {
            DisplayText::value(text).map_err(TransactionDataError::ValueNotDisplayable)
        };
        Ok(match self {
            Self::Text(value) => RowValue::Text(text(&value)?),
            Self::Number(value) => RowValue::Number(text(&value)?),
            Self::Boolean(b) => RowValue::Boolean(b),
            Self::Date(date) => RowValue::Date(date),
            Self::Image(url) => RowValue::Image(url),
            Self::Frequency(f) => RowValue::Frequency(f),
        })
    }
}
