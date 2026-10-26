//! The display metadata of a transaction data type: its claim metadata (EC TS12 v1.0.1,
//! Section 3.3.2) and its UI elements catalogue (Section 3.3.3).

use rustc_hash::FxHashSet;
use siros_display::{Locale, Localized};

use crate::error::TransactionDataError;
use crate::json::{Fields, Json};
use crate::view::Level;

/// The claim metadata and the UI labels of one transaction data type.
pub(crate) struct DisplayMetadata {
    pub(crate) claims: ClaimMetadata,
    pub(crate) ui_labels: UiLabels,
}

/// Claim metadata: for payload paths, a visualisation level and localised labels.
#[derive(Clone)]
pub(crate) struct ClaimMetadata(Vec<Claim>);

/// The metadata of one claim.
#[derive(Clone)]
pub(crate) struct Claim {
    path: Vec<String>,
    level: Option<Level>,
    labels: Vec<Label>,
}

/// A text for one locale.
#[derive(Clone)]
pub(crate) struct Label {
    locale: Locale,
    text: String,
}

impl Localized for Label {
    fn locale(&self) -> Option<&Locale> {
        Some(&self.locale)
    }
}

impl Label {
    /// The text.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

/// The UI elements catalogue. An element without an entry has no label.
#[derive(Clone)]
pub(crate) struct UiLabels {
    pub(crate) affirmative: Vec<Label>,
    pub(crate) denial: Vec<Label>,
    pub(crate) title: Vec<Label>,
    pub(crate) security_hint: Vec<Label>,
}

const CLAIMS: &str = "claims";
const UI_LABELS: &str = "ui_labels";

impl ClaimMetadata {
    /// The claim metadata of the array `value`: SD-JWT VC claim metadata (Section 9) with
    /// `visualisation` (EC TS12 v1.0.1, Section 3.3.2).
    ///
    /// A path through an array element (an index or `null`, SD-JWT VC Section 9.1) labels no
    /// row: the wallet shows an array whole.
    pub(crate) fn parse(value: Json) -> Result<Self, TransactionDataError> {
        let Json::Array(items) = value else {
            return Err(TransactionDataError::MetadataMalformed(CLAIMS));
        };
        let mut claims = Vec::new();
        for item in items {
            if let Some(claim) = Claim::parse(item)? {
                claims.push(claim);
            }
        }
        let mut paths = FxHashSet::default();
        if !claims.iter().all(|c| paths.insert(c.path.as_slice())) {
            return Err(TransactionDataError::MetadataMalformed(CLAIMS));
        }
        Ok(Self(claims))
    }

    /// The metadata of the claim at `path`.
    pub(crate) fn get(&self, path: &[String]) -> Option<&Claim> {
        self.0.iter().find(|c| c.path == path)
    }
}

impl Claim {
    /// The claim metadata `value`; `None` for a path through an array element.
    fn parse(value: Json) -> Result<Option<Self>, TransactionDataError> {
        let malformed = TransactionDataError::MetadataMalformed(CLAIMS);
        let Json::Object(object) = value else {
            return Err(malformed);
        };
        let mut fields = object.into_fields();
        let Some(Json::Array(components)) = fields.take("path") else {
            return Err(malformed);
        };
        let mut path = Vec::with_capacity(components.len());
        for component in components {
            match component {
                Json::String(key) => path.push(key),
                Json::Null => return Ok(None),
                Json::Number(n) if n.is_integer() && !n.text().starts_with('-') => return Ok(None),
                _ => return Err(malformed),
            }
        }
        if path.is_empty() {
            return Err(malformed);
        }
        let level = match fields.take("visualisation") {
            None => None,
            Some(Json::Number(n)) => {
                Some(n.text().parse().ok().and_then(Level::of).ok_or(malformed)?)
            }
            Some(_) => return Err(malformed),
        };
        let labels = match fields.take("display") {
            None => Vec::new(),
            Some(Json::Array(entries)) => entries
                .into_iter()
                .map(|entry| claim_label(entry).ok_or(malformed))
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(malformed),
        };
        Ok(Some(Self {
            path,
            level,
            labels,
        }))
    }

    /// The `visualisation` level, when the metadata sets one.
    pub(crate) fn level(&self) -> Option<Level> {
        self.level
    }

    /// The labels, one per locale.
    pub(crate) fn labels(&self) -> &[Label] {
        &self.labels
    }
}

/// A claim display entry: `label`, and a language tag in exactly one of `locale` (SD-JWT VC,
/// Section 9.2) and `lang` (EC TS12 v1.0.1, Section 2.3).
fn claim_label(entry: Json) -> Option<Label> {
    let Json::Object(object) = entry else {
        return None;
    };
    let mut fields = object.into_fields();
    let tag = match (fields.take("locale"), fields.take("lang")) {
        (Some(Json::String(tag)), None) | (None, Some(Json::String(tag))) => tag,
        _ => return None,
    };
    label(tag, fields.take("label"))
}

/// The label of `text` for the language tag `tag`.
fn label(tag: String, text: Option<Json>) -> Option<Label> {
    let Some(Json::String(text)) = text else {
        return None;
    };
    Some(Label {
        locale: Locale::parse(&tag).ok()?,
        text,
    })
}

impl UiLabels {
    /// The catalogue of the object `value`. An identifier other than the four of Section 3.3.3
    /// is passed over.
    pub(crate) fn parse(value: Json) -> Result<Self, TransactionDataError> {
        let Json::Object(object) = value else {
            return Err(TransactionDataError::MetadataMalformed(UI_LABELS));
        };
        let mut fields = object.into_fields();
        Ok(Self {
            affirmative: element(&mut fields, "affirmative_action_label", 30)?,
            denial: element(&mut fields, "denial_action_label", 30)?,
            title: element(&mut fields, "transaction_title", 50)?,
            security_hint: element(&mut fields, "security_hint", 250)?,
        })
    }
}

/// The labels of element `name`: an array of `{lang, value}`, each value at most `max`
/// characters (Section 3.3.3).
fn element(
    fields: &mut Fields,
    name: &str,
    max: usize,
) -> Result<Vec<Label>, TransactionDataError> {
    let malformed = TransactionDataError::MetadataMalformed(UI_LABELS);
    let entries = match fields.take(name) {
        None => return Ok(Vec::new()),
        Some(Json::Array(entries)) => entries,
        Some(_) => return Err(malformed),
    };
    entries
        .into_iter()
        .map(|entry| {
            let Json::Object(object) = entry else {
                return Err(malformed);
            };
            let mut fields = object.into_fields();
            let Some(Json::String(tag)) = fields.take("lang") else {
                return Err(malformed);
            };
            label(tag, fields.take("value"))
                .filter(|l| l.text.chars().count() <= max)
                .ok_or(malformed)
        })
        .collect()
}
